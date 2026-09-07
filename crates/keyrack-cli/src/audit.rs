// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of KeyRack.
//
// KeyRack is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// KeyRack is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with KeyRack. If not, see <https://www.gnu.org/licenses/>.
//
// Alternative commercial licensing is available; contact the Licensor.

//! Audit log subcommands: verify Ed25519 signatures and BLAKE3 hash chain.

use clap::{Args, Subcommand};
use std::io::BufRead as _;
use std::path::PathBuf;

#[derive(Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

#[derive(Subcommand)]
pub enum AuditCommand {
    /// Verify a JSONL audit log's BLAKE3 hash chain and, with `--key`, its
    /// Ed25519 signatures.
    ///
    /// The hash chain is always checked: `KeyRack` maintains it whether or not
    /// signing is enabled, and it needs no key, so tamper evidence is
    /// verifiable from the log alone. Pass `--key` to additionally verify
    /// authenticity. Exits 0 only if every event passes every check performed.
    Verify {
        /// Path to the JSONL audit log file.
        log_file: PathBuf,

        /// Path to the Ed25519 signing key file (exactly 32 raw bytes, same
        /// format the service writes when `audit_signing_key_path` is set).
        /// Omit to check the hash chain only.
        #[arg(long)]
        key: Option<PathBuf>,
    },
}

pub fn run(args: AuditArgs) -> anyhow::Result<()> {
    match args.command {
        AuditCommand::Verify { log_file, key } => verify(&log_file, key.as_deref()),
    }
}

fn load_verifying_key(key_path: &std::path::Path) -> anyhow::Result<ed25519_dalek::VerifyingKey> {
    let key_bytes = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("cannot read key file {}: {e}", key_path.display()))?;

    anyhow::ensure!(
        key_bytes.len() == 32,
        "key file must be exactly 32 bytes, got {}",
        key_bytes.len()
    );

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key_bytes);
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
}

fn verify(log_file: &std::path::Path, key_path: Option<&std::path::Path>) -> anyhow::Result<()> {
    // ── Load the signing key, when one was supplied ────────────────────
    // Without a key the chain is still fully checkable: KeyRack chains every
    // event regardless of whether signing is enabled.
    let verifying_key = key_path.map(load_verifying_key).transpose()?;

    // ── Read and verify JSONL ──────────────────────────────────────────
    let file = std::fs::File::open(log_file)
        .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", log_file.display()))?;
    let reader = std::io::BufReader::new(file);

    let mut total: u64 = 0;
    let mut failures: u64 = 0;
    // Hash chain: the first event's previous_hash must be the genesis hash;
    // each subsequent event's previous_hash must equal the preceding event's
    // chain link (blake3 over its signature hex when signed, over its
    // canonical JSON when not).
    let mut expected_prev_hash = keyrack_core::audit::CHAIN_GENESIS_HASH.to_string();

    for (line_idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| anyhow::anyhow!("I/O error reading log: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }

        let event_num = line_idx + 1;
        total += 1;

        let event: keyrack_core::audit::AuditEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                failures += 1;
                println!("event {event_num}: FAIL (malformed JSON: {e})");
                continue;
            }
        };

        let sig_ok = verifying_key.as_ref().map_or(true, |vk| {
            keyrack_core::audit::AuditSigner::verify_event(&event, vk)
        });

        let chain_ok = event
            .previous_hash
            .as_deref()
            .is_some_and(|h| h == expected_prev_hash);

        if sig_ok && chain_ok {
            println!("event {event_num}: OK");
        } else {
            failures += 1;
            if !sig_ok {
                println!("event {event_num}: FAIL (invalid signature)");
            }
            if !chain_ok {
                let got = event.previous_hash.as_deref().unwrap_or("<none>");
                println!(
                    "event {event_num}: FAIL (hash chain break — expected {expected_prev_hash}, got {got})"
                );
            }
        }

        // Advance the expected hash using whatever the current event records,
        // even if it failed, so a single bad event does not cascade into a
        // reported break on every event after it.
        expected_prev_hash = keyrack_core::audit::chain_link(&event);
    }

    let checked = if verifying_key.is_some() {
        "hash chain + Ed25519 signatures"
    } else {
        "hash chain only (no --key given; tamper evidence, not authenticity)"
    };
    println!(
        "\n{}/{total} events OK — checked {checked}",
        total - failures
    );

    if failures > 0 {
        anyhow::bail!("{failures} event(s) failed verification");
    }

    Ok(())
}
