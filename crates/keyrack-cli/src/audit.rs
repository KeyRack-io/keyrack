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
    /// Verify a JSONL audit log's Ed25519 signatures and BLAKE3 hash chain.
    ///
    /// Each event is checked for a valid signature against the provided key and
    /// for correct linkage in the BLAKE3 hash chain.  Exits 0 only if every
    /// event passes both checks.
    Verify {
        /// Path to the JSONL audit log file.
        log_file: PathBuf,

        /// Path to the Ed25519 signing key file (exactly 32 raw bytes, same
        /// format the service writes when `audit_signing_key_path` is set).
        #[arg(long)]
        key: PathBuf,
    },
}

pub fn run(args: AuditArgs) -> anyhow::Result<()> {
    match args.command {
        AuditCommand::Verify { log_file, key } => verify(&log_file, &key),
    }
}

fn verify(log_file: &std::path::Path, key_path: &std::path::Path) -> anyhow::Result<()> {
    // ── Load the signing key (32-byte raw seed) ────────────────────────
    let key_bytes = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("cannot read key file {}: {e}", key_path.display()))?;

    anyhow::ensure!(
        key_bytes.len() == 32,
        "key file must be exactly 32 bytes, got {}",
        key_bytes.len()
    );

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key_bytes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // ── Read and verify JSONL ──────────────────────────────────────────
    let file = std::fs::File::open(log_file)
        .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", log_file.display()))?;
    let reader = std::io::BufReader::new(file);

    let mut total: u64 = 0;
    let mut failures: u64 = 0;
    // Hash chain: first event's previous_hash must be 64 hex zeros;
    // each subsequent event's previous_hash == hex(blake3(prev_sig_hex_bytes)).
    let mut expected_prev_hash = "0".repeat(64);

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

        let sig_ok = keyrack_core::audit::AuditSigner::verify_event(&event, &verifying_key);

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

        // Advance the expected hash for the next event using whatever
        // signature the current event records (even if invalid).
        if let Some(sig_hex) = &event.signature {
            expected_prev_hash = hex_encode(blake3::hash(sig_hex.as_bytes()).as_bytes());
        }
    }

    println!("\n{}/{total} events OK", total - failures);

    if failures > 0 {
        anyhow::bail!("{failures} event(s) failed verification");
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
