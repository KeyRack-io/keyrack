// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private line-based development harness. Not a cross-track IPC contract.
mod core;
mod credential;
mod fixture;
mod source;

use crate::core::creation::CreationPlan;
use crate::core::{Error, Limits, MonotonicClock, Operation, Signed, Worker};
use crate::source::{LocalFixture, Source, VaultFixture};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::VerifyingKey;
use keyrack_core::custody::Canonical;
use keyrack_core::{material::ParentWrappedMaterial, wrapping::WrappingIdentifier};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{self, BufRead, Write},
    sync::mpsc,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Generate {
        grant: String,
    },
    Execute {
        signed: Signed,
        principal: String,
        operation: Operation,
        input: String,
    },
    Fence {
        signed: Signed,
    },
}

fn write(value: &serde_json::Value) -> Result<(), Error> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, value).map_err(|_| Error::Material)?;
    stdout.write_all(b"\n").map_err(|_| Error::Material)?;
    stdout.flush().map_err(|_| Error::Material)
}

fn run() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || args[1] != "--provisional-harness" {
        return Err(Error::Context);
    }
    let public: [u8; 32] = STANDARD
        .decode(&args[2])
        .map_err(|_| Error::Authority)?
        .try_into()
        .map_err(|_| Error::Authority)?;
    let verifier = VerifyingKey::from_bytes(&public).map_err(|_| Error::Authority)?;
    let context = fixture::context();
    let descriptor = ParentWrappedMaterial::new(
        context.provider_ref.clone(),
        context.security_domain.clone(),
        context.parent,
        context.version,
        context.key_format.clone(),
        context.mechanism.clone(),
        WrappingIdentifier::new("fixture-only").unwrap(),
    )
    .map_err(|_| Error::Context)?;
    core::match_descriptor(&descriptor, &context)?;
    let token_file = match std::env::var("KEYRACK_WORKER_VAULT_TOKEN_FILE") {
        Ok(path) => Some(path),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => return Err(Error::Credential),
    };
    let native = token_file.is_some();
    let source = if let Some(token_file) = token_file {
        // The trusted launcher supplies the credential separately from stdin.
        let token = credential::load(std::path::Path::new(&token_file))?;
        let vault = VaultFixture::new(
            &std::env::var("VAULT_ADDR").map_err(|_| Error::Context)?,
            token,
            std::env::var("KEYRACK_WORKER_VAULT_PARENT").map_err(|_| Error::Context)?,
        )?;
        Source::Vault(Box::new(vault))
    } else {
        Source::Local(LocalFixture::new(&context)?)
    };
    let mut worker = Worker::new(
        verifier,
        context.security_domain.as_str().to_owned(),
        source,
        MonotonicClock::new(),
        Limits {
            resident_keys: 8,
            residence_ms: 60_000,
            uses_per_residency: 10_000,
            authority_horizon_ms: 60_000,
        },
    )?;
    if native {
        let plan: CreationPlan = serde_json::from_str(
            &std::env::var("KEYRACK_WORKER_CREATION_PLAN").map_err(|_| Error::Context)?,
        )
        .map_err(|_| Error::Context)?;
        worker.reserve_creation(plan, fixture::custody_context(&context))?;
    }
    // Output backpressure must never hold custody or block expiry/fencing. The
    // writer owns only operation results; saturation terminates and drops keys.
    let (out_tx, out_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        while let Ok(value) = out_rx.recv() {
            if write(&value).is_err() {
                break;
            }
        }
    });
    let emit = |value| out_tx.try_send(value).map_err(|_| Error::Limit);
    emit(
        json!({"event": "provisional_ready", "worker": worker.instance,
        "context_sha256": core::context_digest(&context)?, "pid": std::process::id(),
        "creation_request": worker.creation_request().map(|r| r.canonical_bytes().map(|b| STANDARD.encode(b))).transpose().map_err(|_| Error::Context)?,
        "custody_context": STANDARD.encode(fixture::custody_context(&context).canonical_bytes().map_err(|_| Error::Context)?),
        "observation_key": worker.observation_key().map(|k| STANDARD.encode(k.key.as_bytes()))}),
    )?;
    // Bounded queue and bounded frames. Reader owns no credentials or key bytes.
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        loop {
            let mut line = Vec::new();
            let result = read_frame(&mut input, &mut line);
            if result.is_err() {
                let _ = tx.send(Err(Error::Limit));
                break;
            }
            if line.is_empty() {
                break;
            }
            if tx.send(Ok(line)).is_err() {
                break;
            }
        }
    });
    loop {
        worker.expire();
        let frame = match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(result) => result?,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        };
        let result = match serde_json::from_slice::<Request>(&frame) {
            Ok(Request::Generate { grant }) => STANDARD.decode(grant)
                .map_err(|_| Error::Authority)
                .and_then(|bytes| worker.generate(&bytes))
                .and_then(|evidence| Ok(json!({
                    "creation": STANDARD.encode(evidence.result.canonical_bytes().map_err(|_| Error::Material)?),
                    "authority": STANDARD.encode(evidence.grant.canonical_bytes().map_err(|_| Error::Material)?),
                    "material": STANDARD.encode(evidence.material.canonical_bytes().map_err(|_| Error::Material)?),
                }))),
            Ok(Request::Execute {
                signed,
                principal,
                operation,
                input,
            }) => STANDARD
                .decode(input)
                .map_err(|_| Error::Context)
                .and_then(|input| worker.execute(&signed, &principal, &context, operation, &input))
                .map(|output| json!({"output": STANDARD.encode(output)})),
            Ok(Request::Fence { signed }) => worker
                .fence(&signed)
                .map(|observation| json!({"local_fence": observation})),
            Err(_) => Err(Error::Context),
        };
        emit(result.unwrap_or_else(|error| json!({"error": error.to_string()})))?;
    }
}

fn read_frame(reader: &mut impl BufRead, output: &mut Vec<u8>) -> Result<(), Error> {
    loop {
        let bytes = reader.fill_buf().map_err(|_| Error::Material)?;
        if bytes.is_empty() {
            return if output.is_empty() {
                Ok(())
            } else {
                Err(Error::Context)
            };
        }
        let end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1);
        let count = end.unwrap_or(bytes.len());
        if output.len() + count > 65_536 {
            return Err(Error::Limit);
        }
        output.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(());
        }
    }
}

fn main() {
    if let Err(error) = run() {
        // Static redacted errors only. Never print request bodies or provider errors.
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod frame_tests {
    use super::*;
    #[test]
    fn rejects_oversized_and_truncated_frames() {
        assert!(read_frame(&mut &vec![b'x'; 65_537][..], &mut Vec::new()).is_err());
        assert!(read_frame(&mut &b"{}"[..], &mut Vec::new()).is_err());
        assert!(read_frame(&mut &b"{}\n"[..], &mut Vec::new()).is_ok());
    }
}
