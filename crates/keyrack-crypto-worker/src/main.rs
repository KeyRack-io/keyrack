// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private line-based development harness. Not a cross-track IPC contract.
mod core;
mod credential;
mod delivery;
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
    io::{self, BufRead},
    sync::{mpsc, Arc},
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

// Drop stops and joins the writer before the worker's owned state disappears.
struct Stop<C: core::Clock> {
    delivery: Arc<delivery::Delivery<C>>,
    writer: Option<std::thread::JoinHandle<()>>,
}
impl<C: core::Clock> Drop for Stop<C> {
    fn drop(&mut self) {
        self.delivery.stop();
        if let Some(w) = self.writer.take() {
            let _ = w.join();
        }
    }
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
    let clock = Arc::new(MonotonicClock::new());
    let mut worker = Worker::new(
        verifier,
        context.security_domain.as_str().to_owned(),
        source,
        clock.clone(),
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
    let delivery = Arc::new(delivery::Delivery::new(worker.instance.clone(), clock));
    let writer = delivery::spawn(delivery.clone())?;
    let _stop = Stop {
        delivery: delivery.clone(),
        writer: Some(writer),
    };
    let emit = |value| delivery.control(&value);
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
        if delivery.stopped() {
            return Err(Error::Material);
        }
        let frame = match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(result) => result?,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        };
        let result = match serde_json::from_slice::<Request>(&frame) {
            Ok(Request::Generate { grant }) => STANDARD.decode(grant)
                .map_err(|_| Error::Authority)
                .and_then(|bytes| worker.generate(&bytes))
                .and_then(|evidence| {
                    let grant = &evidence.grant.claims;
                    let authority = delivery::Authority {
                        worker: worker.instance.clone(), generation: grant.authority.generation.get(),
                        sequence: grant.sequence.get(), grant_sha256: core::digest(&evidence.grant.canonical_bytes().map_err(|_| Error::Authority)?),
                        not_before: grant.validity.not_before, expires: grant.validity.not_after.min(grant.ancestor_not_after),
                    };
                    delivery.enqueue(delivery::Prepared::new(authority, &json!({
                    "creation": STANDARD.encode(evidence.result.canonical_bytes().map_err(|_| Error::Material)?),
                    "authority": STANDARD.encode(evidence.grant.canonical_bytes().map_err(|_| Error::Material)?),
                    "material": STANDARD.encode(evidence.material.canonical_bytes().map_err(|_| Error::Material)?),
                }))?)
                }),
            Ok(Request::Execute {
                signed,
                principal,
                operation,
                input,
            }) => STANDARD
                .decode(input)
                .map_err(|_| Error::Context)
                .and_then(|input| worker.execute_for_delivery(&signed, &principal, &context, operation, &input))
                .and_then(|(authority, output)| delivery.enqueue(delivery::Prepared::new(authority, &json!({"output": STANDARD.encode(output.as_slice())}))?)),
            Ok(Request::Fence { signed }) => delivery
                .fence(|| worker.fence(&signed))
                .and_then(|observation| emit(json!({"local_fence": observation}))),
            Err(_) => Err(Error::Context),
        };
        if let Err(error) = result {
            emit(json!({"error": error.to_string()}))?;
        }
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
