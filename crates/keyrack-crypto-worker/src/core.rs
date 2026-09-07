// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private custody engine. No public API, persisted format, or integration receipt.
use std::{collections::HashMap, time::Instant};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signature, VerifyingKey};
use keyrack_core::{
    key::KeySpec,
    material::ParentWrappedMaterial,
    wrapping::{WrappedKeyFormat, WrappingContext, WrappingKeyPurpose},
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) mod creation;

pub(crate) const MAX_INPUT: usize = 16 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum Error {
    #[error("worker credential file must be a private regular file owned by worker uid")]
    Credential,
    #[error("invalid authority")]
    Authority,
    #[error("expired authority")]
    Expired,
    #[error("replayed or fenced request")]
    Replay,
    #[error("unsupported or mismatched context")]
    Context,
    #[error("material unavailable or unauthenticated")]
    Material,
    #[error("worker limit exceeded")]
    Limit,
    #[error("cryptographic operation failed")]
    Crypto,
}

pub(crate) trait Clock {
    fn millis(&self) -> u64;
}

impl<T: Clock> Clock for std::sync::Arc<T> {
    fn millis(&self) -> u64 {
        (**self).millis()
    }
}

pub(crate) struct MonotonicClock(Instant);
impl MonotonicClock {
    pub(crate) fn new() -> Self {
        Self(Instant::now())
    }
}
impl Clock for MonotonicClock {
    fn millis(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

// Deliberately neither Clone, Debug nor Serialize. No raw-key operation exists.
pub(crate) struct Secret(pub(crate) Zeroizing<Vec<u8>>);

pub(crate) trait MaterialSource {
    // Called only after independent authority checks. Must authenticate the
    // complete context before returning the secret, not just compare metadata.
    fn open(&mut self, context: &WrappingContext) -> Result<Secret, Error>;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Operation {
    Encrypt,
    Decrypt,
}

/// Private test-authority body, not a neutral authority contract. All deadlines
/// are offsets from this worker's monotonic boot, never caller-controlled clocks.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Grant {
    pub(crate) worker: String,
    pub(crate) principal: String,
    pub(crate) context_sha256: [u8; 32],
    pub(crate) operation: Operation,
    pub(crate) input_sha256: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) sequence: u64,
    pub(crate) not_before_ms: u64,
    pub(crate) expires_ms: u64,
    pub(crate) ancestor_expires_ms: u64,
    pub(crate) residency_until_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fence {
    pub(crate) worker: String,
    pub(crate) security_domain: String,
    pub(crate) generation: u64,
    pub(crate) expires_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub(crate) enum AuthorityMessage {
    Grant(Grant),
    Fence(Fence),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Signed {
    // Signature covers exact bytes, prefixed with a harness-only domain.
    pub(crate) body: String,
    pub(crate) signature: Vec<u8>,
}

pub(crate) const SIGNING_DOMAIN: &[u8] = b"KeyRack:UNAPPROVED-worker-harness-authority\0";

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn context_digest(context: &WrappingContext) -> Result<[u8; 32], Error> {
    Ok(digest(
        &context.canonical_bytes().map_err(|_| Error::Context)?,
    ))
}

/// Reuse the existing material descriptor without adding a worker lifecycle or
/// treating this structural match as proof of custody, authority or freshness.
pub(crate) fn match_descriptor(
    descriptor: &ParentWrappedMaterial,
    context: &WrappingContext,
) -> Result<(), Error> {
    if descriptor.provider_ref() != &context.provider_ref
        || descriptor.parent() != context.parent
        || descriptor.security_domain() != &context.security_domain
        || descriptor.wrapping_context_version() != context.version
        || descriptor.key_format() != &context.key_format
        || descriptor.mechanism() != &context.mechanism
    {
        return Err(Error::Context);
    }
    context.canonical_bytes().map_err(|_| Error::Context)?;
    Ok(())
}

struct Resident {
    key: Secret,
    lease: u64,
    until: u64,
    uses: u64,
}

/// Local observations only, deliberately distinct from creation evidence.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ResidencyCleanup {
    worker: String,
    context_sha256: [u8; 32],
    lease: u64,
    event: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct LocalFenceApplied {
    worker: String,
    security_domain: String,
    generation: u64,
    purged: Vec<ResidencyCleanup>,
    event: &'static str,
}

pub(crate) struct Limits {
    pub(crate) resident_keys: usize,
    pub(crate) residence_ms: u64,
    pub(crate) uses_per_residency: u64,
    pub(crate) authority_horizon_ms: u64,
}

pub(crate) struct Worker<S, C> {
    pub(crate) instance: String,
    domain: String,
    verifier: VerifyingKey,
    source: S,
    clock: C,
    limits: Limits,
    generation: Option<u64>,
    fenced: bool,
    sequence: u64,
    next_lease: u64,
    resident: HashMap<[u8; 32], Resident>,
    creation: Option<creation::Reservation>,
}

impl<S: MaterialSource, C: Clock> Worker<S, C> {
    pub(crate) fn new(
        verifier: VerifyingKey,
        domain: String,
        source: S,
        clock: C,
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.resident_keys == 0
            || limits.residence_ms == 0
            || limits.uses_per_residency == 0
            || limits.authority_horizon_ms == 0
        {
            return Err(Error::Limit);
        }
        let mut incarnation = [0; 32];
        OsRng.fill_bytes(&mut incarnation);
        let instance =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, incarnation);
        Ok(Self {
            instance,
            domain,
            verifier,
            source,
            clock,
            limits,
            generation: None,
            fenced: false,
            sequence: 0,
            next_lease: 0,
            resident: HashMap::new(),
            creation: None,
        })
    }

    fn verify(&self, signed: &Signed) -> Result<AuthorityMessage, Error> {
        if signed.body.len() > 4096 {
            return Err(Error::Limit);
        }
        let signature = Signature::from_slice(&signed.signature).map_err(|_| Error::Authority)?;
        let mut message = SIGNING_DOMAIN.to_vec();
        message.extend_from_slice(signed.body.as_bytes());
        self.verifier
            .verify_strict(&message, &signature)
            .map_err(|_| Error::Authority)?;
        serde_json::from_str(&signed.body).map_err(|_| Error::Authority)
    }

    fn check_time(&self, grant: &Grant) -> Result<(), Error> {
        let now = self.clock.millis();
        if now < grant.not_before_ms
            || now >= grant.expires_ms
            || now >= grant.ancestor_expires_ms
            || now >= grant.residency_until_ms
            || grant.expires_ms > now.saturating_add(self.limits.authority_horizon_ms)
        {
            return Err(Error::Expired);
        }
        Ok(())
    }

    /// Serialized execution: no caller can hold a key/lease or crypto task outside
    /// this mutable borrow. A fence cannot acknowledge until this call returns.
    pub(crate) fn execute(
        &mut self,
        signed: &Signed,
        principal: &str,
        context: &WrappingContext,
        operation: Operation,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.expire();
        let max_input = match operation {
            Operation::Encrypt => MAX_INPUT,
            Operation::Decrypt => MAX_INPUT + 28,
        };
        if input.len() > max_input {
            return Err(Error::Limit);
        }
        let AuthorityMessage::Grant(grant) = self.verify(signed)? else {
            return Err(Error::Authority);
        };
        let binding = context_digest(context)?;
        if grant.worker != self.instance
            || grant.principal != principal
            || principal.is_empty()
            || principal.len() > 256
            || grant.context_sha256 != binding
            || grant.operation != operation
            || grant.input_sha256 != digest(input)
            || context.security_domain.as_str() != self.domain
            || context.child_spec != KeySpec::Aes256
            || context.key_format != WrappedKeyFormat::RawSecret
            || context.purpose != WrappingKeyPurpose::EncryptDecrypt
        {
            return Err(Error::Authority);
        }
        self.check_time(&grant)?;
        if !self.creation_allows_use() {
            return Err(Error::Material);
        }
        if self.fenced
            || grant.generation == 0
            || grant.sequence <= self.sequence
            || self
                .generation
                .is_some_and(|generation| generation != grant.generation)
        {
            return Err(Error::Replay);
        }
        // Consume before materialization: failed attempts cannot replay an
        // operation whose outcome might be ambiguous to the coordinator.
        self.generation = Some(grant.generation);
        self.sequence = grant.sequence;
        if !self.resident.contains_key(&binding) {
            if self.resident.len() >= self.limits.resident_keys {
                return Err(Error::Limit);
            }
            let now = self.clock.millis();
            let key = self.source.open(context)?;
            if key.0.len() != 32 {
                return Err(Error::Material);
            }
            self.check_time(&grant)?;
            self.next_lease = self.next_lease.checked_add(1).ok_or(Error::Limit)?;
            self.resident.insert(
                binding,
                Resident {
                    key,
                    lease: self.next_lease,
                    until: grant
                        .residency_until_ms
                        .min(now.saturating_add(self.limits.residence_ms)),
                    uses: 0,
                },
            );
        }
        let resident = self.resident.get_mut(&binding).ok_or(Error::Material)?;
        if self.clock.millis() >= resident.until {
            self.remove(binding);
            return Err(Error::Expired);
        }
        if resident.uses >= self.limits.uses_per_residency {
            return Err(Error::Limit);
        }
        resident.uses += 1;
        // The primitive's temporary expanded key is scoped to this operation.
        let cipher = Aes256Gcm::new_from_slice(&resident.key.0).map_err(|_| Error::Crypto)?;
        let aad = context.canonical_bytes().map_err(|_| Error::Context)?;
        let output = match operation {
            Operation::Encrypt => {
                let mut nonce = [0; 12];
                OsRng.fill_bytes(&mut nonce);
                let encrypted = cipher
                    .encrypt(
                        &Nonce::from(nonce),
                        Payload {
                            msg: input,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| Error::Crypto)?;
                let mut output = nonce.to_vec();
                output.extend(encrypted);
                output
            }
            Operation::Decrypt => {
                if input.len() < 28 {
                    return Err(Error::Crypto);
                }
                cipher
                    .decrypt(
                        &Nonce::from(
                            <[u8; 12]>::try_from(&input[..12]).map_err(|_| Error::Crypto)?,
                        ),
                        Payload {
                            msg: &input[12..],
                            aad: &aad,
                        },
                    )
                    .map_err(|_| Error::Crypto)?
            }
        };
        // Suppress (and zeroize) even application plaintext if work outlasted
        // permission. Parent/network time cannot silently extend the lease.
        let output = Zeroizing::new(output);
        self.check_time(&grant)?;
        if self.clock.millis() >= self.resident[&binding].until {
            self.remove(binding);
            return Err(Error::Expired);
        }
        Ok(output.to_vec())
    }

    pub(crate) fn execute_for_delivery(
        &mut self,
        signed: &Signed,
        principal: &str,
        context: &WrappingContext,
        operation: Operation,
        input: &[u8],
    ) -> Result<(crate::delivery::Authority, Zeroizing<Vec<u8>>), Error> {
        let output = Zeroizing::new(self.execute(signed, principal, context, operation, input)?);
        let AuthorityMessage::Grant(g) = self.verify(signed)? else {
            return Err(Error::Authority);
        };
        let resident = self
            .resident
            .get(&context_digest(context)?)
            .ok_or(Error::Expired)?;
        Ok((
            crate::delivery::Authority {
                worker: g.worker,
                generation: g.generation,
                sequence: g.sequence,
                grant_sha256: digest(signed.body.as_bytes()),
                not_before: g.not_before_ms,
                expires: g
                    .expires_ms
                    .min(g.ancestor_expires_ms)
                    .min(g.residency_until_ms)
                    .min(resident.until),
            },
            output,
        ))
    }

    fn remove(&mut self, binding: [u8; 32]) -> Option<ResidencyCleanup> {
        self.resident.remove(&binding).map(|resident| {
            let lease = resident.lease;
            drop(resident); // Zeroizing buffer destroyed before observation.
            ResidencyCleanup {
                worker: self.instance.clone(),
                context_sha256: binding,
                lease,
                event: "local_secret_buffer_dropped",
            }
        })
    }

    pub(crate) fn expire(&mut self) -> Vec<ResidencyCleanup> {
        let now = self.clock.millis();
        let expired: Vec<_> = self
            .resident
            .iter()
            .filter(|(_, value)| now >= value.until)
            .map(|(key, _)| *key)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.remove(key))
            .collect()
    }

    pub(crate) fn fence(&mut self, signed: &Signed) -> Result<LocalFenceApplied, Error> {
        let AuthorityMessage::Fence(fence) = self.verify(signed)? else {
            return Err(Error::Authority);
        };
        if fence.worker != self.instance
            || fence.security_domain != self.domain
            || fence.expires_ms <= self.clock.millis()
        {
            return Err(Error::Authority);
        }
        if fence.generation == 0 || self.generation.is_some_and(|g| fence.generation <= g) {
            return Err(Error::Replay);
        }
        self.generation = Some(fence.generation);
        self.fenced = true; // No reinstatement protocol is invented by this slice.
        let keys: Vec<_> = self.resident.keys().copied().collect();
        let purged = keys
            .into_iter()
            .filter_map(|key| self.remove(key))
            .collect();
        Ok(LocalFenceApplied {
            worker: self.instance.clone(),
            security_domain: self.domain.clone(),
            generation: fence.generation,
            purged,
            event: "worker_locally_fenced",
        })
    }
}

#[cfg(test)]
mod tests;
