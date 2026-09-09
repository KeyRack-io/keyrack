// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical creation consumer, behind a private development reservation adapter.
//! This neither qualifies a Vault profile nor publishes into the A2 journal.
use super::{digest, Clock, Error, MaterialSource, Worker};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, VerifyingKey};
use keyrack_core::{
    creation::CreationOwner,
    custody::{
        AuthorityGrant, AuthorityIdentity, AuthorityScope, Canonical, ClockDomain, ClockReading,
        CreationOutcome, CreationResult, CryptoOperation, CustodyContext,
        CustodyMaterialDescriptor, Evidence, EvidenceKey, ExecutorIncarnation, RequestBinding,
        WrappingIdentifier,
    },
};
use serde::{Deserialize, Serialize};
use std::result::Result;
use uuid::Uuid;

/// Trusted test-launcher input, never accepted from the coordinator's request
/// stream. It simulates a storage reservation; it is NOT evidence of one.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreationPlan {
    pub operation: Uuid,
    pub attempt: Uuid,
    pub owner: CreationOwner,
    pub envelope_ref: String,
    pub principal: String,
}

impl CreationPlan {
    /// PROPOSED request transcript, not an addition to the canonical contract:
    /// domain || canonical context hash || operation UUID || attempt UUID ||
    /// owner UUID || owner generation u64be || length-prefixed UTF-8 reference ||
    /// length-prefixed UTF-8 principal || key bits u16be. Lengths are u32be.
    pub(crate) fn binding(
        &self,
        executor: ExecutorIncarnation,
        context: &CustodyContext,
    ) -> Result<RequestBinding, Error> {
        if self.operation.is_nil()
            || self.attempt.is_nil()
            || self.owner.instance.is_nil()
            || self.owner.generation == 0
        {
            return Err(Error::Context);
        }
        WrappingIdentifier::new(&self.envelope_ref).map_err(|_| Error::Context)?;
        WrappingIdentifier::new(&self.principal).map_err(|_| Error::Context)?;
        let context_sha256 = context.sha256().map_err(|_| Error::Context)?;
        let mut bytes = b"KeyRack:PROPOSED-worker-generate-request-v1\0".to_vec();
        bytes.extend_from_slice(&context_sha256);
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.attempt.as_bytes());
        bytes.extend_from_slice(self.owner.instance.as_bytes());
        bytes.extend_from_slice(&self.owner.generation.to_be_bytes());
        for text in [&self.envelope_ref, &self.principal] {
            bytes.extend_from_slice(&(text.len() as u32).to_be_bytes());
            bytes.extend_from_slice(text.as_bytes());
        }
        bytes.extend_from_slice(&256_u16.to_be_bytes());
        Ok(RequestBinding {
            operation: self.operation,
            attempt: self.attempt,
            executor,
            context_sha256,
            request_sha256: digest(&bytes),
        })
    }
}

/// Private adapter capability. Local plaintext fixture generation cannot
/// implement a successful native-wrapped-only observation.
pub(crate) trait NativeGeneration: MaterialSource {
    fn prepare_generation(&mut self, _context: &CustodyContext) -> Result<(), Error> {
        Ok(())
    }
    fn generate_wrapped(
        &mut self,
        context: &CustodyContext,
        envelope_ref: &WrappingIdentifier,
    ) -> Result<CustodyMaterialDescriptor, Error>;
    // Generated ciphertext remains unusable until the post-call checks succeed.
    fn activate_generated(&mut self);
}

enum AttemptState {
    Ready,
    Consumed,
    Complete,
}

pub(super) struct Reservation {
    plan: CreationPlan,
    context: CustodyContext,
    expected: RequestBinding,
    state: AttemptState,
}

pub(crate) struct CreationEvidence {
    pub(crate) grant: Evidence<AuthorityGrant>,
    pub(crate) result: Evidence<CreationResult>,
    pub(crate) material: CustodyMaterialDescriptor,
}

pub(crate) fn authority_key(key: VerifyingKey) -> EvidenceKey {
    EvidenceKey {
        issuer: WrappingIdentifier::new("development-authority").unwrap(),
        key_id: WrappingIdentifier::new("development-authority-key").unwrap(),
        key,
    }
}

impl<S: MaterialSource, C: Clock> Worker<S, C> {
    /// One bounded reservation per harness incarnation, installed by its trusted
    /// launcher before IPC admission. No caller can replace a consumed attempt.
    pub(crate) fn reserve_creation(
        &mut self,
        plan: CreationPlan,
        context: CustodyContext,
    ) -> Result<(), Error> {
        if self.creation.is_some() || self.sequence != 0 || self.fenced {
            return Err(Error::Replay);
        }
        // Exact fixture allowlist, enabled only in this unpublished harness.
        let supported = crate::fixture::custody_context(&context.wrapping);
        context
            .require_profile(&[supported.profile])
            .map_err(|_| Error::Context)?;
        if context.wrapping != crate::fixture::context()
            || context.wrapping.security_domain.as_str() != self.domain
        {
            return Err(Error::Context);
        }
        let executor = ExecutorIncarnation::new(
            STANDARD
                .decode(&self.instance)
                .map_err(|_| Error::Context)?
                .try_into()
                .map_err(|_| Error::Context)?,
        )
        .map_err(|_| Error::Context)?;
        let expected = plan.binding(executor, &context)?;
        self.creation = Some(Reservation {
            plan,
            context,
            expected,
            state: AttemptState::Ready,
        });
        Ok(())
    }

    pub(crate) fn creation_allows_use(&self) -> bool {
        self.creation
            .as_ref()
            .map_or(true, |r| matches!(r.state, AttemptState::Complete))
    }

    pub(crate) fn creation_request(&self) -> Option<&RequestBinding> {
        self.creation.as_ref().map(|r| &r.expected)
    }

    pub(crate) fn observation_key(&self) -> EvidenceKey {
        EvidenceKey {
            issuer: WrappingIdentifier::new("development-worker-observation").unwrap(),
            key_id: WrappingIdentifier::new("incarnation-key").unwrap(),
            key: self.observer.verifying_key(),
        }
    }

    fn check_creation(&self, grant: &AuthorityGrant) -> Result<(), Error> {
        let r = self.creation.as_ref().ok_or(Error::Context)?;
        let expected_authority = AuthorityIdentity {
            issuer: authority_key(self.verifier).issuer,
            scope: AuthorityScope::SecurityDomain {
                provider_ref: r.context.wrapping.provider_ref.clone(),
                security_domain: r.context.wrapping.security_domain.clone(),
            },
            // Trusted harness policy, not bootstrapped from a coordinator claim.
            generation: std::num::NonZeroU64::new(1).unwrap(),
        };
        if grant.authority != expected_authority {
            return Err(Error::Authority);
        }
        grant
            .check_request(
                &r.expected,
                &r.context,
                &WrappingIdentifier::new(&r.plan.principal).map_err(|_| Error::Context)?,
                CryptoOperation::GenerateWrapped,
                ClockReading {
                    domain: ClockDomain::ExecutorMonotonicMilliseconds(r.expected.executor),
                    milliseconds: self.clock.millis(),
                },
            )
            .map_err(|_| Error::Authority)?;
        if grant.validity.not_after
            > self
                .clock
                .millis()
                .saturating_add(self.limits.authority_horizon_ms)
        {
            return Err(Error::Expired);
        }
        if self.fenced
            || self
                .generation
                .is_some_and(|g| g != grant.authority.generation.get())
        {
            return Err(Error::Replay);
        }
        Ok(())
    }
}

impl<S: NativeGeneration, C: Clock> Worker<S, C> {
    pub(crate) fn generate(&mut self, bytes: &[u8]) -> Result<CreationEvidence, Error> {
        let evidence = Evidence::<AuthorityGrant>::from_canonical_bytes(bytes)
            .map_err(|_| Error::Authority)?;
        let authenticated = evidence
            .clone()
            .authenticate(&authority_key(self.verifier))
            .map_err(|_| Error::Authority)?;
        let grant = authenticated.claims();
        self.check_creation(grant)?;
        let r = self.creation.as_mut().ok_or(Error::Context)?;
        if !matches!(r.state, AttemptState::Ready) || grant.sequence.get() <= self.sequence {
            return Err(Error::Replay);
        }
        // Consume before even the metadata read: timeout/lost reply/invalid
        // material remains unresolved. A new sequence cannot generate again.
        r.state = AttemptState::Consumed;
        self.sequence = grant.sequence.get();
        self.generation = Some(grant.authority.generation.get());
        let context = r.context.clone();
        let envelope_ref =
            WrappingIdentifier::new(&r.plan.envelope_ref).map_err(|_| Error::Context)?;
        self.source.prepare_generation(&context)?;
        self.check_creation(grant)?;
        let material = self.source.generate_wrapped(&context, &envelope_ref)?;
        self.check_creation(grant)?;
        let r = self.creation.as_mut().ok_or(Error::Context)?;
        if material.context != r.context || material.envelope_ref.as_str() != r.plan.envelope_ref {
            return Err(Error::Material);
        }
        let claims = CreationResult {
            request: r.expected.clone(),
            owner: r.plan.owner,
            material_sha256: material.sha256().map_err(|_| Error::Material)?,
            outcome: CreationOutcome::NativeWrappedOnlyGenerated,
        };
        claims
            .check_attempt(&r.expected, r.plan.owner, &material)
            .map_err(|_| Error::Material)?;
        let mut result = Evidence {
            issuer: WrappingIdentifier::new("development-worker-observation").unwrap(),
            key_id: WrappingIdentifier::new("incarnation-key").unwrap(),
            claims,
            signature: [0; 64],
        };
        result.signature = self
            .observer
            .sign(&result.signing_bytes().map_err(|_| Error::Material)?)
            .to_bytes();
        self.check_creation(grant)?;
        self.creation.as_mut().ok_or(Error::Context)?.state = AttemptState::Complete;
        self.source.activate_generated();
        Ok(CreationEvidence {
            grant: evidence,
            result,
            material,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
