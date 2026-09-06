// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared, versioned custody boundary, not a provider or authority service.
//!
//! Signatures over canonical bytes authenticate claim provenance, not truth.
//! Parsing is not authentication;
//! [`AuthenticatedEvidence`] is not current authorization or proof of erasure.
//! Consumers must independently enforce trusted issuer/scope mappings, profile
//! qualification, replay/generation state, ancestor authority, credential isolation
//! and in-flight fencing. No type here enables a provider capability or converts
//! into the storage journal's `VerifiedA2Closure`.
//!
//! See `docs/CUSTODY_CONTRACT.md` and the shared vectors for the byte grammar.
//! Legacy material and wrapping V1 codecs are unchanged. [`CustodyContext`] is a
//! new, explicit authenticated frame around V1, never an implicit V1 upgrade.
//!
//! Receipt families cannot substitute for each other, even after authentication:
//!
//! ```compile_fail
//! use keyrack_core::custody::{CreationResult, LeaseCleanupResult};
//! fn publish(_: CreationResult) {}
//! fn wrong(receipt: LeaseCleanupResult) { publish(receipt); }
//! ```
//! ```compile_fail
//! use keyrack_core::custody::{AuthenticatedEvidence, LeaseCleanupResult, RevocationResult};
//! fn fence(_: AuthenticatedEvidence<RevocationResult>) {}
//! fn wrong(receipt: AuthenticatedEvidence<LeaseCleanupResult>) { fence(receipt); }
//! ```

mod codec;
mod evidence;

pub use crate::wrapping::{VersionedKeyId, WrappingContext, WrappingIdentifier};
pub use codec::Canonical;
pub use evidence::{AuthenticatedEvidence, Evidence, EvidenceClaims, EvidenceKey};

use crate::creation::CreationOwner;
use crate::key::ProviderRef;
use std::num::NonZeroU64;
use uuid::Uuid;

pub const MAX_CONTRACT_BYTES: usize = 65_536;
pub const MAX_RECEIPT_LEASES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    #[error("invalid custody encoding: {0}")]
    Encoding(&'static str),
    #[error("invalid custody binding: {0}")]
    Binding(&'static str),
    #[error("custody signature or trusted signer mismatch")]
    Authentication,
    #[error(transparent)]
    Wrapping(#[from] crate::wrapping::WrappingError),
}

pub type Result<T> = std::result::Result<T, ContractError>;

/// Execution placement only; not a strength ordering or hardware attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionBoundary {
    ProviderSessionObject,
    ProviderJournaledTemporaryObject,
    /// Plaintext is permitted in a trusted-host worker, never the coordinator.
    TrustedHostWorkerMemory,
}

/// Exact, version-bearing profile name. Unknown names may be decoded but MUST
/// be rejected by a consumer without a locally qualified exact-match profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyProfile {
    pub boundary: ExecutionBoundary,
    pub id: WrappingIdentifier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyContext {
    pub wrapping: WrappingContext,
    pub profile: CustodyProfile,
}

impl CustodyContext {
    /// Exact trusted allowlist, with no backend-name inference or fallback.
    /// Entries must come from independently qualified local configuration.
    pub fn require_profile(&self, qualified: &[CustodyProfile]) -> Result<()> {
        self.validate()?;
        if !qualified.contains(&self.profile) {
            return Err(ContractError::Binding("unqualified custody profile"));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.wrapping.canonical_bytes()?;
        if self.wrapping.child.lid == self.wrapping.parent.lid {
            return Err(ContractError::Binding("self parent"));
        }
        Ok(())
    }
}

/// Transport descriptor only, NOT a new `KeyMaterial` persistence variant.
/// It names no operable child handle. The envelope hash is outside the wrapping
/// context: including it in AAD would depend circularly on the resulting wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyMaterialDescriptor {
    pub context: CustodyContext,
    /// Opaque storage identity; never a caller-controlled URL to dereference.
    pub envelope_ref: WrappingIdentifier,
    pub envelope_sha256: [u8; 32],
}

/// Fresh, unguessable executor boot identity, generated inside its trust boundary.
/// Rejecting zero is structural, not a test of randomness or freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutorIncarnation([u8; 32]);

impl ExecutorIncarnation {
    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            return Err(ContractError::Binding("zero executor incarnation"));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact attempt and intended executor, not a storage-owner fencing token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBinding {
    pub operation: Uuid,
    pub attempt: Uuid,
    pub executor: ExecutorIncarnation,
    pub context_sha256: [u8; 32],
    /// Hash of the exact operation-specific request transcript. Its format must
    /// be independently approved; this module does not canonicalize RPC input.
    pub request_sha256: [u8; 32],
}

impl RequestBinding {
    pub fn validate(&self) -> Result<()> {
        if self.operation.is_nil() || self.attempt.is_nil() {
            return Err(ContractError::Binding("nil request identity"));
        }
        Ok(())
    }
}

/// Domain-level fences do not require one message per resident key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityScope {
    Context([u8; 32]),
    SecurityDomain {
        provider_ref: ProviderRef,
        security_domain: WrappingIdentifier,
    },
}

impl AuthorityScope {
    pub fn covers(&self, context: &CustodyContext) -> Result<bool> {
        context.validate()?;
        Ok(match self {
            Self::Context(digest) => digest == &context.sha256()?,
            Self::SecurityDomain {
                provider_ref,
                security_domain,
            } => {
                provider_ref == &context.wrapping.provider_ref
                    && security_domain == &context.wrapping.security_domain
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityIdentity {
    pub issuer: WrappingIdentifier,
    pub scope: AuthorityScope,
    pub generation: NonZeroU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOperation {
    GenerateWrapped,
    Encrypt,
    Decrypt,
}

/// No implicit conversion between wall time and process-relative time. Consumers
/// choose the supported domain from trusted configuration, never from the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockDomain {
    UnixMilliseconds,
    ExecutorMonotonicMilliseconds(ExecutorIncarnation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockReading {
    pub domain: ClockDomain,
    pub milliseconds: u64,
}

/// Half-open interval `[not_before, not_after)`. No default duration or renewal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    pub clock: ClockDomain,
    pub not_before: u64,
    pub not_after: u64,
}

impl Validity {
    pub fn validate(&self) -> Result<()> {
        if self.not_before >= self.not_after {
            return Err(ContractError::Binding("empty validity interval"));
        }
        Ok(())
    }

    pub fn check_at(&self, now: ClockReading) -> Result<()> {
        self.validate()?;
        if self.clock != now.domain
            || now.milliseconds < self.not_before
            || now.milliseconds >= self.not_after
        {
            return Err(ContractError::Binding("clock or validity mismatch"));
        }
        Ok(())
    }

    fn check_executor(&self, executor: ExecutorIncarnation) -> Result<()> {
        self.validate()?;
        if matches!(self.clock, ClockDomain::ExecutorMonotonicMilliseconds(id) if id != executor) {
            return Err(ContractError::Binding(
                "clock belongs to another incarnation",
            ));
        }
        Ok(())
    }
}

/// Unverified authority claim. A cache lease is deliberately not part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityGrant {
    pub authority: AuthorityIdentity,
    pub request: RequestBinding,
    pub principal: WrappingIdentifier,
    pub operation: CryptoOperation,
    pub sequence: NonZeroU64,
    pub validity: Validity,
    /// Effective ancestor ceiling in the same clock domain, from independently
    /// validated ancestor authority, not from a cache-hit renewal.
    pub ancestor_not_after: u64,
}

impl AuthorityGrant {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.validity.check_executor(self.request.executor)?;
        if matches!(self.authority.scope, AuthorityScope::Context(digest) if digest != self.request.context_sha256)
        {
            return Err(ContractError::Binding("grant scope/context mismatch"));
        }
        if self.ancestor_not_after <= self.validity.not_before {
            return Err(ContractError::Binding("empty ancestor authority interval"));
        }
        Ok(())
    }

    /// Structural/time checks ONLY. `expected` must come from trusted local
    /// resolution, not fields copied out of this claim. Still requires signature,
    /// issuer-policy binding, current generation and atomic replay consumption.
    pub fn check_request(
        &self,
        expected: &RequestBinding,
        context: &CustodyContext,
        principal: &WrappingIdentifier,
        operation: CryptoOperation,
        now: ClockReading,
    ) -> Result<()> {
        self.validate()?;
        if matches!(
            operation,
            CryptoOperation::Encrypt | CryptoOperation::Decrypt
        ) && context.wrapping.purpose != crate::wrapping::WrappingKeyPurpose::EncryptDecrypt
        {
            return Err(ContractError::Binding("operation forbidden by key purpose"));
        }
        if &self.request != expected
            || &self.principal != principal
            || self.operation != operation
            || self.request.context_sha256 != context.sha256()?
            || !self.authority.scope.covers(context)?
        {
            return Err(ContractError::Binding("authority request mismatch"));
        }
        self.validity.check_at(now)?;
        if now.milliseconds >= self.ancestor_not_after {
            return Err(ContractError::Binding("ancestor authority expired"));
        }
        Ok(())
    }
}

/// Counter is unique within one fresh incarnation; never a portable key handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseIdentity {
    pub executor: ExecutorIncarnation,
    pub counter: NonZeroU64,
}

/// Description of resident material, not permission to use it. Residency may
/// outlive authority, but no crypto use may do so. Hits renew neither deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRecord {
    pub lease: LeaseIdentity,
    pub context_sha256: [u8; 32],
    pub authority: AuthorityIdentity,
    pub residency: Validity,
}

impl LeaseRecord {
    pub fn check_context(&self, context: &CustodyContext) -> Result<()> {
        self.canonical_bytes()?;
        if self.context_sha256 != context.sha256()? || !self.authority.scope.covers(context)? {
            return Err(ContractError::Binding("lease context mismatch"));
        }
        Ok(())
    }
}

/// Creation provenance is independent of later residency cleanup or revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreationOutcome {
    ProviderSessionClosed {
        session: WrappingIdentifier,
    },
    ProviderTemporaryObjectDestroyed {
        object: WrappingIdentifier,
    },
    /// Claim of native wrapped-only generation, not a disguised object closure.
    NativeWrappedOnlyGenerated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreationResult {
    pub request: RequestBinding,
    /// Storage attempt owner is distinct from the executor and authority epochs.
    pub owner: CreationOwner,
    pub material_sha256: [u8; 32],
    pub outcome: CreationOutcome,
}

impl CreationResult {
    /// Compare against trusted reservation state, not identities copied from the
    /// result. Provenance/profile verification is a separate required step.
    pub fn check_attempt(
        &self,
        request: &RequestBinding,
        owner: CreationOwner,
        material: &CustodyMaterialDescriptor,
    ) -> Result<()> {
        if &self.request != request || self.owner != owner {
            return Err(ContractError::Binding("creation attempt/owner mismatch"));
        }
        self.check_material(material)
    }

    pub fn check_material(&self, material: &CustodyMaterialDescriptor) -> Result<()> {
        self.canonical_bytes()?;
        if self.request.context_sha256 != material.context.sha256()?
            || self.material_sha256 != material.sha256()?
        {
            return Err(ContractError::Binding("creation material mismatch"));
        }
        let compatible = matches!(
            (&self.outcome, material.context.profile.boundary),
            (
                CreationOutcome::ProviderSessionClosed { .. },
                ExecutionBoundary::ProviderSessionObject
            ) | (
                CreationOutcome::ProviderTemporaryObjectDestroyed { .. },
                ExecutionBoundary::ProviderJournaledTemporaryObject
            ) | (
                CreationOutcome::NativeWrappedOnlyGenerated,
                ExecutionBoundary::TrustedHostWorkerMemory
            )
        );
        if !compatible {
            return Err(ContractError::Binding("creation outcome/profile mismatch"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseCleanupReason {
    Released,
    ResidencyExpired,
    AuthorityFenced,
}

/// Local observation for ONE exact lease; not key destruction or a global fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseCleanupResult {
    pub record: LeaseRecord,
    pub reason: LeaseCleanupReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationCommand {
    pub fence: Uuid,
    pub executor: ExecutorIncarnation,
    pub authority: AuthorityIdentity,
    pub validity: Validity,
}

/// Both outcomes require a fence serialized with admission and output release.
/// No variant represents "still running, probably safe".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlightDisposition {
    Drained,
    OutputsSuppressed,
}

/// Local applied-fence observation, NEVER all-holder completion. The bounded
/// sorted lease list is diagnostic, not an exhaustive holder census. The fence
/// applies to the entire scope, including material not named in this list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationResult {
    pub fence: Uuid,
    pub executor: ExecutorIncarnation,
    pub authority: AuthorityIdentity,
    pub command_sha256: [u8; 32],
    pub in_flight: InFlightDisposition,
    pub observed_leases: Vec<LeaseIdentity>,
}

impl RevocationResult {
    pub fn check_command(&self, command: &RevocationCommand) -> Result<()> {
        self.canonical_bytes()?;
        if self.fence != command.fence
            || self.executor != command.executor
            || self.authority != command.authority
            || self.command_sha256 != command.sha256()?
        {
            return Err(ContractError::Binding("fence command mismatch"));
        }
        Ok(())
    }
}
