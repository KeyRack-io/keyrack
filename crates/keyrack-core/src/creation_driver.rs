// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Provider creation/cleanup orchestration for the existing A2 storage protocol.
//!
//! No provider is qualified or registered by this module. In particular, the
//! ordinary `CryptoProvider` Generate/Destroy methods are NOT an implementation
//! of this adapter. Tests use a visibly scripted provider, not a software fallback.
//! The legacy V1 creation journal is not silently a shared-custody-frame journal;
//! no worker-memory result is accepted as an A2 object closure here.
//!
//! Exactly one durable dispatch decision precedes provider effects. Retrying a
//! Reserved attempt never repeats Generate. Staged recovery uses the exact stored
//! bytes, closes the exact creation object/session, verifies provenance, then
//! resolves and publishes. Ambiguous earlier outcomes remain pending. This is
//! crash-safe bookkeeping under trusted storage/integration, not a proof against
//! a malicious coordinator or database administrator.

use crate::creation::{
    invalid, A2ClosureClaim, A2ClosureVerifier, CreationDispatch, CreationPhase, CreationRequest,
    CreationSnapshot, VerifiedA2Closure,
};
use crate::error::Result;
use crate::key::KeyRecord;
use crate::storage::StorageBackend;
use async_trait::async_trait;
use std::sync::Arc;

/// Trusted integration extension for a separately qualified exact provider tuple.
/// There is deliberately no in-tree runtime implementation or default acceptance.
/// Implementations must enforce exact provider/domain/parent/spec/format/purpose/
/// context, native template/trusted-wrap policy, nonce/use bounds, and authority
/// inside the claimed trust boundary. A supported mechanism name is insufficient.
#[async_trait]
pub trait A2CreationProvider: A2ClosureVerifier {
    /// Read-only qualification/policy/currentness checks. Called before new
    /// dispatch and again before publication; denial must not create an object.
    /// Cleanup is NOT conditional on this permission remaining valid.
    async fn preflight(&self, request: &CreationRequest) -> Result<()>;

    /// One provider-native create+wrap attempt. Correlate before any possible
    /// effect; never return plaintext key bytes or an independently operable
    /// child handle. An error can mean effects occurred. This must not internally
    /// retry non-idempotent Generate after an ambiguous response.
    async fn generate_and_wrap(&self, request: &CreationRequest) -> Result<Vec<u8>>;

    /// Close/reconcile the EXACT original creation session/object, idempotently
    /// and serialized with other uses/cleanup of that attempt. Do not use a new
    /// session's empty label search, expiry or Drop as proof of original closure.
    /// Return a repeatable claim backed by independently verifiable provenance,
    /// including the original envelope digest; errors leave cleanup owed.
    /// Must be safe even after Generate or staging failed, and MUST NOT generate,
    /// unwrap or rewrap to obtain a closure claim or replace lost envelope bytes.
    async fn close_creation(&self, request: &CreationRequest) -> Result<A2ClosureClaim>;
}

/// No pending variant is permission to regenerate, proof of closure or revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreationPendingReason {
    /// May be in flight, or may have lost a provider/dispatch response. Explicit
    /// qualified reconciliation is required; this runner cannot infer absence.
    DispatchAlreadyClaimed,
    GenerationUncertain,
    StagingUncertain,
    CleanupUnconfirmed,
    ClosureRejected,
    ResolutionUncertain,
    PublicationRefused,
}

#[derive(Debug)]
pub enum CreationProgress {
    Committed(Box<KeyRecord>),
    Pending(CreationPendingReason),
}

/// Unregistered engine. Installing a provider here is a trusted integration
/// decision, not user configuration that qualifies an arbitrary backend.
#[derive(Clone)]
pub struct A2CreationDriver {
    storage: Arc<dyn StorageBackend>,
    provider: Arc<dyn A2CreationProvider>,
}

impl A2CreationDriver {
    pub fn new(storage: Arc<dyn StorageBackend>, provider: Arc<dyn A2CreationProvider>) -> Self {
        Self { storage, provider }
    }

    /// Caller cancellation detaches the owned operation, allowing its cleanup to
    /// finish. Runtime shutdown/panic can still interrupt it; the durable claim
    /// then requires recovery. No async destructor or timeout certifies cleanup.
    pub async fn run(&self, request: CreationRequest) -> Result<CreationProgress> {
        request.validate()?;
        let owned = self.clone();
        tokio::spawn(async move { owned.drive(request).await })
            .await
            .map_err(|_| invalid("creation task interrupted; reconciliation required"))?
    }

    async fn drive(&self, request: CreationRequest) -> Result<CreationProgress> {
        let journal = self.storage.reserve_creation(&request).await?;
        journal.validate()?;
        if journal.request.fingerprint()? != request.fingerprint()? {
            return Err(invalid("reservation intent mismatch"));
        }
        if journal.phase == CreationPhase::Committed {
            return journal
                .committed_record
                .map(|record| CreationProgress::Committed(Box::new(record)))
                .ok_or(invalid("missing committed creation result"));
        }
        if journal.phase != CreationPhase::Reserved {
            return self.resume_staged(&request).await;
        }
        if journal.dispatch_started {
            return Ok(CreationProgress::Pending(
                CreationPendingReason::DispatchAlreadyClaimed,
            ));
        }
        self.provider.preflight(&request).await?;
        match self
            .storage
            .claim_creation_dispatch(request.operation, request.owner)
            .await?
        {
            CreationDispatch::Existing(_) => {
                // Another runner may still be using its fresh decision. Do not
                // race its generation or infer quiescence from the journal phase.
                return Ok(CreationProgress::Pending(
                    CreationPendingReason::DispatchAlreadyClaimed,
                ));
            }
            CreationDispatch::Started(claimed) => {
                if claimed.request.fingerprint()? != request.fingerprint()?
                    || claimed.phase != CreationPhase::Reserved
                    || !claimed.dispatch_started
                {
                    return Err(invalid("invalid dispatch decision"));
                }
            }
        }
        let generated = self.provider.generate_and_wrap(&request).await;
        let staged = match &generated {
            Ok(bytes) => {
                self.storage
                    .stage_creation(request.operation, request.owner, 1, bytes)
                    .await
            }
            Err(_) => Err(invalid("generation outcome unknown")),
        };
        // Cleanup remains owed after ANY possible provider effect, even when
        // bytes are invalid, staging failed, or the parent was disabled meanwhile.
        let Ok(closure) = self.provider.close_creation(&request).await else {
            return Ok(CreationProgress::Pending(
                CreationPendingReason::CleanupUnconfirmed,
            ));
        };
        let Ok(bytes) = generated else {
            return Ok(CreationProgress::Pending(
                CreationPendingReason::GenerationUncertain,
            ));
        };
        if staged.is_err() {
            // This includes commit-then-lost-response. A later snapshot may show
            // Staged; only that immutable snapshot may be resumed, never a rewrap.
            return Ok(CreationProgress::Pending(
                CreationPendingReason::StagingUncertain,
            ));
        }
        self.resolve_and_publish(&request, &bytes, closure).await
    }

    async fn snapshot(&self, request: &CreationRequest) -> Result<CreationSnapshot> {
        let snapshot = self
            .storage
            .creation_snapshot(request.operation, request.owner)
            .await?;
        if snapshot.journal.request.fingerprint()? != request.fingerprint()? {
            return Err(invalid("recovery intent mismatch"));
        }
        // Validate even an out-of-tree backend's returned snapshot, rather than
        // trusting its public fields as an authorization/evidence constructor.
        CreationSnapshot::new(snapshot.journal, snapshot.envelope, request.owner)
    }

    async fn resume_staged(&self, request: &CreationRequest) -> Result<CreationProgress> {
        let snapshot = self.snapshot(request).await?;
        match snapshot.journal.phase {
            CreationPhase::Reserved => Ok(CreationProgress::Pending(
                CreationPendingReason::DispatchAlreadyClaimed,
            )),
            CreationPhase::Committed => snapshot
                .journal
                .committed_record
                .map(|record| CreationProgress::Committed(Box::new(record)))
                .ok_or(invalid("missing committed result")),
            CreationPhase::Staged | CreationPhase::Resolved => {
                let bytes = snapshot
                    .envelope
                    .ok_or(invalid("missing recovery envelope"))?;
                let claim = if snapshot.journal.phase == CreationPhase::Resolved {
                    snapshot
                        .journal
                        .closure
                        .ok_or(invalid("missing recorded closure"))?
                } else {
                    match self.provider.close_creation(request).await {
                        Ok(claim) => claim,
                        Err(_) => {
                            return Ok(CreationProgress::Pending(
                                CreationPendingReason::CleanupUnconfirmed,
                            ))
                        }
                    }
                };
                // Reverify recorded raw claims too; decoding a Resolved journal
                // is not a substitute for the integration's provenance verifier.
                self.resolve_and_publish(request, &bytes, claim).await
            }
        }
    }

    async fn resolve_and_publish(
        &self,
        request: &CreationRequest,
        bytes: &[u8],
        claim: A2ClosureClaim,
    ) -> Result<CreationProgress> {
        let Ok(closure) = VerifiedA2Closure::verify(request, bytes, claim, self.provider.as_ref())
        else {
            return Ok(CreationProgress::Pending(
                CreationPendingReason::ClosureRejected,
            ));
        };
        if self
            .storage
            .resolve_creation(request.operation, request.owner, 2, &closure)
            .await
            .is_err()
        {
            return Ok(CreationProgress::Pending(
                CreationPendingReason::ResolutionUncertain,
            ));
        }
        // Denial here leaves a cleaned, resolved but unpublished attempt. It must
        // never abandon prior cleanup or convert revocation into new permission.
        if self.provider.preflight(request).await.is_err() {
            return Ok(CreationProgress::Pending(
                CreationPendingReason::PublicationRefused,
            ));
        }
        match self
            .storage
            .publish_creation(request.operation, request.owner, 3)
            .await
        {
            Ok(record) => Ok(CreationProgress::Committed(Box::new(record))),
            Err(_) => Ok(CreationProgress::Pending(
                CreationPendingReason::PublicationRefused,
            )),
        }
    }
}
