// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Provider creation/cleanup orchestration for the existing A2 storage protocol.
//!
//! No provider is qualified or registered by this module. In particular, the
//! ordinary `CryptoProvider` Generate/Destroy methods are NOT an implementation
//! of this adapter: [`WrappingCreationProvider`] drives creation from the
//! ADR-0005 wrapping operations and from the provider's own closure verifier,
//! and a provider that has neither cannot be installed here.
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
    invalid, A2ClosureClaim, A2ClosureVerifier, CreationBinding, CreationDispatch, CreationPhase,
    CreationRequest, CreationSnapshot, VerifiedA2Closure,
};
use crate::error::Result;
use crate::key::KeyRecord;
use crate::provider::{CryptoProvider, KeyHandle, WrappedKeyLease};
use crate::storage::StorageBackend;
use crate::wrapping::{
    WrappedKeyLifecycle, WrappingCapability, WrappingContext, WrappingOperation,
};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

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
    ///
    /// One implementation owns one creation, reserved before the effect. A
    /// second call must be refused before it can generate anything, whether it
    /// carries the same request or another: the first object is still owed a
    /// close and nothing else can give it one.
    async fn generate_and_wrap(&self, request: &CreationRequest) -> Result<Vec<u8>>;

    /// Close/reconcile the EXACT original creation session/object, idempotently
    /// and serialized with other uses/cleanup of that attempt. Do not use a new
    /// session's empty label search, expiry or Drop as proof of original closure.
    /// Return a repeatable claim backed by independently verifiable provenance,
    /// including the original envelope digest; errors leave cleanup owed.
    /// The claim must be bound to the creation the effect was reserved for,
    /// not to the request presented here: a closure of one creation presented
    /// for another must be refused rather than certified.
    /// Must be safe even after Generate or staging failed, and MUST NOT generate,
    /// unwrap or rewrap to obtain a closure claim or replace lost envelope bytes.
    async fn close_creation(&self, request: &CreationRequest) -> Result<A2ClosureClaim>;
}

/// What this adapter owns: one creation, from before its first effect until
/// whatever that effect turned out to be is closed.
///
/// The slot is filled before Generate, not after it returns, because the owner
/// of a cleanup has to exist before there is anything to clean up. Once filled
/// it is never vacated by a failure, a wrong-context response or a cancelled
/// caller: each of those can leave an object that only this attempt can close.
enum WrappingAttempt {
    /// Reserved before Generate. An effect may exist and no lease is known,
    /// either because the call has not returned or because it failed. This is
    /// unresolved, and no closure can be claimed from it.
    Reserved(CreationBinding),
    /// Generate returned something closable, whether or not it was acceptable.
    Open {
        binding: CreationBinding,
        lease: WrappedKeyLease,
        envelope_digest: [u8; 32],
    },
}

impl WrappingAttempt {
    fn binding(&self) -> &CreationBinding {
        match self {
            Self::Reserved(binding) | Self::Open { binding, .. } => binding,
        }
    }
}

/// Drives journaled creation from a provider's ADR-0005 wrapping operations.
///
/// This adapter supplies no evidence of its own. It obtains a closure fact from
/// the provider and then submits it to that provider's own verifier, so a
/// provider without one cannot be installed here at all; an adapter that
/// returned a claim because a call succeeded would be exactly the accept-all
/// verifier this protocol refuses to have.
///
/// One instance drives one attempt in one process. Its record of what to close
/// is process memory: a restart leaves the durable journal to reconciliation
/// rather than inferring that cleanup happened.
///
/// One attempt means one, and the attempt is a specific creation rather than a
/// free slot: after the first reservation, a request that is not that creation
/// is refused before it can have an effect, and so is a second attempt at the
/// same one. Displacing the reservation would leave the first object with no
/// owner to close it while the journal still owed that cleanup.
pub struct WrappingCreationProvider {
    provider: Arc<dyn CryptoProvider>,
    /// The parent's resident object, resolved by the caller from the exact
    /// parent version that the request's material binds.
    parent: KeyHandle,
    lifecycle: WrappedKeyLifecycle,
    verifier: Arc<dyn A2ClosureVerifier>,
    attempt: Mutex<Option<WrappingAttempt>>,
    /// Held across a whole generation or closure, so effects and cleanup on one
    /// attempt are serialized rather than interleaved by concurrent callers.
    serialize: tokio::sync::Mutex<()>,
}

impl WrappingCreationProvider {
    /// Refuse a provider that cannot evidence its own closures.
    pub fn new(
        provider: Arc<dyn CryptoProvider>,
        parent: KeyHandle,
        lifecycle: WrappedKeyLifecycle,
    ) -> Result<Self> {
        let verifier = provider
            .wrapping_closure_verifier()
            .ok_or(invalid("provider cannot evidence wrapped-key closure"))?;
        Ok(Self {
            provider,
            parent,
            lifecycle,
            verifier,
            attempt: Mutex::new(None),
            serialize: tokio::sync::Mutex::new(()),
        })
    }

    /// Take the one attempt slot for `binding`, before any effect exists.
    ///
    /// Refuses whether the slot holds another creation or the same one: a
    /// second Generate for the same request is a second object, and the first
    /// one is still owed a close.
    fn reserve(&self, binding: &CreationBinding) -> Result<()> {
        let mut slot = self
            .attempt
            .lock()
            .map_err(|_| invalid("attempt state lock poisoned"))?;
        if let Some(held) = slot.as_ref() {
            return Err(if held.binding() == binding {
                invalid("this attempt has already generated; it cannot generate again")
            } else {
                invalid("this adapter owns another creation attempt that is still owed cleanup")
            });
        }
        *slot = Some(WrappingAttempt::Reserved(binding.clone()));
        Ok(())
    }

    /// Record what Generate returned, under the reservation already held.
    ///
    /// If this fails the reservation stands, so the attempt stays unresolved
    /// and owed reconciliation rather than silently losing its object.
    fn retain(
        &self,
        binding: &CreationBinding,
        lease: WrappedKeyLease,
        envelope: &[u8],
    ) -> Result<()> {
        let mut slot = self
            .attempt
            .lock()
            .map_err(|_| invalid("attempt state lock poisoned"))?;
        *slot = Some(WrappingAttempt::Open {
            binding: binding.clone(),
            lease,
            envelope_digest: *blake3::hash(envelope).as_bytes(),
        });
        Ok(())
    }

    /// Refuse a tuple the provider does not declare for `operation`.
    fn require(&self, context: &WrappingContext, operation: WrappingOperation) -> Result<()> {
        self.provider
            .wrapping_capabilities()
            .require(&WrappingCapability::requested(
                context,
                operation,
                self.lifecycle,
            ))
            .map_err(|e| {
                crate::error::KeyRackError::Provider(format!(
                    "provider does not support the requested wrapping tuple for {operation:?}: {e}"
                ))
            })
    }
}

#[async_trait]
impl A2CreationProvider for WrappingCreationProvider {
    /// A child that cannot be opened and closed again must not be created, so
    /// every operation the child's whole life needs is required up front.
    async fn preflight(&self, request: &CreationRequest) -> Result<()> {
        let context = request.context()?;
        for operation in [
            WrappingOperation::Generate,
            WrappingOperation::Open,
            WrappingOperation::Close,
        ] {
            self.require(&context, operation)?;
        }
        Ok(())
    }

    async fn generate_and_wrap(&self, request: &CreationRequest) -> Result<Vec<u8>> {
        let _serialized = self.serialize.lock().await;
        let context = request.context()?;
        self.require(&context, WrappingOperation::Generate)?;
        // Taken from the request before the call, and carried into it, so the
        // provider records which creation its object belongs to and this
        // adapter knows what it owns even if the call never answers.
        let binding = CreationBinding::of(request)?;
        self.reserve(&binding)?;
        let generated = self
            .provider
            .generate_wrapped_key(&context, &self.parent, &binding)
            .await?;
        let bound = generated.lease.context_sha256()
            == context
                .context_sha256()
                .map_err(|_| invalid("invalid creation context"))?;
        // Retained either way. A lease for the wrong context still names an
        // object that exists and that nothing else can close, so it is kept and
        // the creation is refused, rather than dropped along with the only way
        // to clean it up.
        self.retain(&binding, generated.lease, &generated.envelope)?;
        if !bound {
            return Err(invalid("provider lease does not bind the creation context"));
        }
        Ok(generated.envelope)
    }

    async fn close_creation(&self, request: &CreationRequest) -> Result<A2ClosureClaim> {
        let _serialized = self.serialize.lock().await;
        let binding = CreationBinding::of(request)?;
        let (lease, envelope_digest) = {
            let guard = self
                .attempt
                .lock()
                .map_err(|_| invalid("attempt state lock poisoned"))?;
            match guard.as_ref() {
                None => return Err(invalid("this process holds no creation object to close")),
                // Refused before the provider is asked: the object this adapter
                // holds was generated for a different creation, and closing it
                // would produce a real fact about the wrong one.
                Some(held) if held.binding() != &binding => {
                    return Err(invalid(
                        "this adapter's object belongs to another creation operation, attempt or owner",
                    ))
                }
                Some(WrappingAttempt::Reserved(_)) => {
                    return Err(invalid(
                        "generation left no closable object; the attempt is unresolved and requires reconciliation",
                    ))
                }
                Some(WrappingAttempt::Open {
                    lease,
                    envelope_digest,
                    ..
                }) => (lease.clone(), *envelope_digest),
            }
        };
        let closure = self.provider.close_wrapped_key(&lease).await?;
        if closure.context_sha256 != lease.context_sha256() {
            return Err(invalid("closure does not bind the closed object's context"));
        }
        let claim = A2ClosureClaim {
            // The fingerprint reserved before the effect, not one computed from
            // whatever request arrived at close time.
            intent_fingerprint: binding.fingerprint(),
            envelope_digest,
            fact: closure.fact,
        };
        // Verified before it leaves this adapter, by the provider that made it,
        // against the binding that provider recorded at generation.
        self.verifier.verify(request, &claim)?;
        Ok(claim)
    }
}

impl A2ClosureVerifier for WrappingCreationProvider {
    fn verify(&self, request: &CreationRequest, claim: &A2ClosureClaim) -> Result<()> {
        self.verifier.verify(request, claim)
    }
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
