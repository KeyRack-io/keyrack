// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real `SQLite` transactions with a SCRIPTED, NON-CRYPTOGRAPHIC provider.
//! These tests qualify orchestration, not a wrapping mechanism or trust boundary.

use async_trait::async_trait;
use keyrack_core::creation::{
    invalid, A2ClosureClaim, A2ClosureFact, A2ClosureVerifier, CreationDispatch, CreationJournal,
    CreationOwner, CreationPhase, CreationRequest, CreationSnapshot, VerifiedA2Closure,
};
use keyrack_core::creation_driver::{
    A2CreationDriver, A2CreationProvider, CreationPendingReason as Pending, CreationProgress,
};
use keyrack_core::error::Result;
use keyrack_core::hsm::HsmConnection;
use keyrack_core::key::{KeyRecord, KeyState};
use keyrack_core::lid::Lid;
use keyrack_core::rotation::{RotationJob, RotationJobState};
use keyrack_core::storage::{AliasRecord, KeyFilter, Page, StorageBackend};
use keyrack_sqlite::SqliteStorage;
use keyrack_test_support::creation_conformance::{fixture, TEST_ENVELOPE};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    ClaimBefore,
    ClaimAfter,
    StageBefore,
    StageAfter,
    ResolveBefore,
    ResolveAfter,
    PublishBefore,
    PublishAfter,
}

struct Store {
    inner: Arc<SqliteStorage>,
    fault: Mutex<Option<Fault>>,
    disable_after_stage: AtomicBool,
    corrupt_snapshot: AtomicBool,
}
impl Store {
    fn fires(&self, expected: Fault) -> bool {
        let mut fault = self.fault.lock().unwrap();
        if *fault == Some(expected) {
            *fault = None;
            true
        } else {
            false
        }
    }
}

#[async_trait]
impl StorageBackend for Store {
    async fn reserve_creation(&self, r: &CreationRequest) -> Result<CreationJournal> {
        self.inner.reserve_creation(r).await
    }
    async fn get_creation(&self, op: Uuid) -> Result<CreationJournal> {
        self.inner.get_creation(op).await
    }
    async fn claim_creation_dispatch(
        &self,
        op: Uuid,
        owner: CreationOwner,
    ) -> Result<CreationDispatch> {
        if self.fires(Fault::ClaimBefore) {
            return Err(invalid("injected before dispatch commit"));
        }
        let value = self.inner.claim_creation_dispatch(op, owner).await?;
        if self.fires(Fault::ClaimAfter) {
            return Err(invalid("injected lost dispatch response"));
        }
        Ok(value)
    }
    async fn creation_snapshot(&self, op: Uuid, owner: CreationOwner) -> Result<CreationSnapshot> {
        let mut snapshot = self.inner.creation_snapshot(op, owner).await?;
        if self.corrupt_snapshot.load(Ordering::SeqCst) {
            if let Some(bytes) = &mut snapshot.envelope {
                bytes[0] ^= 1;
            }
        }
        Ok(snapshot)
    }
    async fn stage_creation(
        &self,
        op: Uuid,
        owner: CreationOwner,
        rev: u64,
        bytes: &[u8],
    ) -> Result<CreationJournal> {
        if self.fires(Fault::StageBefore) {
            return Err(invalid("injected before staging"));
        }
        let value = self.inner.stage_creation(op, owner, rev, bytes).await?;
        if self.disable_after_stage.swap(false, Ordering::SeqCst) {
            let mut parent = self
                .inner
                .get_key(&value.request.material()?.parent().lid)
                .await?;
            parent.state = KeyState::Disabled;
            parent.occ_version += 1;
            self.inner.update_key(&parent).await?;
        }
        if self.fires(Fault::StageAfter) {
            return Err(invalid("injected lost staging response"));
        }
        Ok(value)
    }
    async fn resolve_creation(
        &self,
        op: Uuid,
        owner: CreationOwner,
        rev: u64,
        proof: &VerifiedA2Closure,
    ) -> Result<CreationJournal> {
        if self.fires(Fault::ResolveBefore) {
            return Err(invalid("injected before resolution"));
        }
        let value = self.inner.resolve_creation(op, owner, rev, proof).await?;
        if self.fires(Fault::ResolveAfter) {
            return Err(invalid("injected lost resolution response"));
        }
        Ok(value)
    }
    async fn publish_creation(
        &self,
        op: Uuid,
        owner: CreationOwner,
        rev: u64,
    ) -> Result<KeyRecord> {
        if self.fires(Fault::PublishBefore) {
            return Err(invalid("injected before publication"));
        }
        let value = self.inner.publish_creation(op, owner, rev).await?;
        if self.fires(Fault::PublishAfter) {
            return Err(invalid("injected lost publication response"));
        }
        Ok(value)
    }
    // Ordinary methods delegate unchanged; only creation methods inject faults.
    async fn read_creation_envelope(&self, op: Uuid) -> Result<Vec<u8>> {
        self.inner.read_creation_envelope(op).await
    }
    async fn create_key(&self, record: &KeyRecord) -> Result<()> {
        self.inner.create_key(record).await
    }
    async fn get_key(&self, lid: &Lid) -> Result<KeyRecord> {
        self.inner.get_key(lid).await
    }
    async fn update_key(&self, record: &KeyRecord) -> Result<()> {
        self.inner.update_key(record).await
    }
    async fn list_keys(&self, filter: &KeyFilter) -> Result<Page<KeyRecord>> {
        self.inner.list_keys(filter).await
    }
    async fn list_children(&self, parent: &Lid) -> Result<Vec<KeyRecord>> {
        self.inner.list_children(parent).await
    }
    async fn create_alias(&self, alias: &AliasRecord) -> Result<()> {
        self.inner.create_alias(alias).await
    }
    async fn resolve_alias(&self, name: &str) -> Result<Lid> {
        self.inner.resolve_alias(name).await
    }
    async fn delete_alias(&self, name: &str) -> Result<()> {
        self.inner.delete_alias(name).await
    }
    async fn list_aliases(&self) -> Result<Vec<AliasRecord>> {
        self.inner.list_aliases().await
    }
    async fn create_hsm_connection(&self, conn: &HsmConnection) -> Result<()> {
        self.inner.create_hsm_connection(conn).await
    }
    async fn get_hsm_connection(&self, id: &str) -> Result<HsmConnection> {
        self.inner.get_hsm_connection(id).await
    }
    async fn update_hsm_connection(&self, conn: &HsmConnection) -> Result<()> {
        self.inner.update_hsm_connection(conn).await
    }
    async fn list_hsm_connections(&self) -> Result<Vec<HsmConnection>> {
        self.inner.list_hsm_connections().await
    }
    async fn delete_hsm_connection(&self, id: &str) -> Result<()> {
        self.inner.delete_hsm_connection(id).await
    }
    async fn create_rotation_job(&self, job: &RotationJob) -> Result<()> {
        self.inner.create_rotation_job(job).await
    }
    async fn get_rotation_job(&self, id: &str) -> Result<RotationJob> {
        self.inner.get_rotation_job(id).await
    }
    async fn update_rotation_job(&self, job: &RotationJob) -> Result<()> {
        self.inner.update_rotation_job(job).await
    }
    async fn list_rotation_jobs(
        &self,
        state: Option<RotationJobState>,
    ) -> Result<Vec<RotationJob>> {
        self.inner.list_rotation_jobs(state).await
    }
    async fn ping(&self) -> Result<()> {
        self.inner.ping().await
    }
}

#[derive(Clone, Copy, Default)]
enum Behavior {
    #[default]
    Normal,
    GenerateLostResponse,
    OversizedEnvelope,
    CleanupFails,
    WrongIntent,
    WrongEnvelope,
    WrongObject,
    Deny,
    DenyPublish,
    Pause,
    PauseFirstClose,
    Panic,
}

struct Attempt {
    claim: A2ClosureClaim,
    closed: bool,
}
#[derive(Default)]
struct Provider {
    behavior: Mutex<Behavior>,
    attempts: Mutex<HashMap<Uuid, Attempt>>,
    generates: AtomicUsize,
    closes: AtomicUsize,
    preflights: AtomicUsize,
    verifies: AtomicUsize,
    entered: Notify,
    release: Notify,
    close_entered: Notify,
    close_release: Notify,
}
impl Provider {
    fn behavior(&self) -> Behavior {
        *self.behavior.lock().unwrap()
    }
    fn set(&self, behavior: Behavior) {
        *self.behavior.lock().unwrap() = behavior;
    }
    fn generated(&self) -> usize {
        self.generates.load(Ordering::SeqCst)
    }
    fn closed(&self) -> usize {
        self.closes.load(Ordering::SeqCst)
    }
}
impl A2ClosureVerifier for Provider {
    fn verify(&self, request: &CreationRequest, claim: &A2ClosureClaim) -> Result<()> {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        let attempts = self.attempts.lock().unwrap();
        let attempt = attempts
            .get(&request.operation)
            .ok_or(invalid("no independent provider record"))?;
        if !attempt.closed || &attempt.claim != claim {
            return Err(invalid("closure provenance mismatch"));
        }
        Ok(())
    }
}
#[async_trait]
impl A2CreationProvider for Provider {
    async fn preflight(&self, _: &CreationRequest) -> Result<()> {
        let count = self.preflights.fetch_add(1, Ordering::SeqCst);
        match self.behavior() {
            Behavior::Deny => Err(invalid("test qualification denied")),
            Behavior::DenyPublish if count > 0 => Err(invalid("test authority no longer valid")),
            _ => Ok(()),
        }
    }
    async fn generate_and_wrap(&self, request: &CreationRequest) -> Result<Vec<u8>> {
        self.generates.fetch_add(1, Ordering::SeqCst);
        let behavior = self.behavior();
        let bytes = if matches!(behavior, Behavior::OversizedEnvelope) {
            vec![1; 65_537]
        } else {
            TEST_ENVELOPE.to_vec()
        };
        let claim = A2ClosureClaim {
            intent_fingerprint: request.fingerprint()?,
            envelope_digest: *blake3::hash(&bytes).as_bytes(),
            fact: A2ClosureFact::SessionClosed {
                session: request.correlation.clone(),
            },
        };
        {
            let mut attempts = self.attempts.lock().unwrap();
            assert!(
                !attempts.contains_key(&request.operation),
                "DUPLICATE GENERATE"
            );
            attempts.insert(
                request.operation,
                Attempt {
                    claim,
                    closed: false,
                },
            );
        }
        self.entered.notify_one();
        if matches!(behavior, Behavior::Pause) {
            self.release.notified().await;
        }
        assert!(
            !matches!(behavior, Behavior::Panic),
            "injected provider task loss"
        );
        if matches!(behavior, Behavior::GenerateLostResponse) {
            return Err(invalid("injected lost Generate response"));
        }
        Ok(bytes)
    }
    async fn close_creation(&self, request: &CreationRequest) -> Result<A2ClosureClaim> {
        let prior_closes = self.closes.fetch_add(1, Ordering::SeqCst);
        let behavior = self.behavior();
        if matches!(behavior, Behavior::PauseFirstClose) && prior_closes == 0 {
            self.close_entered.notify_one();
            self.close_release.notified().await;
        }
        if matches!(behavior, Behavior::CleanupFails) {
            return Err(invalid("injected cleanup failure"));
        }
        let mut attempts = self.attempts.lock().unwrap();
        let attempt = attempts
            .get_mut(&request.operation)
            .ok_or(invalid("not confirmed absent"))?;
        attempt.closed = true;
        let mut claim = attempt.claim.clone();
        match behavior {
            Behavior::WrongIntent => claim.intent_fingerprint[0] ^= 1,
            Behavior::WrongEnvelope => claim.envelope_digest[0] ^= 1,
            Behavior::WrongObject => {
                claim.fact = A2ClosureFact::SessionClosed {
                    session: "unrelated-session".into(),
                }
            }
            _ => {}
        }
        Ok(claim)
    }
}

async fn setup() -> (Arc<Store>, Arc<Provider>, A2CreationDriver, CreationRequest) {
    let inner = Arc::new(SqliteStorage::in_memory().unwrap());
    let (parent, request) = fixture();
    inner.create_key(&parent).await.unwrap();
    let store = Arc::new(Store {
        inner,
        fault: Mutex::new(None),
        disable_after_stage: AtomicBool::new(false),
        corrupt_snapshot: AtomicBool::new(false),
    });
    let provider = Arc::new(Provider::default());
    let driver = A2CreationDriver::new(store.clone(), provider.clone());
    (store, provider, driver, request)
}
fn committed(value: CreationProgress) -> KeyRecord {
    match value {
        CreationProgress::Committed(record) => *record,
        other @ CreationProgress::Pending(_) => panic!("expected committed, got {other:?}"),
    }
}
#[allow(clippy::needless_pass_by_value)] // Terminal assertion consumes the test result.
fn pending(value: CreationProgress, reason: Pending) {
    assert!(
        matches!(value, CreationProgress::Pending(actual) if actual == reason),
        "{value:?}"
    );
}

#[tokio::test]
async fn creates_stages_closes_verifies_publishes_and_never_recreates_on_retry() {
    let (store, provider, driver, request) = setup().await;
    committed(driver.run(request.clone()).await.unwrap());
    assert_eq!(
        store
            .read_creation_envelope(request.operation)
            .await
            .unwrap(),
        TEST_ENVELOPE
    );
    assert_eq!(provider.generated(), 1);
    assert_eq!(provider.closed(), 1);
    assert_eq!(provider.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(provider.preflights.load(Ordering::SeqCst), 2);
    provider.set(Behavior::Deny);
    committed(driver.run(request).await.unwrap()); // recorded result, not renewed authority
    assert_eq!(provider.generated(), 1);
    assert_eq!(provider.closed(), 1);
}

#[tokio::test]
async fn unqualified_adapter_cannot_dispatch() {
    let (store, provider, driver, request) = setup().await;
    provider.set(Behavior::Deny);
    assert!(driver.run(request.clone()).await.is_err());
    assert_eq!(provider.generated(), 0);
    assert!(
        !store
            .get_creation(request.operation)
            .await
            .unwrap()
            .dispatch_started
    );
}

#[tokio::test]
async fn concurrent_identical_attempts_obtain_only_one_provider_dispatch() {
    let (_, provider, driver, request) = setup().await;
    provider.set(Behavior::Pause);
    let first = {
        let driver = driver.clone();
        let request = request.clone();
        tokio::spawn(async move { driver.run(request).await })
    };
    provider.entered.notified().await;
    let mut others = vec![];
    for _ in 0..12 {
        let driver = driver.clone();
        let request = request.clone();
        others.push(tokio::spawn(async move { driver.run(request).await }));
    }
    for other in others {
        pending(
            other.await.unwrap().unwrap(),
            Pending::DispatchAlreadyClaimed,
        );
    }
    assert_eq!(provider.generated(), 1);
    assert_eq!(provider.closed(), 0); // retries do not race the active generation
    provider.release.notify_one();
    committed(first.await.unwrap().unwrap());
}

#[tokio::test]
async fn staged_retry_can_finish_while_original_close_is_in_flight() {
    let (store, provider, driver, request) = setup().await;
    provider.set(Behavior::PauseFirstClose);
    let original = {
        let driver = driver.clone();
        let request = request.clone();
        tokio::spawn(async move { driver.run(request).await })
    };
    provider.close_entered.notified().await;
    assert_eq!(
        store.get_creation(request.operation).await.unwrap().phase,
        CreationPhase::Staged
    );
    assert!(store.get_key(&request.record.lid).await.is_err());
    // Both invocations can enter the adapter, whose effect/receipt operation is
    // serialized and idempotent. The fake's attempt mutex supplies that contract.
    let retry = committed(driver.run(request.clone()).await.unwrap());
    provider.close_release.notify_one();
    let first = committed(original.await.unwrap().unwrap());
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(retry).unwrap()
    );
    assert_eq!(provider.generated(), 1);
    assert_eq!(provider.closed(), 2);
    assert_eq!(
        store
            .read_creation_envelope(request.operation)
            .await
            .unwrap(),
        TEST_ENVELOPE
    );
}

#[tokio::test]
async fn lost_dispatch_commit_response_never_becomes_a_new_generate_ticket() {
    let (store, provider, driver, request) = setup().await;
    *store.fault.lock().unwrap() = Some(Fault::ClaimAfter);
    assert!(driver.run(request.clone()).await.is_err());
    assert!(
        store
            .get_creation(request.operation)
            .await
            .unwrap()
            .dispatch_started
    );
    pending(
        driver.run(request).await.unwrap(),
        Pending::DispatchAlreadyClaimed,
    );
    assert_eq!(provider.generated(), 0);
}

#[tokio::test]
async fn failed_dispatch_transaction_can_be_retried_without_false_ambiguity() {
    let (store, provider, driver, request) = setup().await;
    *store.fault.lock().unwrap() = Some(Fault::ClaimBefore);
    assert!(driver.run(request.clone()).await.is_err());
    assert!(
        !store
            .get_creation(request.operation)
            .await
            .unwrap()
            .dispatch_started
    );
    committed(driver.run(request).await.unwrap());
    assert_eq!(provider.generated(), 1);
}

#[tokio::test]
async fn lost_generate_response_still_attempts_cleanup_and_never_regenerates() {
    let (store, provider, driver, request) = setup().await;
    provider.set(Behavior::GenerateLostResponse);
    pending(
        driver.run(request.clone()).await.unwrap(),
        Pending::GenerationUncertain,
    );
    assert_eq!(provider.closed(), 1);
    assert!(store.get_key(&request.record.lid).await.is_err());
    pending(
        driver.run(request).await.unwrap(),
        Pending::DispatchAlreadyClaimed,
    );
    assert_eq!(provider.generated(), 1);
}

#[tokio::test]
async fn invalid_envelope_and_stage_failure_do_not_abandon_cleanup() {
    for oversized in [false, true] {
        let (store, provider, driver, request) = setup().await;
        if oversized {
            provider.set(Behavior::OversizedEnvelope);
        } else {
            *store.fault.lock().unwrap() = Some(Fault::StageBefore);
        }
        pending(
            driver.run(request.clone()).await.unwrap(),
            Pending::StagingUncertain,
        );
        assert_eq!(provider.closed(), 1);
        assert!(store.get_key(&request.record.lid).await.is_err());
        assert_eq!(
            store.get_creation(request.operation).await.unwrap().phase,
            CreationPhase::Reserved
        );
        pending(
            driver.run(request).await.unwrap(),
            Pending::DispatchAlreadyClaimed,
        );
        assert_eq!(provider.generated(), 1);
    }
}

#[tokio::test]
async fn lost_stage_response_recovers_identical_stored_bytes_without_rewrap() {
    let (store, provider, driver, request) = setup().await;
    *store.fault.lock().unwrap() = Some(Fault::StageAfter);
    pending(
        driver.run(request.clone()).await.unwrap(),
        Pending::StagingUncertain,
    );
    assert_eq!(
        store
            .creation_snapshot(request.operation, request.owner)
            .await
            .unwrap()
            .envelope
            .unwrap(),
        TEST_ENVELOPE
    );
    assert!(store
        .read_creation_envelope(request.operation)
        .await
        .is_err());
    let restarted_runner = A2CreationDriver::new(store.clone(), provider.clone());
    committed(restarted_runner.run(request).await.unwrap());
    assert_eq!(provider.generated(), 1);
    assert_eq!(provider.closed(), 2); // exact idempotent cleanup, never Generate
}

#[tokio::test]
async fn cleanup_failure_and_wrong_provenance_never_publish() {
    for behavior in [
        Behavior::CleanupFails,
        Behavior::WrongIntent,
        Behavior::WrongEnvelope,
        Behavior::WrongObject,
    ] {
        let (store, provider, driver, request) = setup().await;
        provider.set(behavior);
        let expected = if matches!(behavior, Behavior::CleanupFails) {
            Pending::CleanupUnconfirmed
        } else {
            Pending::ClosureRejected
        };
        pending(driver.run(request.clone()).await.unwrap(), expected);
        assert!(store.get_key(&request.record.lid).await.is_err());
        assert_eq!(
            store.get_creation(request.operation).await.unwrap().phase,
            CreationPhase::Staged
        );
        provider.set(Behavior::Normal);
        committed(driver.run(request).await.unwrap());
        assert_eq!(provider.generated(), 1);
    }
}

#[tokio::test]
async fn lost_resolution_and_publication_responses_resume_without_new_provider_effects() {
    for fault in [
        Fault::ResolveBefore,
        Fault::ResolveAfter,
        Fault::PublishBefore,
        Fault::PublishAfter,
    ] {
        let (store, provider, driver, request) = setup().await;
        *store.fault.lock().unwrap() = Some(fault);
        let expected = if matches!(fault, Fault::ResolveBefore | Fault::ResolveAfter) {
            Pending::ResolutionUncertain
        } else {
            Pending::PublicationRefused
        };
        pending(driver.run(request.clone()).await.unwrap(), expected);
        committed(
            A2CreationDriver::new(store.clone(), provider.clone())
                .run(request)
                .await
                .unwrap(),
        );
        assert_eq!(provider.generated(), 1);
        assert_eq!(
            provider.closed(),
            if fault == Fault::ResolveBefore { 2 } else { 1 }
        );
    }
}

#[tokio::test]
async fn disabled_parent_or_expired_authority_preempts_publication_but_not_cleanup() {
    for deny_authority in [false, true] {
        let (store, provider, driver, request) = setup().await;
        if deny_authority {
            provider.set(Behavior::DenyPublish);
        } else {
            store.disable_after_stage.store(true, Ordering::SeqCst);
        }
        pending(
            driver.run(request.clone()).await.unwrap(),
            Pending::PublicationRefused,
        );
        assert_eq!(provider.closed(), 1);
        assert!(store.get_key(&request.record.lid).await.is_err());
        assert_eq!(
            store.get_creation(request.operation).await.unwrap().phase,
            CreationPhase::Resolved
        );
    }
}

#[tokio::test]
async fn corrupt_recovery_snapshot_is_not_a_new_envelope_or_closure() {
    let (store, provider, driver, request) = setup().await;
    *store.fault.lock().unwrap() = Some(Fault::StageAfter);
    pending(
        driver.run(request.clone()).await.unwrap(),
        Pending::StagingUncertain,
    );
    store.corrupt_snapshot.store(true, Ordering::SeqCst);
    assert!(driver.run(request.clone()).await.is_err());
    assert_eq!(provider.generated(), 1);
    assert_eq!(provider.closed(), 1);
    assert!(store.get_key(&request.record.lid).await.is_err());
}

#[tokio::test]
async fn caller_cancellation_does_not_cancel_the_owned_cleanup_task() {
    let (store, provider, driver, request) = setup().await;
    provider.set(Behavior::Pause);
    let caller = {
        let request = request.clone();
        tokio::spawn(async move { driver.run(request).await })
    };
    provider.entered.notified().await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    provider.release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if store.get_creation(request.operation).await.unwrap().phase
                == CreationPhase::Committed
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(provider.closed(), 1);
}

#[tokio::test]
async fn task_loss_leaves_durable_ambiguity_not_a_drop_based_cleanup_receipt() {
    let (store, provider, driver, request) = setup().await;
    provider.set(Behavior::Panic);
    assert!(driver.run(request.clone()).await.is_err());
    assert!(
        store
            .get_creation(request.operation)
            .await
            .unwrap()
            .dispatch_started
    );
    assert_eq!(provider.closed(), 0);
    pending(
        driver.run(request.clone()).await.unwrap(),
        Pending::DispatchAlreadyClaimed,
    );
    assert_eq!(provider.generated(), 1);
    assert!(store.get_key(&request.record.lid).await.is_err());
}
