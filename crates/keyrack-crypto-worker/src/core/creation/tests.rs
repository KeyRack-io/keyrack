// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::core::{Limits, MonotonicClock, Secret};
use ed25519_dalek::SigningKey;
use keyrack_core::custody::{Validity, WrappingContext};
use rand::rngs::OsRng;
use std::{cell::Cell, num::NonZeroU64, rc::Rc};
use zeroize::Zeroizing;

pub(crate) fn plan() -> CreationPlan {
    CreationPlan {
        operation: Uuid::new_v4(),
        attempt: Uuid::new_v4(),
        owner: CreationOwner {
            instance: Uuid::new_v4(),
            generation: 7,
        },
        envelope_ref: "fixture-reservation-envelope".into(),
        principal: "alice".into(),
    }
}
pub(crate) fn grant<S: MaterialSource, C: Clock>(worker: &Worker<S, C>) -> AuthorityGrant {
    let request = worker.creation_request().unwrap().clone();
    let context = crate::fixture::context();
    AuthorityGrant {
        authority: AuthorityIdentity {
            issuer: authority_key(worker.verifier).issuer,
            scope: AuthorityScope::SecurityDomain {
                provider_ref: context.provider_ref,
                security_domain: context.security_domain,
            },
            generation: NonZeroU64::new(1).unwrap(),
        },
        request: request.clone(),
        principal: WrappingIdentifier::new("alice").unwrap(),
        operation: CryptoOperation::GenerateWrapped,
        sequence: NonZeroU64::new(1).unwrap(),
        validity: Validity {
            clock: ClockDomain::ExecutorMonotonicMilliseconds(request.executor),
            not_before: 0,
            not_after: 4_000,
        },
        ancestor_not_after: 3_000,
    }
}
pub(crate) fn sign(claims: AuthorityGrant, key: &SigningKey) -> Vec<u8> {
    let identity = authority_key(key.verifying_key());
    let mut evidence = Evidence {
        issuer: identity.issuer,
        key_id: identity.key_id,
        claims,
        signature: [0; 64],
    };
    evidence.signature = key.sign(&evidence.signing_bytes().unwrap()).to_bytes();
    evidence.canonical_bytes().unwrap()
}
pub(crate) fn authorize<S: NativeGeneration, C: Clock>(
    worker: &mut Worker<S, C>,
    key: &SigningKey,
) -> CreationEvidence {
    worker
        .reserve_creation(
            plan(),
            crate::fixture::custody_context(&crate::fixture::context()),
        )
        .unwrap();
    worker.generate(&sign(grant(worker), key)).unwrap()
}
pub(crate) fn generated_source<S: NativeGeneration>(source: S) -> S {
    let key = SigningKey::generate(&mut OsRng);
    let mut worker = Worker::new(
        key.verifying_key(),
        "development-only".into(),
        source,
        MonotonicClock::new(),
        limits(),
    )
    .unwrap();
    authorize(&mut worker, &key);
    worker.source
}
fn limits() -> Limits {
    Limits {
        resident_keys: 1,
        residence_ms: 1_000,
        uses_per_residency: 3,
        authority_horizon_ms: 10_000,
    }
}
struct TestClock(Rc<Cell<u64>>);
impl Clock for TestClock {
    fn millis(&self) -> u64 {
        self.0.get()
    }
}
struct Probe {
    prepared: usize,
    prepare_delay: u64,
    calls: usize,
    active: bool,
    fail: bool,
    wrong_descriptor: bool,
    now: Rc<Cell<u64>>,
    delay: u64,
}
impl MaterialSource for Probe {
    fn open(&mut self, _: &WrappingContext) -> Result<Secret, Error> {
        if !self.active {
            return Err(Error::Material);
        }
        Ok(Secret(Zeroizing::new(vec![3; 32])))
    }
}
impl NativeGeneration for Probe {
    fn prepare_generation(&mut self, _: &CustodyContext) -> Result<(), Error> {
        self.prepared += 1;
        self.now.set(self.now.get() + self.prepare_delay);
        Ok(())
    }
    fn generate_wrapped(
        &mut self,
        context: &CustodyContext,
        envelope_ref: &WrappingIdentifier,
    ) -> Result<CustodyMaterialDescriptor, Error> {
        self.calls += 1;
        self.now.set(self.now.get() + self.delay);
        if self.fail {
            return Err(Error::Material);
        }
        Ok(CustodyMaterialDescriptor {
            context: context.clone(),
            envelope_ref: if self.wrong_descriptor {
                WrappingIdentifier::new("wrong-envelope").unwrap()
            } else {
                envelope_ref.clone()
            },
            envelope_sha256: digest(b"test-envelope"),
        })
    }
    fn activate_generated(&mut self) {
        self.active = true;
    }
}
fn setup() -> (Worker<Probe, TestClock>, SigningKey) {
    let key = SigningKey::generate(&mut OsRng);
    let now = Rc::new(Cell::new(0));
    let source = Probe {
        prepared: 0,
        prepare_delay: 0,
        calls: 0,
        active: false,
        fail: false,
        wrong_descriptor: false,
        now: now.clone(),
        delay: 0,
    };
    let mut worker = Worker::new(
        key.verifying_key(),
        "development-only".into(),
        source,
        TestClock(now),
        limits(),
    )
    .unwrap();
    worker
        .reserve_creation(
            plan(),
            crate::fixture::custody_context(&crate::fixture::context()),
        )
        .unwrap();
    (worker, key)
}

#[test]
fn canonical_creation_binds_reservation_material_and_independent_authority() {
    let (mut worker, key) = setup();
    assert_eq!(worker.source.calls, 0);
    let signed = sign(grant(&worker), &key);
    let observation_key = worker.observation_key();
    let output = worker.generate(&signed).unwrap();
    let receipt = output
        .result
        .clone()
        .authenticate(&observation_key)
        .unwrap();
    let authority = output
        .grant
        .authenticate(&authority_key(key.verifying_key()))
        .unwrap();
    let reserved = worker.creation.as_ref().unwrap();
    receipt
        .claims()
        .check_attempt(&reserved.expected, reserved.plan.owner, &output.material)
        .unwrap();
    assert_eq!(receipt.claims().request, authority.claims().request);
    assert_eq!(
        receipt.claims().outcome,
        CreationOutcome::NativeWrappedOnlyGenerated
    );
    assert_eq!(worker.source.calls, 1);
    assert!(worker.source.active);
    assert!(worker.generate(&signed).is_err());
    let mut replay = grant(&worker);
    replay.sequence = NonZeroU64::new(2).unwrap();
    assert!(worker.generate(&sign(replay, &key)).is_err());
    assert_eq!(worker.source.calls, 1);
    let mut changed = output.material.clone();
    changed.envelope_sha256[0] ^= 1;
    assert!(receipt.claims().check_material(&changed).is_err());
    changed = output.material;
    changed.context.profile.id = WrappingIdentifier::new("another-profile").unwrap();
    assert!(receipt.claims().check_material(&changed).is_err());
    let other_key = authority_key(key.verifying_key());
    assert!(output.result.authenticate(&other_key).is_err());
}

#[test]
fn invalid_authority_never_reaches_native_generation() {
    for case in 0..15 {
        let (mut worker, key) = setup();
        let mut g = grant(&worker);
        match case {
            0 => g.request.operation = Uuid::new_v4(),
            1 => g.request.attempt = Uuid::new_v4(),
            2 => g.request.executor = ExecutorIncarnation::new([9; 32]).unwrap(),
            3 => g.request.context_sha256[0] ^= 1,
            4 => g.request.request_sha256[0] ^= 1,
            5 => g.principal = WrappingIdentifier::new("mallory").unwrap(),
            6 => g.operation = CryptoOperation::Encrypt,
            7 => g.authority.generation = NonZeroU64::new(2).unwrap(),
            8 => g.authority.scope = AuthorityScope::Context(g.request.context_sha256),
            9 => g.validity.clock = ClockDomain::UnixMilliseconds,
            10 => g.validity.not_before = 1,
            11 => worker.clock.0.set(g.validity.not_after),
            12 => worker.clock.0.set(g.ancestor_not_after),
            13 => worker.sequence = 1,
            14 => worker.fenced = true,
            _ => unreachable!(),
        }
        // A different executor must also own its claimed clock to be encodable.
        if case == 2 {
            g.validity.clock = ClockDomain::ExecutorMonotonicMilliseconds(g.request.executor);
        }
        assert!(worker.generate(&sign(g, &key)).is_err(), "case {case}");
        assert_eq!(worker.source.calls, 0, "case {case}");
    }
    let (mut worker, key) = setup();
    let other = SigningKey::generate(&mut OsRng);
    assert!(worker.generate(&sign(grant(&worker), &other)).is_err());
    assert_eq!(worker.source.calls, 0);
    // A forged packet must not consume the legitimate reservation.
    assert!(worker.generate(&sign(grant(&worker), &key)).is_ok());
}

#[test]
fn owner_reference_and_generation_options_are_bound_before_provider_call() {
    for case in 0..5 {
        let (mut worker, key) = setup();
        let reserved = worker.creation.as_ref().unwrap();
        let mut substitute = reserved.plan.clone();
        match case {
            0 => substitute.owner.instance = Uuid::new_v4(),
            1 => substitute.owner.generation += 1,
            2 => substitute.envelope_ref.push('x'),
            3 => substitute.attempt = Uuid::new_v4(),
            4 => substitute.principal = "mallory".into(),
            _ => unreachable!(),
        }
        let mut g = grant(&worker);
        g.request = substitute
            .binding(g.request.executor, &reserved.context)
            .unwrap();
        assert!(worker.generate(&sign(g, &key)).is_err());
        assert_eq!(worker.source.calls, 0);
    }
}

#[test]
fn unresolved_or_expired_generation_never_activates_or_retries() {
    for case in 0..3 {
        let (mut worker, key) = setup();
        match case {
            0 => worker.source.fail = true,
            1 => worker.source.delay = 3_000,
            2 => worker.source.wrong_descriptor = true,
            _ => unreachable!(),
        }
        assert!(worker.generate(&sign(grant(&worker), &key)).is_err());
        assert_eq!(worker.source.calls, 1);
        assert!(!worker.source.active);
        // Even fresh authority with a higher sequence cannot retry this attempt.
        let mut retry = grant(&worker);
        retry.sequence = NonZeroU64::new(2).unwrap();
        retry.validity.not_after = 5_000;
        retry.ancestor_not_after = 5_000;
        assert!(worker.generate(&sign(retry, &key)).is_err());
        assert_eq!(worker.source.calls, 1);
        assert!(worker
            .reserve_creation(
                plan(),
                crate::fixture::custody_context(&crate::fixture::context())
            )
            .is_err());
    }
}

#[test]
fn restart_rejects_previous_incarnation_even_with_same_reservation() {
    let (old, key) = setup();
    let signed = sign(grant(&old), &key);
    let reservation = old.creation.as_ref().unwrap();
    let (mut new, _) = setup();
    new.verifier = key.verifying_key();
    new.creation = None;
    new.reserve_creation(reservation.plan.clone(), reservation.context.clone())
        .unwrap();
    assert!(new.generate(&signed).is_err());
    assert_eq!(new.source.calls, 0);
    // Durable reuse prevention across boots is a separate, UNMET journal gate.
}

#[test]
fn unknown_profile_and_invalid_owner_cannot_install_a_reservation() {
    let (mut worker, _) = setup();
    worker.creation = None;
    let mut context = crate::fixture::custody_context(&crate::fixture::context());
    context.profile.id = WrappingIdentifier::new("unrecognized-v2").unwrap();
    assert!(worker.reserve_creation(plan(), context).is_err());
    let mut invalid = plan();
    invalid.owner.generation = 0;
    assert!(worker
        .reserve_creation(
            invalid,
            crate::fixture::custody_context(&crate::fixture::context())
        )
        .is_err());
    assert_eq!(worker.source.calls, 0);
}

#[test]
fn metadata_delay_cannot_start_generation_after_authority_expires() {
    let (mut worker, key) = setup();
    worker.source.prepare_delay = 3_000;
    assert!(worker.generate(&sign(grant(&worker), &key)).is_err());
    assert_eq!(worker.source.prepared, 1);
    assert_eq!(worker.source.calls, 0);
    assert!(!worker.source.active);
}

#[test]
fn authority_expiring_during_finalization_suppresses_signed_result_and_activation() {
    struct AdvancingClock(Cell<u64>);
    impl Clock for AdvancingClock {
        fn millis(&self) -> u64 {
            let now = self.0.get();
            self.0.set(now + 1);
            now
        }
    }
    let (old, key) = setup();
    let mut worker = Worker::new(
        key.verifying_key(),
        "development-only".into(),
        old.source,
        AdvancingClock(Cell::new(0)),
        limits(),
    )
    .unwrap();
    worker
        .reserve_creation(
            plan(),
            crate::fixture::custody_context(&crate::fixture::context()),
        )
        .unwrap();
    let mut g = grant(&worker);
    g.validity.not_after = 6;
    g.ancestor_not_after = 6;
    assert!(worker.generate(&sign(g, &key)).is_err());
    assert_eq!(worker.source.calls, 1);
    assert!(!worker.source.active);
    assert!(matches!(
        worker.creation.as_ref().unwrap().state,
        AttemptState::Consumed
    ));
}
