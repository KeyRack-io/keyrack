// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::{fixture::context, source::LocalFixture};
use ed25519_dalek::{Signer, SigningKey};
use std::{cell::Cell, rc::Rc};

#[derive(Clone)]
struct TestClock(Rc<Cell<u64>>);
impl Clock for TestClock {
    fn millis(&self) -> u64 {
        self.0.get()
    }
}

fn sign(key: &SigningKey, body: &AuthorityMessage) -> Signed {
    let body = serde_json::to_string(body).unwrap();
    let mut bytes = SIGNING_DOMAIN.to_vec();
    bytes.extend_from_slice(body.as_bytes());
    Signed {
        signature: key.sign(&bytes).to_bytes().to_vec(),
        body,
    }
}

fn setup() -> (Worker<LocalFixture, TestClock>, SigningKey, TestClock) {
    let key = SigningKey::generate(&mut OsRng);
    let clock = TestClock(Rc::new(Cell::new(0)));
    let worker = Worker::new(
        key.verifying_key(),
        "development-only".into(),
        LocalFixture::new(&context()).unwrap(),
        clock.clone(),
        Limits {
            resident_keys: 1,
            residence_ms: 1_000,
            uses_per_residency: 3,
            authority_horizon_ms: 10_000,
        },
    )
    .unwrap();
    (worker, key, clock)
}

fn grant<S, C>(worker: &Worker<S, C>, seq: u64, op: Operation, input: &[u8]) -> Grant {
    Grant {
        worker: worker.instance.clone(),
        principal: "alice".into(),
        context_sha256: context_digest(&context()).unwrap(),
        operation: op,
        input_sha256: digest(input),
        generation: 1,
        sequence: seq,
        not_before_ms: 0,
        expires_ms: 500,
        ancestor_expires_ms: 400,
        residency_until_ms: 1_000,
    }
}

fn encrypt(
    worker: &mut Worker<LocalFixture, TestClock>,
    key: &SigningKey,
    sequence: u64,
) -> Result<Vec<u8>, Error> {
    let signed = sign(
        key,
        &AuthorityMessage::Grant(grant(worker, sequence, Operation::Encrypt, b"message")),
    );
    worker.execute(&signed, "alice", &context(), Operation::Encrypt, b"message")
}

#[test]
fn crypto_round_trip_and_no_replayed_operation() {
    let (mut worker, key, _) = setup();
    let encrypted = encrypt(&mut worker, &key, 1).unwrap();
    assert_eq!(encrypt(&mut worker, &key, 1), Err(Error::Replay));
    let signed = sign(
        &key,
        &AuthorityMessage::Grant(grant(&worker, 2, Operation::Decrypt, &encrypted)),
    );
    assert_eq!(
        worker
            .execute(&signed, "alice", &context(), Operation::Decrypt, &encrypted)
            .unwrap(),
        b"message"
    );
}

#[test]
fn maximum_plaintext_round_trips_and_ciphertext_bound_is_exact() {
    let (mut worker, key, _) = setup();
    let input = vec![42; MAX_INPUT];
    let signed = sign(
        &key,
        &AuthorityMessage::Grant(grant(&worker, 1, Operation::Encrypt, &input)),
    );
    let encrypted = worker
        .execute(&signed, "alice", &context(), Operation::Encrypt, &input)
        .unwrap();
    assert_eq!(encrypted.len(), MAX_INPUT + 28);
    let signed = sign(
        &key,
        &AuthorityMessage::Grant(grant(&worker, 2, Operation::Decrypt, &encrypted)),
    );
    assert_eq!(
        worker
            .execute(&signed, "alice", &context(), Operation::Decrypt, &encrypted)
            .unwrap(),
        input
    );
    let oversized = vec![0; MAX_INPUT + 29];
    assert_eq!(
        worker.execute(&signed, "alice", &context(), Operation::Decrypt, &oversized),
        Err(Error::Limit)
    );
}

#[test]
fn forged_and_individually_mismatched_authority_never_materializes() {
    for case in 0..12 {
        let (mut worker, key, _) = setup();
        let mut g = grant(&worker, 1, Operation::Encrypt, b"message");
        match case {
            0 => g.worker.push('x'),
            1 => g.principal = "mallory".into(),
            2 => g.context_sha256[0] ^= 1,
            3 => g.operation = Operation::Decrypt,
            4 => g.input_sha256[0] ^= 1,
            5 => g.generation = 0,
            6 => g.sequence = 0,
            7 => g.expires_ms = 0,
            8 => g.ancestor_expires_ms = 0,
            9 => g.not_before_ms = 1,
            10 => g.residency_until_ms = 0,
            _ => {}
        }
        let mut signed = sign(&key, &AuthorityMessage::Grant(g));
        if case == 11 {
            signed.signature[0] ^= 1;
        }
        assert!(
            worker
                .execute(&signed, "alice", &context(), Operation::Encrypt, b"message")
                .is_err(),
            "case {case}"
        );
        assert!(worker.resident.is_empty(), "case {case}");
    }
}

#[test]
fn warm_material_does_not_renew_ancestor_authority_or_residency() {
    let (mut worker, key, clock) = setup();
    encrypt(&mut worker, &key, 1).unwrap();
    clock.0.set(399);
    encrypt(&mut worker, &key, 2).unwrap();
    assert_eq!(worker.resident.values().next().unwrap().until, 1_000);
    clock.0.set(400);
    assert_eq!(encrypt(&mut worker, &key, 3), Err(Error::Expired));
    assert_eq!(worker.resident.len(), 1); // Retained bytes are not permission.
    clock.0.set(1_000);
    let cleanup = worker.expire();
    assert_eq!(cleanup.len(), 1);
    assert_eq!(cleanup[0].event, "local_secret_buffer_dropped");
    assert!(worker.resident.is_empty());
}

#[test]
fn lease_deadline_and_use_limit_are_independent_of_fresh_grants() {
    let (mut worker, key, clock) = setup();
    worker.limits.residence_ms = 100;
    for seq in 1..=3 {
        encrypt(&mut worker, &key, seq).unwrap();
    }
    assert_eq!(encrypt(&mut worker, &key, 4), Err(Error::Limit));
    clock.0.set(99);
    assert_eq!(worker.resident.values().next().unwrap().until, 100);
    clock.0.set(100);
    assert_eq!(worker.expire().len(), 1);
}

#[test]
fn stale_generation_cannot_use_authentic_material() {
    let (mut worker, key, _) = setup();
    encrypt(&mut worker, &key, 1).unwrap();
    let mut g = grant(&worker, 2, Operation::Encrypt, b"message");
    g.generation = 2;
    let signed = sign(&key, &AuthorityMessage::Grant(g));
    assert_eq!(
        worker.execute(&signed, "alice", &context(), Operation::Encrypt, b"message"),
        Err(Error::Replay)
    );
}

#[test]
fn local_fence_purges_and_cannot_be_reused_as_creation_or_grant() {
    let (mut worker, key, _) = setup();
    encrypt(&mut worker, &key, 1).unwrap();
    let signed = sign(
        &key,
        &AuthorityMessage::Fence(Fence {
            worker: worker.instance.clone(),
            security_domain: "development-only".into(),
            generation: 2,
            expires_ms: 1_000,
        }),
    );
    let result = worker.fence(&signed).unwrap();
    assert_eq!(result.purged.len(), 1);
    assert_eq!(result.event, "worker_locally_fenced");
    let text = serde_json::to_string(&result).unwrap();
    assert!(!text.contains("closed") && !text.contains("destroyed"));
    assert_eq!(worker.fence(&signed).unwrap_err(), Error::Replay);
    assert_eq!(
        worker.execute(&signed, "alice", &context(), Operation::Encrypt, b"message"),
        Err(Error::Authority)
    );
    assert_eq!(encrypt(&mut worker, &key, 2), Err(Error::Replay));
    assert!(worker.resident.is_empty());
}

#[test]
fn wrong_domain_and_wrong_incarnation_fences_do_not_purge() {
    let (mut worker, key, _) = setup();
    encrypt(&mut worker, &key, 1).unwrap();
    for (instance, domain) in [
        (worker.instance.clone(), "other"),
        ("other".into(), "development-only"),
    ] {
        let signed = sign(
            &key,
            &AuthorityMessage::Fence(Fence {
                worker: instance,
                security_domain: domain.into(),
                generation: 2,
                expires_ms: 1_000,
            }),
        );
        assert_eq!(worker.fence(&signed).unwrap_err(), Error::Authority);
        assert_eq!(worker.resident.len(), 1);
    }
}

#[test]
fn restart_refuses_a_valid_old_incarnation_grant() {
    let (worker, key, clock) = setup();
    let signed = sign(
        &key,
        &AuthorityMessage::Grant(grant(&worker, 1, Operation::Encrypt, b"message")),
    );
    let mut restarted = Worker::new(
        key.verifying_key(),
        "development-only".into(),
        LocalFixture::new(&context()).unwrap(),
        clock,
        worker.limits,
    )
    .unwrap();
    assert_ne!(worker.instance, restarted.instance);
    assert_eq!(
        restarted.execute(&signed, "alice", &context(), Operation::Encrypt, b"message"),
        Err(Error::Authority)
    );
}

struct DelayedSource {
    source: LocalFixture,
    clock: TestClock,
}
impl MaterialSource for DelayedSource {
    fn open(&mut self, context: &WrappingContext) -> Result<Secret, Error> {
        let secret = self.source.open(context)?;
        self.clock.0.set(401);
        Ok(secret)
    }
}

#[test]
fn authority_expiring_during_materialization_never_releases_result_or_caches_key() {
    let (worker, key, clock) = setup();
    let mut delayed = Worker::new(
        key.verifying_key(),
        "development-only".into(),
        DelayedSource {
            source: worker.source,
            clock: clock.clone(),
        },
        clock,
        worker.limits,
    )
    .unwrap();
    let signed = sign(
        &key,
        &AuthorityMessage::Grant(grant(&delayed, 1, Operation::Encrypt, b"message")),
    );
    assert_eq!(
        delayed.execute(&signed, "alice", &context(), Operation::Encrypt, b"message"),
        Err(Error::Expired)
    );
    assert!(delayed.resident.is_empty());
}

#[test]
fn oversized_input_and_capacity_failure_are_bounded() {
    let (mut worker, key, _) = setup();
    let signed = sign(
        &key,
        &AuthorityMessage::Grant(grant(&worker, 1, Operation::Encrypt, b"message")),
    );
    assert_eq!(
        worker.execute(
            &signed,
            "alice",
            &context(),
            Operation::Encrypt,
            &vec![0; MAX_INPUT + 1]
        ),
        Err(Error::Limit)
    );
    encrypt(&mut worker, &key, 1).unwrap();
    let mut other = context();
    other.child.version = std::num::NonZeroU64::new(2).unwrap();
    let mut g = grant(&worker, 2, Operation::Encrypt, b"message");
    g.context_sha256 = context_digest(&other).unwrap();
    let signed = sign(&key, &AuthorityMessage::Grant(g));
    assert_eq!(
        worker.execute(&signed, "alice", &other, Operation::Encrypt, b"message"),
        Err(Error::Limit)
    );
}
