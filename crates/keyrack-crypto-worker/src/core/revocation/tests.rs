// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::{
    core::*,
    delivery::{Authority, Prepared, Sink, Writer},
    fixture,
};
use ed25519_dalek::SigningKey;
use keyrack_core::{
    custody::{InFlightDisposition, Validity},
    key::ProviderRef,
    lid::Lid,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::{
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use uuid::Uuid;
use zeroize::Zeroizing;

struct Time(AtomicU64);
impl Clock for Time {
    fn millis(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Source;
impl MaterialSource for Source {
    fn open(&mut self, _: &WrappingContext) -> Result<Secret, Error> {
        Ok(Secret(Zeroizing::new(vec![42; 32])))
    }
}
type TestWorker = Worker<Source, Arc<Time>>;
fn setup() -> (TestWorker, SigningKey, Arc<Time>, Delivery<Arc<Time>>) {
    let key = SigningKey::generate(&mut OsRng);
    let time = Arc::new(Time(AtomicU64::new(0)));
    let worker = Worker::new(
        key.verifying_key(),
        "development-only".into(),
        Source,
        time.clone(),
        Limits {
            resident_keys: 160,
            residence_ms: 1000,
            uses_per_residency: 5,
            authority_horizon_ms: 1000,
        },
    )
    .unwrap();
    let delivery = Delivery::new(worker.instance.clone(), time.clone());
    (worker, key, time, delivery)
}
fn command(worker: &TestWorker) -> RevocationCommand {
    RevocationCommand {
        fence: Uuid::new_v4(),
        executor: worker.executor().unwrap(),
        authority: keyrack_core::custody::AuthorityIdentity {
            issuer: authority_key(worker.verifier).issuer,
            scope: AuthorityScope::SecurityDomain {
                provider_ref: fixture::context().provider_ref,
                security_domain: WrappingIdentifier::new("development-only").unwrap(),
            },
            generation: NonZeroU64::new(2).unwrap(),
        },
        validity: Validity {
            clock: ClockDomain::ExecutorMonotonicMilliseconds(worker.executor().unwrap()),
            not_before: 0,
            not_after: 500,
        },
    }
}
fn signed(key: &SigningKey, command: RevocationCommand) -> Vec<u8> {
    let trusted = authority_key(key.verifying_key());
    let mut evidence = Evidence {
        issuer: command.authority.issuer.clone(),
        key_id: trusted.key_id,
        claims: command,
        signature: [0; 64],
    };
    evidence.signature = key.sign(&evidence.signing_bytes().unwrap()).to_bytes();
    evidence.canonical_bytes().unwrap()
}
fn use_key(
    worker: &mut TestWorker,
    key: &SigningKey,
    seq: u64,
    context: &WrappingContext,
) -> Result<(Authority, Zeroizing<Vec<u8>>), Error> {
    let body = serde_json::to_string(&AuthorityMessage::Grant(Grant {
        worker: worker.instance.clone(),
        principal: "alice".into(),
        context_sha256: context_digest(context).unwrap(),
        operation: Operation::Encrypt,
        input_sha256: digest(b"data"),
        generation: 1,
        sequence: seq,
        not_before_ms: 0,
        expires_ms: 500,
        ancestor_expires_ms: 500,
        residency_until_ms: 1000,
    }))
    .unwrap();
    let mut message = SIGNING_DOMAIN.to_vec();
    message.extend_from_slice(body.as_bytes());
    worker.execute_for_delivery(
        &Signed {
            body,
            signature: key.sign(&message).to_bytes().to_vec(),
        },
        "alice",
        context,
        Operation::Encrypt,
        b"data",
    )
}
fn enqueue(worker: &mut TestWorker, key: &SigningKey, delivery: &Delivery<Arc<Time>>, seq: u64) {
    let (authority, output) = use_key(worker, key, seq, &fixture::context()).unwrap();
    delivery
        .enqueue(
            Prepared::new(
                authority,
                &json!({"output":STANDARD.encode(output.as_slice())}),
            )
            .unwrap(),
        )
        .unwrap();
}
#[derive(Default)]
struct Capture(Vec<Value>);
impl Sink for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.push(serde_json::from_slice(bytes).unwrap());
        Ok(bytes.len())
    }
}
fn drain(writer: &mut Writer, delivery: &Delivery<Arc<Time>>, sink: &mut Capture) {
    for _ in 0..20 {
        writer.step(delivery, sink).unwrap();
    }
}
fn verify(
    worker: &TestWorker,
    result: &Evidence<RevocationResult>,
    command: &RevocationCommand,
) -> RevocationResult {
    let bytes = result.canonical_bytes().unwrap();
    let result = Evidence::<RevocationResult>::from_canonical_bytes(&bytes)
        .unwrap()
        .authenticate(&worker.observation_key())
        .unwrap();
    result.claims().check_command(command).unwrap();
    result.claims().clone()
}
#[test]
fn canonical_receipt_maps_empty_committed_pending_and_mixed_scope() {
    for (committed, pending) in [(false, false), (true, false), (false, true), (true, true)] {
        let (mut worker, key, _, delivery) = setup();
        let mut writer = Writer::new();
        let mut sink = Capture::default();
        if committed {
            enqueue(&mut worker, &key, &delivery, 1);
            drain(&mut writer, &delivery, &mut sink);
        }
        if pending {
            enqueue(&mut worker, &key, &delivery, 2);
            writer.step(&delivery, &mut sink).unwrap();
        }
        let command = command(&worker);
        let evidence = worker
            .revoke(&signed(&key, command.clone()), &delivery)
            .unwrap();
        let result = verify(&worker, &evidence, &command);
        assert_eq!(
            result.in_flight,
            if pending {
                InFlightDisposition::OutputsSuppressed
            } else {
                InFlightDisposition::Drained
            }
        );
        assert_eq!(
            result.observed_leases.len(),
            usize::from(committed || pending)
        );
        assert!(worker.resident.is_empty());
        assert!(worker.fenced);
        drain(&mut writer, &delivery, &mut sink);
        assert_eq!(
            sink.0.iter().filter(|r| r["event"] == "release").count(),
            usize::from(committed)
        );
        assert!(worker.revoke(&signed(&key, command), &delivery).is_err());
        assert!(use_key(&mut worker, &key, 3, &fixture::context()).is_err());
    }
}
#[test]
fn signed_wrong_scope_clock_generation_and_executor_leave_work_untouched() {
    for case in 0..11 {
        let (mut worker, key, time, delivery) = setup();
        enqueue(&mut worker, &key, &delivery, 1);
        let mut command = command(&worker);
        match case {
            0 => command.authority.issuer = WrappingIdentifier::new("other-issuer").unwrap(),
            1 => command.authority.scope = AuthorityScope::Context([9; 32]),
            2 => {
                if let AuthorityScope::SecurityDomain { provider_ref, .. } =
                    &mut command.authority.scope
                {
                    *provider_ref = ProviderRef::new("other-provider");
                }
            }
            3 => {
                if let AuthorityScope::SecurityDomain {
                    security_domain, ..
                } = &mut command.authority.scope
                {
                    *security_domain = WrappingIdentifier::new("other-domain").unwrap();
                }
            }
            4 => {
                command.executor = ExecutorIncarnation::new([9; 32]).unwrap();
                command.validity.clock =
                    ClockDomain::ExecutorMonotonicMilliseconds(command.executor);
            }
            5 => command.validity.clock = ClockDomain::UnixMilliseconds,
            6 => command.validity.not_before = 1,
            7 => {
                time.0.store(500, Ordering::SeqCst);
            }
            8 => command.validity.not_after = 1001,
            9 => command.authority.generation = NonZeroU64::new(1).unwrap(),
            _ => command.validity.not_after = 1,
        }
        if case == 10 {
            time.0.store(1, Ordering::SeqCst);
        }
        assert!(worker.revoke(&signed(&key, command), &delivery).is_err());
        assert!(!worker.fenced);
        assert_eq!(worker.generation, Some(1));
        assert_eq!(worker.resident.len(), 1);
        time.0.store(0, Ordering::SeqCst);
        let mut sink = Capture::default();
        drain(&mut Writer::new(), &delivery, &mut sink);
        assert_eq!(sink.0.iter().filter(|r| r["event"] == "release").count(), 1);
    }
}
#[test]
fn initial_generation_and_signature_are_not_bootstrapped_from_command() {
    let (mut worker, key, _, delivery) = setup();
    let mut current = command(&worker);
    current.authority.generation = NonZeroU64::new(1).unwrap();
    assert!(worker.revoke(&signed(&key, current), &delivery).is_err());
    let bytes = signed(&key, command(&worker));
    let mut tampered = bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(worker.revoke(&tampered, &delivery).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(worker.revoke(&trailing, &delivery).is_err());
    let other = SigningKey::generate(&mut OsRng);
    assert!(worker
        .revoke(&signed(&other, command(&worker)), &delivery)
        .is_err());
    assert!(!worker.fenced);
    assert!(worker.generation.is_none());
    assert!(worker.revoke(&bytes, &delivery).is_ok());
}
#[test]
fn diagnostics_are_sorted_bounded_and_do_not_limit_domain_purge() {
    let (mut worker, key, _, delivery) = setup();
    for seq in 1..=140_u64 {
        let mut context = fixture::context();
        let mut bytes = [7; 32];
        bytes[..8].copy_from_slice(&seq.to_be_bytes());
        context.child.lid = Lid::from_bytes(bytes);
        use_key(&mut worker, &key, seq, &context).unwrap();
    }
    assert_eq!(worker.resident.len(), 140);
    let command = command(&worker);
    let evidence = worker
        .revoke(&signed(&key, command.clone()), &delivery)
        .unwrap();
    let result = verify(&worker, &evidence, &command);
    assert_eq!(result.observed_leases.len(), MAX_RECEIPT_LEASES);
    assert_eq!(
        result
            .observed_leases
            .iter()
            .map(|l| l.counter.get())
            .collect::<Vec<_>>(),
        (1..=128).collect::<Vec<_>>()
    );
    assert!(result
        .observed_leases
        .iter()
        .all(|l| l.executor == command.executor));
    assert!(worker.resident.is_empty());
}
#[test]
fn indeterminate_capsule_yields_no_receipt_but_still_applies_core_containment() {
    struct Short;
    impl Sink for Short {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len() - 1)
        }
    }
    let (mut worker, key, _, delivery) = setup();
    enqueue(&mut worker, &key, &delivery, 1);
    let mut writer = Writer::new();
    let mut sink = Capture::default();
    loop {
        writer.step(&delivery, &mut sink).unwrap();
        if sink.0.last().is_some_and(|r| r["last"] == true) {
            break;
        }
    }
    assert!(writer.step(&delivery, &mut Short).is_err());
    let command = command(&worker);
    assert!(worker.revoke(&signed(&key, command), &delivery).is_err());
    assert!(worker.fenced);
    assert_eq!(worker.generation, Some(2));
    assert!(worker.resident.is_empty());
}
#[test]
fn receipt_binds_exact_command_and_rejects_reuse_as_authority() {
    let (mut worker, key, _, delivery) = setup();
    let command = command(&worker);
    let evidence = worker
        .revoke(&signed(&key, command.clone()), &delivery)
        .unwrap();
    let result = verify(&worker, &evidence, &command);
    for case in 0..4 {
        let mut other = command.clone();
        match case {
            0 => other.fence = Uuid::new_v4(),
            1 => other.authority.generation = NonZeroU64::new(3).unwrap(),
            2 => other.validity.not_after -= 1,
            _ => other.authority.scope = AuthorityScope::Context([3; 32]),
        }
        assert!(result.check_command(&other).is_err());
    }
    let (mut restarted, _, _, restarted_delivery) = setup();
    restarted.verifier = key.verifying_key();
    assert!(restarted
        .revoke(&signed(&key, command), &restarted_delivery)
        .is_err());
    assert!(restarted
        .revoke(&evidence.canonical_bytes().unwrap(), &restarted_delivery)
        .is_err());
    let wrong_delivery = Delivery::new("other-worker".into(), restarted.clock.clone());
    let command = self::command(&restarted);
    assert!(restarted
        .revoke(&signed(&key, command), &wrong_delivery)
        .is_err());
    assert!(!restarted.fenced);
}
#[test]
fn grants_cannot_admit_another_provider_into_the_fenced_domain() {
    let (mut worker, key, _, _) = setup();
    let mut context = fixture::context();
    context.provider_ref = ProviderRef::new("other-provider");
    assert!(use_key(&mut worker, &key, 1, &context).is_err());
    assert!(worker.resident.is_empty());
}

#[test]
fn receipt_queue_failure_does_not_undo_applied_fence() {
    let (mut worker, key, _, delivery) = setup();
    for _ in 0..4 {
        delivery.control(&json!({"status":"queued"})).unwrap();
    }
    let command = command(&worker);
    let evidence = worker
        .revoke(&signed(&key, command.clone()), &delivery)
        .unwrap();
    let result = verify(&worker, &evidence, &command);
    assert_eq!(result.in_flight, InFlightDisposition::Drained);
    assert!(delivery
        .control(&json!({"revocation":STANDARD.encode(evidence.canonical_bytes().unwrap())}))
        .is_err());
    assert!(worker.fenced);
    assert_eq!(worker.generation, Some(2));
    assert!(use_key(&mut worker, &key, 1, &fixture::context()).is_err());
    assert!(worker.revoke(&signed(&key, command), &delivery).is_err());
}
