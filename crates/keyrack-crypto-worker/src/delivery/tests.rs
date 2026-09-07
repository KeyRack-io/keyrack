// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
struct Preempt {
    time: Arc<Time>,
    capture: Capture,
}
impl Sink for Preempt {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if serde_json::from_slice::<Value>(bytes).unwrap()["event"] == "release" {
            self.time.0.store(101, Ordering::SeqCst); // OS delay after final check.
        }
        self.capture.write(bytes)
    }
}
struct Paused {
    entered: Arc<std::sync::Barrier>,
    resume: Arc<std::sync::Barrier>,
    capture: Capture,
    once: bool,
}
impl Sink for Paused {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.once {
            self.once = true;
            self.entered.wait();
            self.resume.wait();
        }
        self.capture.write(bytes)
    }
}
struct Time(AtomicU64);
impl Clock for Time {
    fn millis(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
#[derive(Default)]
struct Capture {
    records: Vec<Value>,
    blocked: bool,
}
impl Sink for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.blocked {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.records.push(serde_json::from_slice(bytes).unwrap());
        Ok(bytes.len())
    }
}
fn fixture() -> (Arc<Time>, Delivery<Arc<Time>>, Prepared) {
    let time = Arc::new(Time(AtomicU64::new(10)));
    let delivery = Delivery::new("instance".into(), time.clone());
    let prepared = Prepared::new(
        Authority {
            worker: "instance".into(),
            generation: 1,
            sequence: 1,
            grant_sha256: [9; 32],
            not_before: 0,
            expires: 100,
        },
        &json!({"output":STANDARD.encode(vec![42; 16_384])}),
    )
    .unwrap();
    (time, delivery, prepared)
}
fn run(writer: &mut Writer, delivery: &Delivery<Arc<Time>>, sink: &mut Capture) {
    for _ in 0..200 {
        writer.step(delivery, sink).unwrap();
    }
}
fn no_release(delivery: &Delivery<Arc<Time>>, sink: &Capture) {
    assert!(delivery.state.lock().unwrap().permits.is_empty());
    assert!(!sink.records.iter().any(|r| r["event"] == "release"));
    assert!(!sink.records.iter().any(|r| r.get("output").is_some()));
}
#[test]
fn fence_between_authorization_and_enqueue_suppresses() {
    let (_, d, p) = fixture();
    d.fence(|| Ok(())).unwrap();
    assert!(d.enqueue(p).is_err());
    no_release(&d, &Capture::default());
}
#[test]
fn fence_mid_blocked_write_cancels_remaining_staging_and_key() {
    let (_, d, p) = fixture();
    d.enqueue(p).unwrap();
    let mut w = Writer::new();
    let mut sink = Capture::default();
    w.step(&d, &mut sink).unwrap(); // Receiver has only one ciphertext fragment.
    sink.blocked = true;
    w.step(&d, &mut sink).unwrap();
    d.fence(|| Ok(())).unwrap();
    sink.blocked = false;
    run(&mut w, &d, &mut sink);
    assert_eq!(
        sink.records
            .iter()
            .filter(|r| r["event"] == "staged")
            .count(),
        1
    );
    no_release(&d, &sink);
}
#[test]
fn fence_after_enqueue_before_capsule_flush_suppresses() {
    let (_, d, p) = fixture();
    d.enqueue(p).unwrap();
    let mut w = Writer::new();
    let mut sink = Capture::default();
    loop {
        w.step(&d, &mut sink).unwrap();
        if sink.records.last().is_some_and(|r| r["last"] == true) {
            break;
        }
    }
    sink.blocked = true;
    w.step(&d, &mut sink).unwrap(); // Atomic capsule returns EAGAIN.
    d.fence(|| Ok(())).unwrap();
    sink.blocked = false;
    run(&mut w, &d, &mut sink);
    no_release(&d, &sink);
}
#[test]
fn retry_revalidates_deadline_and_incarnation_and_generation() {
    let (time, d, p) = fixture();
    d.enqueue(p).unwrap();
    let mut w = Writer::new();
    let mut sink = Capture::default();
    loop {
        w.step(&d, &mut sink).unwrap();
        if sink.records.last().is_some_and(|r| r["last"] == true) {
            break;
        }
    }
    sink.blocked = true;
    w.step(&d, &mut sink).unwrap();
    time.0.store(100, Ordering::SeqCst);
    sink.blocked = false;
    run(&mut w, &d, &mut sink);
    no_release(&d, &sink);
    for (worker, generation) in [("other", 1), ("instance", 2)] {
        let (_, d, mut p) = fixture();
        d.state.lock().unwrap().policy.generation = Some(1);
        p.authority.worker = worker.into();
        p.authority.generation = generation;
        assert!(d.enqueue(p).is_err());
    }
}
#[test]
fn committed_output_precedes_fence_and_invalid_fence_cannot_cancel() {
    let (_, d, p) = fixture();
    d.enqueue(p).unwrap();
    assert!(d.fence(|| Err::<(), _>(Error::Authority)).is_err());
    let mut w = Writer::new();
    let mut sink = Capture::default();
    run(&mut w, &d, &mut sink);
    d.fence(|| Ok(())).unwrap();
    let capsule = sink.records.last().unwrap();
    assert_eq!(capsule["event"], "release");
    assert_eq!(capsule["generation"], 1);
    assert_eq!(capsule["worker"], "instance");
    let ciphertext = sink
        .records
        .iter()
        .filter(|r| r["event"] == "staged")
        .map(|r| r["data"].as_str().unwrap())
        .collect::<String>();
    let key = Zeroizing::new(STANDARD.decode(capsule["key"].as_str().unwrap()).unwrap());
    let plaintext = Zeroizing::new(
        Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                &Nonce::from([0; 12]),
                STANDARD.decode(ciphertext).unwrap().as_slice(),
            )
            .unwrap(),
    );
    let value: Value = serde_json::from_slice(&plaintext).unwrap();
    assert!(value["output"].is_string());
}

#[test]
fn expiry_sweeps_keys_behind_blocked_control_and_emits_terminal_cancellation() {
    let (time, d, p) = fixture();
    d.control(&json!({"ready":true})).unwrap();
    d.enqueue(p).unwrap();
    let mut w = Writer::new();
    let mut sink = Capture {
        blocked: true,
        ..Capture::default()
    };
    w.step(&d, &mut sink).unwrap();
    time.0.store(100, Ordering::SeqCst);
    w.step(&d, &mut sink).unwrap();
    no_release(&d, &sink);
    sink.blocked = false;
    run(&mut w, &d, &mut sink);
    assert!(sink
        .records
        .iter()
        .filter(|r| r["event"] == "control")
        .any(|r| {
            let decoded = STANDARD.decode(r["data"].as_str().unwrap()).unwrap();
            String::from_utf8(decoded)
                .unwrap()
                .contains("output suppressed")
        }));
}

#[test]
fn fence_arrives_inside_staging_write_without_waiting_for_writer() {
    let (_, d, p) = fixture();
    let d = Arc::new(d);
    d.enqueue(p).unwrap();
    let entered = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    let worker = d.clone();
    let writer_entered = entered.clone();
    let writer_resume = resume.clone();
    let thread = std::thread::spawn(move || {
        let mut w = Writer::new();
        let mut sink = Paused {
            entered: writer_entered,
            resume: writer_resume,
            capture: Capture::default(),
            once: false,
        };
        w.step(&worker, &mut sink).unwrap();
        run(&mut w, &worker, &mut sink.capture);
        sink.capture
    });
    entered.wait();
    d.fence(|| Ok(())).unwrap();
    resume.wait();
    no_release(&d, &thread.join().unwrap());
}

#[test]
fn successful_commit_after_admission_is_never_relabelled_suppressed() {
    let (time, d, p) = fixture();
    d.enqueue(p).unwrap();
    let mut w = Writer::new();
    let mut sink = Preempt {
        time,
        capture: Capture::default(),
    };
    for _ in 0..200 {
        w.step(&d, &mut sink).unwrap();
    }
    assert_eq!(sink.capture.records.last().unwrap()["event"], "release");
    assert!(d.state.lock().unwrap().permits.is_empty());
    d.fence(|| Ok(())).unwrap(); // The prior commit is irrevocable, not suppressed.
}

// These tests enumerate transport facts, not canonical receipt dispositions.
fn cancelled(sink: &Capture, id: u64) -> bool {
    sink.records
        .iter()
        .filter(|r| r["event"] == "control")
        .any(|r| {
            let bytes = STANDARD.decode(r["data"].as_str().unwrap()).unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            value["error"] == "output suppressed" && value["delivery"] == id
        })
}

#[test]
fn fence_cancels_every_precommit_staging_position() {
    let (_, _, sample) = fixture();
    let parts = sample.encoded.len().div_ceil(256);
    for staged in 0..=parts {
        let (_, d, p) = fixture();
        d.enqueue(p).unwrap();
        let mut w = Writer::new();
        let mut sink = Capture::default();
        for _ in 0..staged {
            w.step(&d, &mut sink).unwrap();
        }
        assert_eq!(sink.records.len(), staged);
        d.fence(|| Ok(())).unwrap();
        run(&mut w, &d, &mut sink);
        no_release(&d, &sink);
        assert!(cancelled(&sink, 1));
        assert_eq!(
            sink.records
                .iter()
                .filter(|r| r["event"] == "staged")
                .count(),
            staged
        );
    }
}

#[test]
fn identical_empty_fence_state_can_follow_commit_or_expiry_suppression() {
    let history = |commit: bool| {
        let (time, d, p) = fixture();
        let parts = p.encoded.len().div_ceil(256);
        d.enqueue(p).unwrap();
        let mut w = Writer::new();
        let mut sink = Capture::default();
        for _ in 0..parts {
            w.step(&d, &mut sink).unwrap();
        }
        if commit {
            w.step(&d, &mut sink).unwrap();
        }
        time.0.store(100, Ordering::SeqCst);
        run(&mut w, &d, &mut sink);
        assert!(w.current.is_none());
        assert_eq!(
            sink.records
                .iter()
                .filter(|r| r["event"] == "release")
                .count(),
            usize::from(commit)
        );
        assert_eq!(cancelled(&sink, 1), !commit);
        let before = {
            let s = d.state.lock().unwrap();
            assert!(s.permits.is_empty());
            assert!(s.queue.is_empty());
            (
                s.worker.clone(),
                s.policy,
                s.next,
                s.permits.len(),
                s.queue.len(),
            )
        };
        d.fence(|| Ok(())).unwrap();
        let s = d.state.lock().unwrap();
        (
            before,
            (
                s.worker.clone(),
                s.policy,
                s.next,
                s.permits.len(),
                s.queue.len(),
            ),
        )
    };
    assert_eq!(history(true), history(false));
}

#[test]
fn mixed_committed_and_cancelled_response_history_is_reachable() {
    let (_, d, first) = fixture();
    d.enqueue(first).unwrap();
    let mut w = Writer::new();
    let mut sink = Capture::default();
    run(&mut w, &d, &mut sink); // Delivery 1 irrevocably committed.
    let (_, _, mut second) = fixture();
    second.authority.sequence = 2;
    d.enqueue(second).unwrap();
    w.step(&d, &mut sink).unwrap(); // Delivery 2 only partly staged.
    d.fence(|| Ok(())).unwrap();
    run(&mut w, &d, &mut sink);
    let released: Vec<_> = sink
        .records
        .iter()
        .filter(|r| r["event"] == "release")
        .map(|r| r["id"].as_u64().unwrap())
        .collect();
    assert_eq!(released, vec![1]);
    assert!(cancelled(&sink, 2));
    assert!(!cancelled(&sink, 1));
    assert!(sink
        .records
        .iter()
        .any(|r| r["event"] == "staged" && r["id"] == 2));
}

#[test]
fn injected_short_capsule_write_is_not_non_disclosure_evidence() {
    struct ShortWrite(Vec<u8>);
    impl Sink for ShortWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            // This violates the verified FIFO contract. Omit only the newline:
            // a malicious receiver still has the entire JSON key capsule.
            self.0.extend_from_slice(&bytes[..bytes.len() - 1]);
            Ok(bytes.len() - 1)
        }
    }
    let (_, d, p) = fixture();
    let parts = p.encoded.len().div_ceil(256);
    d.enqueue(p).unwrap();
    let mut w = Writer::new();
    let mut staged = Capture::default();
    for _ in 0..parts {
        w.step(&d, &mut staged).unwrap();
    }
    let mut short = ShortWrite(Vec::new());
    assert!(matches!(w.step(&d, &mut short), Err(Error::Material)));
    assert!(d.state.lock().unwrap().permits.is_empty());
    // The writer loop calls stop() only after step() returns its error. In this
    // interval fence() itself has no retained transport-fault classification.
    d.fence(|| Ok(())).unwrap();
    let capsule: Value = serde_json::from_slice(&short.0).unwrap();
    let key = Zeroizing::new(STANDARD.decode(capsule["key"].as_str().unwrap()).unwrap());
    let ciphertext = staged
        .records
        .iter()
        .map(|r| r["data"].as_str().unwrap())
        .collect::<String>();
    let plaintext = Zeroizing::new(
        Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                &Nonce::from([0; 12]),
                STANDARD.decode(ciphertext).unwrap().as_slice(),
            )
            .unwrap(),
    );
    assert!(serde_json::from_slice::<Value>(&plaintext).unwrap()["output"].is_string());
    d.stop();
    assert!(d.stopped());
}

#[test]
fn empty_queue_and_permits_can_hide_writer_held_cancellation() {
    let (time, d, p) = fixture();
    let parts = p.encoded.len().div_ceil(256);
    d.enqueue(p).unwrap();
    let mut w = Writer::new();
    let mut sink = Capture::default();
    for _ in 0..parts {
        w.step(&d, &mut sink).unwrap();
    }
    time.0.store(100, Ordering::SeqCst);
    d.expire();
    {
        let s = d.state.lock().unwrap();
        assert!(s.queue.is_empty());
        assert!(s.permits.is_empty());
    }
    assert!(w.current.is_some());
    assert!(!cancelled(&sink, 1)); // Cancellation is still unresolved to the reader.
    d.fence(|| Ok(())).unwrap();
    run(&mut w, &d, &mut sink);
    no_release(&d, &sink);
    assert!(cancelled(&sink, 1));
}
