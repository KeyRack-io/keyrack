// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private cancellable transport supplying facts for canonical revocation evidence.
use crate::core::{Clock, Error};
use crate::release_state::{Phase as Release, Policy, Window};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use keyrack_core::custody::InFlightDisposition;
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroizing;

// POSIX minimum PIPE_BUF. Every record, including a release key, is one write.
const ATOMIC: usize = 512;
const QUEUED: usize = 4;
const RESULTS: usize = 3;
// Incarnation-local evidence is never evicted. A full ledger rejects admission;
// restart requires a fresh incarnation/grants and does not prove prior outcomes.
const OUTCOMES: usize = 4096;

#[derive(Clone)]
pub(crate) struct Authority {
    pub worker: String,
    pub generation: u64,
    pub sequence: u64,
    pub grant_sha256: [u8; 32],
    pub not_before: u64,
    pub expires: u64,
}
#[derive(serde::Serialize)]
struct Capsule<'a> {
    event: &'static str,
    id: u64,
    worker: &'a str,
    generation: u64,
    sequence: u64,
    grant_sha256: String,
    key: &'a str,
}
struct Outcome {
    authority: Authority,
    phase: Release,
}
struct Permit {
    key: Zeroizing<[u8; 32]>,
}
pub(crate) struct Prepared {
    authority: Authority,
    key: Zeroizing<[u8; 32]>,
    encoded: String,
}
impl Prepared {
    pub fn new(authority: Authority, value: &Value) -> Result<Self, Error> {
        let plain = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Material)?);
        if plain.len() > 65_536 {
            return Err(Error::Limit);
        }
        let mut key = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(key.as_mut());
        // Each independently random transport key encrypts exactly one message.
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| Error::Crypto)?;
        let bytes = cipher
            .encrypt(&Nonce::from([0; 12]), plain.as_slice())
            .map_err(|_| Error::Crypto)?;
        Ok(Self {
            authority,
            key,
            encoded: STANDARD.encode(bytes),
        })
    }
}
struct Job {
    id: Option<u64>,
    records: VecDeque<Zeroizing<Vec<u8>>>,
}
struct State {
    worker: String,
    policy: Policy,
    next: u64,
    permits: HashMap<u64, Permit>,
    outcomes: BTreeMap<u64, Outcome>,
    faulted: bool,
    queue: VecDeque<Job>,
}
impl State {
    fn suppress(&mut self, id: u64) {
        if let Some(outcome) = self.outcomes.get_mut(&id) {
            if outcome.phase == Release::Pending {
                outcome.phase = Release::Suppressed;
            }
        }
        // A terminal outcome contains metadata only, never a transport key.
        self.permits.remove(&id);
    }
    fn suppress_pending(&mut self) {
        for (id, _) in self.permits.drain() {
            if let Some(outcome) = self.outcomes.get_mut(&id) {
                if outcome.phase == Release::Pending {
                    outcome.phase = Release::Suppressed;
                }
            }
        }
    }
    fn fail_transport(&mut self) {
        self.faulted = true;
        self.policy.stop();
        self.suppress_pending();
        self.queue.clear();
    }
}
pub(crate) struct Delivery<C> {
    state: Mutex<State>,
    clock: C,
}
fn record<T: serde::Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Material)?);
    bytes.push(b'\n');
    if bytes.len() > ATOMIC {
        return Err(Error::Limit);
    }
    Ok(bytes)
}
// Control frames can exceed PIPE_BUF (ready contains canonical request/context),
// but contain no operation output. Chunk them using the same bounded framing.
fn chunks(id: Option<u64>, encoded: &str) -> Result<VecDeque<Zeroizing<Vec<u8>>>, Error> {
    encoded.as_bytes().chunks(256).enumerate().map(|(part, bytes)| {
        record(&json!({"event": if id.is_some() {"staged"} else {"control"},
            "id": id, "part": part, "data": std::str::from_utf8(bytes).map_err(|_| Error::Material)?,
            "last": (part + 1) * 256 >= encoded.len()}))
    }).collect()
}
impl<C: Clock> Delivery<C> {
    pub fn new(worker: String, clock: C) -> Self {
        Self {
            clock,
            state: Mutex::new(State {
                worker,
                policy: Policy::default(),
                next: 0,
                permits: HashMap::new(),
                outcomes: BTreeMap::new(),
                faulted: false,
                queue: VecDeque::new(),
            }),
        }
    }
    fn window(state: &State, a: &Authority) -> Window {
        Window {
            incarnation_matches: a.worker == state.worker,
            generation: a.generation,
            not_before: a.not_before,
            expires: a.expires,
        }
    }
    fn allowed(&self, state: &State, a: &Authority) -> bool {
        state
            .policy
            .allows(Self::window(state, a), self.clock.millis())
    }
    pub fn enqueue(&self, prepared: Prepared) -> Result<(), Error> {
        let mut s = self.state.lock().map_err(|_| Error::Material)?;
        if !self.allowed(&s, &prepared.authority) {
            return Err(Error::Expired);
        }
        if s.queue.len() >= QUEUED || s.permits.len() >= RESULTS || s.outcomes.len() >= OUTCOMES {
            return Err(Error::Limit);
        }
        s.next = s.next.checked_add(1).ok_or(Error::Limit)?;
        let id = s.next;
        let records = chunks(Some(id), &prepared.encoded)?;
        let window = Self::window(&s, &prepared.authority);
        if !s.policy.admit(window, self.clock.millis()) {
            return Err(Error::Expired);
        }
        s.outcomes.insert(
            id,
            Outcome {
                phase: Release::Pending,
                authority: prepared.authority,
            },
        );
        s.permits.insert(id, Permit { key: prepared.key });
        s.queue.push_back(Job {
            id: Some(id),
            records,
        });
        Ok(())
    }
    pub fn control(&self, value: &Value) -> Result<(), Error> {
        let encoded = STANDARD.encode(serde_json::to_vec(value).map_err(|_| Error::Material)?);
        if encoded.len() > 90_000 {
            return Err(Error::Limit);
        }
        let mut s = self.state.lock().map_err(|_| Error::Material)?;
        if s.policy.stopped() || s.queue.len() >= QUEUED {
            return Err(Error::Limit);
        }
        s.queue.push_back(Job {
            id: None,
            records: chunks(None, &encoded)?,
        });
        Ok(())
    }
    // Validation, core purge and transport cancellation share the release lock.
    // Invalid fences cannot cancel anything. Keys are dropped before observation.
    pub fn fence<T>(
        &self,
        worker: &str,
        generation: u64,
        apply: impl FnOnce() -> Result<T, Error>,
    ) -> Result<(T, InFlightDisposition), Error> {
        let mut s = self.state.lock().map_err(|_| Error::Material)?;
        // This gate belongs to one trusted provider/domain and incarnation.
        // Never attest another worker's or a newer generation's release state.
        if s.worker != worker
            || generation == 0
            || s.outcomes
                .values()
                .any(|o| o.authority.worker != worker || o.authority.generation >= generation)
        {
            return Err(Error::Authority);
        }
        let observation = apply()?;
        s.policy.fence(true);
        s.suppress_pending();
        // Apply valid authority revocation and purge even on a failed transport,
        // but never turn uncertain disclosure into a successful observation.
        if s.faulted
            || s.outcomes
                .values()
                .any(|o| matches!(o.phase, Release::Pending | Release::Indeterminate))
        {
            return Err(Error::Material);
        }
        // Conservative scope-wide postcondition: historical cancellations also
        // justify suppression, without claiming those notifications are pending.
        // Prior commits remain irrevocable; a mixed history is wire value 2.
        let disposition = if s.outcomes.values().any(|o| o.phase == Release::Suppressed) {
            InFlightDisposition::OutputsSuppressed
        } else {
            InFlightDisposition::Drained
        };
        Ok((observation, disposition))
    }
    pub fn stop(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.policy.stop();
            s.suppress_pending();
            s.queue.clear();
        }
    }
    fn fail_transport(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.fail_transport();
        }
    }
    pub fn stopped(&self) -> bool {
        self.state.lock().map_or(true, |s| s.policy.stopped())
    }
    fn expire(&self) {
        let mut s = self.state.lock().unwrap();
        let expired: Vec<_> = s
            .permits
            .keys()
            .filter(|id| !self.allowed(&s, &s.outcomes[id].authority))
            .copied()
            .collect();
        for id in expired {
            s.suppress(id);
        }
    }
    fn active(&self, id: u64) -> Result<bool, Error> {
        let mut s = self.state.lock().map_err(|_| Error::Material)?;
        let outcome = s.outcomes.get(&id).ok_or(Error::Material)?;
        match outcome.phase {
            Release::Pending => {
                if !s.permits.contains_key(&id) {
                    return Err(Error::Material);
                }
                if self.allowed(&s, &outcome.authority) {
                    Ok(true)
                } else {
                    s.suppress(id);
                    Ok(false)
                }
            }
            Release::Suppressed => Ok(false),
            // Absence of a permit is never itself evidence of suppression.
            Release::Committed | Release::Indeterminate => Err(Error::Material),
        }
    }
    fn release(&self, id: u64, sink: &mut impl Sink) -> Result<Release, Error> {
        let mut s = self.state.lock().map_err(|_| Error::Material)?;
        let outcome = s.outcomes.get(&id).ok_or(Error::Material)?;
        match outcome.phase {
            Release::Committed | Release::Suppressed => return Ok(outcome.phase),
            Release::Indeterminate => return Err(Error::Material),
            Release::Pending => {}
        }
        if !self.allowed(&s, &outcome.authority) {
            s.suppress(id);
            return Ok(Release::Suppressed);
        }
        let a = &outcome.authority;
        let p = s.permits.get(&id).ok_or(Error::Material)?;
        let encoded_key = Zeroizing::new(STANDARD.encode(p.key.as_ref()));
        let capsule = record(&Capsule {
            event: "release",
            id,
            worker: &a.worker,
            generation: a.generation,
            sequence: a.sequence,
            grant_sha256: STANDARD.encode(a.grant_sha256),
            key: encoded_key.as_str(),
        });
        let capsule = match capsule {
            Ok(capsule) => capsule,
            Err(error) => {
                // No syscall attempted: cancellation is known, transport failed.
                s.fail_transport();
                return Err(error);
            }
        };
        // Final admission, syscall, terminal evidence and fault latch all share
        // the fence mutex. No fence can observe an unrecorded capsule result.
        let window = Self::window(&s, a);
        let State {
            policy, outcomes, ..
        } = &mut *s;
        let outcome = outcomes.get_mut(&id).ok_or(Error::Material)?;
        let phase = policy.release(&mut outcome.phase, window, self.clock.millis(), || {
            atomic(sink, &capsule)
        });
        if !matches!(phase, Ok(Release::Pending)) {
            s.permits.remove(&id);
        }
        if phase.is_err() {
            // The kernel retained Indeterminate, not Suppressed. All other
            // uncommitted keys can still be cancelled; prior commits survive.
            s.fail_transport();
        }
        phase
    }
}
pub(crate) trait Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize>;
}
fn atomic(sink: &mut impl Sink, bytes: &[u8]) -> Result<bool, Error> {
    match sink.write(bytes) {
        Ok(n) if n == bytes.len() => Ok(true),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        _ => Err(Error::Material), // A partial write violates the verified pipe contract.
    }
}
pub(crate) struct Writer {
    current: Option<Job>,
}
impl Writer {
    pub fn new() -> Self {
        Self { current: None }
    }
    // One nonblocking record per step. No secret key is held by the writer.
    pub fn step<C: Clock>(
        &mut self,
        delivery: &Delivery<C>,
        sink: &mut impl Sink,
    ) -> Result<(), Error> {
        let result = self.step_inner(delivery, sink);
        if result.is_err() {
            delivery.fail_transport();
            self.current = None;
        }
        result
    }
    fn step_inner<C: Clock>(
        &mut self,
        delivery: &Delivery<C>,
        sink: &mut impl Sink,
    ) -> Result<(), Error> {
        delivery.expire();
        if delivery.stopped() {
            self.current = None;
            return Ok(());
        }
        if self.current.is_none() {
            self.current = delivery.state.lock().unwrap().queue.pop_front();
        }
        let Some(job) = self.current.as_mut() else {
            return Ok(());
        };
        if let Some(id) = job.id {
            if !delivery.active(id)? {
                job.id = None;
                job.records = chunks(
                    None,
                    &STANDARD.encode(
                        serde_json::to_vec(&json!({"error":"output suppressed", "delivery":id}))
                            .map_err(|_| Error::Material)?,
                    ),
                )?;
            }
        }
        if let Some(bytes) = job.records.front() {
            if atomic(sink, bytes)? {
                job.records.pop_front();
            }
        } else if let Some(id) = job.id {
            match delivery.release(id, sink)? {
                Release::Committed => self.current = None,
                Release::Pending => {}
                Release::Indeterminate => return Err(Error::Material),
                Release::Suppressed => {
                    job.id = None;
                    job.records = chunks(
                        None,
                        &STANDARD.encode(
                            serde_json::to_vec(
                                &json!({"error":"output suppressed", "delivery":id}),
                            )
                            .map_err(|_| Error::Material)?,
                        ),
                    )?;
                }
            }
        } else {
            self.current = None;
        }
        Ok(())
    }
}
#[cfg(unix)]
struct Pipe(std::io::Stdout);
#[cfg(unix)]
impl Pipe {
    fn new() -> Result<Self, Error> {
        use rustix::fs::{fcntl_getfl, fcntl_setfl, fstat, FileType, OFlags};
        let stdout = std::io::stdout();
        if FileType::from_raw_mode(fstat(&stdout).map_err(|_| Error::Material)?.st_mode)
            != FileType::Fifo
        {
            return Err(Error::Context);
        }
        let flags = fcntl_getfl(&stdout).map_err(|_| Error::Material)?;
        fcntl_setfl(&stdout, flags | OFlags::NONBLOCK).map_err(|_| Error::Material)?;
        Ok(Self(stdout))
    }
}
#[cfg(unix)]
impl Sink for Pipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        rustix::io::write(&self.0, bytes).map_err(Into::into)
    }
}
pub(crate) fn spawn<C: Clock + Send + Sync + 'static>(
    delivery: Arc<Delivery<C>>,
) -> Result<std::thread::JoinHandle<()>, Error> {
    #[cfg(unix)]
    {
        let mut sink = Pipe::new()?;
        Ok(std::thread::spawn(move || {
            let mut writer = Writer::new();
            while !delivery.stopped() {
                if writer.step(&delivery, &mut sink).is_err() {
                    delivery.stop();
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }))
    }
    #[cfg(not(unix))]
    {
        let _ = delivery;
        Err(Error::Context)
    }
}

#[cfg(test)]
mod tests;
