// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private cancellable response transport. No canonical revocation receipt.
use crate::core::{Clock, Error};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroizing;

// POSIX minimum PIPE_BUF. Every record, including a release key, is one write.
const ATOMIC: usize = 512;
const QUEUED: usize = 4;
const RESULTS: usize = 3;

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
struct Permit {
    authority: Authority,
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
    generation: Option<u64>,
    fenced: bool,
    stopped: bool,
    next: u64,
    permits: HashMap<u64, Permit>,
    queue: VecDeque<Job>,
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
                generation: None,
                fenced: false,
                stopped: false,
                next: 0,
                permits: HashMap::new(),
                queue: VecDeque::new(),
            }),
        }
    }
    fn allowed(&self, state: &State, a: &Authority) -> bool {
        let now = self.clock.millis();
        !state.stopped
            && !state.fenced
            && a.worker == state.worker
            && a.generation != 0
            && state.generation.map_or(true, |g| g == a.generation)
            && now >= a.not_before
            && now < a.expires
    }
    pub fn enqueue(&self, prepared: Prepared) -> Result<(), Error> {
        let mut s = self.state.lock().map_err(|_| Error::Material)?;
        if !self.allowed(&s, &prepared.authority) {
            return Err(Error::Expired);
        }
        if s.queue.len() >= QUEUED || s.permits.len() >= RESULTS {
            return Err(Error::Limit);
        }
        s.next = s.next.checked_add(1).ok_or(Error::Limit)?;
        let id = s.next;
        let records = chunks(Some(id), &prepared.encoded)?;
        s.generation = Some(prepared.authority.generation);
        s.permits.insert(
            id,
            Permit {
                authority: prepared.authority,
                key: prepared.key,
            },
        );
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
        if s.stopped || s.queue.len() >= QUEUED {
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
    pub fn fence<T>(&self, apply: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let mut s = self.state.lock().map_err(|_| Error::Material)?;
        let observation = apply()?;
        s.fenced = true;
        s.permits.clear();
        Ok(observation)
    }
    pub fn stop(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.stopped = true;
            s.permits.clear();
            s.queue.clear();
        }
    }
    pub fn stopped(&self) -> bool {
        self.state.lock().map_or(true, |s| s.stopped)
    }
    fn expire(&self) {
        let mut s = self.state.lock().unwrap();
        let expired: Vec<_> = s
            .permits
            .iter()
            .filter(|(_, p)| !self.allowed(&s, &p.authority))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            s.permits.remove(&id);
        }
    }
    fn active(&self, id: u64) -> bool {
        let mut s = self.state.lock().unwrap();
        let active = s
            .permits
            .get(&id)
            .is_some_and(|p| self.allowed(&s, &p.authority));
        if !active {
            s.permits.remove(&id);
        }
        active
    }
    fn release(&self, id: u64, sink: &mut impl Sink) -> Result<Release, Error> {
        let mut s = self.state.lock().map_err(|_| Error::Material)?;
        let Some(p) = s.permits.get(&id) else {
            return Ok(Release::Suppressed);
        };
        if !self.allowed(&s, &p.authority) {
            s.permits.remove(&id);
            return Ok(Release::Suppressed);
        }
        let a = &p.authority;
        let encoded_key = Zeroizing::new(STANDARD.encode(p.key.as_ref()));
        let capsule = record(&Capsule {
            event: "release",
            id,
            worker: &a.worker,
            generation: a.generation,
            sequence: a.sequence,
            grant_sha256: STANDARD.encode(a.grant_sha256),
            key: encoded_key.as_str(),
        })?;
        // Final authorization check immediately before the nonblocking syscall.
        // No fence can linearize between this check and that syscall's result.
        if !self.allowed(&s, &p.authority) {
            s.permits.remove(&id);
            return Ok(Release::Suppressed);
        }
        if atomic(sink, &capsule)? {
            s.permits.remove(&id);
            Ok(Release::Committed)
        } else {
            Ok(Release::Pending)
        }
    }
}
enum Release {
    Pending,
    Committed,
    Suppressed,
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
        if let Some(id) = job.id.filter(|id| !delivery.active(*id)) {
            job.id = None;
            job.records = chunks(
                None,
                &STANDARD.encode(
                    serde_json::to_vec(&json!({"error":"output suppressed", "delivery":id}))
                        .map_err(|_| Error::Material)?,
                ),
            )?;
        }
        if let Some(bytes) = job.records.front() {
            if atomic(sink, bytes)? {
                job.records.pop_front();
            }
        } else if let Some(id) = job.id {
            match delivery.release(id, sink)? {
                Release::Committed => self.current = None,
                Release::Pending => {}
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
