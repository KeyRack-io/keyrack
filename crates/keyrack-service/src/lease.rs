// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of KeyRack.
//
// KeyRack is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// KeyRack is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with KeyRack. If not, see <https://www.gnu.org/licenses/>.
//
// Alternative commercial licensing is available; contact the Licensor.

//! Cleanup of wrapped-key use leases that the request cannot await.
//!
//! A close the request awaited is reported by the request's own result, or
//! logged when the operation's own error is the one returned. A
//! close it could not await — because the request was cancelled, or because
//! the awaited close failed and is being retried — runs here instead, and is
//! recorded only as a cleanup outcome in the service log and metrics. That
//! record says what the provider answered after the request had gone; it is
//! never verified closure, never closure evidence for a creation, and never
//! part of an operation's response or audit outcome.

use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::provider::{CryptoProvider, KeyHandle, WrappedKeyClosure, WrappedKeyLease};
use keyrack_core::wrapping::WrappingContext;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;

/// What happened to one close that the request did not await.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// Handed to the cleanup owner; nothing is known about closure yet.
    Scheduled,
    /// The provider reported the lease closed after the request had returned.
    /// Unverified: nobody inside the request observed it.
    ClosedAfterReturn,
    /// The provider refused or failed the close. Cleanup is still owed.
    CloseFailed,
    /// Still pending when the shutdown drain ended, or arriving after it.
    /// Closure is unknown; only provider or process teardown remains, and
    /// that is not a closure fact.
    Abandoned,
}

impl CleanupOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::ClosedAfterReturn => "closed_after_return",
            Self::CloseFailed => "close_failed",
            Self::Abandoned => "abandoned",
        }
    }
}

/// Totals per [`CleanupOutcome`] since this owner was created.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupCounts {
    pub scheduled: u64,
    pub closed_after_return: u64,
    pub close_failed: u64,
    pub abandoned: u64,
}

/// The key version a lease is opened for, as named in cleanup records.
#[derive(Debug, Clone)]
pub(crate) struct LeaseUse {
    pub(crate) key_id: String,
    pub(crate) version: u64,
    pub(crate) provider: String,
}

/// What a cleanup record names. Never key material.
#[derive(Debug, Clone)]
struct LeaseSubject {
    key_id: String,
    version: u64,
    provider: String,
    object: String,
    context_sha256: [u8; 32],
}

impl LeaseSubject {
    fn new(used: LeaseUse, lease: &WrappedKeyLease) -> Self {
        Self {
            key_id: used.key_id,
            version: used.version,
            provider: used.provider,
            object: lease.object().as_str().to_owned(),
            context_sha256: lease.context_sha256(),
        }
    }
}

type CloseTask = JoinHandle<Result<WrappedKeyClosure>>;

/// An open wrapped lease that is owed a close.
///
/// [`close`](Self::close) closes it within the request. Dropping it while
/// still owed — the request was cancelled, or the close failed — hands the
/// close to the [`LeaseCleanup`] instead.
pub(crate) struct LeaseGuard {
    owner: LeaseCleanup,
    provider: Arc<dyn CryptoProvider>,
    lease: Option<WrappedKeyLease>,
    handle: KeyHandle,
    subject: LeaseSubject,
    in_flight: Option<CloseTask>,
}

impl LeaseGuard {
    pub(crate) fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    /// Close the lease and wait for the provider's answer.
    ///
    /// The close runs on the cleanup owner, so cancelling this future does not
    /// stop it. A failed close is returned, and the lease stays owed: the
    /// owner retries it once.
    pub(crate) async fn close(mut self) -> Result<()> {
        let Some(lease) = self.lease.clone() else {
            return Ok(());
        };
        let provider = Arc::clone(&self.provider);
        let Some(task) = self
            .owner
            .spawn(async move { provider.close_wrapped_key(&lease).await })
        else {
            return Err(KeyRackError::ProviderUnavailable(
                "wrapped lease cleanup has stopped".into(),
            ));
        };
        let joined = self.in_flight.insert(task).await;
        self.in_flight = None;
        match joined {
            Ok(Ok(_)) => {
                self.lease = None;
                Ok(())
            }
            Ok(Err(error)) => {
                let subject = &self.subject;
                tracing::error!(
                    key_id = %subject.key_id,
                    version = subject.version,
                    provider = %subject.provider,
                    object = %subject.object,
                    context_sha256 = %hex(&subject.context_sha256),
                    error = %error,
                    "wrapped lease close failed; retrying outside the request"
                );
                Err(error)
            }
            Err(error) => Err(close_did_not_finish(&error)),
        }
    }
}

/// One close attempt, run as its own task so that a panic in the provider is
/// a failed attempt rather than the end of the cleanup task that must record
/// an outcome.
async fn attempt_close(
    provider: Arc<dyn CryptoProvider>,
    lease: WrappedKeyLease,
) -> Result<WrappedKeyClosure> {
    tokio::spawn(async move { provider.close_wrapped_key(&lease).await })
        .await
        .unwrap_or_else(|error| Err(close_did_not_finish(&error)))
}

fn close_did_not_finish(error: &tokio::task::JoinError) -> KeyRackError {
    if error.is_panic() {
        KeyRackError::Provider("wrapped lease close panicked in the provider".into())
    } else {
        KeyRackError::Provider(format!("wrapped lease close did not finish: {error}"))
    }
}

fn publish_pending(len: usize) {
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!("keyrack_wrapped_lease_cleanup_pending").set(len as f64);
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            self.owner.detach(
                Arc::clone(&self.provider),
                lease,
                &self.subject,
                self.in_flight.take(),
            );
        }
    }
}

#[derive(Default)]
struct Counters {
    scheduled: AtomicU64,
    closed_after_return: AtomicU64,
    close_failed: AtomicU64,
    abandoned: AtomicU64,
}

struct Inner {
    stopped: AtomicBool,
    next: AtomicU64,
    limit: usize,
    pending: Mutex<BTreeMap<u64, LeaseSubject>>,
    counters: Counters,
}

/// Default for [`LeaseCleanup::new`]'s `limit`.
pub const DEFAULT_CLEANUP_LIMIT: usize = 1024;

/// Owner of every wrapped-lease open and close that must not depend on the
/// request future that started it.
#[derive(Clone)]
pub struct LeaseCleanup {
    tracker: TaskTracker,
    inner: Arc<Inner>,
}

impl Default for LeaseCleanup {
    fn default() -> Self {
        Self::new(DEFAULT_CLEANUP_LIMIT)
    }
}

impl LeaseCleanup {
    /// An owner that refuses new wrapped-key uses while `limit` closes are
    /// outstanding.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            tracker: TaskTracker::new(),
            inner: Arc::new(Inner {
                stopped: AtomicBool::new(false),
                next: AtomicU64::new(0),
                limit,
                pending: Mutex::new(BTreeMap::new()),
                counters: Counters::default(),
            }),
        }
    }

    /// The outstanding-close limit this owner was created with.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.inner.limit
    }

    /// Open a wrapped child for one use.
    ///
    /// The open runs on the owner: a provider open may block and cannot be
    /// cancelled, so a lease it produces after the request has gone is still
    /// owned, and closed.
    ///
    /// Refused as unavailable while [`limit`](Self::limit) closes are pending:
    /// a client can cancel requests at will, and every cancelled use leaves a
    /// close behind, so new uses wait for the backlog instead of growing it.
    pub(crate) async fn open(
        &self,
        provider: Arc<dyn CryptoProvider>,
        context: WrappingContext,
        parent: KeyHandle,
        envelope: Vec<u8>,
        used: LeaseUse,
    ) -> Result<LeaseGuard> {
        if self.pending() >= self.inner.limit {
            return Err(KeyRackError::ProviderUnavailable(format!(
                "wrapped lease cleanup backlog is at its limit of {}; retry later",
                self.inner.limit
            )));
        }
        let (answer, answered) = tokio::sync::oneshot::channel();
        let owner = self.clone();
        let opening = self.spawn(async move {
            let opened = provider
                .open_wrapped_key(&context, &parent, &envelope)
                .await
                .map(|lease| LeaseGuard {
                    handle: lease.handle().clone(),
                    subject: LeaseSubject::new(used, &lease),
                    lease: Some(lease),
                    provider,
                    owner,
                    in_flight: None,
                });
            // A guard nobody received is dropped here, which schedules its close.
            drop(answer.send(opened));
        });
        if opening.is_none() {
            return Err(KeyRackError::ProviderUnavailable(
                "wrapped lease cleanup has stopped".into(),
            ));
        }
        answered
            .await
            .map_err(|_| KeyRackError::Provider("wrapped lease open did not finish".into()))?
    }

    #[must_use]
    pub fn counts(&self) -> CleanupCounts {
        let c = &self.inner.counters;
        CleanupCounts {
            scheduled: c.scheduled.load(Ordering::SeqCst),
            closed_after_return: c.closed_after_return.load(Ordering::SeqCst),
            close_failed: c.close_failed.load(Ordering::SeqCst),
            abandoned: c.abandoned.load(Ordering::SeqCst),
        }
    }

    /// Closes handed over and not yet answered.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending_map().len()
    }

    /// Stop the owner at `deadline`.
    ///
    /// Work already handed over, and work handed over while waiting, gets
    /// until `deadline`. Every close still pending then is recorded as
    /// [`CleanupOutcome::Abandoned`], as is anything handed over afterwards.
    /// That includes a close whose task finished without an outcome: the
    /// tracker finishing is not closure. Returns how many were abandoned here.
    pub async fn drain(&self, deadline: tokio::time::Instant) -> usize {
        self.tracker.close();
        let _ = tokio::time::timeout_at(deadline, self.tracker.wait()).await;
        self.inner.stopped.store(true, Ordering::SeqCst);
        let abandoned = {
            let mut pending = self.pending_map();
            let taken = std::mem::take(&mut *pending);
            publish_pending(0);
            taken
        };
        for subject in abandoned.values() {
            self.record(CleanupOutcome::Abandoned, subject, None);
        }
        abandoned.len()
    }

    /// Run `work` on the owner, or `None` once it has stopped or outside a
    /// runtime.
    fn spawn<F>(&self, work: F) -> Option<JoinHandle<F::Output>>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        if self.inner.stopped.load(Ordering::SeqCst) {
            return None;
        }
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        Some(self.tracker.spawn_on(work, &runtime))
    }

    /// Take over a close the request can no longer await: watch `in_flight`
    /// if one was already running, otherwise close. One retry follows a
    /// failure.
    fn detach(
        &self,
        provider: Arc<dyn CryptoProvider>,
        lease: WrappedKeyLease,
        subject: &LeaseSubject,
        in_flight: Option<CloseTask>,
    ) {
        let id = self.inner.next.fetch_add(1, Ordering::SeqCst);
        {
            let mut pending = self.pending_map();
            pending.insert(id, subject.clone());
            publish_pending(pending.len());
        }
        let owner = self.clone();
        let spawned = self.spawn(async move {
            let first = match in_flight {
                Some(task) => task
                    .await
                    .unwrap_or_else(|error| Err(close_did_not_finish(&error))),
                None => attempt_close(Arc::clone(&provider), lease.clone()).await,
            };
            let result = match first {
                Ok(closure) => Ok(closure),
                Err(_) => attempt_close(provider, lease).await,
            };
            owner.settle(id, result);
        });
        if spawned.is_some() {
            self.record(CleanupOutcome::Scheduled, subject, None);
        } else if self.take_pending(id).is_some() {
            self.record(CleanupOutcome::Abandoned, subject, None);
        }
    }

    fn take_pending(&self, id: u64) -> Option<LeaseSubject> {
        let mut pending = self.pending_map();
        let subject = pending.remove(&id);
        publish_pending(pending.len());
        subject
    }

    fn settle(&self, id: u64, result: Result<WrappedKeyClosure>) {
        // Absent once abandoned at the drain deadline: that record stands.
        let Some(subject) = self.take_pending(id) else {
            return;
        };
        match result {
            Ok(_) => self.record(CleanupOutcome::ClosedAfterReturn, &subject, None),
            Err(error) => {
                self.record(
                    CleanupOutcome::CloseFailed,
                    &subject,
                    Some(&error.to_string()),
                );
            }
        }
    }

    fn pending_map(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, LeaseSubject>> {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn record(&self, outcome: CleanupOutcome, subject: &LeaseSubject, error: Option<&str>) {
        let counter = match outcome {
            CleanupOutcome::Scheduled => &self.inner.counters.scheduled,
            CleanupOutcome::ClosedAfterReturn => &self.inner.counters.closed_after_return,
            CleanupOutcome::CloseFailed => &self.inner.counters.close_failed,
            CleanupOutcome::Abandoned => &self.inner.counters.abandoned,
        };
        counter.fetch_add(1, Ordering::SeqCst);
        metrics::counter!(
            "keyrack_wrapped_lease_cleanup_total",
            "outcome" => outcome.label()
        )
        .increment(1);
        let context = hex(&subject.context_sha256);
        match outcome {
            CleanupOutcome::Scheduled | CleanupOutcome::ClosedAfterReturn => tracing::warn!(
                outcome = outcome.label(),
                key_id = %subject.key_id,
                version = subject.version,
                provider = %subject.provider,
                object = %subject.object,
                context_sha256 = %context,
                "wrapped lease cleanup outside the request (unverified closure)"
            ),
            CleanupOutcome::CloseFailed | CleanupOutcome::Abandoned => tracing::error!(
                outcome = outcome.label(),
                key_id = %subject.key_id,
                version = subject.version,
                provider = %subject.provider,
                object = %subject.object,
                context_sha256 = %context,
                error = error.unwrap_or(""),
                "wrapped lease cleanup outside the request did not close (cleanup owed)"
            ),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A close whose task ended without settling (it cannot be retried any
    /// more) must not let a finished drain report a clean shutdown.
    #[tokio::test]
    async fn drain_abandons_what_is_still_pending_after_its_tasks_finish() {
        let owner = LeaseCleanup::default();
        owner.pending_map().insert(
            0,
            LeaseSubject {
                key_id: "lid_test".into(),
                version: 1,
                provider: "default".into(),
                object: "object".into(),
                context_sha256: [0; 32],
            },
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let abandoned = owner.drain(deadline).await;
        assert_eq!(
            (abandoned, owner.counts().abandoned, owner.pending()),
            (1, 1, 0)
        );
    }
}
