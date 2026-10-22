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
//! A close the request awaited is reported by the request's own result. A
//! close it could not await — because the request was cancelled, or because
//! the awaited close failed and is being retried — runs here instead, and is
//! recorded only as a cleanup outcome in the service log and metrics. That
//! record says what the provider answered after the request had gone; it is
//! never verified closure, never closure evidence for a creation, and never
//! part of an operation's response or audit outcome.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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

/// What a cleanup record names. Never key material.
#[derive(Debug, Clone)]
pub(crate) struct LeaseSubject {
    pub(crate) key_id: String,
    pub(crate) version: u64,
    pub(crate) provider: String,
    pub(crate) object: String,
    pub(crate) context_sha256: [u8; 32],
}

#[derive(Default)]
struct Counters {
    scheduled: AtomicU64,
    closed_after_return: AtomicU64,
    close_failed: AtomicU64,
    abandoned: AtomicU64,
}

#[derive(Default)]
struct Inner {
    stopped: AtomicBool,
    next: AtomicU64,
    pending: Mutex<BTreeMap<u64, LeaseSubject>>,
    counters: Counters,
}

/// Owner of every wrapped-lease open and close that must not depend on the
/// request future that started it.
#[derive(Clone, Default)]
pub struct LeaseCleanup {
    tracker: TaskTracker,
    inner: Arc<Inner>,
}

impl LeaseCleanup {
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
    /// Returns how many were abandoned here.
    pub async fn drain(&self, deadline: tokio::time::Instant) -> usize {
        self.tracker.close();
        let drained = tokio::time::timeout_at(deadline, self.tracker.wait())
            .await
            .is_ok();
        self.inner.stopped.store(true, Ordering::SeqCst);
        if drained {
            return 0;
        }
        let abandoned = std::mem::take(&mut *self.pending_map());
        for subject in abandoned.values() {
            self.record(CleanupOutcome::Abandoned, subject, None);
        }
        abandoned.len()
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
