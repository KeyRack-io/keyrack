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

//! Graceful shutdown drain.

use crate::state::ServiceState;
use std::future::Future;
use std::time::Duration;

/// How a drain ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    /// Servers and workers finished before the deadline.
    pub tasks_drained: bool,
    /// Lease closes still pending at the deadline, recorded as abandoned.
    pub cleanups_abandoned: usize,
}

/// Drain `tasks` (servers and workers), then wrapped-lease cleanup, within one
/// `budget`.
///
/// Requests drain first because cancelling them is what hands closes to the
/// cleanup owner. Cleanup gets whatever remains of the same budget, with no
/// extension: shutdown never takes longer than `budget`.
pub async fn drain(
    state: &ServiceState,
    tasks: impl Future<Output = ()>,
    budget: Duration,
) -> DrainReport {
    let deadline = tokio::time::Instant::now() + budget;
    let tasks_drained = tokio::time::timeout_at(deadline, tasks).await.is_ok();
    let cleanups_abandoned = state.lease_cleanup.drain(deadline).await;
    DrainReport {
        tasks_drained,
        cleanups_abandoned,
    }
}
