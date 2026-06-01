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

//! Rotation-job state machine per `KEYRACK_SPEC.md` §5.6.
//!
//! ```text
//! pending → acknowledged → completed | failed
//!                        \→ expired (auto on expires_at)
//! ```
//!
//! Each rotation of a parent key creates one `RotationJob` per
//! dependent key. The consuming service (Volume, Bucket, etc.) polls
//! for pending jobs, acknowledges, re-wraps, and completes/fails.

use crate::lid::Lid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Default expiry: 24 hours from creation.
pub const DEFAULT_EXPIRY_SECS: i64 = 24 * 60 * 60;

/// Rotation job lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationJobState {
    Pending,
    Acknowledged,
    Completed,
    Failed,
    Expired,
}

impl RotationJobState {
    #[must_use]
    pub fn valid_transitions(&self) -> &'static [RotationJobState] {
        match self {
            Self::Pending => &[Self::Acknowledged, Self::Expired],
            Self::Acknowledged => &[Self::Completed, Self::Failed, Self::Expired],
            Self::Completed | Self::Failed | Self::Expired => &[],
        }
    }

    #[must_use]
    pub fn can_transition_to(&self, target: Self) -> bool {
        self.valid_transitions().contains(&target)
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Expired)
    }
}

impl std::fmt::Display for RotationJobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::Acknowledged => f.write_str("acknowledged"),
            Self::Completed => f.write_str("completed"),
            Self::Failed => f.write_str("failed"),
            Self::Expired => f.write_str("expired"),
        }
    }
}

/// A cooperative rotation job record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationJob {
    pub job_id: String,
    /// LID of the parent key that was rotated.
    pub parent_lid: Lid,
    /// LID of the dependent key that needs re-wrapping.
    pub dependent_lid: Lid,
    /// The new key version number on the parent.
    pub new_version: u64,
    pub state: RotationJobState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub failure_reason: Option<String>,
}

impl RotationJob {
    /// Create a new pending rotation job with default expiry.
    #[must_use]
    pub fn new(
        job_id: impl Into<String>,
        parent_lid: Lid,
        dependent_lid: Lid,
        new_version: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            job_id: job_id.into(),
            parent_lid,
            dependent_lid,
            new_version,
            state: RotationJobState::Pending,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(DEFAULT_EXPIRY_SECS),
            acknowledged_at: None,
            completed_at: None,
            failure_reason: None,
        }
    }

    /// Transition to a new state. Returns `Err` on invalid transition.
    pub fn transition_to(
        &mut self,
        target: RotationJobState,
    ) -> std::result::Result<(), (RotationJobState, RotationJobState)> {
        let from = self.state;
        if !from.can_transition_to(target) {
            return Err((from, target));
        }

        let now = Utc::now();
        match target {
            RotationJobState::Acknowledged => self.acknowledged_at = Some(now),
            RotationJobState::Completed => self.completed_at = Some(now),
            _ => {}
        }
        self.state = target;
        Ok(())
    }

    /// Mark as failed with a reason.
    pub fn fail(
        &mut self,
        reason: impl Into<String>,
    ) -> std::result::Result<(), (RotationJobState, RotationJobState)> {
        self.failure_reason = Some(reason.into());
        self.transition_to(RotationJobState::Failed)
    }

    /// Check if the job has expired (by wall clock).
    #[must_use]
    pub fn is_expired(&self) -> bool {
        !self.state.is_terminal() && Utc::now() >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AttributeSet, AttributeValue};
    use crate::canon::{canonicalize, CanonicalizationVersion};

    fn test_lid(name: &str) -> Lid {
        let mut attrs = AttributeSet::new();
        attrs.insert("name", AttributeValue::String(name.into()));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        Lid::derive(CanonicalizationVersion::V1, &form)
    }

    #[test]
    fn happy_path_lifecycle() {
        let mut job = RotationJob::new("job-1", test_lid("parent"), test_lid("child"), 2);
        assert_eq!(job.state, RotationJobState::Pending);

        assert!(job.transition_to(RotationJobState::Acknowledged).is_ok());
        assert!(job.acknowledged_at.is_some());

        assert!(job.transition_to(RotationJobState::Completed).is_ok());
        assert!(job.completed_at.is_some());
        assert!(job.state.is_terminal());
    }

    #[test]
    fn fail_path() {
        let mut job = RotationJob::new("job-2", test_lid("p"), test_lid("c"), 3);
        job.transition_to(RotationJobState::Acknowledged).unwrap();
        job.fail("re-wrap failed: HSM timeout").unwrap();
        assert_eq!(job.state, RotationJobState::Failed);
        assert_eq!(job.failure_reason.as_deref(), Some("re-wrap failed: HSM timeout"));
    }

    #[test]
    fn expire_from_pending() {
        let mut job = RotationJob::new("job-3", test_lid("p"), test_lid("c"), 1);
        assert!(job.transition_to(RotationJobState::Expired).is_ok());
        assert!(job.state.is_terminal());
    }

    #[test]
    fn expire_from_acknowledged() {
        let mut job = RotationJob::new("job-4", test_lid("p"), test_lid("c"), 1);
        job.transition_to(RotationJobState::Acknowledged).unwrap();
        assert!(job.transition_to(RotationJobState::Expired).is_ok());
    }

    #[test]
    fn invalid_transitions() {
        let mut job = RotationJob::new("job-5", test_lid("p"), test_lid("c"), 1);
        assert!(job.transition_to(RotationJobState::Completed).is_err());
        assert!(job.transition_to(RotationJobState::Failed).is_err());

        job.transition_to(RotationJobState::Acknowledged).unwrap();
        job.transition_to(RotationJobState::Completed).unwrap();

        assert!(job.transition_to(RotationJobState::Pending).is_err());
    }

    #[test]
    fn terminal_states_have_no_transitions() {
        assert!(RotationJobState::Completed.valid_transitions().is_empty());
        assert!(RotationJobState::Failed.valid_transitions().is_empty());
        assert!(RotationJobState::Expired.valid_transitions().is_empty());
    }

    #[test]
    fn serde_round_trip() {
        let job = RotationJob::new("job-rt", test_lid("p"), test_lid("c"), 5);
        let json = serde_json::to_string(&job).unwrap();
        let parsed: RotationJob = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.job_id, "job-rt");
        assert_eq!(parsed.new_version, 5);
    }
}
