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

//! Cascade-disable with hard-boundary semantics.
//!
//! When a key is disabled, all descendant keys in the hierarchy must
//! also become unusable for new operations. This module defines the
//! cascade model and invalidation protocol.
//!
//! **Hard boundary**: even if NATS subscribers are offline, the
//! service-side state change ensures fail-closed behaviour. Subscribers
//! are notified for cache zeroization, but the state transition does
//! not depend on acknowledgements completing.
//!
//! The cascade has three phases:
//!
//! 1. **State change**: the target key transitions to `Disabled` (or
//!    `PendingDeletion`). This is the authoritative signal.
//! 2. **Cache zeroize**: in-process caches holding key material for
//!    descendant keys are zeroized.
//! 3. **Invalidation broadcast**: a NATS message
//!    (`kms.key.state-changed.<lid>`) is published for each affected
//!    key. Subscribers acknowledge.
//!
//! The cascade result reports per-subscriber ack state, but the state
//! change succeeds regardless of ack completeness (§5.4 / invariant 6).

use crate::lid::Lid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default timeout for invalidation ack-wait.
pub const DEFAULT_ACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum configurable ack-wait timeout.
pub const MAX_ACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Per-subscriber ack state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckState {
    /// Subscriber acknowledged the invalidation.
    Acknowledged,
    /// Subscriber did not respond within the timeout.
    TimedOut,
    /// Error sending the invalidation to this subscriber.
    Error(String),
}

/// Per-key notification status within a cascade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyNotificationStatus {
    pub lid: Lid,
    /// Per-subscriber ack results.
    pub subscribers: Vec<SubscriberAck>,
}

/// A subscriber's ack result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberAck {
    pub subscriber_id: String,
    pub state: AckState,
}

/// Result of a cascade-disable operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeResult {
    /// The root key that was disabled.
    pub root_lid: Lid,
    /// All keys affected by the cascade (including the root).
    pub affected_keys: Vec<Lid>,
    /// Per-key notification status.
    pub notification_status: Vec<KeyNotificationStatus>,
    /// Wall-clock duration of the cascade (state change + notification).
    pub duration_ms: u64,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

impl CascadeResult {
    /// Whether all notifications were acknowledged.
    #[must_use]
    pub fn all_acknowledged(&self) -> bool {
        self.notification_status.iter().all(|k| {
            k.subscribers
                .iter()
                .all(|s| s.state == AckState::Acknowledged)
        })
    }

    /// Count of keys with at least one unacknowledged subscriber.
    #[must_use]
    pub fn unacknowledged_count(&self) -> usize {
        self.notification_status
            .iter()
            .filter(|k| {
                k.subscribers
                    .iter()
                    .any(|s| s.state != AckState::Acknowledged)
            })
            .count()
    }
}

/// Cascade invalidation sink trait.
///
/// Implemented by the NATS layer to broadcast `kms.key.state-changed.<lid>`
/// and `kms.cache.invalidate.<lid>` messages. The service layer calls
/// `invalidate_key` for each affected key and collects ack results.
#[async_trait::async_trait]
pub trait InvalidationSink: Send + Sync {
    /// Broadcast invalidation for a single key and wait for acks.
    async fn invalidate_key(
        &self,
        lid: &Lid,
        timeout: Duration,
    ) -> crate::error::Result<Vec<SubscriberAck>>;
}

/// No-op invalidation sink for testing (no subscribers, immediate success).
pub struct NoopInvalidationSink;

#[async_trait::async_trait]
impl InvalidationSink for NoopInvalidationSink {
    async fn invalidate_key(
        &self,
        _lid: &Lid,
        _timeout: Duration,
    ) -> crate::error::Result<Vec<SubscriberAck>> {
        Ok(vec![])
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
    fn cascade_result_all_acked() {
        let result = CascadeResult {
            root_lid: test_lid("root"),
            affected_keys: vec![test_lid("root"), test_lid("child")],
            notification_status: vec![
                KeyNotificationStatus {
                    lid: test_lid("root"),
                    subscribers: vec![SubscriberAck {
                        subscriber_id: "sub-1".into(),
                        state: AckState::Acknowledged,
                    }],
                },
                KeyNotificationStatus {
                    lid: test_lid("child"),
                    subscribers: vec![SubscriberAck {
                        subscriber_id: "sub-1".into(),
                        state: AckState::Acknowledged,
                    }],
                },
            ],
            duration_ms: 42,
            started_at: Utc::now(),
            completed_at: Utc::now(),
        };

        assert!(result.all_acknowledged());
        assert_eq!(result.unacknowledged_count(), 0);
    }

    #[test]
    fn cascade_result_partial_ack() {
        let result = CascadeResult {
            root_lid: test_lid("root"),
            affected_keys: vec![test_lid("root"), test_lid("child")],
            notification_status: vec![
                KeyNotificationStatus {
                    lid: test_lid("root"),
                    subscribers: vec![SubscriberAck {
                        subscriber_id: "sub-1".into(),
                        state: AckState::Acknowledged,
                    }],
                },
                KeyNotificationStatus {
                    lid: test_lid("child"),
                    subscribers: vec![SubscriberAck {
                        subscriber_id: "sub-1".into(),
                        state: AckState::TimedOut,
                    }],
                },
            ],
            duration_ms: 30_001,
            started_at: Utc::now(),
            completed_at: Utc::now(),
        };

        assert!(!result.all_acknowledged());
        assert_eq!(result.unacknowledged_count(), 1);
    }

    #[tokio::test]
    async fn noop_sink_returns_empty() {
        let sink = NoopInvalidationSink;
        let acks = sink
            .invalidate_key(&test_lid("x"), DEFAULT_ACK_TIMEOUT)
            .await
            .unwrap();
        assert!(acks.is_empty());
    }

    #[test]
    fn serde_round_trip() {
        let result = CascadeResult {
            root_lid: test_lid("root"),
            affected_keys: vec![test_lid("root")],
            notification_status: vec![KeyNotificationStatus {
                lid: test_lid("root"),
                subscribers: vec![SubscriberAck {
                    subscriber_id: "sub-a".into(),
                    state: AckState::Error("connection refused".into()),
                }],
            }],
            duration_ms: 100,
            started_at: Utc::now(),
            completed_at: Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: CascadeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.affected_keys.len(), 1);
        assert!(!parsed.all_acknowledged());
    }
}
