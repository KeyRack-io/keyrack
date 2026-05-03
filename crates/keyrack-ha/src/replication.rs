// Copyright 2026 a partner OÜ — BUSL-1.1

//! State replication and consensus for namespace/policy changes.
//!
//! Uses NATS JetStream for durable, ordered replication of state-change
//! events across nodes. Only the leader proposes changes; followers
//! apply them from the stream.

use serde::{Deserialize, Serialize};

/// A replicated state change event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub sequence: u64,
    pub proposer: String,
    pub kind: StateChangeKind,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateChangeKind {
    NamespaceRegistered {
        namespace: String,
        yaml_hash: String,
    },
    NamespaceUpdated {
        namespace: String,
        yaml_hash: String,
    },
    PolicyBundleUpdated {
        bundle_hash: String,
    },
    KeyRotationScheduled {
        key_id: String,
    },
    NodeJoined {
        node_id: String,
    },
    NodeLeft {
        node_id: String,
    },
}

/// Replication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// NATS JetStream subject for state changes.
    pub stream_subject: String,
    /// Stream name.
    pub stream_name: String,
    /// Max age for stream messages.
    pub max_age_secs: u64,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            stream_subject: "keyrack.cluster.state".into(),
            stream_name: "KEYRACK_STATE".into(),
            max_age_secs: 86400 * 7, // 7 days
        }
    }
}

/// Replication manager — publishes (leader) or subscribes (follower)
/// to the state change stream.
pub struct ReplicationManager {
    config: ReplicationConfig,
    sequence: std::sync::atomic::AtomicU64,
}

impl ReplicationManager {
    pub fn new(config: ReplicationConfig) -> Self {
        Self {
            config,
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Propose a state change (leader only). In the full implementation,
    /// this publishes to NATS JetStream.
    pub fn propose(&self, proposer: &str, kind: StateChangeKind) -> StateChange {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let change = StateChange {
            sequence: seq,
            proposer: proposer.to_owned(),
            kind,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        tracing::info!(seq, proposer, "state change proposed");
        change
    }

    pub fn config(&self) -> &ReplicationConfig {
        &self.config
    }
}
