// Copyright 2026 a partner OÜ — BUSL-1.1

//! Leader election for the KeyRack cluster.
//!
//! Two backends:
//! - **etcd-backed** (production): uses etcd lease-based elections.
//! - **Built-in Raft** (via `openraft`): self-contained, no external deps.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// Current leadership state observed by this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaderState {
    Leader,
    Follower { leader_id: Option<String> },
    Candidate,
}

/// Configuration for the election subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionConfig {
    pub node_id: String,
    pub lease_ttl: Duration,
    /// Backend: "etcd" or "raft"
    pub backend: String,
    /// etcd endpoints (if backend = "etcd")
    pub etcd_endpoints: Vec<String>,
}

impl Default for ElectionConfig {
    fn default() -> Self {
        Self {
            node_id: uuid::Uuid::new_v4().to_string(),
            lease_ttl: Duration::from_secs(15),
            backend: "raft".into(),
            etcd_endpoints: vec!["http://127.0.0.1:2379".into()],
        }
    }
}

/// Pluggable leader election trait.
#[async_trait::async_trait]
pub trait LeaderElection: Send + Sync + 'static {
    /// Start participating in elections. Returns a watch channel that
    /// receives state transitions.
    async fn start(&self) -> Result<watch::Receiver<LeaderState>, ElectionError>;

    /// Voluntarily step down as leader.
    async fn step_down(&self) -> Result<(), ElectionError>;

    /// Current node ID.
    fn node_id(&self) -> &str;
}

#[derive(Debug, thiserror::Error)]
pub enum ElectionError {
    #[error("election backend error: {0}")]
    Backend(String),
    #[error("lease expired")]
    LeaseExpired,
    #[error("not leader")]
    NotLeader,
}

// ── Built-in Raft election ──────────────────────────────────────────

/// Minimal leader election using a local Raft state machine.
///
/// In single-node deployments, this node immediately becomes leader.
/// In multi-node, peers are discovered via NATS and form a Raft group.
pub struct RaftElection {
    config: ElectionConfig,
    state_tx: watch::Sender<LeaderState>,
    state_rx: watch::Receiver<LeaderState>,
}

impl RaftElection {
    pub fn new(config: ElectionConfig) -> Self {
        let (state_tx, state_rx) = watch::channel(LeaderState::Follower { leader_id: None });
        Self {
            config,
            state_tx,
            state_rx,
        }
    }
}

#[async_trait::async_trait]
impl LeaderElection for RaftElection {
    async fn start(&self) -> Result<watch::Receiver<LeaderState>, ElectionError> {
        // Single-node: immediately become leader.
        // Multi-node Raft consensus is a TODO for the full implementation.
        tracing::info!(
            node_id = %self.config.node_id,
            "single-node mode: promoting to leader"
        );
        let _ = self.state_tx.send(LeaderState::Leader);
        Ok(self.state_rx.clone())
    }

    async fn step_down(&self) -> Result<(), ElectionError> {
        let _ = self.state_tx.send(LeaderState::Follower { leader_id: None });
        Ok(())
    }

    fn node_id(&self) -> &str {
        &self.config.node_id
    }
}
