// Copyright 2026 a partner OÜ — BUSL-1.1

//! Cluster membership and configuration.
//!
//! Manages the set of nodes in the cluster, their health status,
//! and the active topology (active-active for reads, leader for writes).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Cluster-wide configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub cluster_name: String,
    pub min_nodes: usize,
    pub heartbeat_interval: Duration,
    pub failure_threshold: u32,
    /// Minimum version for rolling upgrade compatibility.
    pub min_compatible_version: String,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            cluster_name: "keyrack".into(),
            min_nodes: 1,
            heartbeat_interval: Duration::from_secs(5),
            failure_threshold: 3,
            min_compatible_version: "0.1.0".into(),
        }
    }
}

/// A node's membership record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub address: String,
    pub version: String,
    pub state: NodeState,
    #[serde(skip)]
    pub last_heartbeat: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeState {
    Joining,
    Active,
    Draining,
    Left,
    Suspect,
}

/// Cluster membership manager.
pub struct ClusterMembership {
    config: ClusterConfig,
    nodes: HashMap<String, NodeInfo>,
    local_node_id: String,
}

impl ClusterMembership {
    pub fn new(config: ClusterConfig, local_node_id: String) -> Self {
        Self {
            config,
            nodes: HashMap::new(),
            local_node_id,
        }
    }

    /// Register a node (self or peer discovered via NATS).
    pub fn add_node(&mut self, info: NodeInfo) {
        tracing::info!(node_id = %info.node_id, addr = %info.address, "node joined cluster");
        self.nodes.insert(info.node_id.clone(), info);
    }

    /// Record a heartbeat from a peer.
    pub fn heartbeat(&mut self, node_id: &str) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.last_heartbeat = Some(Instant::now());
            if node.state == NodeState::Suspect {
                node.state = NodeState::Active;
            }
        }
    }

    /// Mark stale nodes as suspect based on heartbeat timeout.
    pub fn check_health(&mut self) {
        let timeout = self.config.heartbeat_interval * self.config.failure_threshold;
        for node in self.nodes.values_mut() {
            if node.node_id == self.local_node_id {
                continue;
            }
            if let Some(last) = node.last_heartbeat {
                if last.elapsed() > timeout && node.state == NodeState::Active {
                    tracing::warn!(node_id = %node.node_id, "node suspected failed");
                    node.state = NodeState::Suspect;
                }
            }
        }
    }

    /// Initiate graceful drain of a node (for rolling upgrade).
    pub fn drain_node(&mut self, node_id: &str) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            tracing::info!(node_id = %node.node_id, "draining node");
            node.state = NodeState::Draining;
        }
    }

    /// Active (healthy) nodes count.
    pub fn active_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|n| n.state == NodeState::Active)
            .count()
    }

    /// Whether the cluster has quorum (> 50% of min_nodes).
    pub fn has_quorum(&self) -> bool {
        self.active_count() >= (self.config.min_nodes + 1) / 2
    }

    /// Check if all nodes are running compatible versions for rolling upgrade.
    pub fn version_compatible(&self) -> bool {
        self.nodes.values().all(|n| {
            n.version >= self.config.min_compatible_version
        })
    }

    pub fn nodes(&self) -> &HashMap<String, NodeInfo> {
        &self.nodes
    }

    pub fn config(&self) -> &ClusterConfig {
        &self.config
    }
}
