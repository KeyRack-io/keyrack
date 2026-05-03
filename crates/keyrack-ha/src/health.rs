// Copyright 2026 a partner OÜ — BUSL-1.1

//! Health checking and split-brain protection.

use serde::{Deserialize, Serialize};

/// Cluster health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealth {
    pub status: HealthStatus,
    pub active_nodes: usize,
    pub total_nodes: usize,
    pub has_quorum: bool,
    pub leader_id: Option<String>,
    pub split_brain_detected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Critical,
}

impl ClusterHealth {
    pub fn evaluate(
        active_nodes: usize,
        total_nodes: usize,
        has_quorum: bool,
        leader_id: Option<String>,
    ) -> Self {
        let split_brain_detected = false; // TODO: detect via NATS fencing tokens

        let status = if !has_quorum || split_brain_detected {
            HealthStatus::Critical
        } else if active_nodes < total_nodes {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        Self {
            status,
            active_nodes,
            total_nodes,
            has_quorum,
            leader_id,
            split_brain_detected,
        }
    }
}

/// Backup metadata for disaster recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub backup_id: String,
    pub timestamp: String,
    pub node_id: String,
    pub includes_metadata: bool,
    /// HSM material is operator-managed, but we document the associations.
    pub hsm_connection_ids: Vec<String>,
    pub key_count: u64,
    pub namespace_count: u64,
}
