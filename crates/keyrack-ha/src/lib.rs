// Copyright 2026 a partner OÜ — BUSL-1.1

//! keyrack-ha — High-availability clustering for KeyRack.
//!
//! Provides:
//! - Leader election (etcd-backed or built-in Raft via `openraft`)
//! - Consensus for state changes (namespace registration, policy updates)
//! - Rolling upgrade support (version skew handling, schema migration)
//! - HSM session affinity / connection pooling per node
//! - Cross-node cache invalidation (NATS-based)
//! - Split-brain protection
//! - Disaster recovery: metadata backup/restore

#![forbid(unsafe_code)]

pub mod election;
pub mod cluster;
pub mod replication;
pub mod health;

pub use cluster::ClusterConfig;
pub use election::LeaderElection;
