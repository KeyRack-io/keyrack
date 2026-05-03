// Copyright 2026 a partner OÜ — BUSL-1.1

//! Pool configuration.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Pool configuration for a specific key spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSpec {
    /// Key specification identifier (e.g., "rsa-2048", "ecdsa-p256").
    pub key_spec: String,
    /// Target pool depth (steady state).
    pub target_depth: usize,
    /// Low-water mark: refill starts when depth drops below this.
    pub low_water_mark: usize,
    /// Maximum pool depth (cap to avoid unbounded memory).
    pub max_depth: usize,
}

impl Default for PoolSpec {
    fn default() -> Self {
        Self {
            key_spec: "rsa-2048".into(),
            target_depth: 100,
            low_water_mark: 20,
            max_depth: 500,
        }
    }
}

/// Top-level pool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    pub specs: Vec<PoolSpec>,
    /// How often the refill watcher checks pool depths.
    pub refill_interval: Duration,
    /// How many keys to generate per refill batch.
    pub refill_batch_size: usize,
    /// Whether to allow on-demand fallback when pool is empty.
    pub allow_on_demand_fallback: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            specs: vec![
                PoolSpec {
                    key_spec: "rsa-2048".into(),
                    target_depth: 100,
                    low_water_mark: 20,
                    max_depth: 500,
                },
                PoolSpec {
                    key_spec: "rsa-3072".into(),
                    target_depth: 50,
                    low_water_mark: 10,
                    max_depth: 200,
                },
                PoolSpec {
                    key_spec: "ecdsa-p256".into(),
                    target_depth: 200,
                    low_water_mark: 50,
                    max_depth: 1000,
                },
            ],
            refill_interval: Duration::from_secs(5),
            refill_batch_size: 10,
            allow_on_demand_fallback: true,
        }
    }
}
