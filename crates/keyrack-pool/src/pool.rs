// Copyright 2026 a partner OÜ — BUSL-1.1

//! Pre-generation pool and refill watcher.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, Notify};

use crate::config::{PoolConfig, PoolSpec};
use crate::metrics::PoolMetrics;

/// A pre-generated key waiting to be bound to a caller.
#[derive(Debug, Clone)]
pub struct PooledKey {
    pub pool_entry_id: String,
    pub key_spec: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Opaque key material (encrypted at rest in the pool).
    pub wrapped_material: Vec<u8>,
}

/// Pluggable key generator trait — the pool calls this to refill.
#[async_trait::async_trait]
pub trait KeyGenerator: Send + Sync + 'static {
    async fn generate(&self, key_spec: &str) -> Result<PooledKey, PoolError>;
}

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("pool exhausted for spec {0}, on-demand fallback disabled")]
    Exhausted(String),
    #[error("generation failed: {0}")]
    GenerationFailed(String),
}

/// The key pool, organized by key spec.
pub struct KeyPool {
    config: PoolConfig,
    pools: Arc<Mutex<HashMap<String, Vec<PooledKey>>>>,
    metrics: Arc<PoolMetrics>,
    refill_notify: Arc<Notify>,
}

impl KeyPool {
    pub fn new(config: PoolConfig) -> Self {
        let mut pools = HashMap::new();
        for spec in &config.specs {
            pools.insert(spec.key_spec.clone(), Vec::with_capacity(spec.max_depth));
        }

        Self {
            config,
            pools: Arc::new(Mutex::new(pools)),
            metrics: Arc::new(PoolMetrics::new()),
            refill_notify: Arc::new(Notify::new()),
        }
    }

    /// Take a pre-generated key from the pool, or return an error
    /// if the pool is exhausted and fallback is disabled.
    pub async fn take(&self, key_spec: &str) -> Result<PooledKey, PoolError> {
        let mut pools = self.pools.lock().await;
        if let Some(pool) = pools.get_mut(key_spec) {
            if let Some(key) = pool.pop() {
                self.metrics.record_take(key_spec);

                // Check if we've hit the low-water mark.
                let spec_config = self.spec_for(key_spec);
                if let Some(sc) = spec_config {
                    if pool.len() < sc.low_water_mark {
                        self.refill_notify.notify_one();
                    }
                }

                return Ok(key);
            }
        }

        self.metrics.record_exhaustion(key_spec);

        if self.config.allow_on_demand_fallback {
            // Caller should fall back to on-demand generation.
            Err(PoolError::Exhausted(key_spec.to_owned()))
        } else {
            Err(PoolError::Exhausted(key_spec.to_owned()))
        }
    }

    /// Add a pre-generated key to the pool.
    pub async fn put(&self, key: PooledKey) {
        let mut pools = self.pools.lock().await;
        let spec = key.key_spec.clone();
        let pool = pools.entry(spec.clone()).or_default();

        let max = self.spec_for(&spec).map_or(500, |s| s.max_depth);
        if pool.len() < max {
            pool.push(key);
            self.metrics.record_refill(&spec);
        }
    }

    /// Current depth of each pool, for metrics/monitoring.
    pub async fn depths(&self) -> HashMap<String, usize> {
        let pools = self.pools.lock().await;
        pools.iter().map(|(k, v)| (k.clone(), v.len())).collect()
    }

    /// Start the background refill watcher. This spawns a tokio task
    /// that periodically checks pool depths and calls the generator.
    pub fn start_refill_watcher(
        self: &Arc<Self>,
        generator: Arc<dyn KeyGenerator>,
    ) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        let notify = Arc::clone(&pool.refill_notify);
        let interval = pool.config.refill_interval;
        let batch_size = pool.config.refill_batch_size;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = notify.notified() => {},
                    _ = tokio::time::sleep(interval) => {},
                }

                let depths = pool.depths().await;
                for spec in &pool.config.specs {
                    let current = depths.get(&spec.key_spec).copied().unwrap_or(0);
                    if current < spec.low_water_mark {
                        let needed = (spec.target_depth - current).min(batch_size);
                        tracing::debug!(
                            spec = %spec.key_spec,
                            current,
                            target = spec.target_depth,
                            generating = needed,
                            "refilling pool"
                        );
                        for _ in 0..needed {
                            match generator.generate(&spec.key_spec).await {
                                Ok(key) => pool.put(key).await,
                                Err(e) => {
                                    tracing::warn!(spec = %spec.key_spec, err = %e, "refill generation failed");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    pub fn metrics(&self) -> &PoolMetrics {
        &self.metrics
    }

    fn spec_for(&self, key_spec: &str) -> Option<&PoolSpec> {
        self.config.specs.iter().find(|s| s.key_spec == key_spec)
    }
}
