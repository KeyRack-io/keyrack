// Copyright 2026 a partner OÜ — BUSL-1.1

//! Pool metrics for operator monitoring.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub struct PoolMetrics {
    takes: Mutex<HashMap<String, AtomicU64>>,
    refills: Mutex<HashMap<String, AtomicU64>>,
    exhaustions: Mutex<HashMap<String, AtomicU64>>,
}

impl PoolMetrics {
    pub fn new() -> Self {
        Self {
            takes: Mutex::new(HashMap::new()),
            refills: Mutex::new(HashMap::new()),
            exhaustions: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_take(&self, spec: &str) {
        increment(&self.takes, spec);
    }

    pub fn record_refill(&self, spec: &str) {
        increment(&self.refills, spec);
    }

    pub fn record_exhaustion(&self, spec: &str) {
        increment(&self.exhaustions, spec);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            takes: read_all(&self.takes),
            refills: read_all(&self.refills),
            exhaustions: read_all(&self.exhaustions),
        }
    }
}

impl Default for PoolMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub takes: HashMap<String, u64>,
    pub refills: HashMap<String, u64>,
    pub exhaustions: HashMap<String, u64>,
}

fn increment(map: &Mutex<HashMap<String, AtomicU64>>, key: &str) {
    let mut m = map.lock().unwrap();
    m.entry(key.to_owned())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

fn read_all(map: &Mutex<HashMap<String, AtomicU64>>) -> HashMap<String, u64> {
    let m = map.lock().unwrap();
    m.iter()
        .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
        .collect()
}
