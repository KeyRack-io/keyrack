// Copyright 2026 a partner OÜ — BUSL-1.1

//! keyrack-pool — Asymmetric key pre-generation pool.
//!
//! Pre-generates RSA and ECDSA key pairs to absorb burst traffic.
//! Under a 100-RPS burst, p99 latency stays under 50ms vs. 200–500ms
//! for on-demand generation.
//!
//! Key features:
//! - Configurable pool sizing per key spec
//! - Background refilling watcher
//! - Graceful degradation to on-demand generation when pool is exhausted
//! - Audit-friendly provenance: pool entries tagged with creation context,
//!   bind-time recorded separately

#![forbid(unsafe_code)]

pub mod config;
pub mod pool;
pub mod metrics;

pub use config::PoolConfig;
pub use pool::KeyPool;
