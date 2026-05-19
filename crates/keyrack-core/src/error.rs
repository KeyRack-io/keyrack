// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

//! Shared error types for `keyrack-core`.

use crate::key::KeyState;
use crate::lid::Lid;

/// Top-level error type for core operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyRackError {
    #[error("key not found: {0}")]
    KeyNotFound(Lid),

    #[error("invalid state transition from {from:?} to {to:?} for key {lid}")]
    InvalidStateTransition {
        lid: Lid,
        from: KeyState,
        to: KeyState,
    },

    #[error("operation {operation} not permitted in state {state:?} for key {lid}")]
    OperationNotPermitted {
        lid: Lid,
        state: KeyState,
        operation: &'static str,
    },

    #[error("tag \"{key}\" is an identity tag and cannot be modified")]
    ImmutableTag { key: String },

    #[error("encryption context mismatch")]
    EncryptionContextMismatch,

    #[error("optimistic concurrency conflict on key {lid}: expected version {expected}, found {actual}")]
    OptimisticConcurrencyConflict {
        lid: Lid,
        expected: u64,
        actual: u64,
    },

    #[error("resolution depth limit exceeded (max {max_depth})")]
    DepthLimitExceeded { max_depth: u32 },

    #[error("cycle detected during resolution at key {lid}")]
    CycleDetected { lid: Lid },

    #[error("provider error: {0}")]
    Provider(String),

    #[error("provider unavailable: {0}")]
    ProviderUnavailable(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("authorization denied: {reason}")]
    AuthorizationDenied { reason: String },

    #[error("cascade disable failed: {reason}")]
    CascadeDisableFailed { reason: String },

    #[error("{0}")]
    Other(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, KeyRackError>;
