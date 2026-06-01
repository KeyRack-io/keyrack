// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of KeyRack.
//
// KeyRack is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// KeyRack is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with KeyRack. If not, see <https://www.gnu.org/licenses/>.
//
// Alternative commercial licensing is available; contact the Licensor.

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
