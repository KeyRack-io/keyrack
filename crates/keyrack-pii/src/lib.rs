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

//! PII tokenization helpers for KeyRack.
//!
//! Provides deterministic, non-reversible tokenization of personally
//! identifiable information (PII) using BLAKE3 keyed hashing with a
//! per-tenant salt.  Tokenized values can be used as attribute values
//! without exposing raw PII in the key hierarchy.
//!
//! ## Quick start
//!
//! ```
//! use keyrack_pii::{Tokenizer, Preset};
//!
//! let tok = Tokenizer::new(b"my-tenant-salt-at-least-32-bytes!");
//!
//! // Deterministic tokenization
//! let token = tok.tokenize("alice@example.com", Preset::Email);
//! assert!(token.starts_with("tok:email:"));
//!
//! // Same input always produces the same token
//! assert_eq!(token, tok.tokenize("alice@example.com", Preset::Email));
//!
//! // Different tenant salt → different token
//! let tok2 = Tokenizer::new(b"other-tenant-salt-at-least-32-b!");
//! assert_ne!(token, tok2.tokenize("alice@example.com", Preset::Email));
//! ```

#![forbid(unsafe_code)]

mod preset;
mod tokenizer;

pub use preset::Preset;
pub use tokenizer::Tokenizer;

/// Convenience: tokenize a single value with an ephemeral tokenizer.
///
/// For repeated use, prefer constructing a [`Tokenizer`] once and
/// reusing it.
pub fn tokenize(salt: &[u8], value: &str, preset: Preset) -> String {
    Tokenizer::new(salt).tokenize(value, preset)
}
