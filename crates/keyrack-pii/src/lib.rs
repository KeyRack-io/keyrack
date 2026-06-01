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
