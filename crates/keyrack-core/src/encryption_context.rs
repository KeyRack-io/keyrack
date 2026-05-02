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

//! Encryption context (AAD) plumbing.
//!
//! An `EncryptionContext` is a set of key-value string pairs that callers
//! supply at encrypt time. The pre-image is **opaque** — KeyRack does not
//! interpret the values. Only the BLAKE3 hash is persisted in the
//! ciphertext header (`KEYRACK_SPEC.md` §5.3, SPEC.md §4).
//!
//! At decrypt time the caller must supply the same context. KeyRack
//! re-hashes it and compares; mismatch → `EncryptionContextMismatch`.
//!
//! ## Canonical hashing
//!
//! To guarantee determinism the pairs are sorted by key (lexicographic
//! byte order) before hashing. Each pair is encoded as:
//!
//! ```text
//! key_len_u32_le || key_bytes || value_len_u32_le || value_bytes
//! ```
//!
//! An empty context hashes to `[0u8; 32]` (all-zero, not the BLAKE3
//! of empty input). This makes "no context supplied" distinguishable
//! from "context supplied but empty map" in storage, though both are
//! semantically valid.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Zero hash sentinel for "no encryption context supplied".
pub const ZERO_CONTEXT_HASH: [u8; 32] = [0u8; 32];

/// Opaque encryption context (AAD key-value pairs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionContext(BTreeMap<String, String>);

impl EncryptionContext {
    /// Create an empty encryption context.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Insert a key-value pair.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Compute the BLAKE3 hash of this context in canonical form.
    ///
    /// Returns `ZERO_CONTEXT_HASH` for an empty context.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        if self.0.is_empty() {
            return ZERO_CONTEXT_HASH;
        }

        let mut hasher = blake3::Hasher::new();
        // BTreeMap iteration is already sorted by key.
        for (k, v) in &self.0 {
            hasher.update(&(k.len() as u32).to_le_bytes());
            hasher.update(k.as_bytes());
            hasher.update(&(v.len() as u32).to_le_bytes());
            hasher.update(v.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Serialize the context into the opaque byte form used as AES-GCM AAD.
    ///
    /// This is the same canonical encoding fed to the hash, so the AAD
    /// binds the same data that the hash commits to.
    #[must_use]
    pub fn to_aad_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for (k, v) in &self.0 {
            buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
            buf.extend_from_slice(k.as_bytes());
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(v.as_bytes());
        }
        buf
    }
}

impl Default for EncryptionContext {
    fn default() -> Self {
        Self::new()
    }
}

impl From<BTreeMap<String, String>> for EncryptionContext {
    fn from(map: BTreeMap<String, String>) -> Self {
        Self(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_context_is_zero_hash() {
        let ctx = EncryptionContext::new();
        assert_eq!(ctx.hash(), ZERO_CONTEXT_HASH);
    }

    #[test]
    fn non_empty_context_is_not_zero() {
        let mut ctx = EncryptionContext::new();
        ctx.insert("tenant", "acme");
        assert_ne!(ctx.hash(), ZERO_CONTEXT_HASH);
    }

    #[test]
    fn hash_is_deterministic() {
        let mut a = EncryptionContext::new();
        a.insert("key1", "val1");
        a.insert("key2", "val2");

        let mut b = EncryptionContext::new();
        b.insert("key2", "val2");
        b.insert("key1", "val1");

        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn different_contexts_different_hashes() {
        let mut a = EncryptionContext::new();
        a.insert("tenant", "acme");

        let mut b = EncryptionContext::new();
        b.insert("tenant", "globex");

        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn aad_bytes_deterministic() {
        let mut a = EncryptionContext::new();
        a.insert("b", "2");
        a.insert("a", "1");

        let mut b = EncryptionContext::new();
        b.insert("a", "1");
        b.insert("b", "2");

        assert_eq!(a.to_aad_bytes(), b.to_aad_bytes());
    }

    #[test]
    fn serde_round_trip() {
        let mut ctx = EncryptionContext::new();
        ctx.insert("tenant", "acme");
        ctx.insert("purpose", "dek");
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: EncryptionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, parsed);
    }
}
