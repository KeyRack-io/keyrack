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

//! Cryptographic provider trait and key-handle types.
//!
//! A `CryptoProvider` is the boundary between KeyRack's key-management
//! logic and the actual cryptographic backend. W1 ships two in-tree
//! implementations:
//!
//! - [`SoftwareProvider`](software::SoftwareProvider) — pure-Rust,
//!   suitable for dev/test/single-node.
//! - [`InMemoryProvider`](inmem::InMemoryProvider) — ephemeral,
//!   test-fixture provider.
//!
//! Production deployments use out-of-tree providers (PKCS#11, KMIP)
//! via the `keyrack-pkcs11` and `keyrack-kmip` crates.
//!
//! ## V1-mandatory algorithms
//!
//! | Usage | Algorithm | Notes |
//! |---|---|---|
//! | Encrypt/Decrypt | AES-256-GCM | 12-byte nonce, 16-byte tag |
//! | Sign/Verify | Ed25519 | RFC 8032 |
//! | Sign/Verify | ECDSA P-256 SHA-256 | FIPS 186-4 |
//! | Sign/Verify | RSA PKCS1v15 SHA-256 | 2048–4096 bit keys |

pub mod inmem;
pub mod software;

use crate::error::Result;
use crate::key::KeySpec;
use crate::sensitive::Sensitive;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Opaque handle to key material managed by a provider.
///
/// The `key_id` is provider-internal (e.g. a UUID, HSM object label,
/// PKCS#11 handle). KeyRack stores it alongside the `KeyRecord` so it
/// can address the right material in the backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyHandle {
    pub key_id: String,
    pub key_spec: KeySpec,
}

/// Algorithm selector for signing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
    RsaPkcs1v15Sha256,
}

/// Algorithm selector for encryption operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
}

/// Result of an encrypt operation: ciphertext including nonce + tag.
#[derive(Debug, Clone)]
pub struct EncryptOutput {
    pub ciphertext: Vec<u8>,
}

/// Result of a data-key generation.
#[derive(Debug)]
pub struct GenerateDataKeyOutput {
    pub plaintext_key: Sensitive<Vec<u8>>,
    pub encrypted_key: Vec<u8>,
}

/// Cryptographic provider trait.
///
/// All methods are async — HSM providers (PKCS#11, KMIP) need I/O.
/// Software and in-memory providers run synchronously but are wrapped
/// in the same async interface for uniformity.
///
/// Providers must be `Send + Sync` (shared across Tokio tasks).
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Generate key material for the given spec. Returns a handle that
    /// can be used in subsequent encrypt/decrypt/sign/verify calls.
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle>;

    /// Encrypt `plaintext` using the key identified by `handle`.
    ///
    /// `aad` (Additional Authenticated Data) is bound into the
    /// ciphertext tag for AES-GCM. Pass an empty slice for no AAD.
    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput>;

    /// Decrypt `ciphertext` that was produced by [`encrypt`](Self::encrypt).
    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>>;

    /// Sign `message` using the key identified by `handle`.
    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>>;

    /// Verify a `signature` over `message`.
    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool>;

    /// Generate `length` bytes of cryptographically secure random data.
    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>>;

    /// Destroy key material. After this call, the handle is invalid.
    ///
    /// Providers should zeroize any cached material and delete
    /// the backend object. Not all providers support true destruction
    /// (HSMs may merely mark the object as destroyed).
    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()>;
}
