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

//! Pure-Rust software provider using `RustCrypto` primitives.
//!
//! Suitable for development, testing, and single-node deployments
//! without an HSM. Key material lives in process memory (zeroized
//! on drop).
//!
//! **Not for production HSM-grade security** — use `keyrack-pkcs11`
//! or `keyrack-kmip` for that.

use crate::error::{KeyRackError, Result};
use crate::key::KeySpec;
use crate::provider::{
    CryptoOperation, CryptoProvider, EncryptOutput, KeyHandle, KeySpecCapability,
    ProviderCapabilities, SigningAlgorithm,
};
use crate::sensitive::Sensitive;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroize;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1v15::{SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey};
use rsa::pss::{SigningKey as RsaPssSigningKey, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _, Verifier as _};
use rsa::RsaPrivateKey;
use sha2::Sha256;

/// Key material stored in the software provider.
///
/// Each variant holds the private key bytes or structured key for its
/// algorithm. Material is zeroized when the entry is removed.
enum KeyMaterial {
    Aes256(Vec<u8>),
    Ed25519(ed25519_dalek::SigningKey),
    EcdsaP256(P256SigningKey),
    Rsa(Box<RsaPrivateKey>),
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        match self {
            Self::Aes256(ref mut bytes) => bytes.zeroize(),
            // ed25519_dalek::SigningKey stores 32 bytes internally;
            // we overwrite via a zeroed key (best-effort).
            Self::Ed25519(ref mut key) => {
                let zero = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
                *key = zero;
            }
            Self::EcdsaP256(_) | Self::Rsa(_) => {
                // RustCrypto types don't expose a zeroize path;
                // memory is freed on drop. HSM providers handle
                // this properly; software provider is dev/test only.
            }
        }
    }
}

/// Pure-Rust software crypto provider.
pub struct SoftwareProvider {
    keys: RwLock<HashMap<String, KeyMaterial>>,
}

impl SoftwareProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    fn get_material<'a, F, R>(
        keys: &'a HashMap<String, KeyMaterial>,
        handle: &KeyHandle,
        extract: F,
    ) -> Result<R>
    where
        F: FnOnce(&'a KeyMaterial) -> Option<R>,
    {
        let mat = keys
            .get(&handle.key_id)
            .ok_or_else(|| KeyRackError::Provider(format!("key not found: {}", handle.key_id)))?;
        extract(mat)
            .ok_or_else(|| KeyRackError::Provider("key type mismatch".into()))
    }
}

impl Default for SoftwareProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CryptoProvider for SoftwareProvider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        let id = Uuid::new_v4().to_string();
        let material = match spec {
            KeySpec::Aes256 => {
                let mut key = vec![0u8; 32];
                OsRng.fill_bytes(&mut key);
                KeyMaterial::Aes256(key)
            }
            KeySpec::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
                KeyMaterial::Ed25519(signing_key)
            }
            KeySpec::EcdsaP256Sha256 => {
                let signing_key = P256SigningKey::random(&mut OsRng);
                KeyMaterial::EcdsaP256(signing_key)
            }
            KeySpec::RsaPkcs1v15Sha256 { key_size }
            | KeySpec::RsaPssSha256 { key_size } => {
                let bits = *key_size as usize;
                if !(2048..=4096).contains(&bits) {
                    return Err(KeyRackError::Provider(format!(
                        "RSA key size must be 2048–4096, got {bits}"
                    )));
                }
                let private_key = RsaPrivateKey::new(&mut OsRng, bits)
                    .map_err(|e| KeyRackError::Provider(format!("RSA keygen failed: {e}")))?;
                KeyMaterial::Rsa(Box::new(private_key))
            }
        };

        self.keys
            .write()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?
            .insert(id.clone(), material);

        Ok(KeyHandle {
            key_id: id,
            key_spec: spec.clone(),
        })
    }

    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;

        let aes_key: &[u8] = Self::get_material(&keys, handle, |m| match m {
            KeyMaterial::Aes256(k) => Some(k.as_slice()),
            _ => None,
        })?;

        let cipher = Aes256Gcm::new_from_slice(aes_key)
            .map_err(|e| KeyRackError::Provider(format!("AES init failed: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from(nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ct = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| KeyRackError::Provider(format!("AES-GCM encrypt failed: {e}")))?;

        // Wire format: 12-byte nonce || ciphertext+tag
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);

        Ok(EncryptOutput { ciphertext: out })
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        if ciphertext.len() < 12 + 16 {
            return Err(KeyRackError::Provider(
                "ciphertext too short (need at least nonce + tag)".into(),
            ));
        }

        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;

        let aes_key: &[u8] = Self::get_material(&keys, handle, |m| match m {
            KeyMaterial::Aes256(k) => Some(k.as_slice()),
            _ => None,
        })?;

        let cipher = Aes256Gcm::new_from_slice(aes_key)
            .map_err(|e| KeyRackError::Provider(format!("AES init failed: {e}")))?;

        let (nonce_bytes, ct) = ciphertext.split_at(12);
        let nonce_arr: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
            KeyRackError::Provider("invalid nonce length".into())
        })?;
        let nonce = aes_gcm::Nonce::from(nonce_arr);

        let payload = Payload { msg: ct, aad };

        let pt = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| KeyRackError::Provider(
                "AES-GCM authentication failed: wrong key, corrupted ciphertext, or AAD mismatch".into(),
            ))?;

        Ok(Sensitive::new(pt))
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;

        match algorithm {
            SigningAlgorithm::Ed25519 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Ed25519(k) => Some(k),
                    _ => None,
                })?;
                let sig = sk.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
            SigningAlgorithm::EcdsaP256Sha256 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP256(k) => Some(k),
                    _ => None,
                })?;
                let sig: p256::ecdsa::Signature = sk.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            SigningAlgorithm::RsaPkcs1v15Sha256 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let signing_key = RsaSigningKey::<Sha256>::new(private_key.clone());
                let sig = signing_key
                    .sign(message);
                Ok(sig.to_vec())
            }
            SigningAlgorithm::RsaPssSha256 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let signing_key = RsaPssSigningKey::<Sha256>::new(private_key.clone());
                let sig = signing_key.sign_with_rng(&mut OsRng, message);
                Ok(sig.to_vec())
            }
        }
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;

        match algorithm {
            SigningAlgorithm::Ed25519 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Ed25519(k) => Some(k),
                    _ => None,
                })?;
                let vk = sk.verifying_key();
                let sig = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid Ed25519 sig: {e}")))?;
                Ok(vk.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::EcdsaP256Sha256 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP256(k) => Some(k),
                    _ => None,
                })?;
                let vk = P256VerifyingKey::from(sk);
                let sig = p256::ecdsa::DerSignature::from_bytes(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid ECDSA sig: {e}")))?;
                Ok(vk.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::RsaPkcs1v15Sha256 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let verifying_key =
                    RsaVerifyingKey::<Sha256>::new(private_key.to_public_key());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid RSA sig: {e}")))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::RsaPssSha256 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let verifying_key =
                    RsaPssVerifyingKey::<Sha256>::new(private_key.to_public_key());
                let sig = rsa::pss::Signature::try_from(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid RSA-PSS sig: {e}")))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
        }
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        let mut buf = vec![0u8; length];
        OsRng.fill_bytes(&mut buf);
        Ok(Sensitive::new(buf))
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        self.keys
            .write()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?
            .remove(&handle.key_id);
        Ok(())
    }

    fn capabilities(&self) -> ProviderCapabilities {
        use CryptoOperation::*;

        let symmetric_ops = vec![GenerateKey, Encrypt, Decrypt, GenerateDataKey, ReEncrypt, DestroyKey];
        let signing_ops = vec![GenerateKey, Sign, Verify, DestroyKey];

        ProviderCapabilities {
            provider_name: "software".into(),
            key_specs: vec![
                KeySpecCapability { key_spec: KeySpec::Aes256, operations: symmetric_ops },
                KeySpecCapability { key_spec: KeySpec::Ed25519, operations: signing_ops.clone() },
                KeySpecCapability { key_spec: KeySpec::EcdsaP256Sha256, operations: signing_ops.clone() },
                KeySpecCapability { key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 }, operations: signing_ops.clone() },
                KeySpecCapability { key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 3072 }, operations: signing_ops.clone() },
                KeySpecCapability { key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 }, operations: signing_ops.clone() },
                KeySpecCapability { key_spec: KeySpec::RsaPssSha256 { key_size: 2048 }, operations: signing_ops.clone() },
                KeySpecCapability { key_spec: KeySpec::RsaPssSha256 { key_size: 3072 }, operations: signing_ops.clone() },
                KeySpecCapability { key_spec: KeySpec::RsaPssSha256 { key_size: 4096 }, operations: signing_ops },
            ],
            supports_generate_random: true,
            supports_atomic_data_key: false,
            supports_atomic_re_encrypt: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn aes256_encrypt_decrypt_round_trip() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

        let plaintext = b"hello, keyrack!";
        let aad = b"context";

        let ct = provider.encrypt(&handle, plaintext, aad).await.unwrap();
        let pt = provider.decrypt(&handle, &ct.ciphertext, aad).await.unwrap();

        assert_eq!(pt.expose().as_slice(), plaintext);
    }

    #[tokio::test]
    async fn aes256_wrong_aad_fails() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

        let ct = provider.encrypt(&handle, b"secret", b"aad1").await.unwrap();
        let result = provider.decrypt(&handle, &ct.ciphertext, b"aad2").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn ed25519_sign_verify() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key(&KeySpec::Ed25519).await.unwrap();

        let msg = b"manifest hash";
        let sig = provider
            .sign(&handle, SigningAlgorithm::Ed25519, msg)
            .await
            .unwrap();

        assert!(provider
            .verify(&handle, SigningAlgorithm::Ed25519, msg, &sig)
            .await
            .unwrap());

        // Tampered message fails.
        assert!(!provider
            .verify(&handle, SigningAlgorithm::Ed25519, b"tampered", &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn ecdsa_p256_sign_verify() {
        let provider = SoftwareProvider::new();
        let handle = provider
            .generate_key(&KeySpec::EcdsaP256Sha256)
            .await
            .unwrap();

        let msg = b"ecdsa test message";
        let sig = provider
            .sign(&handle, SigningAlgorithm::EcdsaP256Sha256, msg)
            .await
            .unwrap();

        assert!(provider
            .verify(&handle, SigningAlgorithm::EcdsaP256Sha256, msg, &sig)
            .await
            .unwrap());

        assert!(!provider
            .verify(&handle, SigningAlgorithm::EcdsaP256Sha256, b"wrong", &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn rsa_sign_verify() {
        let provider = SoftwareProvider::new();
        let handle = provider
            .generate_key(&KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 })
            .await
            .unwrap();

        let msg = b"rsa test message";
        let sig = provider
            .sign(&handle, SigningAlgorithm::RsaPkcs1v15Sha256, msg)
            .await
            .unwrap();

        assert!(provider
            .verify(&handle, SigningAlgorithm::RsaPkcs1v15Sha256, msg, &sig)
            .await
            .unwrap());

        assert!(!provider
            .verify(
                &handle,
                SigningAlgorithm::RsaPkcs1v15Sha256,
                b"wrong",
                &sig
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn generate_random_returns_requested_length() {
        let provider = SoftwareProvider::new();
        let r = provider.generate_random(64).await.unwrap();
        assert_eq!(r.expose().len(), 64);
    }

    #[tokio::test]
    async fn destroy_key_removes_material() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();
        provider.destroy_key(&handle).await.unwrap();

        let result = provider.encrypt(&handle, b"test", b"").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn type_mismatch_returns_error() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

        // Trying to sign with an AES key should fail.
        let result = provider
            .sign(&handle, SigningAlgorithm::Ed25519, b"msg")
            .await;
        assert!(result.is_err());
    }
}
