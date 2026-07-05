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
    CryptoOperation, CryptoProvider, EncryptOutput, KeyHandle, KeySpecCapability, MacAlgorithm,
    ProviderCapabilities, SigningAlgorithm,
};
use crate::sensitive::Sensitive;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroize;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use hmac::{Hmac, Mac};
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1v15::{SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey};
use rsa::pss::{SigningKey as RsaPssSigningKey, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::hazmat::{
    PrehashSigner as _, PrehashVerifier as _, RandomizedPrehashSigner as _,
};
use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _, Verifier as _};
use rsa::RsaPrivateKey;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

/// Key material stored in the software provider.
///
/// Each variant holds the private key bytes or structured key for its
/// algorithm. Material is zeroized when the entry is removed.
enum KeyMaterial {
    Aes256(Vec<u8>),
    Aes128(Vec<u8>),
    Ed25519(ed25519_dalek::SigningKey),
    EcdsaP256(P256SigningKey),
    EcdsaP384(P384SigningKey),
    Rsa(Box<RsaPrivateKey>),
    /// HMAC secret (32 bytes). Stored as raw bytes like the symmetric keys.
    Hmac256(Vec<u8>),
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        match self {
            Self::Aes256(ref mut bytes)
            | Self::Aes128(ref mut bytes)
            | Self::Hmac256(ref mut bytes) => bytes.zeroize(),
            // ed25519_dalek::SigningKey stores 32 bytes internally;
            // we overwrite via a zeroed key (best-effort).
            Self::Ed25519(ref mut key) => {
                let zero = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
                *key = zero;
            }
            Self::EcdsaP256(_) | Self::EcdsaP384(_) | Self::Rsa(_) => {
                // RustCrypto types don't expose a zeroize path;
                // memory is freed on drop. HSM providers handle
                // this properly; software provider is dev/test only.
            }
        }
    }
}

/// AES-GCM seal with a 12-byte random nonce, generic over the cipher
/// (AES-128 or AES-256). Wire format: `nonce || ciphertext+tag`.
fn gcm_encrypt<C>(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>
where
    C: KeyInit + Aead,
{
    let cipher = C::new_from_slice(key)
        .map_err(|e| KeyRackError::Provider(format!("AES init failed: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut nonce = aes_gcm::aead::Nonce::<C>::default();
    nonce.copy_from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| KeyRackError::Provider(format!("AES-GCM encrypt failed: {e}")))?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-GCM open mirroring [`gcm_encrypt`], generic over the cipher.
fn gcm_decrypt<C>(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>
where
    C: KeyInit + Aead,
{
    let cipher = C::new_from_slice(key)
        .map_err(|e| KeyRackError::Provider(format!("AES init failed: {e}")))?;

    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let mut nonce = aes_gcm::aead::Nonce::<C>::default();
    nonce.copy_from_slice(nonce_bytes);

    cipher
        .decrypt(&nonce, Payload { msg: ct, aad })
        .map_err(|_| {
            KeyRackError::Provider(
                "AES-GCM authentication failed: wrong key, corrupted ciphertext, or AAD mismatch"
                    .into(),
            )
        })
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
        extract(mat).ok_or_else(|| KeyRackError::Provider("key type mismatch".into()))
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
            KeySpec::Aes128 => {
                let mut key = vec![0u8; 16];
                OsRng.fill_bytes(&mut key);
                KeyMaterial::Aes128(key)
            }
            KeySpec::Hmac256 => {
                let mut key = vec![0u8; 32];
                OsRng.fill_bytes(&mut key);
                KeyMaterial::Hmac256(key)
            }
            KeySpec::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
                KeyMaterial::Ed25519(signing_key)
            }
            KeySpec::EcdsaP256Sha256 => {
                let signing_key = P256SigningKey::random(&mut OsRng);
                KeyMaterial::EcdsaP256(signing_key)
            }
            KeySpec::EcdsaP384 => {
                let signing_key = P384SigningKey::random(&mut OsRng);
                KeyMaterial::EcdsaP384(signing_key)
            }
            KeySpec::RsaPkcs1v15Sha256 { key_size } | KeySpec::RsaPssSha256 { key_size } => {
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

        let ciphertext = Self::get_material(&keys, handle, |m| match m {
            KeyMaterial::Aes256(k) => Some(gcm_encrypt::<Aes256Gcm>(k, plaintext, aad)),
            KeyMaterial::Aes128(k) => Some(gcm_encrypt::<Aes128Gcm>(k, plaintext, aad)),
            _ => None,
        })??;

        Ok(EncryptOutput { ciphertext })
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

        let plaintext = Self::get_material(&keys, handle, |m| match m {
            KeyMaterial::Aes256(k) => Some(gcm_decrypt::<Aes256Gcm>(k, ciphertext, aad)),
            KeyMaterial::Aes128(k) => Some(gcm_decrypt::<Aes128Gcm>(k, ciphertext, aad)),
            _ => None,
        })??;

        Ok(Sensitive::new(plaintext))
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
                let sig = signing_key.sign(message);
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
            SigningAlgorithm::RsaPkcs1v15Sha384 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let signing_key = RsaSigningKey::<Sha384>::new(private_key.clone());
                Ok(signing_key.sign(message).to_vec())
            }
            SigningAlgorithm::RsaPkcs1v15Sha512 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let signing_key = RsaSigningKey::<Sha512>::new(private_key.clone());
                Ok(signing_key.sign(message).to_vec())
            }
            SigningAlgorithm::RsaPssSha384 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let signing_key = RsaPssSigningKey::<Sha384>::new(private_key.clone());
                Ok(signing_key.sign_with_rng(&mut OsRng, message).to_vec())
            }
            SigningAlgorithm::RsaPssSha512 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let signing_key = RsaPssSigningKey::<Sha512>::new(private_key.clone());
                Ok(signing_key.sign_with_rng(&mut OsRng, message).to_vec())
            }
            SigningAlgorithm::EcdsaP384Sha384 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP384(k) => Some(k),
                    _ => None,
                })?;
                // p384 ECDSA's default digest is SHA-384.
                let sig: p384::ecdsa::Signature = sk.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            SigningAlgorithm::EcdsaP256Sha384 => {
                // P-256 key signed against a SHA-384 digest: hash here, then
                // sign the prehash (ECDSA reduces the digest mod n).
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP256(k) => Some(k),
                    _ => None,
                })?;
                let digest = Sha384::digest(message);
                let sig: p256::ecdsa::Signature = sk
                    .sign_prehash(&digest)
                    .map_err(|e| KeyRackError::Provider(format!("ECDSA sign failed: {e}")))?;
                Ok(sig.to_der().as_bytes().to_vec())
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
                let verifying_key = RsaVerifyingKey::<Sha256>::new(private_key.to_public_key());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid RSA sig: {e}")))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::RsaPssSha256 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let verifying_key = RsaPssVerifyingKey::<Sha256>::new(private_key.to_public_key());
                let sig = rsa::pss::Signature::try_from(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid RSA-PSS sig: {e}")))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::RsaPkcs1v15Sha384 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let verifying_key = RsaVerifyingKey::<Sha384>::new(private_key.to_public_key());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid RSA sig: {e}")))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::RsaPkcs1v15Sha512 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let verifying_key = RsaVerifyingKey::<Sha512>::new(private_key.to_public_key());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid RSA sig: {e}")))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::RsaPssSha384 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let verifying_key = RsaPssVerifyingKey::<Sha384>::new(private_key.to_public_key());
                let sig = rsa::pss::Signature::try_from(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid RSA-PSS sig: {e}")))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::RsaPssSha512 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let verifying_key = RsaPssVerifyingKey::<Sha512>::new(private_key.to_public_key());
                let sig = rsa::pss::Signature::try_from(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid RSA-PSS sig: {e}")))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::EcdsaP384Sha384 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP384(k) => Some(k),
                    _ => None,
                })?;
                let vk = P384VerifyingKey::from(sk);
                let sig = p384::ecdsa::DerSignature::from_bytes(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid ECDSA sig: {e}")))?;
                Ok(vk.verify(message, &sig).is_ok())
            }
            SigningAlgorithm::EcdsaP256Sha384 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP256(k) => Some(k),
                    _ => None,
                })?;
                let vk = P256VerifyingKey::from(sk);
                let digest = Sha384::digest(message);
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .map_err(|e| KeyRackError::Provider(format!("invalid ECDSA sig: {e}")))?;
                Ok(vk.verify_prehash(&digest, &sig).is_ok())
            }
        }
    }

    async fn sign_digest(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        if algorithm == SigningAlgorithm::Ed25519 {
            return Err(KeyRackError::Provider(
                "DIGEST signing invalid for Ed25519".into(),
            ));
        }
        let expected = algorithm.digest_len().ok_or_else(|| {
            KeyRackError::Provider("DIGEST signing not supported for this algorithm".into())
        })?;
        if digest.len() != expected {
            return Err(KeyRackError::Provider(format!(
                "digest length {} does not match algorithm hash length {expected}",
                digest.len()
            )));
        }

        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;

        match algorithm {
            SigningAlgorithm::Ed25519 => unreachable!("handled above"),
            SigningAlgorithm::RsaPkcs1v15Sha256
            | SigningAlgorithm::RsaPkcs1v15Sha384
            | SigningAlgorithm::RsaPkcs1v15Sha512 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let sig = match algorithm {
                    SigningAlgorithm::RsaPkcs1v15Sha256 => {
                        RsaSigningKey::<Sha256>::new(private_key.clone()).sign_prehash(digest)
                    }
                    SigningAlgorithm::RsaPkcs1v15Sha384 => {
                        RsaSigningKey::<Sha384>::new(private_key.clone()).sign_prehash(digest)
                    }
                    _ => RsaSigningKey::<Sha512>::new(private_key.clone()).sign_prehash(digest),
                }
                .map_err(|e| KeyRackError::Provider(format!("RSA prehash sign failed: {e}")))?;
                Ok(sig.to_vec())
            }
            SigningAlgorithm::RsaPssSha256
            | SigningAlgorithm::RsaPssSha384
            | SigningAlgorithm::RsaPssSha512 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let sig = match algorithm {
                    SigningAlgorithm::RsaPssSha256 => {
                        RsaPssSigningKey::<Sha256>::new(private_key.clone())
                            .sign_prehash_with_rng(&mut OsRng, digest)
                    }
                    SigningAlgorithm::RsaPssSha384 => {
                        RsaPssSigningKey::<Sha384>::new(private_key.clone())
                            .sign_prehash_with_rng(&mut OsRng, digest)
                    }
                    _ => RsaPssSigningKey::<Sha512>::new(private_key.clone())
                        .sign_prehash_with_rng(&mut OsRng, digest),
                }
                .map_err(|e| KeyRackError::Provider(format!("RSA-PSS prehash sign failed: {e}")))?;
                Ok(sig.to_vec())
            }
            SigningAlgorithm::EcdsaP256Sha256 | SigningAlgorithm::EcdsaP256Sha384 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP256(k) => Some(k),
                    _ => None,
                })?;
                let sig: p256::ecdsa::Signature = sk.sign_prehash(digest).map_err(|e| {
                    KeyRackError::Provider(format!("ECDSA prehash sign failed: {e}"))
                })?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
            SigningAlgorithm::EcdsaP384Sha384 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP384(k) => Some(k),
                    _ => None,
                })?;
                let sig: p384::ecdsa::Signature = sk.sign_prehash(digest).map_err(|e| {
                    KeyRackError::Provider(format!("ECDSA prehash sign failed: {e}"))
                })?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
        }
    }

    async fn verify_digest(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        if algorithm == SigningAlgorithm::Ed25519 {
            return Err(KeyRackError::Provider(
                "DIGEST verification invalid for Ed25519".into(),
            ));
        }
        let expected = algorithm.digest_len().ok_or_else(|| {
            KeyRackError::Provider("DIGEST verification not supported for this algorithm".into())
        })?;
        if digest.len() != expected {
            return Err(KeyRackError::Provider(format!(
                "digest length {} does not match algorithm hash length {expected}",
                digest.len()
            )));
        }

        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;

        match algorithm {
            SigningAlgorithm::Ed25519 => unreachable!("handled above"),
            SigningAlgorithm::RsaPkcs1v15Sha256
            | SigningAlgorithm::RsaPkcs1v15Sha384
            | SigningAlgorithm::RsaPkcs1v15Sha512 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature) else {
                    return Ok(false);
                };
                let pubkey = private_key.to_public_key();
                let ok = match algorithm {
                    SigningAlgorithm::RsaPkcs1v15Sha256 => {
                        RsaVerifyingKey::<Sha256>::new(pubkey).verify_prehash(digest, &sig)
                    }
                    SigningAlgorithm::RsaPkcs1v15Sha384 => {
                        RsaVerifyingKey::<Sha384>::new(pubkey).verify_prehash(digest, &sig)
                    }
                    _ => RsaVerifyingKey::<Sha512>::new(pubkey).verify_prehash(digest, &sig),
                };
                Ok(ok.is_ok())
            }
            SigningAlgorithm::RsaPssSha256
            | SigningAlgorithm::RsaPssSha384
            | SigningAlgorithm::RsaPssSha512 => {
                let private_key = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::Rsa(k) => Some(k.as_ref()),
                    _ => None,
                })?;
                let Ok(sig) = rsa::pss::Signature::try_from(signature) else {
                    return Ok(false);
                };
                let pubkey = private_key.to_public_key();
                let ok = match algorithm {
                    SigningAlgorithm::RsaPssSha256 => {
                        RsaPssVerifyingKey::<Sha256>::new(pubkey).verify_prehash(digest, &sig)
                    }
                    SigningAlgorithm::RsaPssSha384 => {
                        RsaPssVerifyingKey::<Sha384>::new(pubkey).verify_prehash(digest, &sig)
                    }
                    _ => RsaPssVerifyingKey::<Sha512>::new(pubkey).verify_prehash(digest, &sig),
                };
                Ok(ok.is_ok())
            }
            SigningAlgorithm::EcdsaP256Sha256 | SigningAlgorithm::EcdsaP256Sha384 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP256(k) => Some(k),
                    _ => None,
                })?;
                let vk = P256VerifyingKey::from(sk);
                let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else {
                    return Ok(false);
                };
                Ok(vk.verify_prehash(digest, &sig).is_ok())
            }
            SigningAlgorithm::EcdsaP384Sha384 => {
                let sk = Self::get_material(&keys, handle, |m| match m {
                    KeyMaterial::EcdsaP384(k) => Some(k),
                    _ => None,
                })?;
                let vk = P384VerifyingKey::from(sk);
                let Ok(sig) = p384::ecdsa::Signature::from_der(signature) else {
                    return Ok(false);
                };
                Ok(vk.verify_prehash(digest, &sig).is_ok())
            }
        }
    }

    async fn generate_mac(
        &self,
        handle: &KeyHandle,
        algorithm: MacAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;

        let key = Self::get_material(&keys, handle, |m| match m {
            KeyMaterial::Hmac256(k) => Some(k.clone()),
            _ => None,
        })?;

        let mac = match algorithm {
            MacAlgorithm::HmacSha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key)
                    .map_err(|e| KeyRackError::Provider(format!("HMAC key error: {e}")))?;
                m.update(message);
                m.finalize().into_bytes().to_vec()
            }
            MacAlgorithm::HmacSha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(&key)
                    .map_err(|e| KeyRackError::Provider(format!("HMAC key error: {e}")))?;
                m.update(message);
                m.finalize().into_bytes().to_vec()
            }
            MacAlgorithm::HmacSha512 => {
                let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&key)
                    .map_err(|e| KeyRackError::Provider(format!("HMAC key error: {e}")))?;
                m.update(message);
                m.finalize().into_bytes().to_vec()
            }
        };
        Ok(mac)
    }

    async fn verify_mac(
        &self,
        handle: &KeyHandle,
        algorithm: MacAlgorithm,
        message: &[u8],
        mac: &[u8],
    ) -> Result<bool> {
        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;

        let key = Self::get_material(&keys, handle, |m| match m {
            KeyMaterial::Hmac256(k) => Some(k.clone()),
            _ => None,
        })?;

        let ok = match algorithm {
            MacAlgorithm::HmacSha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key)
                    .map_err(|e| KeyRackError::Provider(format!("HMAC key error: {e}")))?;
                m.update(message);
                m.verify_slice(mac).is_ok()
            }
            MacAlgorithm::HmacSha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(&key)
                    .map_err(|e| KeyRackError::Provider(format!("HMAC key error: {e}")))?;
                m.update(message);
                m.verify_slice(mac).is_ok()
            }
            MacAlgorithm::HmacSha512 => {
                let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&key)
                    .map_err(|e| KeyRackError::Provider(format!("HMAC key error: {e}")))?;
                m.update(message);
                m.verify_slice(mac).is_ok()
            }
        };
        Ok(ok)
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
        use CryptoOperation::{
            Decrypt, DestroyKey, Encrypt, GenerateDataKey, GenerateKey, GenerateMac, ReEncrypt,
            Sign, Verify, VerifyMac,
        };

        let symmetric_ops = vec![
            GenerateKey,
            Encrypt,
            Decrypt,
            GenerateDataKey,
            ReEncrypt,
            DestroyKey,
        ];
        let signing_ops = vec![GenerateKey, Sign, Verify, DestroyKey];
        let mac_ops = vec![GenerateKey, GenerateMac, VerifyMac, DestroyKey];

        ProviderCapabilities {
            provider_name: "software".into(),
            key_specs: vec![
                KeySpecCapability {
                    key_spec: KeySpec::Aes256,
                    operations: symmetric_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::Aes128,
                    operations: symmetric_ops,
                },
                KeySpecCapability {
                    key_spec: KeySpec::Ed25519,
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::EcdsaP256Sha256,
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::EcdsaP384,
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::Hmac256,
                    operations: mac_ops,
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 3072 },
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 },
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPssSha256 { key_size: 2048 },
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPssSha256 { key_size: 3072 },
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPssSha256 { key_size: 4096 },
                    operations: signing_ops,
                },
            ],
            supports_generate_random: true,
            supports_atomic_data_key: false,
            supports_atomic_re_encrypt: false,
        }
    }

    async fn export_key_material(&self, handle: &KeyHandle) -> Result<Sensitive<Vec<u8>>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;

        let bytes = Self::get_material(&keys, handle, |m| match m {
            KeyMaterial::Aes256(k) | KeyMaterial::Aes128(k) | KeyMaterial::Hmac256(k) => {
                Some(k.clone())
            }
            _ => None,
        })?;

        Ok(Sensitive::new(bytes))
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
        let pt = provider
            .decrypt(&handle, &ct.ciphertext, aad)
            .await
            .unwrap();

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
            .verify(&handle, SigningAlgorithm::RsaPkcs1v15Sha256, b"wrong", &sig)
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

    // ── Proto-alignment additions ──────────────────────────────────

    #[tokio::test]
    async fn ecdsa_p384_raw_sign_verify() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key(&KeySpec::EcdsaP384).await.unwrap();

        let msg = b"p384 raw message";
        let sig = provider
            .sign(&handle, SigningAlgorithm::EcdsaP384Sha384, msg)
            .await
            .unwrap();
        assert!(provider
            .verify(&handle, SigningAlgorithm::EcdsaP384Sha384, msg, &sig)
            .await
            .unwrap());
        assert!(!provider
            .verify(
                &handle,
                SigningAlgorithm::EcdsaP384Sha384,
                b"tampered",
                &sig
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn rsa_pss_sha512_raw_sign_verify() {
        let provider = SoftwareProvider::new();
        let handle = provider
            .generate_key(&KeySpec::RsaPssSha256 { key_size: 2048 })
            .await
            .unwrap();

        let msg = b"rsa pss sha512 raw message";
        let sig = provider
            .sign(&handle, SigningAlgorithm::RsaPssSha512, msg)
            .await
            .unwrap();
        assert!(provider
            .verify(&handle, SigningAlgorithm::RsaPssSha512, msg, &sig)
            .await
            .unwrap());
        assert!(!provider
            .verify(&handle, SigningAlgorithm::RsaPssSha512, b"tampered", &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn ecdsa_p256_sha256_digest_round_trip() {
        let provider = SoftwareProvider::new();
        let handle = provider
            .generate_key(&KeySpec::EcdsaP256Sha256)
            .await
            .unwrap();

        let digest = Sha256::digest(b"some message").to_vec();
        let sig = provider
            .sign_digest(&handle, SigningAlgorithm::EcdsaP256Sha256, &digest)
            .await
            .unwrap();
        assert!(provider
            .verify_digest(&handle, SigningAlgorithm::EcdsaP256Sha256, &digest, &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn rsa_pkcs1v15_sha384_digest_round_trip() {
        let provider = SoftwareProvider::new();
        let handle = provider
            .generate_key(&KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 })
            .await
            .unwrap();

        let digest = Sha384::digest(b"another message").to_vec();
        let sig = provider
            .sign_digest(&handle, SigningAlgorithm::RsaPkcs1v15Sha384, &digest)
            .await
            .unwrap();
        assert!(provider
            .verify_digest(&handle, SigningAlgorithm::RsaPkcs1v15Sha384, &digest, &sig)
            .await
            .unwrap());

        // Wrong digest length is rejected.
        assert!(provider
            .sign_digest(&handle, SigningAlgorithm::RsaPkcs1v15Sha384, b"short")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn raw_sign_matches_digest_verify_rsa_pkcs1v15_sha256() {
        let provider = SoftwareProvider::new();
        let handle = provider
            .generate_key(&KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 })
            .await
            .unwrap();

        let msg = b"cross-check message";
        let sig = provider
            .sign(&handle, SigningAlgorithm::RsaPkcs1v15Sha256, msg)
            .await
            .unwrap();
        // RAW = sign(hash(msg)); verifying the externally-computed digest must agree.
        let digest = Sha256::digest(msg).to_vec();
        assert!(provider
            .verify_digest(&handle, SigningAlgorithm::RsaPkcs1v15Sha256, &digest, &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn raw_sign_matches_digest_verify_ecdsa_p256() {
        let provider = SoftwareProvider::new();
        let handle = provider
            .generate_key(&KeySpec::EcdsaP256Sha256)
            .await
            .unwrap();

        let msg = b"cross-check ecdsa message";
        let sig = provider
            .sign(&handle, SigningAlgorithm::EcdsaP256Sha256, msg)
            .await
            .unwrap();
        let digest = Sha256::digest(msg).to_vec();
        assert!(provider
            .verify_digest(&handle, SigningAlgorithm::EcdsaP256Sha256, &digest, &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn ed25519_digest_signing_rejected() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key(&KeySpec::Ed25519).await.unwrap();
        let result = provider
            .sign_digest(&handle, SigningAlgorithm::Ed25519, &[0u8; 32])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn hmac_sha256_generate_verify() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key(&KeySpec::Hmac256).await.unwrap();

        let msg = b"mac me";
        let mac = provider
            .generate_mac(&handle, MacAlgorithm::HmacSha256, msg)
            .await
            .unwrap();
        assert!(provider
            .verify_mac(&handle, MacAlgorithm::HmacSha256, msg, &mac)
            .await
            .unwrap());
        // Tampered message must fail verification.
        assert!(!provider
            .verify_mac(&handle, MacAlgorithm::HmacSha256, b"tampered", &mac)
            .await
            .unwrap());
    }

    // If you flip either flag to true you MUST have overridden the
    // corresponding method to keep plaintext in-boundary AND added a
    // test proving it. This guard converts a silent capability lie
    // into a conscious, reviewed change.
    #[test]
    fn capability_flags_are_honest() {
        let provider = SoftwareProvider::new();
        let caps = provider.capabilities();
        assert!(
            !caps.supports_atomic_data_key,
            "supports_atomic_data_key must be false without a generate_data_key override"
        );
        assert!(
            !caps.supports_atomic_re_encrypt,
            "supports_atomic_re_encrypt must be false without a re_encrypt override"
        );
    }

    #[tokio::test]
    async fn aes128_encrypt_decrypt_round_trip() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key(&KeySpec::Aes128).await.unwrap();

        let plaintext = b"hello aes-128";
        let aad = b"ctx";
        let ct = provider.encrypt(&handle, plaintext, aad).await.unwrap();
        let pt = provider
            .decrypt(&handle, &ct.ciphertext, aad)
            .await
            .unwrap();
        assert_eq!(pt.expose().as_slice(), plaintext);
    }
}
