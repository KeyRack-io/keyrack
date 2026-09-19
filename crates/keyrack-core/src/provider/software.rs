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

use crate::creation::{
    invalid, A2ClosureClaim, A2ClosureFact, A2ClosureVerifier, CreationBinding, CreationRequest,
};
use crate::error::{KeyRackError, Result};
use crate::key::{KeySpec, ProviderRef};
use crate::provider::{
    CryptoOperation, CryptoProvider, EncryptOutput, GeneratedWrappedKey, KeyHandle,
    KeySpecCapability, MacAlgorithm, ProviderCapabilities, SigningAlgorithm, WrappedKeyClosure,
    WrappedKeyLease,
};
use crate::sensitive::Sensitive;
use crate::wrapping::{
    WrappedKeyFormat, WrappedKeyLifecycle, WrappingCapabilities, WrappingCapability,
    WrappingContext, WrappingContextVersion, WrappingIdentifier, WrappingKeyPurpose,
    WrappingOperation,
};
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
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

/// Exact mechanism identity of the software wrapping profile.
///
/// The name leads with `software` on purpose. This mechanism wraps a child
/// under an AES-256 parent that is itself held in this process's heap, and
/// unwraps the child back into that heap for the life of a lease. It activates
/// the hierarchy path; it contains nothing. A capability dump that shows this
/// mechanism is showing an unqualified backend, not provider-contained custody.
pub const SOFTWARE_WRAPPING_MECHANISM: &str = "software:aes-256-gcm:v1";

/// Bound on remembered closure records. Exceeding it evicts the oldest, after
/// which that object's closure can no longer be evidenced or re-closed.
const MAX_RECORDED_CLOSURES: usize = 4096;

/// Exact wrapped-child envelope length: 12-byte nonce, 32-byte child, 16-byte tag.
const SOFTWARE_ENVELOPE_BYTES: usize = 12 + 32 + 16;

/// Whether an object was created by generation or by opening stored material.
/// Only a generation object can evidence the closure of a creation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectOrigin {
    Generated,
    Opened,
}

/// Bindings of one transient child object, held only in process memory.
#[derive(Debug, Clone)]
struct ObjectBinding {
    context_sha256: [u8; 32],
    envelope_blake3: [u8; 32],
    origin: ObjectOrigin,
    /// The creation this object was generated for, absent for an opened child.
    /// Kept because context is identical across attempts at the same child: it
    /// is what lets the verifier refuse a real closure presented for another
    /// creation.
    creation: Option<CreationBinding>,
}

/// Open and closed child objects for this provider incarnation.
#[derive(Debug, Default)]
struct WrappingState {
    open: HashMap<String, ObjectBinding>,
    closed: HashMap<String, ObjectBinding>,
    closed_order: VecDeque<String>,
    issued: u64,
}

impl WrappingState {
    fn record_closed(&mut self, object: String, binding: ObjectBinding) {
        if self.closed_order.len() >= MAX_RECORDED_CLOSURES {
            if let Some(evicted) = self.closed_order.pop_front() {
                self.closed.remove(&evicted);
            }
        }
        self.closed_order.push_back(object.clone());
        self.closed.insert(object, binding);
    }
}

/// Optional provider identity, so a context naming a different backend is
/// refused rather than served. Unscoped providers rely on the caller having
/// resolved them and on the context being authenticated as wrapping AAD.
#[derive(Debug, Clone)]
struct WrappingScope {
    provider_ref: ProviderRef,
    security_domain: WrappingIdentifier,
}

/// The wrapping profile this provider implements, one tuple per operation it
/// can actually perform. `Rewrap` is absent because it is not implemented.
fn software_wrapping_capabilities() -> WrappingCapabilities {
    let mechanism = WrappingIdentifier::new(SOFTWARE_WRAPPING_MECHANISM)
        .expect("software wrapping mechanism is a valid identifier");
    let tuples = [
        WrappingOperation::Generate,
        WrappingOperation::Open,
        WrappingOperation::Close,
    ]
    .into_iter()
    .map(|operation| WrappingCapability {
        parent_spec: KeySpec::Aes256,
        child_spec: KeySpec::Aes256,
        key_format: WrappedKeyFormat::RawSecret,
        purpose: WrappingKeyPurpose::EncryptDecrypt,
        mechanism: mechanism.clone(),
        context_version: WrappingContextVersion::V1,
        operation,
        // The child is unwrapped into this process's memory and stays there
        // until the lease is closed or the process exits. That is a session
        // object; it is not a journaled temporary object in a backend.
        lifecycle: WrappedKeyLifecycle::SessionObject,
    })
    .collect();
    WrappingCapabilities::new(tuples).expect("software wrapping profile is structurally valid")
}

/// Pure-Rust software crypto provider.
pub struct SoftwareProvider {
    keys: RwLock<HashMap<String, KeyMaterial>>,
    /// Distinguishes this process's objects from any other incarnation's. A
    /// restart invalidates every object and every closure record it issued.
    incarnation: Uuid,
    scope: Option<WrappingScope>,
    wrapping: Arc<RwLock<WrappingState>>,
}

impl SoftwareProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            incarnation: Uuid::new_v4(),
            scope: None,
            wrapping: Arc::new(RwLock::new(WrappingState::default())),
        }
    }

    /// Bind this provider to one exact provider ref and security domain, so a
    /// wrapping context naming another backend is refused. This is an identity
    /// check on metadata, not an isolation boundary.
    #[must_use]
    pub fn scoped(provider_ref: ProviderRef, security_domain: WrappingIdentifier) -> Self {
        Self {
            scope: Some(WrappingScope {
                provider_ref,
                security_domain,
            }),
            ..Self::new()
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

    /// Refuse an undeclared tuple, a context that names another backend, or a
    /// parent handle that is not the spec the context binds; otherwise return
    /// the canonical context bytes to authenticate the wrapping with.
    fn admit(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        operation: WrappingOperation,
    ) -> Result<Vec<u8>> {
        self.wrapping_capabilities()
            .require(&WrappingCapability::requested(
                context,
                operation,
                WrappedKeyLifecycle::SessionObject,
            ))
            .map_err(|e| KeyRackError::Provider(format!("software wrapping refused: {e}")))?;
        if let Some(scope) = &self.scope {
            if scope.provider_ref != context.provider_ref
                || scope.security_domain != context.security_domain
            {
                return Err(KeyRackError::Provider(
                    "software wrapping refused: context names another provider or security domain"
                        .into(),
                ));
            }
        }
        if parent.key_spec != context.parent_spec {
            return Err(KeyRackError::Provider(
                "software wrapping refused: parent handle is not the spec bound by the context"
                    .into(),
            ));
        }
        context
            .canonical_bytes()
            .map_err(|e| KeyRackError::Provider(format!("software wrapping refused: {e}")))
    }

    fn seal_under_parent(&self, parent: &KeyHandle, child: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;
        Self::get_material(&keys, parent, |m| match m {
            KeyMaterial::Aes256(k) => Some(gcm_encrypt::<Aes256Gcm>(k, child, aad)),
            _ => None,
        })?
    }

    fn open_under_parent(
        &self,
        parent: &KeyHandle,
        envelope: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;
        Self::get_material(&keys, parent, |m| match m {
            KeyMaterial::Aes256(k) => Some(gcm_decrypt::<Aes256Gcm>(k, envelope, aad)),
            _ => None,
        })?
    }

    /// Hold an unwrapped child in process memory under a fresh object identity
    /// and return the lease that owes a close.
    fn retain_child(
        &self,
        context: &WrappingContext,
        child: KeyMaterial,
        envelope: &[u8],
        origin: ObjectOrigin,
        creation: Option<CreationBinding>,
    ) -> Result<WrappedKeyLease> {
        let binding = ObjectBinding {
            context_sha256: context
                .context_sha256()
                .map_err(|e| KeyRackError::Provider(format!("invalid wrapping context: {e}")))?,
            envelope_blake3: *blake3::hash(envelope).as_bytes(),
            origin,
            creation,
        };
        // Lock order is wrapping state, then keys; every wrapping path keeps it.
        let object = {
            let mut state = self
                .wrapping
                .write()
                .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;
            state.issued = state
                .issued
                .checked_add(1)
                .ok_or_else(|| KeyRackError::Provider("object identities exhausted".into()))?;
            let object = format!("kr-sw-a2-{}-{}", self.incarnation, state.issued);
            state.open.insert(object.clone(), binding);
            object
        };
        self.keys
            .write()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?
            .insert(object.clone(), child);
        WrappedKeyLease::new(
            KeyHandle {
                key_id: object.clone(),
                key_spec: context.child_spec.clone(),
            },
            WrappingIdentifier::new(object)
                .map_err(|e| KeyRackError::Provider(format!("invalid object identity: {e}")))?,
            context,
        )
    }
}

/// Verifies closure facts this provider incarnation actually recorded.
///
/// Evidence is a process-memory record of a destruction this incarnation
/// performed. It is deliberately unable to speak for any other incarnation: a
/// claim about an object from a previous process is refused rather than assumed
/// from the fact that the process is gone, which leaves an interrupted creation
/// to explicit reconciliation instead of inferring cleanup.
struct SoftwareClosureVerifier {
    incarnation: Uuid,
    state: Arc<RwLock<WrappingState>>,
}

impl A2ClosureVerifier for SoftwareClosureVerifier {
    fn verify(&self, request: &CreationRequest, claim: &A2ClosureClaim) -> Result<()> {
        let A2ClosureFact::TemporaryObjectDestroyed { object } = &claim.fact else {
            return Err(invalid("software closure must destroy a temporary object"));
        };
        if !object.starts_with(&format!("kr-sw-a2-{}-", self.incarnation)) {
            return Err(invalid(
                "closure names an object this provider incarnation did not issue",
            ));
        }
        let state = self
            .state
            .read()
            .map_err(|_| invalid("wrapping state lock poisoned"))?;
        let binding = state
            .closed
            .get(object)
            .ok_or(invalid("no recorded destruction for the closed object"))?;
        if binding.origin != ObjectOrigin::Generated {
            return Err(invalid(
                "closure names an opened object, not a creation object",
            ));
        }
        // The creation this object was generated for, compared before anything
        // it has in common with other creations. Context, envelope and origin
        // are all equal across two attempts at the same child, so without this
        // a real closure of one attempt certifies another.
        binding
            .creation
            .as_ref()
            .ok_or(invalid("closure names an object with no creation binding"))?
            .require(request)?;
        if binding.envelope_blake3 != claim.envelope_digest {
            return Err(invalid("closure does not bind the staged envelope"));
        }
        let expected = request
            .context()?
            .context_sha256()
            .map_err(|_| invalid("invalid creation context"))?;
        if binding.context_sha256 != expected {
            return Err(invalid("closure does not bind the creation context"));
        }
        Ok(())
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
            supports_key_import: true,
        }
    }

    /// One profile, declared for the three operations it implements.
    ///
    /// Declaring these activates parent-wrapped child keys on this provider. It
    /// asserts no containment: the parent, the envelope and the unwrapped child
    /// all live in this process's memory, so a wrapped child here is exactly as
    /// contained as the parent that wraps it, which is not at all. Nothing in
    /// this declaration makes a software-wrapped child provider-contained.
    fn wrapping_capabilities(&self) -> WrappingCapabilities {
        software_wrapping_capabilities()
    }

    async fn generate_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: &CreationBinding,
    ) -> Result<GeneratedWrappedKey> {
        let aad = self.admit(context, parent, WrappingOperation::Generate)?;
        let mut child = vec![0u8; 32];
        OsRng.fill_bytes(&mut child);
        // Held as key material from here on, so it is zeroized however this
        // function leaves, including the error paths below.
        let child = KeyMaterial::Aes256(child);
        let KeyMaterial::Aes256(bytes) = &child else {
            return Err(KeyRackError::Provider("child material mismatch".into()));
        };
        let envelope = self.seal_under_parent(parent, bytes, &aad)?;
        let lease = self.retain_child(
            context,
            child,
            &envelope,
            ObjectOrigin::Generated,
            Some(creation.clone()),
        )?;
        Ok(GeneratedWrappedKey { envelope, lease })
    }

    async fn open_wrapped_key(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        envelope: &[u8],
    ) -> Result<WrappedKeyLease> {
        let aad = self.admit(context, parent, WrappingOperation::Open)?;
        if envelope.len() != SOFTWARE_ENVELOPE_BYTES {
            return Err(KeyRackError::Provider(
                "wrapped material is not a software AES-256-GCM envelope".into(),
            ));
        }
        // AES-GCM authenticates the canonical context as AAD, so an envelope
        // from another child version, parent or profile fails here rather than
        // yielding a key under the requested bindings.
        let child = KeyMaterial::Aes256(self.open_under_parent(parent, envelope, &aad)?);
        let KeyMaterial::Aes256(bytes) = &child else {
            return Err(KeyRackError::Provider("child material mismatch".into()));
        };
        if bytes.len() != 32 {
            return Err(KeyRackError::Provider(
                "unwrapped child is not an AES-256 key".into(),
            ));
        }
        self.retain_child(context, child, envelope, ObjectOrigin::Opened, None)
    }

    async fn close_wrapped_key(&self, lease: &WrappedKeyLease) -> Result<WrappedKeyClosure> {
        let object = lease.object().as_str().to_owned();
        let binding = {
            let mut state = self
                .wrapping
                .write()
                .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?;
            if let Some(recorded) = state.closed.get(&object).cloned() {
                // Idempotent: a repeated close reports the same fact so that a
                // lost response can be reconciled rather than retried as work.
                if recorded.context_sha256 != lease.context_sha256() {
                    return Err(KeyRackError::Provider(
                        "wrapping lease does not match the closed object's context".into(),
                    ));
                }
                recorded
            } else {
                let open = state
                    .open
                    .remove(&object)
                    .ok_or_else(|| KeyRackError::Provider("unknown wrapping lease".into()))?;
                if open.context_sha256 != lease.context_sha256() {
                    // Leave the object open: a mismatched claim must not destroy
                    // it, and cleanup stays owed to whoever holds the real lease.
                    state.open.insert(object, open);
                    return Err(KeyRackError::Provider(
                        "wrapping lease does not match the open object's context".into(),
                    ));
                }
                // Destroy first, record second, both under this lock. A closure
                // record is a statement that the material is gone, so it must
                // not be observable while the material is still there, and a
                // failure here must leave the object open with cleanup owed
                // rather than a positive record of a destruction that did not
                // happen. Lock order stays wrapping state, then keys.
                match self.keys.write() {
                    Ok(mut keys) => {
                        keys.remove(&object);
                    }
                    Err(e) => {
                        state.open.insert(object, open);
                        return Err(KeyRackError::Provider(format!("lock poisoned: {e}")));
                    }
                }
                state.record_closed(object.clone(), open.clone());
                open
            }
        };
        Ok(WrappedKeyClosure {
            fact: A2ClosureFact::TemporaryObjectDestroyed { object },
            context_sha256: binding.context_sha256,
        })
    }

    fn wrapping_closure_verifier(&self) -> Option<Arc<dyn A2ClosureVerifier>> {
        Some(Arc::new(SoftwareClosureVerifier {
            incarnation: self.incarnation,
            state: Arc::clone(&self.wrapping),
        }))
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

    /// Import externally-generated **symmetric** key material.
    ///
    /// Asymmetric specs are rejected: importing them means parsing a PKCS#8 /
    /// PKCS#1 private key, and accepting a spec we cannot actually seed would
    /// hand the caller a handle to a key that is not the one they imported.
    async fn import_key_material(
        &self,
        spec: &KeySpec,
        material: Sensitive<Vec<u8>>,
    ) -> Result<KeyHandle> {
        let bytes = material.expose();

        // Length is checked against the spec so a short or over-long import is
        // refused rather than silently truncated or zero-padded by the cipher.
        let expect_len = |n: usize| -> Result<Vec<u8>> {
            if bytes.len() == n {
                Ok(bytes.clone())
            } else {
                Err(KeyRackError::Provider(format!(
                    "{spec:?} import expects {n} bytes of key material, got {}",
                    bytes.len()
                )))
            }
        };

        let key_material = match spec {
            KeySpec::Aes256 => KeyMaterial::Aes256(expect_len(32)?),
            KeySpec::Aes128 => KeyMaterial::Aes128(expect_len(16)?),
            KeySpec::Hmac256 => KeyMaterial::Hmac256(expect_len(32)?),
            other => {
                return Err(KeyRackError::Provider(format!(
                    "key import not supported for {other:?} by the software provider \
                     (symmetric specs only)"
                )))
            }
        };

        let id = Uuid::new_v4().to_string();
        self.keys
            .write()
            .map_err(|e| KeyRackError::Provider(format!("lock poisoned: {e}")))?
            .insert(id.clone(), key_material);

        Ok(KeyHandle {
            key_id: id,
            key_spec: spec.clone(),
        })
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

    #[tokio::test]
    async fn import_aes_256_returns_the_imported_material() {
        let provider = SoftwareProvider::new();
        let material: Vec<u8> = (0..32).collect();

        let handle = provider
            .import_key_material(&KeySpec::Aes256, Sensitive::new(material.clone()))
            .await
            .unwrap();

        assert_eq!(handle.key_spec, KeySpec::Aes256);
        let exported = provider.export_key_material(&handle).await.unwrap();
        assert_eq!(exported.expose(), &material);
    }

    #[tokio::test]
    async fn imported_aes_key_decrypts_what_it_encrypts() {
        let provider = SoftwareProvider::new();
        let handle = provider
            .import_key_material(&KeySpec::Aes256, Sensitive::new(vec![7u8; 32]))
            .await
            .unwrap();

        let ct = provider.encrypt(&handle, b"payload", b"aad").await.unwrap();
        let pt = provider
            .decrypt(&handle, &ct.ciphertext, b"aad")
            .await
            .unwrap();
        assert_eq!(pt.expose().as_slice(), b"payload");
    }

    #[tokio::test]
    async fn import_hmac_256_produces_a_usable_mac_key() {
        let provider = SoftwareProvider::new();
        let handle = provider
            .import_key_material(&KeySpec::Hmac256, Sensitive::new(vec![3u8; 32]))
            .await
            .unwrap();

        let mac = provider
            .generate_mac(&handle, MacAlgorithm::HmacSha256, b"m")
            .await
            .unwrap();
        assert!(provider
            .verify_mac(&handle, MacAlgorithm::HmacSha256, b"m", &mac)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn import_rejects_wrong_length_material() {
        let provider = SoftwareProvider::new();
        for (spec, len) in [
            (KeySpec::Aes256, 16usize),
            (KeySpec::Aes128, 32),
            (KeySpec::Hmac256, 31),
        ] {
            let err = provider
                .import_key_material(&spec, Sensitive::new(vec![0u8; len]))
                .await
                .expect_err("wrong-length import must be refused");
            assert!(
                err.to_string().contains("bytes of key material"),
                "unexpected error for {spec:?}/{len}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn import_rejects_asymmetric_specs() {
        let provider = SoftwareProvider::new();
        let err = provider
            .import_key_material(&KeySpec::Ed25519, Sensitive::new(vec![0u8; 32]))
            .await
            .expect_err("asymmetric import is not implemented");
        assert!(
            err.to_string().contains("symmetric specs only"),
            "error message: {err}"
        );
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
