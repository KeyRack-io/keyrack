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

//! PKCS#11 `CryptoProvider` implementation.

use crate::ecdsa_der;
use async_trait::async_trait;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{
    CryptoOperation, CryptoProvider, EncryptOutput, KeyHandle, KeySpecCapability,
    ProviderCapabilities, SigningAlgorithm,
};
use keyrack_core::sensitive::Sensitive;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

/// DER-encoded OID for P-256 (secp256r1): 1.2.840.10045.3.1.7
const P256_OID_DER: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// DER-encoded OID for Ed25519: 1.3.101.112
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// P-256 ECDSA component size in bytes.
const P256_COMPONENT_LEN: usize = 32;

fn make_auth_pin(pin: &str) -> AuthPin {
    AuthPin::new(pin.to_owned().into_boxed_str())
}

/// Classify a cryptoki error as a transient HSM connectivity/session failure.
fn is_transient_pkcs11_error(e: &cryptoki::error::Error) -> bool {
    matches!(
        e,
        cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::DeviceError
                | cryptoki::error::RvError::DeviceRemoved
                | cryptoki::error::RvError::TokenNotPresent
                | cryptoki::error::RvError::SessionClosed
                | cryptoki::error::RvError::SessionHandleInvalid,
            _,
        )
    )
}

/// Map a cryptoki error to the appropriate `KeyRackError` variant,
/// distinguishing transient HSM failures from permanent provider errors.
fn map_pkcs11_error(context: &str, e: &cryptoki::error::Error) -> KeyRackError {
    if is_transient_pkcs11_error(e) {
        KeyRackError::ProviderUnavailable(format!("{context}: {e}"))
    } else {
        KeyRackError::Provider(format!("{context}: {e}"))
    }
}

/// Process-wide registry of initialized PKCS#11 modules, keyed by library
/// path.
///
/// PKCS#11 permits `C_Initialize` only once per library per process. Multiple
/// providers backed by the same library (e.g. several tokens / HSM partitions
/// driven by one vendor `.so`) must therefore share a single initialized
/// context and select different slots. Without sharing, constructing the
/// second provider fails with `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
///
/// `Pkcs11` is internally reference-counted, so cloning the stored handle is
/// cheap and all clones drive the same initialized module.
fn shared_module(lib_path: &str) -> Result<Pkcs11> {
    static MODULES: OnceLock<Mutex<HashMap<String, Pkcs11>>> = OnceLock::new();
    let modules = MODULES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = modules
        .lock()
        .map_err(|_| KeyRackError::Provider("PKCS#11 module registry poisoned".into()))?;

    if let Some(ctx) = guard.get(lib_path) {
        return Ok(ctx.clone());
    }

    let ctx = Pkcs11::new(Path::new(lib_path))
        .map_err(|e| KeyRackError::Provider(format!("load PKCS#11 lib: {e}")))?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|e| KeyRackError::Provider(format!("C_Initialize: {e}")))?;
    guard.insert(lib_path.to_owned(), ctx.clone());
    Ok(ctx)
}

/// Configuration for constructing a [`Pkcs11Provider`].
#[derive(Clone)]
pub struct Pkcs11ProviderConfig {
    pub lib_path: String,
    pub token_label: String,
    pub pin: String,
}

/// PKCS#11 cryptographic provider.
///
/// All cryptographic operations are dispatched to the HSM via PKCS#11.
/// Sessions are opened per-operation — production HSMs benefit from a
/// session pool (future enhancement behind a feature flag).
pub struct Pkcs11Provider {
    ctx: Pkcs11,
    slot: cryptoki::slot::Slot,
    pin: Zeroizing<String>,
}

impl Pkcs11Provider {
    /// Create a new provider by loading the PKCS#11 shared library,
    /// finding the token by label, and verifying connectivity.
    pub fn new(config: &Pkcs11ProviderConfig) -> Result<Self> {
        // Share one initialized module per library path so several providers
        // (e.g. one per tenant token) can be backed by the same `.so` without
        // a second `C_Initialize` failing with ALREADY_INITIALIZED.
        let ctx = shared_module(&config.lib_path)?;

        let slot = find_slot_by_label(&ctx, &config.token_label)?;

        // Verify we can actually log in
        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| KeyRackError::Provider(format!("open session: {e}")))?;
        session
            .login(UserType::User, Some(&make_auth_pin(&config.pin)))
            .map_err(|e| KeyRackError::Provider(format!("login: {e}")))?;
        drop(session);

        tracing::info!(
            token_label = %config.token_label,
            "PKCS#11 provider initialized"
        );

        Ok(Self {
            ctx,
            slot,
            pin: Zeroizing::new(config.pin.clone()),
        })
    }

    /// Run a synchronous PKCS#11 operation on a blocking Tokio thread.
    async fn run<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Session) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let ctx = self.ctx.clone();
        let slot = self.slot;
        let pin = Zeroizing::new(self.pin.as_str().to_owned());

        tokio::task::spawn_blocking(move || {
            let session = ctx
                .open_rw_session(slot)
                .map_err(|e| map_pkcs11_error("open session", &e))?;
            session
                .login(UserType::User, Some(&make_auth_pin(&pin)))
                .map_err(|e| map_pkcs11_error("login", &e))?;
            f(&session)
        })
        .await
        .map_err(|e| KeyRackError::Provider(format!("blocking task: {e}")))?
    }
}

fn find_slot_by_label(ctx: &Pkcs11, label: &str) -> Result<cryptoki::slot::Slot> {
    let slots = ctx
        .get_slots_with_initialized_token()
        .map_err(|e| KeyRackError::Provider(format!("get slots: {e}")))?;

    for slot in &slots {
        if let Ok(info) = ctx.get_token_info(*slot) {
            let token_label = info.label().trim();
            if token_label == label {
                return Ok(*slot);
            }
        }
    }

    Err(KeyRackError::Provider(format!(
        "no token with label \"{label}\" found"
    )))
}

fn find_object(session: &Session, label: &str, class: ObjectClass) -> Result<ObjectHandle> {
    let template = vec![
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(class),
    ];
    let objects = session
        .find_objects(&template)
        .map_err(|e| map_pkcs11_error("find_objects", &e))?;

    objects
        .into_iter()
        .next()
        .ok_or_else(|| KeyRackError::Provider(format!("object not found: {label}")))
}

fn generate_aes_key(session: &Session, label: &str) -> Result<()> {
    let template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::ValueLen(32.into()),
    ];
    session
        .generate_key(&Mechanism::AesKeyGen, &template)
        .map_err(|e| KeyRackError::Provider(format!("AES keygen: {e}")))?;
    Ok(())
}

fn generate_rsa_key_pair(session: &Session, label: &str, key_size: u32) -> Result<()> {
    let bits = u64::from(key_size);
    if !(2048..=4096).contains(&bits) {
        return Err(KeyRackError::Provider(format!(
            "RSA key size must be 2048–4096, got {key_size}"
        )));
    }

    let pub_exponent: Vec<u8> = vec![0x01, 0x00, 0x01]; // 65537
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::ModulusBits(bits.into()),
        Attribute::PublicExponent(pub_exponent),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    session
        .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_template, &priv_template)
        .map_err(|e| KeyRackError::Provider(format!("RSA keygen: {e}")))?;
    Ok(())
}

fn generate_ec_key_pair(session: &Session, label: &str, ec_params: &[u8]) -> Result<()> {
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::EcParams(ec_params.to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    session
        .generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)
        .map_err(|e| KeyRackError::Provider(format!("EC keygen: {e}")))?;
    Ok(())
}

fn generate_ed25519_key_pair(session: &Session, label: &str) -> Result<()> {
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::EcParams(ED25519_OID_DER.to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    session
        .generate_key_pair(
            &Mechanism::EccEdwardsKeyPairGen,
            &pub_template,
            &priv_template,
        )
        .map_err(|e| KeyRackError::Provider(format!("Ed25519 keygen: {e}")))?;
    Ok(())
}

fn pkcs11_encrypt(
    session: &Session,
    label: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptOutput> {
    let obj = find_object(session, label, ObjectClass::SECRET_KEY)?;

    let nonce_bytes = session
        .generate_random_vec(12)
        .map_err(|e| map_pkcs11_error("generate nonce", &e))?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let gcm_params = GcmParams::new(&mut nonce, aad, 128.into())
        .map_err(|e| KeyRackError::Provider(format!("GCM params: {e}")))?;
    let ct = session
        .encrypt(&Mechanism::AesGcm(gcm_params), obj, plaintext)
        .map_err(|e| map_pkcs11_error("AES-GCM encrypt", &e))?;

    // Wire format: 12-byte nonce || ciphertext+tag
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    Ok(EncryptOutput { ciphertext: out })
}

fn pkcs11_decrypt(
    session: &Session,
    label: &str,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Sensitive<Vec<u8>>> {
    if ciphertext.len() < 12 + 16 {
        return Err(KeyRackError::Provider(
            "ciphertext too short (need nonce + tag)".into(),
        ));
    }

    let obj = find_object(session, label, ObjectClass::SECRET_KEY)?;

    let (nonce_slice, ct) = ciphertext.split_at(12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_slice);

    let gcm_params = GcmParams::new(&mut nonce, aad, 128.into())
        .map_err(|e| KeyRackError::Provider(format!("GCM params: {e}")))?;
    let pt = session
        .decrypt(&Mechanism::AesGcm(gcm_params), obj, ct)
        .map_err(|e| {
            if is_transient_pkcs11_error(&e) {
                KeyRackError::ProviderUnavailable(format!("AES-GCM decrypt: {e}"))
            } else {
                KeyRackError::EncryptionContextMismatch
            }
        })?;

    Ok(Sensitive::new(pt))
}

fn pkcs11_sign(
    session: &Session,
    label: &str,
    algorithm: SigningAlgorithm,
    message: &[u8],
) -> Result<Vec<u8>> {
    let priv_handle = find_object(session, label, ObjectClass::PRIVATE_KEY)?;

    match algorithm {
        SigningAlgorithm::Ed25519 => {
            let params = EddsaParams::new(EddsaSignatureScheme::Ed25519);
            session
                .sign(&Mechanism::Eddsa(params), priv_handle, message)
                .map_err(|e| map_pkcs11_error("Ed25519 sign", &e))
        }

        SigningAlgorithm::RsaPkcs1v15Sha256 => session
            .sign(&Mechanism::Sha256RsaPkcs, priv_handle, message)
            .map_err(|e| map_pkcs11_error("RSA sign", &e)),

        SigningAlgorithm::RsaPssSha256 => {
            let pss_params = PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: 32.into(),
            };
            session
                .sign(
                    &Mechanism::Sha256RsaPkcsPss(pss_params),
                    priv_handle,
                    message,
                )
                .map_err(|e| map_pkcs11_error("RSA-PSS sign", &e))
        }

        SigningAlgorithm::EcdsaP256Sha256 => {
            let hash = sha256_hash(message);
            let raw_sig = session
                .sign(&Mechanism::Ecdsa, priv_handle, &hash)
                .map_err(|e| map_pkcs11_error("ECDSA sign", &e))?;
            ecdsa_der::raw_to_der(&raw_sig, P256_COMPONENT_LEN)
        }

        // TODO(proto-align): wire P-384/SHA-384-512/HMAC into pkcs11.
        other => Err(KeyRackError::Provider(format!(
            "unsupported signing algorithm for pkcs11: {other:?}"
        ))),
    }
}

fn pkcs11_verify(
    session: &Session,
    label: &str,
    algorithm: SigningAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let pub_handle = find_object(session, label, ObjectClass::PUBLIC_KEY)?;

    let result = match algorithm {
        SigningAlgorithm::Ed25519 => {
            let params = EddsaParams::new(EddsaSignatureScheme::Ed25519);
            session.verify(&Mechanism::Eddsa(params), pub_handle, message, signature)
        }

        SigningAlgorithm::RsaPkcs1v15Sha256 => {
            session.verify(&Mechanism::Sha256RsaPkcs, pub_handle, message, signature)
        }

        SigningAlgorithm::RsaPssSha256 => {
            let pss_params = PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: 32.into(),
            };
            session.verify(
                &Mechanism::Sha256RsaPkcsPss(pss_params),
                pub_handle,
                message,
                signature,
            )
        }

        SigningAlgorithm::EcdsaP256Sha256 => {
            let hash = sha256_hash(message);
            let raw_sig = ecdsa_der::der_to_raw(signature, P256_COMPONENT_LEN)?;
            session.verify(&Mechanism::Ecdsa, pub_handle, &hash, &raw_sig)
        }

        // TODO(proto-align): wire P-384/SHA-384-512/HMAC into pkcs11.
        other => {
            return Err(KeyRackError::Provider(format!(
                "unsupported signing algorithm for pkcs11: {other:?}"
            )))
        }
    };

    match result {
        Ok(()) => Ok(true),
        Err(cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::SignatureInvalid
            | cryptoki::error::RvError::SignatureLenRange,
            _,
        )) => Ok(false),
        Err(e) => Err(map_pkcs11_error("verify", &e)),
    }
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    sha256_compute(data)
}

/// Pure-Rust SHA-256 (no external dependency for this single use case).
#[allow(clippy::many_single_char_names)]
fn sha256_compute(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

fn destroy_objects_by_label(session: &Session, label: &str) -> Result<()> {
    let template = vec![Attribute::Label(label.as_bytes().to_vec())];
    let objects = session
        .find_objects(&template)
        .map_err(|e| map_pkcs11_error("find for destroy", &e))?;

    for obj in objects {
        session
            .destroy_object(obj)
            .map_err(|e| map_pkcs11_error("destroy_object", &e))?;
    }
    Ok(())
}

#[async_trait]
impl CryptoProvider for Pkcs11Provider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        let spec_owned = spec.clone();
        let label = uuid::Uuid::new_v4().to_string();
        let label_for_closure = label.clone();
        let spec_for_handle = spec.clone();

        self.run(move |session| {
            match &spec_owned {
                KeySpec::Aes256 => generate_aes_key(session, &label_for_closure)?,
                KeySpec::Ed25519 => generate_ed25519_key_pair(session, &label_for_closure)?,
                KeySpec::EcdsaP256Sha256 => {
                    generate_ec_key_pair(session, &label_for_closure, P256_OID_DER)?;
                }
                KeySpec::RsaPkcs1v15Sha256 { key_size } | KeySpec::RsaPssSha256 { key_size } => {
                    generate_rsa_key_pair(session, &label_for_closure, *key_size)?;
                }
                // TODO(proto-align): wire P-384/SHA-384-512/HMAC into pkcs11.
                other => {
                    return Err(KeyRackError::Provider(format!(
                        "unsupported key spec for pkcs11: {other:?}"
                    )));
                }
            }
            Ok(())
        })
        .await?;

        Ok(KeyHandle {
            key_id: label,
            key_spec: spec_for_handle,
        })
    }

    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        let label = handle.key_id.clone();
        let plaintext = plaintext.to_vec();
        let aad = aad.to_vec();

        self.run(move |session| pkcs11_encrypt(session, &label, &plaintext, &aad))
            .await
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        let label = handle.key_id.clone();
        let ciphertext = ciphertext.to_vec();
        let aad = aad.to_vec();

        self.run(move |session| pkcs11_decrypt(session, &label, &ciphertext, &aad))
            .await
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let label = handle.key_id.clone();
        let message = message.to_vec();

        self.run(move |session| pkcs11_sign(session, &label, algorithm, &message))
            .await
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let label = handle.key_id.clone();
        let message = message.to_vec();
        let signature = signature.to_vec();

        self.run(move |session| pkcs11_verify(session, &label, algorithm, &message, &signature))
            .await
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        #[allow(clippy::cast_possible_truncation)]
        let len = length as u32;
        self.run(move |session| {
            let bytes = session
                .generate_random_vec(len)
                .map_err(|e| map_pkcs11_error("generate_random", &e))?;
            Ok(Sensitive::new(bytes))
        })
        .await
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        let label = handle.key_id.clone();

        self.run(move |session| destroy_objects_by_label(session, &label))
            .await
    }

    fn capabilities(&self) -> ProviderCapabilities {
        use CryptoOperation::{
            Decrypt, DestroyKey, Encrypt, GenerateDataKey, GenerateKey, ReEncrypt, Sign, Verify,
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

        ProviderCapabilities {
            provider_name: "pkcs11".into(),
            key_specs: vec![
                KeySpecCapability {
                    key_spec: KeySpec::Aes256,
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
                    key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
                    operations: signing_ops,
                },
            ],
            supports_generate_random: true,
            supports_atomic_data_key: false,
            supports_atomic_re_encrypt: false,
            supports_key_import: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // If you flip either flag to true you MUST have overridden the
    // corresponding method to keep plaintext in-boundary AND added a
    // test proving it. This guard converts a silent capability lie
    // into a conscious, reviewed change.
    //
    // NOTE: Pkcs11Provider cannot be constructed without a live PKCS#11
    // library, so this test inspects the hardcoded values returned by
    // capabilities() at the source level. When SoftHSM integration
    // tests are available, replace this with a live capabilities() call.
    #[test]
    fn capability_flags_are_honest() {
        let caps = ProviderCapabilities {
            provider_name: "pkcs11".into(),
            key_specs: Vec::new(),
            supports_generate_random: true,
            supports_atomic_data_key: false,
            supports_atomic_re_encrypt: false,
            supports_key_import: false,
        };
        assert!(
            !caps.supports_atomic_data_key,
            "supports_atomic_data_key must be false without a generate_data_key override"
        );
        assert!(
            !caps.supports_atomic_re_encrypt,
            "supports_atomic_re_encrypt must be false without a re_encrypt override"
        );
    }

    #[test]
    fn sha256_known_vector() {
        let hash = sha256_compute(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn sha256_abc() {
        let hash = sha256_compute(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }
}
