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

//! KMIP `CryptoProvider` implementation.
//!
//! Delegates all cryptographic operations to a remote KMIP 2.1 server
//! over TLS using TTLV wire encoding. Connections are established
//! lazily and held behind a lock for serialized access; connection
//! pooling is a future enhancement.
//!
//! # Additional authenticated data is not supported
//!
//! KMIP 2.1 does define the transport for AAD: `Authenticated Encryption
//! Additional Data` (tag `0x4200FE`) is an optional field of both the Encrypt
//! and the Decrypt request payload, paired with `Authenticated Encryption Tag`
//! (`0x4200FF`), which the server returns on Encrypt and which the client must
//! replay on Decrypt (OASIS KMIP 2.1 §6.1.16, §6.1.17, §7.3, §7.4).
//!
//! This client implements neither half of that exchange. It sends no AAD field,
//! and it neither captures the Authenticated Encryption Tag from an Encrypt
//! response nor returns it on Decrypt — so even if the AAD were transmitted,
//! there would be no tag through which the binding could be verified, and
//! whether a given server honours the field at all is a per-server capability
//! this client never probes.
//!
//! Consequently [`KmipProvider::encrypt`] and [`KmipProvider::decrypt`] **reject
//! a non-empty `aad`** rather than dropping it. A caller that supplies an
//! encryption context is asserting a binding that this provider cannot deliver;
//! failing tells them so, whereas succeeding would not. An empty `aad` asserts
//! no binding and is still accepted.

use crate::connection::KmipConnection;
use crate::messages;
use crate::ttlv::{self, tag};
use async_trait::async_trait;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{
    CryptoOperation, CryptoProvider, EncryptOutput, KeyHandle, KeySpecCapability,
    ProviderCapabilities, SigningAlgorithm,
};
use keyrack_core::sensitive::Sensitive;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Configuration for a KMIP connection.
///
/// Deliberately does **not** derive `Debug`: it holds `password` in plain
/// text, and a derived `Debug` puts that password into any log line or error
/// that formats the config. `Pkcs11ProviderConfig` omits `Debug` for the same
/// reason.
#[derive(Clone, Serialize, Deserialize)]
pub struct KmipProviderConfig {
    /// KMIP server endpoint (e.g. `kmip://hsm.example.com:5696`).
    pub endpoint: String,

    /// Path to the client TLS certificate (PEM).
    pub client_cert_path: Option<String>,

    /// Path to the client TLS private key (PEM).
    pub client_key_path: Option<String>,

    /// Path to the CA certificate bundle (PEM) for server verification.
    pub ca_cert_path: Option<String>,

    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// KMIP username for credential-based authentication (optional,
    /// most deployments use mutual TLS).
    pub username: Option<String>,

    /// KMIP password (optional).
    pub password: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

/// Version byte prefixing the ciphertext blob this provider returns.
const BLOB_VERSION: u8 = 1;

/// Ciphertext blob layout:
///
/// ```text
/// version(1) | nonce_len(1) | nonce | tag_len(1) | tag | ciphertext
/// ```
///
/// The nonce and tag lengths are written down rather than assumed, because
/// the server chooses them. GCM's recommended nonce is 12 bytes, but the
/// specification permits others and servers do use them — the implementation
/// this provider was first proven against returns 16. Hard-coding 12 makes
/// every encryption fail against such a server, and hard-coding 16 would
/// merely move the failure.
fn frame_blob(nonce: &[u8], tag: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() > u8::MAX as usize || tag.len() > u8::MAX as usize {
        return Err(KeyRackError::Provider(format!(
            "KMIP Encrypt: nonce ({} bytes) or tag ({} bytes) too long to frame",
            nonce.len(),
            tag.len()
        )));
    }
    let mut out = Vec::with_capacity(3 + nonce.len() + tag.len() + ciphertext.len());
    out.push(BLOB_VERSION);
    out.push(nonce.len() as u8);
    out.extend_from_slice(nonce);
    out.push(tag.len() as u8);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Split a blob written by [`frame_blob`] into nonce, tag and ciphertext.
fn unframe_blob(blob: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let malformed = |detail: &str| {
        KeyRackError::Provider(format!(
            "KMIP Decrypt: ciphertext is not a blob this provider produced: {detail}"
        ))
    };

    let (&version, rest) = blob.split_first().ok_or_else(|| malformed("it is empty"))?;
    if version != BLOB_VERSION {
        return Err(malformed(&format!(
            "unknown framing version {version} (this build writes {BLOB_VERSION})"
        )));
    }

    let (&nonce_len, rest) = rest
        .split_first()
        .ok_or_else(|| malformed("no nonce length"))?;
    if rest.len() < nonce_len as usize {
        return Err(malformed("nonce is shorter than its stated length"));
    }
    let (nonce, rest) = rest.split_at(nonce_len as usize);

    let (&tag_len, rest) = rest
        .split_first()
        .ok_or_else(|| malformed("no tag length"))?;
    if rest.len() < tag_len as usize {
        return Err(malformed("tag is shorter than its stated length"));
    }
    let (tag, ciphertext) = rest.split_at(tag_len as usize);

    if tag.is_empty() {
        return Err(malformed(
            "no authentication tag, so nothing binds the ciphertext",
        ));
    }

    Ok((nonce, tag, ciphertext))
}

/// KMIP cryptographic provider.
///
/// All operations delegate to the remote KMIP server via the TTLV
/// wire protocol over TLS. The connection is established lazily on
/// first use.
pub struct KmipProvider {
    config: KmipProviderConfig,
    connection: Mutex<Option<KmipConnection>>,
}

impl KmipProvider {
    /// Create a new KMIP provider from configuration.
    ///
    /// Does not establish a connection until the first operation.
    pub fn new(config: KmipProviderConfig) -> Self {
        tracing::info!(
            endpoint = %config.endpoint,
            "KMIP provider configured"
        );
        Self {
            config,
            connection: Mutex::new(None),
        }
    }

    /// Return the configured endpoint.
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    async fn get_connection(&self) -> Result<tokio::sync::MutexGuard<'_, Option<KmipConnection>>> {
        let mut guard = self.connection.lock().await;
        if guard.is_none() {
            let conn = KmipConnection::connect(&self.config).await?;
            *guard = Some(conn);
        }
        Ok(guard)
    }

    async fn send_request(&self, request: &ttlv::TtlvItem) -> Result<messages::KmipResponse> {
        let mut guard = self.get_connection().await?;
        let conn = guard.as_mut().unwrap();

        let response_item = if let Ok(item) = conn.round_trip(request).await {
            item
        } else {
            // Connection may be stale; reconnect once.
            tracing::debug!(endpoint = %self.config.endpoint, "reconnecting after error");
            let new_conn = KmipConnection::connect(&self.config).await?;
            *conn = new_conn;
            conn.round_trip(request).await?
        };

        messages::parse_response(&response_item)
            .map_err(|e| KeyRackError::Provider(format!("KMIP response parse error: {e}")))
    }

    fn check_response(resp: &messages::KmipResponse) -> Result<()> {
        if resp.result_status != ttlv::result_status::SUCCESS {
            let msg = resp.result_message.as_deref().unwrap_or("unknown error");
            return Err(KeyRackError::Provider(format!(
                "KMIP operation failed (status=0x{:02X}): {msg}",
                resp.result_status
            )));
        }
        Ok(())
    }

    fn key_spec_to_kmip(spec: &KeySpec) -> Result<(u32, i32, bool)> {
        Ok(match spec {
            KeySpec::Aes256 => (ttlv::crypto_algorithm::AES, 256, true),
            KeySpec::Ed25519 => (ttlv::crypto_algorithm::ED25519, 256, false),
            KeySpec::EcdsaP256Sha256 => (ttlv::crypto_algorithm::ECDSA, 256, false),
            KeySpec::RsaPkcs1v15Sha256 { key_size } | KeySpec::RsaPssSha256 { key_size } => {
                (ttlv::crypto_algorithm::RSA, *key_size as i32, false)
            }
            // TODO(proto-align): wire P-384/SHA-384-512/HMAC into kmip.
            other => {
                return Err(KeyRackError::Provider(format!(
                    "unsupported key spec for kmip: {other:?}"
                )))
            }
        })
    }
}

#[async_trait]
impl CryptoProvider for KmipProvider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        let (algorithm, key_length, is_symmetric) = Self::key_spec_to_kmip(spec)?;

        let request = if is_symmetric {
            messages::create_symmetric_key(algorithm, key_length)
        } else {
            messages::create_asymmetric_key(algorithm, key_length)
        };

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let unique_id = resp
            .payload
            .as_ref()
            .and_then(|p| p.find(tag::UNIQUE_ID))
            .and_then(|i| i.as_text())
            .ok_or_else(|| {
                KeyRackError::Provider("KMIP Create: no UniqueIdentifier in response".into())
            })?;

        let unique_id = unique_id.to_string();

        // A created object is Pre-Active, and KMIP forbids cryptographic use
        // of a Pre-Active object. Returning the handle here without
        // activating would hand back a key that exists and refuses every
        // operation, with the failure surfacing later and elsewhere.
        let activate = self
            .send_request(&messages::activate_request(&unique_id))
            .await?;
        Self::check_response(&activate).map_err(|e| {
            KeyRackError::Provider(format!(
                "KMIP Create succeeded but Activate failed for key {unique_id}, \
                 leaving an unusable Pre-Active object on the server: {e}"
            ))
        })?;

        tracing::info!(
            key_id = %unique_id,
            spec = ?spec,
            endpoint = %self.config.endpoint,
            "KMIP key created and activated"
        );

        Ok(KeyHandle {
            key_id: unique_id,
            key_spec: spec.clone(),
        })
    }

    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        let request = messages::encrypt_request(&handle.key_id, plaintext, None, aad);

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let payload = resp
            .payload
            .as_ref()
            .ok_or_else(|| KeyRackError::Provider("KMIP Encrypt: no payload in response".into()))?;

        let ciphertext = payload
            .find(tag::DATA)
            .and_then(|i| i.as_bytes())
            .ok_or_else(|| KeyRackError::Provider("KMIP Encrypt: no Data in response".into()))?
            .to_vec();

        // The server chooses the nonce and returns it; its length is recorded
        // in the blob rather than assumed.
        let iv = payload
            .find(tag::IV_COUNTER_NONCE)
            .and_then(|i| i.as_bytes())
            .unwrap_or_default();
        if iv.is_empty() {
            return Err(KeyRackError::Provider(
                "KMIP Encrypt: no IVCounterNonce in response; the ciphertext could not be \
                 decrypted without the nonce it was produced under"
                    .into(),
            ));
        }

        // Without the tag the mode is not authenticated. Refusing here rather
        // than storing an unauthenticated blob keeps the failure at the point
        // the guarantee is lost, instead of at some later decrypt.
        let tag_bytes = payload
            .find(tag::AUTHENTICATED_ENCRYPTION_TAG)
            .and_then(|i| i.as_bytes())
            .ok_or_else(|| {
                KeyRackError::Provider(
                    "KMIP Encrypt: no AuthenticatedEncryptionTag in response. AES-GCM without \
                     its tag is unauthenticated and cannot be decrypted; refusing rather than \
                     returning a ciphertext that only looks protected"
                        .into(),
                )
            })?;
        Ok(EncryptOutput {
            ciphertext: frame_blob(iv, tag_bytes, &ciphertext)?,
        })
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        // A blob that does not parse cannot have come from this provider, so
        // it is refused rather than sent to the server with a missing tag as
        // though the tag were merely absent.
        let (iv, auth_tag, ct) = unframe_blob(ciphertext)?;

        let request = messages::decrypt_request(&handle.key_id, ct, Some(iv), Some(auth_tag), aad);

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let data = resp
            .payload
            .as_ref()
            .and_then(|p| p.find(tag::DATA))
            .and_then(|i| i.as_bytes())
            .ok_or_else(|| KeyRackError::Provider("KMIP Decrypt: no Data in response".into()))?
            .to_vec();

        Ok(Sensitive::new(data))
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        _algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let request = messages::sign_request(&handle.key_id, message, None);

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let signature = resp
            .payload
            .as_ref()
            .and_then(|p| p.find(tag::SIGNATURE_DATA))
            .and_then(|i| i.as_bytes())
            .ok_or_else(|| {
                KeyRackError::Provider("KMIP Sign: no SignatureData in response".into())
            })?
            .to_vec();

        Ok(signature)
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        _algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let request = messages::verify_request(&handle.key_id, message, signature, None);

        let resp = self.send_request(&request).await?;

        // KMIP returns Success if the signature is valid, or
        // OperationFailed with a specific reason if invalid.
        Ok(resp.result_status == ttlv::result_status::SUCCESS)
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        let request = messages::rng_retrieve_request(length as i32);

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        let data = resp
            .payload
            .as_ref()
            .and_then(|p| p.find(tag::DATA))
            .and_then(|i| i.as_bytes())
            .ok_or_else(|| KeyRackError::Provider("KMIP RNGRetrieve: no Data in response".into()))?
            .to_vec();

        Ok(Sensitive::new(data))
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        // KMIP forbids destroying an Active object, and `generate_key`
        // activates every key it creates, so Destroy on its own always fails.
        // A revoke failure is not fatal: the key may already be deactivated,
        // or predate activation, and Destroy is the operation whose result
        // actually decides whether the key is gone.
        let revoked = match self
            .send_request(&messages::revoke_request(&handle.key_id))
            .await
        {
            Ok(resp) => Self::check_response(&resp),
            Err(e) => Err(e),
        };
        if let Err(e) = revoked {
            tracing::debug!(
                key_id = %handle.key_id,
                error = %e,
                "KMIP Revoke before Destroy did not succeed; attempting Destroy anyway"
            );
        }

        let request = messages::destroy_request(&handle.key_id);

        let resp = self.send_request(&request).await?;
        Self::check_response(&resp)?;

        tracing::info!(
            key_id = %handle.key_id,
            endpoint = %self.config.endpoint,
            "KMIP key destroyed"
        );

        Ok(())
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
            provider_name: "kmip".into(),
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

    fn test_config() -> KmipProviderConfig {
        KmipProviderConfig {
            endpoint: "kmip://localhost:5696".into(),
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
            timeout_secs: 10,
            username: None,
            password: None,
        }
    }

    #[test]
    fn config_serialization() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: KmipProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.endpoint, "kmip://localhost:5696");
        assert_eq!(parsed.timeout_secs, 10);
    }

    #[test]
    fn provider_endpoint() {
        let provider = KmipProvider::new(test_config());
        assert_eq!(provider.endpoint(), "kmip://localhost:5696");
    }

    #[test]
    fn capabilities_report_kmip() {
        let provider = KmipProvider::new(test_config());
        let caps = provider.capabilities();
        assert_eq!(caps.provider_name, "kmip");
        assert!(caps.supports_generate_random);
        assert_eq!(caps.key_specs.len(), 4);
    }

    // If you flip either flag to true you MUST have overridden the
    // corresponding method to keep plaintext in-boundary AND added a
    // test proving it. This guard converts a silent capability lie
    // into a conscious, reviewed change.
    #[test]
    fn capability_flags_are_honest() {
        let provider = KmipProvider::new(test_config());
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

    fn test_handle() -> KeyHandle {
        KeyHandle {
            key_id: "kmip-key-1".into(),
            key_spec: KeySpec::Aes256,
        }
    }

    // ── ciphertext framing ──────────────────────────────────────────
    //
    // These run in-process and need no KMIP server. `test_config` points at a
    // port nothing is listening on, so an error naming the framing problem
    // rather than a connection failure proves the blob was rejected before it
    // reached the wire.
    //
    // AAD binding itself cannot be proved here: whether the server actually
    // covers the additional data with the authentication tag is a property of
    // the server, so it is asserted against a live third-party server in
    // `tests/neutral_server.rs`.

    #[test]
    fn framing_round_trips_whatever_lengths_the_server_chose() {
        // 16 rather than 12: the server picks the nonce length, and the
        // implementation this was proven against picks 16.
        for nonce_len in [12usize, 16] {
            let nonce = vec![0xA5; nonce_len];
            let tag = vec![0x5A; 16];
            let ct = b"ciphertext bytes".to_vec();

            let blob = frame_blob(&nonce, &tag, &ct).unwrap();
            let (got_nonce, got_tag, got_ct) = unframe_blob(&blob).unwrap();

            assert_eq!(got_nonce, &nonce[..], "nonce of {nonce_len} bytes");
            assert_eq!(got_tag, &tag[..]);
            assert_eq!(got_ct, &ct[..]);
        }
    }

    #[tokio::test]
    async fn decrypt_rejects_a_blob_it_cannot_parse() {
        let provider = KmipProvider::new(test_config());
        // Claims a 200-byte nonce it does not carry.
        let err = provider
            .decrypt(&test_handle(), &[BLOB_VERSION, 200, 0, 0], b"")
            .await
            .expect_err("an unparseable blob must be refused");

        let msg = err.to_string();
        assert!(
            msg.contains("not a blob this provider produced"),
            "the error must name the framing problem rather than surface as a \
             connection failure, which is what proves nothing was sent: {msg}"
        );
    }

    #[tokio::test]
    async fn decrypt_refuses_a_blob_with_no_authentication_tag() {
        let provider = KmipProvider::new(test_config());
        // Well-formed framing with a zero-length tag: parseable, and
        // unauthenticated. Sending it on would ask the server to decrypt
        // something nothing binds.
        let blob = [BLOB_VERSION, 1, 0xAA, 0, b'c', b't'];
        let err = provider
            .decrypt(&test_handle(), &blob, b"")
            .await
            .expect_err("a blob with an empty tag must be refused");

        assert!(
            err.to_string().contains("nothing binds the ciphertext"),
            "got: {err}"
        );
    }

    // `re_encrypt` and `generate_data_key` use the trait's default
    // implementations, which compose `encrypt`/`decrypt`, so they inherit
    // whatever those two enforce. `re_encrypt` decrypts first, which makes the
    // framing check reachable without a server.
    #[tokio::test]
    async fn re_encrypt_inherits_the_framing_check() {
        let provider = KmipProvider::new(test_config());
        let err = provider
            .re_encrypt(
                &test_handle(),
                b"ciphertext",
                b"tenant=acme",
                &test_handle(),
                b"tenant=acme",
            )
            .await
            .expect_err("re_encrypt must not accept a blob its decrypt would reject");

        assert!(
            err.to_string()
                .contains("not a blob this provider produced"),
            "expected the framing refusal to propagate, got: {err}"
        );
    }

    #[test]
    fn key_spec_mapping() {
        let (alg, len, sym) = KmipProvider::key_spec_to_kmip(&KeySpec::Aes256).unwrap();
        assert_eq!(alg, crate::ttlv::crypto_algorithm::AES);
        assert_eq!(len, 256);
        assert!(sym);

        let (alg, len, sym) = KmipProvider::key_spec_to_kmip(&KeySpec::Ed25519).unwrap();
        assert_eq!(alg, crate::ttlv::crypto_algorithm::ED25519);
        assert_eq!(len, 256);
        assert!(!sym);

        let (alg, len, sym) =
            KmipProvider::key_spec_to_kmip(&KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 }).unwrap();
        assert_eq!(alg, crate::ttlv::crypto_algorithm::RSA);
        assert_eq!(len, 4096);
        assert!(!sym);
    }
}
