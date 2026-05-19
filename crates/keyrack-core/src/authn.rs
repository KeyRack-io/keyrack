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

//! Authentication trait and built-in extractors.
//!
//! Authentication in `KeyRack` is pluggable — the service binary wires
//! one or more [`Authenticator`] implementations as a gRPC interceptor
//! (or tower layer).  Every RPC extracts a [`Principal`] from the
//! request metadata before the PDP check.
//!
//! Built-in authenticators:
//!
//! - **mTLS** — extracts the principal from the client certificate's
//!   SAN (Common Name or SPIFFE SVID URI).  Production default for
//!   service-to-service calls.
//! - **JWT** — validates a bearer token against a JWKS endpoint.
//!   Suitable for external API callers.
//! - **Bootstrap token** — OSS fallback for deployments without a PDP.
//!   Time-bounded, audit-logged with WARN on every use.

use crate::pdp::{AttributeValue, Principal};
use async_trait::async_trait;
use der::Decode;
use jsonwebtoken::jwk::JwkSet;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::Certificate;

/// Metadata carried on an incoming request.
///
/// Transport-agnostic: both gRPC `MetadataMap` and HTTP headers
/// can be projected into this.
#[derive(Debug, Clone, Default)]
pub struct RequestMetadata {
    /// Header / metadata key-value pairs (lowercase keys).
    pub headers: BTreeMap<String, String>,
    /// For mTLS: the peer certificate chain in DER form (leaf first).
    pub peer_certificates: Vec<Vec<u8>>,
}

/// Result of a successful authentication.
#[derive(Debug, Clone)]
pub struct AuthnResult {
    /// The authenticated principal.
    pub principal: Principal,
    /// Which authenticator recognised the credential.
    pub method: String,
}

/// Error returned when authentication fails.
#[derive(Debug, thiserror::Error)]
pub enum AuthnError {
    /// No recognised credential was found in the request.
    #[error("no credential found")]
    NoCredential,
    /// A credential was found but is invalid (expired, bad signature, etc.).
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
    /// Internal error during authentication.
    #[error("internal auth error: {0}")]
    Internal(String),
}

/// Pluggable authentication interface.
///
/// Implementations inspect [`RequestMetadata`] and either return an
/// [`AuthnResult`] with the identified [`Principal`], or an
/// [`AuthnError`].
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Try to authenticate from the given request metadata.
    ///
    /// Return `Ok(Some(result))` if this authenticator recognised and
    /// validated the credential.  Return `Ok(None)` if this
    /// authenticator does not recognise the credential type (allowing
    /// the next authenticator in the chain to try).  Return `Err` if
    /// the credential was recognised but invalid.
    async fn authenticate(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<Option<AuthnResult>, AuthnError>;
}

/// Chains multiple authenticators, trying each in order.
///
/// The first authenticator that returns `Ok(Some(_))` wins.
/// If an authenticator returns `Err`, the chain short-circuits with
/// that error (the credential was recognised but invalid).
/// If all return `Ok(None)`, the chain returns `AuthnError::NoCredential`.
pub struct AuthenticatorChain {
    authenticators: Vec<Box<dyn Authenticator>>,
}

impl AuthenticatorChain {
    pub fn new(authenticators: Vec<Box<dyn Authenticator>>) -> Self {
        Self { authenticators }
    }

    pub async fn authenticate(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<AuthnResult, AuthnError> {
        for authn in &self.authenticators {
            match authn.authenticate(metadata).await {
                Ok(Some(result)) => return Ok(result),
                Ok(None) => {},
                Err(e) => return Err(e),
            }
        }
        Err(AuthnError::NoCredential)
    }
}

/// Bootstrap-token authenticator.
///
/// OSS fallback for non-PDP deployments.  The operator sets
/// `KMS_BOOTSTRAP_TOKEN` in the environment; any request bearing
/// `Authorization: Bearer <token>` that matches is authenticated as
/// a bootstrap-admin principal.
///
/// **Security notes:**
/// - Time-bounded: the service records the startup instant and
///   rejects the token after `max_age` elapses.
/// - Audit-logged with WARN on every successful use.
/// - Must be empty/unset in production PDP-equipped deployments.
pub struct BootstrapTokenAuthenticator {
    token_hash: [u8; 32],
    created_at: std::time::Instant,
    max_age: std::time::Duration,
}

impl BootstrapTokenAuthenticator {
    /// Create from a plaintext token.  The token is immediately hashed;
    /// the plaintext is not retained.
    #[must_use]
    pub fn new(token: &str, max_age: std::time::Duration) -> Self {
        Self {
            token_hash: blake3::hash(token.as_bytes()).into(),
            created_at: std::time::Instant::now(),
            max_age,
        }
    }
}

#[async_trait]
impl Authenticator for BootstrapTokenAuthenticator {
    async fn authenticate(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<Option<AuthnResult>, AuthnError> {
        let Some(auth_header) = metadata.headers.get("authorization") else {
            return Ok(None);
        };

        let Some(token) = auth_header.strip_prefix("Bearer ") else {
            return Ok(None);
        };

        if self.created_at.elapsed() > self.max_age {
            return Err(AuthnError::InvalidCredential(
                "bootstrap token expired".into(),
            ));
        }

        let candidate_hash: [u8; 32] = blake3::hash(token.as_bytes()).into();
        use subtle::ConstantTimeEq;
        if candidate_hash.ct_eq(&self.token_hash).unwrap_u8() != 1 {
            return Err(AuthnError::InvalidCredential(
                "bootstrap token mismatch".into(),
            ));
        }

        tracing::warn!("bootstrap token used — this should be disabled in production");

        Ok(Some(AuthnResult {
            principal: Principal {
                id: "keyrack:bootstrap-admin".into(),
                principal_type: "Admin".into(),
                attributes: BTreeMap::new(),
            },
            method: "bootstrap_token".into(),
        }))
    }
}

/// mTLS authenticator.
///
/// Extracts the principal from the peer certificate's Subject Alternative
/// Name or Subject CN.  Supports both CN-based and SPIFFE SVID URI
/// extraction.
///
/// **Does not** validate the certificate chain or verify signatures —
/// that is the responsibility of the TLS layer (tonic/rustls).  This
/// authenticator only extracts identity information from the
/// already-validated leaf certificate.
pub struct MtlsAuthenticator;

impl MtlsAuthenticator {
    /// Extract the Common Name from the certificate's Subject field.
    fn extract_cn(cert: &Certificate) -> Option<String> {
        use der::oid::db::rfc4519::CN;
        cert.tbs_certificate
            .subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .find(|atav| atav.oid == CN)
            .and_then(|atav| {
                // The CN value is typically a UTF8String or PrintableString.
                // `ToString` on the `Any` value gives us the decoded string.
                let val = &atav.value;
                der::asn1::Utf8StringRef::try_from(val)
                    .map(|s| s.as_str().to_owned())
                    .or_else(|_| {
                        der::asn1::PrintableStringRef::try_from(val)
                            .map(|s| s.as_str().to_owned())
                    })
                    .or_else(|_| {
                        der::asn1::Ia5StringRef::try_from(val)
                            .map(|s| s.as_str().to_owned())
                    })
                    .ok()
            })
    }
}

#[async_trait]
impl Authenticator for MtlsAuthenticator {
    async fn authenticate(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<Option<AuthnResult>, AuthnError> {
        if metadata.peer_certificates.is_empty() {
            return Ok(None);
        }

        let leaf_der = &metadata.peer_certificates[0];
        let cert = Certificate::from_der(leaf_der).map_err(|e| {
            AuthnError::InvalidCredential(format!("failed to parse peer certificate: {e}"))
        })?;

        let mut attributes = BTreeMap::<String, AttributeValue>::new();

        // Extract serial number (hex-encoded).
        let serial = cert
            .tbs_certificate
            .serial_number
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        attributes.insert(
            "serial_number".into(),
            AttributeValue::String(serial),
        );

        // Extract Common Name from Subject.
        let cn = Self::extract_cn(&cert);
        if let Some(ref cn_val) = cn {
            attributes.insert("cn".into(), AttributeValue::String(cn_val.clone()));
        }

        // Scan Subject Alternative Names for SPIFFE URIs and DNS names.
        let mut spiffe_id: Option<String> = None;
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            const SAN_OID: der::oid::ObjectIdentifier =
                der::oid::ObjectIdentifier::new_unwrap("2.5.29.17");
            for ext in extensions.iter() {
                if ext.extn_id != SAN_OID {
                    continue;
                }
                let san =
                    SubjectAltName::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                        AuthnError::InvalidCredential(format!(
                            "failed to parse SubjectAltName extension: {e}"
                        ))
                    })?;
                for name in san.0.iter() {
                    match name {
                        GeneralName::UniformResourceIdentifier(uri) => {
                            let uri_str = uri.as_str();
                            if uri_str.starts_with("spiffe://") {
                                tracing::debug!(spiffe_id = uri_str, "found SPIFFE ID in SAN");
                                attributes.insert(
                                    "spiffe_id".into(),
                                    AttributeValue::String(uri_str.to_owned()),
                                );
                                spiffe_id = Some(uri_str.to_owned());
                            }
                        }
                        GeneralName::DnsName(dns) => {
                            tracing::debug!(dns_san = dns.as_str(), "found DNS SAN (not used as principal)");
                        }
                        _ => {}
                    }
                }
            }
        }

        // SPIFFE ID takes precedence over CN for the principal ID.
        let principal_id = match (&spiffe_id, &cn) {
            (Some(sid), _) => sid.clone(),
            (None, Some(cn_val)) => cn_val.clone(),
            (None, None) => {
                return Err(AuthnError::InvalidCredential(
                    "peer certificate has neither a CN nor a SPIFFE SAN".into(),
                ));
            }
        };

        Ok(Some(AuthnResult {
            principal: Principal {
                id: principal_id,
                principal_type: "Service".into(),
                attributes,
            },
            method: "mtls".into(),
        }))
    }
}

/// Insecure authenticator that accepts all requests as anonymous.
///
/// **Dev/test only.** Returns a fixed anonymous principal for every
/// request without checking any credential.
pub struct InsecureAuthenticator;

#[async_trait]
impl Authenticator for InsecureAuthenticator {
    async fn authenticate(
        &self,
        _metadata: &RequestMetadata,
    ) -> Result<Option<AuthnResult>, AuthnError> {
        Ok(Some(AuthnResult {
            principal: Principal {
                id: "keyrack:anonymous".into(),
                principal_type: "Service".into(),
                attributes: BTreeMap::new(),
            },
            method: "insecure".into(),
        }))
    }
}

/// Forwarded identity authenticator for trusted service-to-service calls.
///
/// Extracts pre-authenticated principal identity from headers set by a
/// trusted upstream service (e.g. a Barbican shim or API gateway).
///
/// **Security:** This authenticator trusts the headers unconditionally.
/// It MUST only be used behind verified mTLS from known trusted services.
/// Typically deployed as the second authenticator in a chain after mTLS.
///
/// Headers:
/// - `x-keyrack-principal-id` (required): Principal identifier
/// - `x-keyrack-project-id` (optional): Project/tenant scope
/// - `x-keyrack-domain-id` (optional): Domain/organization scope
pub struct ForwardedIdentityAuthenticator;

#[async_trait]
impl Authenticator for ForwardedIdentityAuthenticator {
    async fn authenticate(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<Option<AuthnResult>, AuthnError> {
        let principal_id = match metadata.headers.get("x-keyrack-principal-id") {
            Some(id) if !id.is_empty() => id.clone(),
            Some(_) => {
                return Err(AuthnError::InvalidCredential(
                    "x-keyrack-principal-id header is empty".into(),
                ));
            }
            None => return Ok(None),
        };

        let mut attributes = BTreeMap::new();
        if let Some(project_id) = metadata.headers.get("x-keyrack-project-id") {
            attributes.insert(
                "project_id".into(),
                AttributeValue::String(project_id.clone()),
            );
        }
        if let Some(domain_id) = metadata.headers.get("x-keyrack-domain-id") {
            attributes.insert(
                "domain_id".into(),
                AttributeValue::String(domain_id.clone()),
            );
        }

        Ok(Some(AuthnResult {
            principal: Principal {
                id: principal_id,
                principal_type: "ForwardedIdentity".into(),
                attributes,
            },
            method: "forwarded_identity".into(),
        }))
    }
}

/// JWT bearer token authenticator.
///
/// Validates `Authorization: Bearer <jwt>` against a JWKS endpoint.
/// On construction, fetches the JWKS key set and caches it.  If a
/// token's `kid` is not found in the cache, the JWKS is refreshed once
/// before returning an error.
///
/// Supported algorithms: RS256, RS384, RS512, ES256, ES384, EdDSA.
pub struct JwtAuthenticator {
    jwks_url: String,
    jwks: Arc<RwLock<JwkSet>>,
    required_issuer: Option<String>,
    http: reqwest::Client,
    /// Optional namespace prefix for custom claims to extract.
    claims_namespace: Option<String>,
}

impl JwtAuthenticator {
    /// Create a new JWT authenticator by fetching the JWKS from `jwks_url`.
    ///
    /// - `issuer`: if `Some`, the `iss` claim in every token must match.
    pub async fn new(jwks_url: &str, issuer: Option<&str>) -> Result<Self, AuthnError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AuthnError::Internal(format!("failed to build HTTP client: {e}")))?;

        let jwks = Self::fetch_jwks_with(&http, jwks_url).await?;

        Ok(Self {
            jwks_url: jwks_url.to_owned(),
            jwks: Arc::new(RwLock::new(jwks)),
            required_issuer: issuer.map(ToOwned::to_owned),
            http,
            claims_namespace: None,
        })
    }

    /// Create a `JwtAuthenticator` from a pre-loaded `JwkSet`.
    ///
    /// Useful for tests and environments where the JWKS is loaded from a
    /// local file or embedded in configuration.
    pub fn from_jwks(
        jwks: JwkSet,
        jwks_url: &str,
        issuer: Option<&str>,
    ) -> Self {
        Self {
            jwks_url: jwks_url.to_owned(),
            jwks: Arc::new(RwLock::new(jwks)),
            required_issuer: issuer.map(ToOwned::to_owned),
            http: reqwest::Client::new(),
            claims_namespace: None,
        }
    }

    /// Set a namespace prefix for custom claims to extract into principal
    /// attributes (e.g. `"https://myapp.example.com/"`).
    pub fn with_claims_namespace(mut self, ns: impl Into<String>) -> Self {
        self.claims_namespace = Some(ns.into());
        self
    }

    /// Manually refresh the cached JWKS by re-fetching from the endpoint.
    pub async fn refresh_jwks(&self) -> Result<(), AuthnError> {
        let new_jwks = Self::fetch_jwks_with(&self.http, &self.jwks_url).await?;
        let mut cache = self.jwks.write().await;
        *cache = new_jwks;
        Ok(())
    }

    async fn fetch_jwks_with(http: &reqwest::Client, url: &str) -> Result<JwkSet, AuthnError> {
        let resp = http
            .get(url)
            .send()
            .await
            .map_err(|e| AuthnError::Internal(format!("JWKS fetch failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(AuthnError::Internal(format!(
                "JWKS endpoint returned HTTP {}",
                resp.status()
            )));
        }

        resp.json::<JwkSet>()
            .await
            .map_err(|e| AuthnError::Internal(format!("JWKS parse failed: {e}")))
    }

    fn algorithm_from_jwk(
        alg: &jsonwebtoken::jwk::AlgorithmParameters,
    ) -> Result<jsonwebtoken::Algorithm, AuthnError> {
        use jsonwebtoken::jwk::AlgorithmParameters;
        use jsonwebtoken::Algorithm;
        match alg {
            AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
            AlgorithmParameters::EllipticCurve(ec) => {
                use jsonwebtoken::jwk::EllipticCurve;
                match ec.curve {
                    EllipticCurve::P256 => Ok(Algorithm::ES256),
                    EllipticCurve::P384 => Ok(Algorithm::ES384),
                    _ => Err(AuthnError::InvalidCredential(format!(
                        "unsupported EC curve: {:?}",
                        ec.curve
                    ))),
                }
            }
            AlgorithmParameters::OctetKeyPair(_) => Ok(Algorithm::EdDSA),
            _ => Err(AuthnError::InvalidCredential(
                "unsupported JWK algorithm type".into(),
            )),
        }
    }

    /// Resolve algorithm: prefer the `alg` declared in the JWT header, fall
    /// back to inferring from the JWK key type.
    fn resolve_algorithm(
        header: &jsonwebtoken::Header,
        jwk: &jsonwebtoken::jwk::Jwk,
    ) -> Result<jsonwebtoken::Algorithm, AuthnError> {
        if let Some(key_alg) = &jwk.common.key_algorithm {
            use jsonwebtoken::jwk::KeyAlgorithm;
            let alg = match key_alg {
                KeyAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
                KeyAlgorithm::RS384 => jsonwebtoken::Algorithm::RS384,
                KeyAlgorithm::RS512 => jsonwebtoken::Algorithm::RS512,
                KeyAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
                KeyAlgorithm::ES384 => jsonwebtoken::Algorithm::ES384,
                KeyAlgorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
                other => {
                    return Err(AuthnError::InvalidCredential(format!(
                        "unsupported key algorithm: {other:?}"
                    )));
                }
            };
            return Ok(alg);
        }

        if header.alg != jsonwebtoken::Algorithm::default() {
            return Ok(header.alg);
        }

        Self::algorithm_from_jwk(&jwk.algorithm)
    }

    fn validate_and_decode(
        token: &str,
        jwk: &jsonwebtoken::jwk::Jwk,
        required_issuer: Option<&str>,
    ) -> Result<jsonwebtoken::TokenData<serde_json::Value>, AuthnError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AuthnError::InvalidCredential(format!("malformed JWT header: {e}")))?;

        let algorithm = Self::resolve_algorithm(&header, jwk)?;

        let decoding_key =
            jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|e| {
                AuthnError::InvalidCredential(format!("cannot build decoding key from JWK: {e}"))
            })?;

        let mut validation = jsonwebtoken::Validation::new(algorithm);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // We don't require `aud` by default — callers can layer that on.
        validation.validate_aud = false;

        if let Some(iss) = required_issuer {
            validation.set_issuer(&[iss]);
        }

        jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation).map_err(
            |e| AuthnError::InvalidCredential(format!("JWT validation failed: {e}")),
        )
    }

    fn extract_attributes(
        claims: &serde_json::Value,
        namespace: Option<&str>,
    ) -> BTreeMap<String, AttributeValue> {
        let mut attrs = BTreeMap::new();
        let obj = match claims.as_object() {
            Some(o) => o,
            None => return attrs,
        };

        if let Some(serde_json::Value::String(iss)) = obj.get("iss") {
            attrs.insert("iss".into(), AttributeValue::String(iss.clone()));
        }

        match obj.get("aud") {
            Some(serde_json::Value::String(aud)) => {
                attrs.insert("aud".into(), AttributeValue::String(aud.clone()));
            }
            Some(serde_json::Value::Array(arr)) => {
                let list: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect();
                if !list.is_empty() {
                    attrs.insert("aud".into(), AttributeValue::StringList(list));
                }
            }
            _ => {}
        }

        if let Some(serde_json::Value::String(email)) = obj.get("email") {
            attrs.insert("email".into(), AttributeValue::String(email.clone()));
        }

        if let Some(ns) = namespace {
            for (key, value) in obj {
                if let Some(suffix) = key.strip_prefix(ns) {
                    if !suffix.is_empty() {
                        if let Some(s) = value.as_str() {
                            attrs.insert(suffix.to_owned(), AttributeValue::String(s.to_owned()));
                        } else if let Some(b) = value.as_bool() {
                            attrs.insert(suffix.to_owned(), AttributeValue::Bool(b));
                        } else if let Some(n) = value.as_i64() {
                            attrs.insert(suffix.to_owned(), AttributeValue::Integer(n));
                        }
                    }
                }
            }
        }

        attrs
    }
}

#[async_trait]
impl Authenticator for JwtAuthenticator {
    async fn authenticate(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<Option<AuthnResult>, AuthnError> {
        let Some(auth_header) = metadata.headers.get("authorization") else {
            return Ok(None);
        };

        let Some(token) = auth_header.strip_prefix("Bearer ") else {
            return Ok(None);
        };

        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AuthnError::InvalidCredential(format!("malformed JWT header: {e}")))?;

        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AuthnError::InvalidCredential("JWT header missing `kid`".into()))?;

        // Try to find the key in the current cache, refresh once on miss.
        let token_data = {
            let jwks = self.jwks.read().await;
            let maybe_jwk = jwks.find(kid);
            match maybe_jwk {
                Some(jwk) => {
                    Self::validate_and_decode(token, jwk, self.required_issuer.as_deref())?
                }
                None => {
                    drop(jwks);
                    tracing::debug!(kid, "kid not found in JWKS cache, refreshing");
                    self.refresh_jwks().await?;
                    let jwks = self.jwks.read().await;
                    let jwk = jwks.find(kid).ok_or_else(|| {
                        AuthnError::InvalidCredential(format!(
                            "no JWK found for kid `{kid}` after refresh"
                        ))
                    })?;
                    Self::validate_and_decode(token, jwk, self.required_issuer.as_deref())?
                }
            }
        };

        let sub = token_data
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AuthnError::InvalidCredential("JWT missing `sub` claim".into())
            })?
            .to_owned();

        let attributes =
            Self::extract_attributes(&token_data.claims, self.claims_namespace.as_deref());

        Ok(Some(AuthnResult {
            principal: Principal {
                id: sub,
                principal_type: "jwt".into(),
                attributes,
            },
            method: "jwt".into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bootstrap_token_valid() {
        let authn = BootstrapTokenAuthenticator::new(
            "test-secret-123",
            std::time::Duration::from_secs(3600),
        );
        let mut metadata = RequestMetadata::default();
        metadata
            .headers
            .insert("authorization".into(), "Bearer test-secret-123".into());

        let result = authn.authenticate(&metadata).await.unwrap().unwrap();
        assert_eq!(result.principal.id, "keyrack:bootstrap-admin");
        assert_eq!(result.method, "bootstrap_token");
    }

    #[tokio::test]
    async fn bootstrap_token_mismatch() {
        let authn = BootstrapTokenAuthenticator::new(
            "correct-token",
            std::time::Duration::from_secs(3600),
        );
        let mut metadata = RequestMetadata::default();
        metadata
            .headers
            .insert("authorization".into(), "Bearer wrong-token".into());

        let result = authn.authenticate(&metadata).await;
        assert!(matches!(result, Err(AuthnError::InvalidCredential(_))));
    }

    #[tokio::test]
    async fn bootstrap_token_no_header_skips() {
        let authn = BootstrapTokenAuthenticator::new(
            "token",
            std::time::Duration::from_secs(3600),
        );
        let metadata = RequestMetadata::default();
        let result = authn.authenticate(&metadata).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn bootstrap_token_expired() {
        let authn = BootstrapTokenAuthenticator::new(
            "token",
            std::time::Duration::from_secs(0),
        );
        // Sleep a tiny bit to ensure it's expired
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let mut metadata = RequestMetadata::default();
        metadata
            .headers
            .insert("authorization".into(), "Bearer token".into());

        let result = authn.authenticate(&metadata).await;
        assert!(matches!(result, Err(AuthnError::InvalidCredential(_))));
    }

    #[tokio::test]
    async fn chain_tries_in_order() {
        let chain = AuthenticatorChain::new(vec![
            Box::new(MtlsAuthenticator),
            Box::new(BootstrapTokenAuthenticator::new(
                "my-token",
                std::time::Duration::from_secs(3600),
            )),
        ]);

        let mut metadata = RequestMetadata::default();
        metadata
            .headers
            .insert("authorization".into(), "Bearer my-token".into());

        let result = chain.authenticate(&metadata).await.unwrap();
        assert_eq!(result.method, "bootstrap_token");
    }

    #[tokio::test]
    async fn chain_no_credential() {
        let chain = AuthenticatorChain::new(vec![Box::new(MtlsAuthenticator)]);
        let metadata = RequestMetadata::default();
        let result = chain.authenticate(&metadata).await;
        assert!(matches!(result, Err(AuthnError::NoCredential)));
    }

    #[tokio::test]
    async fn mtls_no_cert_skips() {
        let authn = MtlsAuthenticator;
        let metadata = RequestMetadata::default();
        let result = authn.authenticate(&metadata).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn jwt_no_bearer_skips() {
        let empty_jwks = jsonwebtoken::jwk::JwkSet { keys: vec![] };
        let authn = JwtAuthenticator::from_jwks(
            empty_jwks,
            "https://example.com/.well-known/jwks.json",
            None,
        );
        let metadata = RequestMetadata::default();
        let result = authn.authenticate(&metadata).await.unwrap();
        assert!(result.is_none());
    }
}
