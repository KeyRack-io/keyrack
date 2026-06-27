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
use base64::Engine as _;
use der::{Decode, Encode};
use jsonwebtoken::jwk::JwkSet;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::Certificate;

fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(input)
}

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
                Ok(None) => {}
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
    pub(crate) fn extract_cn(cert: &Certificate) -> Option<String> {
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
                        der::asn1::PrintableStringRef::try_from(val).map(|s| s.as_str().to_owned())
                    })
                    .or_else(|_| {
                        der::asn1::Ia5StringRef::try_from(val).map(|s| s.as_str().to_owned())
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
        let serial = cert.tbs_certificate.serial_number.as_bytes().iter().fold(
            String::new(),
            |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            },
        );
        attributes.insert("serial_number".into(), AttributeValue::String(serial));

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
            for ext in extensions {
                if ext.extn_id != SAN_OID {
                    continue;
                }
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    AuthnError::InvalidCredential(format!(
                        "failed to parse SubjectAltName extension: {e}"
                    ))
                })?;
                for name in &san.0 {
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
                            tracing::debug!(
                                dns_san = dns.as_str(),
                                "found DNS SAN (not used as principal)"
                            );
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

/// Trusted mTLS peer authenticator for platform-internal fast-path.
///
/// Authenticates a peer whose client certificate was issued by a specific
/// trusted CA (identified by Subject DN match against the configured CA cert).
/// On match, derives a platform-scoped principal (`scope=platform`) from the
/// certificate, allowing the caller to skip JWT verification on internal
/// hot paths.
///
/// **This is authn-METHOD SUBSTITUTION, not skip-authn.** The peer IS
/// authenticated (via its verified mTLS certificate); only the JWT
/// revalidation step is avoided.
///
/// **Security properties:**
/// - The TLS layer already verified the certificate chain (signature,
///   expiry, revocation). This authenticator performs an additional
///   application-level trust check: the leaf cert must have been issued
///   by the specifically configured trusted CA.
/// - Returns `Ok(None)` (not an error) if the peer cert is absent or
///   not from the trusted CA, allowing downstream authenticators (JWT)
///   to handle it — preserving fail-closed for untrusted peers.
/// - The derived `scope=platform` integrates with `scope_owner`
///   enforcement: a platform-scoped peer satisfies platform connections
///   but NOT tenant-scoped connections.
///
/// **OPT-IN:** this authenticator is only instantiated when explicitly
/// configured (`authn.type = trusted_mtls_peer`); existing deployments
/// are unchanged.
pub struct TrustedMtlsPeerAuthenticator {
    /// DER-encoded Subject DN of the trusted CA. The leaf cert's Issuer
    /// must match this exactly (byte equality).
    trusted_ca_subject_der: Vec<u8>,
    /// Optional: require the leaf cert to contain a SAN matching this value
    /// (exact match on DNS name or URI).
    required_san: Option<String>,
    /// Optional: require the leaf cert's Subject to contain this OU.
    required_ou: Option<String>,
}

impl TrustedMtlsPeerAuthenticator {
    /// Create from a PEM-encoded trusted CA certificate.
    ///
    /// The CA's Subject DN is extracted and used as the trust anchor.
    pub fn from_ca_pem(pem_bytes: &[u8]) -> Result<Self, AuthnError> {
        let ca_cert = Self::parse_first_pem_cert(pem_bytes)?;
        let trusted_ca_subject_der = ca_cert
            .tbs_certificate
            .subject
            .to_der()
            .map_err(|e| AuthnError::Internal(format!("failed to encode CA subject: {e}")))?;
        Ok(Self {
            trusted_ca_subject_der,
            required_san: None,
            required_ou: None,
        })
    }

    /// Require the peer certificate to have a SAN matching this value.
    #[must_use]
    pub fn with_required_san(mut self, san: String) -> Self {
        self.required_san = Some(san);
        self
    }

    /// Require the peer certificate's Subject to contain this OU.
    #[must_use]
    pub fn with_required_ou(mut self, ou: String) -> Self {
        self.required_ou = Some(ou);
        self
    }

    fn parse_first_pem_cert(pem_bytes: &[u8]) -> Result<Certificate, AuthnError> {
        let pem_str = std::str::from_utf8(pem_bytes)
            .map_err(|e| AuthnError::Internal(format!("trusted CA PEM is not valid UTF-8: {e}")))?;

        let begin_marker = "-----BEGIN CERTIFICATE-----";
        let end_marker = "-----END CERTIFICATE-----";
        let start = pem_str.find(begin_marker).ok_or_else(|| {
            AuthnError::Internal("trusted CA PEM missing BEGIN CERTIFICATE marker".into())
        })? + begin_marker.len();
        let end = pem_str[start..].find(end_marker).ok_or_else(|| {
            AuthnError::Internal("trusted CA PEM missing END CERTIFICATE marker".into())
        })? + start;

        let b64: String = pem_str[start..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der_bytes = base64_decode(&b64).map_err(|e| {
            AuthnError::Internal(format!("trusted CA PEM base64 decode failed: {e}"))
        })?;
        Certificate::from_der(&der_bytes)
            .map_err(|e| AuthnError::Internal(format!("failed to parse trusted CA cert: {e}")))
    }

    fn check_issuer_matches(&self, leaf: &Certificate) -> bool {
        match leaf.tbs_certificate.issuer.to_der() {
            Ok(issuer_der) => issuer_der == self.trusted_ca_subject_der,
            Err(_) => false,
        }
    }

    fn check_san_requirement(&self, leaf: &Certificate) -> bool {
        const SAN_OID: der::oid::ObjectIdentifier =
            der::oid::ObjectIdentifier::new_unwrap("2.5.29.17");
        let Some(ref required) = self.required_san else {
            return true;
        };
        let Some(extensions) = &leaf.tbs_certificate.extensions else {
            return false;
        };
        for ext in extensions {
            if ext.extn_id != SAN_OID {
                continue;
            }
            let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) else {
                continue;
            };
            for name in &san.0 {
                match name {
                    GeneralName::UniformResourceIdentifier(uri) if uri.as_str() == required => {
                        return true;
                    }
                    GeneralName::DnsName(dns) if dns.as_str() == required => {
                        return true;
                    }
                    _ => {}
                }
            }
        }
        false
    }

    fn check_ou_requirement(&self, leaf: &Certificate) -> bool {
        use der::oid::db::rfc4519::OU;
        let Some(ref required_ou) = self.required_ou else {
            return true;
        };
        leaf.tbs_certificate
            .subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .any(|atav| {
                if atav.oid != OU {
                    return false;
                }
                let val = &atav.value;
                der::asn1::Utf8StringRef::try_from(val)
                    .map(|s| s.as_str() == required_ou)
                    .or_else(|_| {
                        der::asn1::PrintableStringRef::try_from(val)
                            .map(|s| s.as_str() == required_ou)
                    })
                    .unwrap_or(false)
            })
    }
}

#[async_trait]
impl Authenticator for TrustedMtlsPeerAuthenticator {
    async fn authenticate(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<Option<AuthnResult>, AuthnError> {
        if metadata.peer_certificates.is_empty() {
            return Ok(None);
        }

        let leaf_der = &metadata.peer_certificates[0];
        let Ok(leaf) = Certificate::from_der(leaf_der) else {
            return Ok(None);
        };

        if !self.check_issuer_matches(&leaf) {
            return Ok(None);
        }

        if !self.check_san_requirement(&leaf) {
            return Ok(None);
        }

        if !self.check_ou_requirement(&leaf) {
            return Ok(None);
        }

        // Trusted peer confirmed. Derive principal from the certificate.
        let mut attributes = BTreeMap::<String, AttributeValue>::new();

        // Inject platform scope for scope_owner enforcement integration.
        attributes.insert("scope".into(), AttributeValue::String("platform".into()));

        let serial = leaf.tbs_certificate.serial_number.as_bytes().iter().fold(
            String::new(),
            |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            },
        );
        attributes.insert("serial_number".into(), AttributeValue::String(serial));

        let cn = MtlsAuthenticator::extract_cn(&leaf);
        if let Some(ref cn_val) = cn {
            attributes.insert("cn".into(), AttributeValue::String(cn_val.clone()));
        }

        // Extract SPIFFE ID if present.
        let mut spiffe_id: Option<String> = None;
        if let Some(extensions) = &leaf.tbs_certificate.extensions {
            const SAN_OID: der::oid::ObjectIdentifier =
                der::oid::ObjectIdentifier::new_unwrap("2.5.29.17");
            for ext in extensions {
                if ext.extn_id != SAN_OID {
                    continue;
                }
                if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                    for name in &san.0 {
                        if let GeneralName::UniformResourceIdentifier(uri) = name {
                            let uri_str = uri.as_str();
                            if uri_str.starts_with("spiffe://") {
                                attributes.insert(
                                    "spiffe_id".into(),
                                    AttributeValue::String(uri_str.to_owned()),
                                );
                                spiffe_id = Some(uri_str.to_owned());
                                break;
                            }
                        }
                    }
                }
            }
        }

        let principal_id = match (&spiffe_id, &cn) {
            (Some(sid), _) => sid.clone(),
            (None, Some(cn_val)) => cn_val.clone(),
            (None, None) => {
                return Err(AuthnError::InvalidCredential(
                    "trusted peer certificate has neither a CN nor a SPIFFE SAN".into(),
                ));
            }
        };

        tracing::info!(
            principal = %principal_id,
            method = "trusted_mtls_peer",
            "platform peer authenticated via trusted mTLS fast-path"
        );

        Ok(Some(AuthnResult {
            principal: Principal {
                id: principal_id,
                principal_type: "TrustedPlatformPeer".into(),
                attributes,
            },
            method: "trusted_mtls_peer".into(),
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
/// Supported algorithms: RS256, RS384, RS512, ES256, ES384, `EdDSA`.
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
    pub fn from_jwks(jwks: JwkSet, jwks_url: &str, issuer: Option<&str>) -> Self {
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
    #[must_use]
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
            AlgorithmParameters::OctetKey(_) => Err(AuthnError::InvalidCredential(
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

        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|e| {
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

        jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
            .map_err(|e| AuthnError::InvalidCredential(format!("JWT validation failed: {e}")))
    }

    fn extract_attributes(
        claims: &serde_json::Value,
        namespace: Option<&str>,
    ) -> BTreeMap<String, AttributeValue> {
        let mut attrs = BTreeMap::new();
        let Some(obj) = claims.as_object() else {
            return attrs;
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
            if let Some(jwk) = maybe_jwk {
                Self::validate_and_decode(token, jwk, self.required_issuer.as_deref())?
            } else {
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
        };

        let sub = token_data
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthnError::InvalidCredential("JWT missing `sub` claim".into()))?
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
#[allow(clippy::field_reassign_with_default)]
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
        let authn =
            BootstrapTokenAuthenticator::new("correct-token", std::time::Duration::from_secs(3600));
        let mut metadata = RequestMetadata::default();
        metadata
            .headers
            .insert("authorization".into(), "Bearer wrong-token".into());

        let result = authn.authenticate(&metadata).await;
        assert!(matches!(result, Err(AuthnError::InvalidCredential(_))));
    }

    #[tokio::test]
    async fn bootstrap_token_no_header_skips() {
        let authn = BootstrapTokenAuthenticator::new("token", std::time::Duration::from_secs(3600));
        let metadata = RequestMetadata::default();
        let result = authn.authenticate(&metadata).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn bootstrap_token_expired() {
        let authn = BootstrapTokenAuthenticator::new("token", std::time::Duration::from_secs(0));
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

    // ── TrustedMtlsPeerAuthenticator tests ────────────────────────────

    struct TestCaBundle {
        params: rcgen::CertificateParams,
        cert: rcgen::Certificate,
        key_pair: rcgen::KeyPair,
    }

    fn test_ca_named(cn: &str) -> TestCaBundle {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, cn);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        TestCaBundle {
            params,
            cert,
            key_pair,
        }
    }

    fn test_ca() -> TestCaBundle {
        test_ca_named("Platform CA")
    }

    fn test_leaf(cn: &str, ca: &TestCaBundle) -> rcgen::Certificate {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.is_ca = rcgen::IsCa::NoCa;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key_pair);
        params.signed_by(&key_pair, &issuer).unwrap()
    }

    fn test_leaf_with_ou(cn: &str, ou: &str, ca: &TestCaBundle) -> rcgen::Certificate {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationalUnitName, ou);
        params.is_ca = rcgen::IsCa::NoCa;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key_pair);
        params.signed_by(&key_pair, &issuer).unwrap()
    }

    fn test_leaf_with_san(cn: &str, san_dns: &str, ca: &TestCaBundle) -> rcgen::Certificate {
        let mut params = rcgen::CertificateParams::new(vec![san_dns.to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.is_ca = rcgen::IsCa::NoCa;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key_pair);
        params.signed_by(&key_pair, &issuer).unwrap()
    }

    fn build_trusted_authn(ca: &TestCaBundle) -> TrustedMtlsPeerAuthenticator {
        let pem = ca.cert.pem();
        TrustedMtlsPeerAuthenticator::from_ca_pem(pem.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn trusted_peer_authenticates_with_scope_platform() {
        let ca = test_ca();
        let leaf = test_leaf("gateway.internal", &ca);
        let authn = build_trusted_authn(&ca);

        let mut metadata = RequestMetadata::default();
        metadata.peer_certificates = vec![leaf.der().to_vec()];

        let result = authn.authenticate(&metadata).await.unwrap().unwrap();
        assert_eq!(result.method, "trusted_mtls_peer");
        assert_eq!(result.principal.id, "gateway.internal");
        assert_eq!(result.principal.principal_type, "TrustedPlatformPeer");
        assert_eq!(
            result.principal.attributes.get("scope"),
            Some(&AttributeValue::String("platform".into()))
        );
    }

    #[tokio::test]
    async fn trusted_peer_no_certs_skips() {
        let ca = test_ca();
        let authn = build_trusted_authn(&ca);
        let metadata = RequestMetadata::default();
        let result = authn.authenticate(&metadata).await.unwrap();
        assert!(result.is_none(), "no peer certs should skip (Ok(None))");
    }

    #[tokio::test]
    async fn trusted_peer_wrong_ca_skips() {
        let trusted_ca = test_ca();
        let other_ca = test_ca_named("Other CA");
        let leaf = test_leaf("intruder", &other_ca);
        let authn = build_trusted_authn(&trusted_ca);

        let mut metadata = RequestMetadata::default();
        metadata.peer_certificates = vec![leaf.der().to_vec()];

        let result = authn.authenticate(&metadata).await.unwrap();
        assert!(result.is_none(), "wrong CA should skip (Ok(None))");
    }

    #[tokio::test]
    async fn trusted_peer_ou_required_and_present() {
        let ca = test_ca();
        let leaf = test_leaf_with_ou("svc", "platform-services", &ca);
        let authn = build_trusted_authn(&ca).with_required_ou("platform-services".into());

        let mut metadata = RequestMetadata::default();
        metadata.peer_certificates = vec![leaf.der().to_vec()];

        let result = authn.authenticate(&metadata).await.unwrap().unwrap();
        assert_eq!(result.principal.id, "svc");
        assert_eq!(
            result.principal.attributes.get("scope"),
            Some(&AttributeValue::String("platform".into()))
        );
    }

    #[tokio::test]
    async fn trusted_peer_ou_required_but_missing() {
        let ca = test_ca();
        let leaf = test_leaf("svc", &ca);
        let authn = build_trusted_authn(&ca).with_required_ou("platform-services".into());

        let mut metadata = RequestMetadata::default();
        metadata.peer_certificates = vec![leaf.der().to_vec()];

        let result = authn.authenticate(&metadata).await.unwrap();
        assert!(result.is_none(), "missing required OU should skip");
    }

    #[tokio::test]
    async fn trusted_peer_san_required_and_present() {
        let ca = test_ca();
        let leaf = test_leaf_with_san("svc", "gateway.platform.internal", &ca);
        let authn = build_trusted_authn(&ca).with_required_san("gateway.platform.internal".into());

        let mut metadata = RequestMetadata::default();
        metadata.peer_certificates = vec![leaf.der().to_vec()];

        let result = authn.authenticate(&metadata).await.unwrap().unwrap();
        assert_eq!(
            result.principal.attributes.get("scope"),
            Some(&AttributeValue::String("platform".into()))
        );
    }

    #[tokio::test]
    async fn trusted_peer_san_required_but_wrong() {
        let ca = test_ca();
        let leaf = test_leaf_with_san("svc", "other.host.internal", &ca);
        let authn = build_trusted_authn(&ca).with_required_san("gateway.platform.internal".into());

        let mut metadata = RequestMetadata::default();
        metadata.peer_certificates = vec![leaf.der().to_vec()];

        let result = authn.authenticate(&metadata).await.unwrap();
        assert!(result.is_none(), "wrong SAN should skip");
    }

    #[tokio::test]
    async fn chain_trusted_peer_first_skips_jwt_for_trusted() {
        let ca = test_ca();
        let leaf = test_leaf("platform-gateway", &ca);
        let authn = build_trusted_authn(&ca);

        let chain = AuthenticatorChain::new(vec![
            Box::new(authn),
            Box::new(BootstrapTokenAuthenticator::new(
                "fallback-token",
                std::time::Duration::from_secs(3600),
            )),
        ]);

        let mut metadata = RequestMetadata::default();
        metadata.peer_certificates = vec![leaf.der().to_vec()];
        metadata
            .headers
            .insert("authorization".into(), "Bearer wrong-token".into());

        let result = chain.authenticate(&metadata).await.unwrap();
        assert_eq!(
            result.method, "trusted_mtls_peer",
            "trusted peer should win, JWT/bootstrap not tried"
        );
    }

    #[tokio::test]
    async fn chain_untrusted_peer_falls_through_to_next() {
        let trusted_ca = test_ca();
        let other_ca = test_ca_named("Untrusted CA");
        let leaf = test_leaf("untrusted", &other_ca);
        let authn = build_trusted_authn(&trusted_ca);

        let chain = AuthenticatorChain::new(vec![
            Box::new(authn),
            Box::new(BootstrapTokenAuthenticator::new(
                "my-token",
                std::time::Duration::from_secs(3600),
            )),
        ]);

        let mut metadata = RequestMetadata::default();
        metadata.peer_certificates = vec![leaf.der().to_vec()];
        metadata
            .headers
            .insert("authorization".into(), "Bearer my-token".into());

        let result = chain.authenticate(&metadata).await.unwrap();
        assert_eq!(
            result.method, "bootstrap_token",
            "untrusted peer should fall through to bootstrap token"
        );
    }

    #[tokio::test]
    async fn chain_no_cert_no_token_rejected() {
        let ca = test_ca();
        let authn = build_trusted_authn(&ca);

        let chain = AuthenticatorChain::new(vec![Box::new(authn), Box::new(MtlsAuthenticator)]);

        let metadata = RequestMetadata::default();
        let result = chain.authenticate(&metadata).await;
        assert!(
            matches!(result, Err(AuthnError::NoCredential)),
            "no cert + no token must be rejected (fail-closed)"
        );
    }
}
