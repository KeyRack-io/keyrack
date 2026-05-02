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

use crate::pdp::Principal;
use async_trait::async_trait;
use std::collections::BTreeMap;

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
        if candidate_hash != self.token_hash {
            return Err(AuthnError::InvalidCredential(
                "bootstrap token mismatch".into(),
            ));
        }

        tracing::warn!("bootstrap token used — this should be disabled in production");

        Ok(Some(AuthnResult {
            principal: Principal {
                id: "keyrack:bootstrap-admin".into(),
                principal_type: "Admin".into(),
            },
            method: "bootstrap_token".into(),
        }))
    }
}

/// mTLS authenticator stub.
///
/// Extracts the principal from the peer certificate's Subject Alternative
/// Name.  Supports both CN-based and SPIFFE SVID URI extraction.
///
/// Full implementation (certificate parsing, SPIFFE validation) is
/// deferred until the TLS stack integration in the service binary.
pub struct MtlsAuthenticator;

#[async_trait]
impl Authenticator for MtlsAuthenticator {
    async fn authenticate(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<Option<AuthnResult>, AuthnError> {
        if metadata.peer_certificates.is_empty() {
            return Ok(None);
        }
        // TODO: parse leaf certificate, extract SAN/CN, validate chain
        Err(AuthnError::Internal(
            "mTLS certificate parsing not yet implemented".into(),
        ))
    }
}

/// JWT bearer token authenticator stub.
///
/// Validates `Authorization: Bearer <jwt>` against a JWKS endpoint.
///
/// Full implementation (JWKS fetching, signature validation, claims
/// extraction) is deferred.
pub struct JwtAuthenticator {
    _jwks_url: String,
}

impl JwtAuthenticator {
    #[must_use]
    pub fn new(jwks_url: impl Into<String>) -> Self {
        Self {
            _jwks_url: jwks_url.into(),
        }
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

        if !auth_header.starts_with("Bearer ey") {
            return Ok(None);
        }

        // TODO: validate JWT signature against JWKS, extract claims
        Err(AuthnError::Internal(
            "JWT validation not yet implemented".into(),
        ))
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
        let authn = JwtAuthenticator::new("https://example.com/.well-known/jwks.json");
        let metadata = RequestMetadata::default();
        let result = authn.authenticate(&metadata).await.unwrap();
        assert!(result.is_none());
    }
}
