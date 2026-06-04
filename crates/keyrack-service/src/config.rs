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

//! Service configuration loaded from YAML or environment variables.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_grpc_addr")]
    pub grpc_addr: String,

    #[serde(default = "default_rest_addr")]
    pub rest_addr: String,

    #[serde(default)]
    pub storage: StorageConfig,

    #[serde(default)]
    pub provider: ProviderConfig,

    #[serde(default)]
    pub pdp: PdpConfig,

    #[serde(default)]
    pub audit: AuditConfig,

    /// Enable Ed25519 signing of audit events for tamper evidence.
    #[serde(default)]
    pub sign_audit_events: bool,

    #[serde(default)]
    pub authn: AuthnConfig,

    #[serde(default)]
    pub provider_deny: Vec<String>,

    #[serde(default = "default_max_plaintext_bytes")]
    pub max_plaintext_bytes: usize,

    #[serde(default)]
    pub nats_notify: Option<NatsNotifyConfig>,

    #[serde(default)]
    pub tls: Option<TlsConfig>,

    #[serde(default)]
    pub grpc_keepalive: Option<GrpcKeepaliveConfig>,

    /// Key record cache configuration. Enables in-memory caching of
    /// `get_key` results for improved latency. The TTL also serves as
    /// the upper bound on time-to-lockout for HYOK disconnect scenarios.
    #[serde(default)]
    pub cache: Option<CacheConfig>,

    /// Path to persistent Ed25519 signing key for audit events.
    /// If not set, an ephemeral key is generated each startup.
    /// Format: 32 raw bytes (the Ed25519 secret seed).
    #[serde(default)]
    pub audit_signing_key_path: Option<String>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            grpc_addr: default_grpc_addr(),
            rest_addr: default_rest_addr(),
            storage: StorageConfig::default(),
            provider: ProviderConfig::default(),
            pdp: PdpConfig::default(),
            audit: AuditConfig::default(),
            sign_audit_events: false,
            authn: AuthnConfig::default(),
            provider_deny: Vec::new(),
            max_plaintext_bytes: default_max_plaintext_bytes(),
            nats_notify: None,
            tls: None,
            grpc_keepalive: None,
            cache: None,
            audit_signing_key_path: None,
        }
    }
}

fn default_max_plaintext_bytes() -> usize {
    4096
}

fn default_grpc_addr() -> String {
    "[::1]:50051".into()
}

fn default_rest_addr() -> String {
    "[::1]:8080".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StorageConfig {
    Sqlite { path: String },
    Postgres { database_url: String },
    Memory,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::Sqlite {
            path: "keyrack.db".into(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderConfig {
    #[default]
    Software,
    InMemory,
    Pkcs11 {
        lib_path: String,
        token_label: String,
        pin: String,
    },
    Kmip {
        host: String,
        port: u16,
        client_cert: String,
        client_key: String,
        ca_cert: Option<String>,
    },
    VaultTransit {
        vault_addr: String,
        vault_token: String,
        mount_path: Option<String>,
    },
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PdpConfig {
    #[default]
    AlwaysAllow,
    AlwaysDeny,
    Http {
        endpoint: String,
        #[serde(default = "default_pdp_timeout")]
        timeout_ms: u64,
        #[serde(default)]
        ca_cert: Option<String>,
        #[serde(default)]
        client_cert: Option<String>,
        #[serde(default)]
        client_key: Option<String>,
    },
    Grpc {
        endpoint: String,
        #[serde(default = "default_pdp_timeout")]
        timeout_ms: u64,
        #[serde(default)]
        ca_cert: Option<String>,
        #[serde(default)]
        client_cert: Option<String>,
        #[serde(default)]
        client_key: Option<String>,
    },
    /// Cedar sidecar PDP — convenience alias for `Http` pointing at a
    /// `keyrack-cedar-pdp` instance (e.g. `http://cedar-pdp:8181/v1/authorize`).
    Cedar {
        endpoint: String,
        #[serde(default = "default_pdp_timeout")]
        timeout_ms: u64,
    },
}

fn default_pdp_timeout() -> u64 {
    5000
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditConfig {
    #[default]
    Stdout,
    File {
        path: String,
    },
    Nats {
        url: String,
    },
}

/// Authentication configuration.
///
/// Use `Chain` variant to combine multiple authenticators (tried in order).
/// For production deployments, consider `Chain { authenticators: [Mtls, ForwardedIdentity] }`
/// or `Chain { authenticators: [Jwt { ... }, BootstrapToken { ... }] }`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthnConfig {
    /// Mutual TLS client-certificate authentication. Production default.
    #[default]
    Mtls,
    /// JWT bearer token validated against a JWKS endpoint.
    Jwt {
        jwks_url: String,
        #[serde(default)]
        issuer: Option<String>,
        /// Not enforced at the authn layer (core sets `validate_aud = false`).
        /// The `aud` claim is extracted into principal attributes so the PDP
        /// can enforce audience restrictions.
        #[serde(default)]
        audience: Option<String>,
        #[serde(default)]
        claims_namespace: Option<String>,
    },
    /// OSS fallback: bootstrap bearer token, time-bounded.
    BootstrapToken {
        #[serde(default = "default_bootstrap_max_age_secs")]
        max_age_secs: u64,
    },
    /// Trust `x-keyrack-principal-id` header from an already-authenticated
    /// upstream service (e.g. the Barbican shim). Only safe behind mTLS.
    ForwardedIdentity,
    /// Skip authentication entirely (dev/test only).
    Insecure,
    /// Chain of authenticators tried in order (first match wins).
    Chain { authenticators: Vec<AuthnConfig> },
}

fn default_bootstrap_max_age_secs() -> u64 {
    900
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsNotifyConfig {
    pub url: String,
    #[serde(default = "default_audit_prefix")]
    pub audit_subject_prefix: String,
    #[serde(default = "default_state_changed_prefix")]
    pub state_changed_subject_prefix: String,
    #[serde(default = "default_invalidation_prefix")]
    pub invalidation_subject_prefix: String,
}

fn default_audit_prefix() -> String {
    "kms.audit".into()
}

fn default_state_changed_prefix() -> String {
    "kms.key.state-changed".into()
}

fn default_invalidation_prefix() -> String {
    "kms.cache.invalidate".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub server_cert: String,
    pub server_key: String,
    /// If set, enables mTLS by validating client certificates against this CA.
    pub ca_cert: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcKeepaliveConfig {
    #[serde(default = "default_keepalive_time_secs")]
    pub time_secs: u64,
    #[serde(default = "default_keepalive_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_keepalive_time_secs() -> u64 {
    30
}

fn default_keepalive_timeout_secs() -> u64 {
    10
}

/// Configuration for the key record cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of key records to cache (default: 10,000).
    #[serde(default = "default_cache_max_capacity")]
    pub max_capacity: u64,
    /// Cache TTL in seconds (default: 300 = 5 minutes).
    /// For HYOK deployments, this is the upper bound on time-to-lockout
    /// after a tenant disconnects their HSM.
    #[serde(default = "default_cache_ttl_secs")]
    pub ttl_secs: u64,
}

fn default_cache_max_capacity() -> u64 {
    10_000
}

fn default_cache_ttl_secs() -> u64 {
    300
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_capacity: default_cache_max_capacity(),
            ttl_secs: default_cache_ttl_secs(),
        }
    }
}

impl ServiceConfig {
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let config = ServiceConfig::default();
        assert_eq!(config.grpc_addr, "[::1]:50051");
    }

    #[test]
    fn yaml_round_trip() {
        let config = ServiceConfig {
            grpc_addr: "0.0.0.0:50051".into(),
            rest_addr: "[::1]:8080".into(),
            storage: StorageConfig::Postgres {
                database_url: "postgres://localhost/keyrack".into(),
            },
            provider: ProviderConfig::Software,
            pdp: PdpConfig::AlwaysAllow,
            audit: AuditConfig::Stdout,
            sign_audit_events: false,
            authn: AuthnConfig::Insecure,
            provider_deny: Vec::new(),
            max_plaintext_bytes: default_max_plaintext_bytes(),
            nats_notify: None,
            tls: None,
            grpc_keepalive: None,
            cache: None,
            audit_signing_key_path: None,
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed = ServiceConfig::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.grpc_addr, "0.0.0.0:50051");
    }
}
