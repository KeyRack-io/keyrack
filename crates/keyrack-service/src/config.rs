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

    /// Legacy single-provider config. Kept for back-compat: if `providers`
    /// is empty, this field is used to synthesize one "default" provider.
    #[serde(default)]
    pub provider: ProviderConfig,

    /// Named providers for multi-provider routing. Supersedes the single
    /// `provider` field when non-empty.
    #[serde(default)]
    pub providers: Vec<NamedProvider>,

    /// Name of the default provider to use for new keys when no routing
    /// rule matches. Required when `providers` has more than one entry.
    #[serde(default)]
    pub default_provider: Option<String>,

    /// Routing rules that assign new keys to specific providers based on
    /// their identity tags. Rules are evaluated in order; the first match wins.
    #[serde(default)]
    pub provider_routing: Vec<ProviderRoutingRule>,

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

/// A named provider entry in the `providers` list.
///
/// The `name` field is the routing key; the remaining fields describe the
/// provider type (via `#[serde(flatten)]` from [`ProviderConfig`]).
///
/// YAML example:
/// ```yaml
/// providers:
///   - name: default
///     type: software
///   - name: tenant-hsm
///     type: pkcs11
///     lib_path: /usr/lib/pkcs11.so
///     token_label: TenantToken
///     pin: 1234
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedProvider {
    pub name: String,
    #[serde(flatten)]
    pub provider: ProviderConfig,
}

/// A single provider-routing rule.
///
/// If ALL tags in `match_tags` are present with the specified values on a
/// new key's identity tags, the key is assigned to `provider`. Rules are
/// evaluated in order; the first match wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRoutingRule {
    /// Identity-tag predicate. All entries must match (AND logic).
    #[serde(rename = "match", default)]
    pub match_tags: std::collections::BTreeMap<String, String>,
    /// Name of the provider to use when this rule matches.
    pub provider: String,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            grpc_addr: default_grpc_addr(),
            rest_addr: default_rest_addr(),
            storage: StorageConfig::default(),
            provider: ProviderConfig::default(),
            providers: Vec::new(),
            default_provider: None,
            provider_routing: Vec::new(),
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

impl ServiceConfig {
    /// Resolve the canonical list of named providers and the default name.
    ///
    /// - If `providers` is empty: synthesises one `NamedProvider` named
    ///   `"default"` from the legacy `provider` field.
    /// - Otherwise: validates uniqueness and resolves the default name
    ///   (`default_provider` if set, or the sole provider name if there is
    ///   exactly one).
    ///
    /// Returns `Err(String)` on misconfiguration.
    pub fn resolved_providers(&self) -> Result<(Vec<NamedProvider>, String), String> {
        if self.providers.is_empty() {
            let synthetic = NamedProvider {
                name: "default".into(),
                provider: self.provider.clone(),
            };
            return Ok((vec![synthetic], "default".into()));
        }

        // Validate uniqueness.
        let mut seen = std::collections::HashSet::new();
        for p in &self.providers {
            if !seen.insert(p.name.clone()) {
                return Err(format!("duplicate provider name: '{}'", p.name));
            }
        }

        let default_name = match &self.default_provider {
            Some(name) => name.clone(),
            None => {
                if self.providers.len() == 1 {
                    self.providers[0].name.clone()
                } else {
                    return Err(
                        "default_provider must be set when more than one provider is configured"
                            .into(),
                    );
                }
            }
        };

        if !seen.contains(&default_name) {
            return Err(format!(
                "default_provider '{}' is not among the configured providers",
                default_name
            ));
        }

        Ok((self.providers.clone(), default_name))
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
            providers: Vec::new(),
            default_provider: None,
            provider_routing: Vec::new(),
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

    #[test]
    fn single_provider_back_compat() {
        let yaml = "provider:\n  type: software\n";
        let config = ServiceConfig::from_yaml(yaml).unwrap();
        let (providers, default) = config.resolved_providers().unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name, "default");
        assert_eq!(default, "default");
        assert!(matches!(providers[0].provider, ProviderConfig::Software));
    }

    #[test]
    fn multi_provider_with_routing() {
        let yaml = r#"
provider:
  type: software
providers:
  - name: default
    type: software
  - name: tenant-b
    type: in_memory
default_provider: default
provider_routing:
  - match:
      tenant: acme
    provider: tenant-b
"#;
        let config = ServiceConfig::from_yaml(yaml).unwrap();
        let (providers, default) = config.resolved_providers().unwrap();
        assert_eq!(providers.len(), 2);
        assert_eq!(default, "default");
        assert_eq!(config.provider_routing.len(), 1);
        assert_eq!(
            config.provider_routing[0].match_tags.get("tenant"),
            Some(&"acme".to_string())
        );
        assert_eq!(config.provider_routing[0].provider, "tenant-b");
    }

    #[test]
    fn resolved_providers_requires_default_for_multiple() {
        let yaml = r#"
providers:
  - name: a
    type: software
  - name: b
    type: in_memory
"#;
        let config = ServiceConfig::from_yaml(yaml).unwrap();
        assert!(config.resolved_providers().is_err());
    }

    #[test]
    fn resolved_providers_rejects_unknown_default() {
        let yaml = r#"
providers:
  - name: a
    type: software
default_provider: missing
"#;
        let config = ServiceConfig::from_yaml(yaml).unwrap();
        assert!(config.resolved_providers().is_err());
    }
}
