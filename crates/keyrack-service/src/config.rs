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

use keyrack_core::secret::SecretString;
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

    /// Authorization decision point. **Mandatory — there is no default.**
    ///
    /// A missing `pdp:` block used to fall back to `always_allow`, which
    /// silently disabled authorization. It is now a hard startup error; see
    /// [`ServiceConfig::resolved_pdp`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdp: Option<PdpConfig>,

    #[serde(default)]
    pub audit: AuditConfig,

    /// Enable Ed25519 signing of audit events, which adds *authenticity* on
    /// top of the BLAKE3 hash chain.
    ///
    /// The hash chain itself is always maintained and does not depend on this
    /// flag: chaining gives tamper evidence, signing gives authenticity, and
    /// they are separately available.
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
    /// Format: 32 raw bytes (the Ed25519 secret seed). Created on first start
    /// if the file does not exist.
    ///
    /// Required whenever `sign_audit_events` is true, unless
    /// `audit_signing_key_ephemeral` is explicitly set.
    #[serde(default)]
    pub audit_signing_key_path: Option<String>,

    /// Accept a per-startup audit signing key instead of a persistent one.
    ///
    /// Development-only. An ephemeral key means every signature written before
    /// the last restart becomes unverifiable, so signing no longer provides
    /// the authenticity it advertises. Opting in must be deliberate.
    #[serde(default)]
    pub audit_signing_key_ephemeral: bool,
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
///     # Either an inline `pin:` (dev/single-HSM) or a `pin_ref:` reference
///     # resolved under KEYRACK_SECRET_ROOT (production). Exactly one.
///     pin_ref: "file:tenant-hsm.pin"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedProvider {
    pub name: String,
    #[serde(flatten)]
    pub provider: ProviderConfig,
}

/// A single provider-routing rule.
///
/// Rules are evaluated in order; the first rule whose `match_tags` are all
/// present on a new key's identity tags wins.
///
/// ## Actions
///
/// - **route** (default): pin to a specific provider; caller cannot override.
/// - **delegate**: caller may select from a bounded set of providers.
/// - **`delegate_any`**: caller may select any registered provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRoutingRule {
    /// Identity-tag predicate. All entries must match (AND logic).
    #[serde(rename = "match", default)]
    pub match_tags: std::collections::BTreeMap<String, String>,
    /// For `route` rules: name of the provider to pin to.
    /// For `delegate` and `delegate_any` rules: unused (ignored if present).
    #[serde(default)]
    pub provider: Option<String>,
    /// The rule action. Defaults to "route" for backward compatibility.
    #[serde(default = "default_rule_action")]
    pub action: RuleActionConfig,
    /// For `delegate` action: the set of allowed providers.
    #[serde(default)]
    pub allowed_providers: Vec<String>,
}

fn default_rule_action() -> RuleActionConfig {
    RuleActionConfig::Route
}

/// The action a routing rule takes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleActionConfig {
    #[default]
    Route,
    Delegate,
    DelegateAny,
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
            // No default PDP: an operator must state the authorization
            // decision explicitly, including when they want none.
            pdp: None,
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
            audit_signing_key_ephemeral: false,
        }
    }
}

/// Startup error for a config with no `pdp:` block.
pub const PDP_REQUIRED_ERROR: &str = "config error: `pdp:` is required and has no default. \
     KeyRack will not start without an explicit authorization decision. Set \
     `pdp: {type: cedar|http|grpc, endpoint: ...}` for a real policy decision point, \
     `pdp: {type: always_deny}` to deny every request, or `pdp: {type: always_allow}` \
     to disable authorization entirely (development only).";

/// Startup error for signing enabled with no persistent key and no opt-in.
pub const AUDIT_SIGNING_KEY_REQUIRED_ERROR: &str =
    "config error: `sign_audit_events: true` requires `audit_signing_key_path` so that \
     signatures stay verifiable across restarts. Set `audit_signing_key_path: <file>` \
     (created on first start), or set `audit_signing_key_ephemeral: true` to accept a \
     per-startup key that leaves every signature written before the last restart \
     unverifiable (development only). The BLAKE3 hash chain is maintained either way.";

impl ServiceConfig {
    /// Check every fail-closed startup invariant that can be decided from the
    /// config alone.
    ///
    /// Called before anything binds a socket or opens a backend so that a
    /// misconfigured deployment refuses to serve rather than serving wrongly.
    ///
    /// # Errors
    /// Returns a human-actionable message for the first violated invariant.
    pub fn validate(&self) -> Result<(), String> {
        self.resolved_pdp()?;
        self.validate_audit_signing()?;
        Ok(())
    }

    /// The configured PDP, or an error when `pdp:` was omitted.
    ///
    /// # Errors
    /// Returns [`PDP_REQUIRED_ERROR`] when no `pdp:` block is present.
    pub fn resolved_pdp(&self) -> Result<&PdpConfig, String> {
        self.pdp.as_ref().ok_or_else(|| PDP_REQUIRED_ERROR.into())
    }

    /// Reject audit signing that cannot survive a restart unless the operator
    /// opted into an ephemeral key.
    ///
    /// # Errors
    /// Returns [`AUDIT_SIGNING_KEY_REQUIRED_ERROR`] when signing is enabled
    /// with neither a key path nor the ephemeral opt-in.
    pub fn validate_audit_signing(&self) -> Result<(), String> {
        if !self.sign_audit_events {
            return Ok(());
        }
        let has_key_path = self
            .audit_signing_key_path
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty());
        if has_key_path || self.audit_signing_key_ephemeral {
            return Ok(());
        }
        Err(AUDIT_SIGNING_KEY_REQUIRED_ERROR.into())
    }

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
                "default_provider '{default_name}' is not among the configured providers"
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
        /// Inline PIN (Model A back-compat). Held in a redacting secret type so
        /// it never leaks via `Debug`/`Serialize`. Mutually exclusive with
        /// `pin_ref`; exactly one must be set.
        #[serde(default)]
        pin: Option<SecretString>,
        /// Secret reference to the PIN, e.g. `"file:tenant-a.pin"`, resolved
        /// KeyRack-side under the `KEYRACK_SECRET_ROOT` allowlist root. The
        /// reference is not itself a secret. Mutually exclusive with `pin`.
        #[serde(default)]
        pin_ref: Option<String>,
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

/// Authorization decision point.
///
/// Deliberately **not** `Default`: there is no safe implicit choice, so the
/// variant is always spelled out in config. `AlwaysAllow` disables
/// authorization and the service logs a prominent warning when it is selected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PdpConfig {
    /// No authorization at all — every request is permitted. Development only.
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
/// Use `Chain` variant to accept multiple independent credential types (tried
/// in order). A chain does not compose credential proofs: use
/// `MtlsBoundForwardedIdentity` when an mTLS workload delegates an end-user
/// identity.
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
    /// Accept a forwarded end-user identity only when it is carried by the
    /// specifically pinned mTLS workload.
    ///
    /// This is intentionally one authenticator rather than a `Chain` of
    /// `Mtls` and `ForwardedIdentity`: a chain selects the first successful
    /// identity and does not bind the two credentials. The tenant header is
    /// required and becomes the `scope=tenant:<id>` principal attribute used
    /// by `scope_owner` enforcement. This profile is gRPC-only unless the
    /// chain also contains a credential type supported by the REST listener.
    /// Its CA must be the same PEM material configured as the gRPC TLS client
    /// CA, and at least one exact SAN/OU workload pin is mandatory.
    MtlsBoundForwardedIdentity {
        trusted_ca_cert_path: String,
        #[serde(default)]
        required_san: Option<String>,
        #[serde(default)]
        required_ou: Option<String>,
    },
    /// Trusted mTLS peer: platform-internal fast-path authentication.
    ///
    /// A peer whose client cert was issued by the configured trusted CA
    /// authenticates as a platform-scoped principal (`scope=platform`),
    /// skipping JWT verification. OPT-IN: only active when explicitly
    /// configured. Place first in a Chain to get the fast-path benefit.
    ///
    /// SECURITY — the trust decision is `leaf cert Issuer DN == trusted CA
    /// Subject DN`, so it grants `scope=platform` to **every** certificate
    /// issued by `trusted_ca_cert_path`. Two operator requirements:
    /// 1. Use a CA **dedicated** to the platform gateway, OR set
    ///    `required_san`/`required_ou` to pin the specific peer. A shared
    ///    corporate CA without SAN/OU would grant platform scope to ALL its
    ///    clients (the server logs a warning at startup in that case).
    /// 2. The gRPC server's TLS `client_ca_root` MUST be configured to
    ///    cryptographically verify peer certs against this CA (or a bundle
    ///    including it) — this authenticator trusts the TLS-verified chain
    ///    and only matches the Issuer DN; it does not re-verify signatures.
    ///    If TLS does not verify the platform CA, peer certs simply never
    ///    reach the fast-path (fail-safe no-op), and it will not work.
    TrustedMtlsPeer {
        /// Path to the PEM-encoded CA certificate that signs trusted
        /// platform peers. The leaf cert's Issuer must match this CA's
        /// Subject DN.
        trusted_ca_cert_path: String,
        /// Optional: require the peer cert to have a SAN matching this
        /// value (DNS name or URI, exact match).
        #[serde(default)]
        required_san: Option<String>,
        /// Optional: require the peer cert's Subject to contain this OU.
        #[serde(default)]
        required_ou: Option<String>,
    },
    /// Skip authentication entirely (dev/test only).
    Insecure,
    /// Chain of authenticators tried in order (first match wins).
    Chain { authenticators: Vec<AuthnConfig> },
}

impl AuthnConfig {
    /// Validate the startup invariants required by delegated mTLS profiles.
    ///
    /// Signature verification happens in the gRPC TLS layer. Requiring that
    /// layer plus an exact workload pin prevents a header-binding profile from
    /// silently degrading into an issuer-name-only trust decision.
    pub fn validate_delegated_mtls_contract(&self, tls: Option<&TlsConfig>) -> Result<(), String> {
        match self {
            Self::MtlsBoundForwardedIdentity {
                trusted_ca_cert_path,
                required_san,
                required_ou,
            } => {
                if trusted_ca_cert_path.trim().is_empty() {
                    return Err(
                        "mtls_bound_forwarded_identity requires trusted_ca_cert_path".into(),
                    );
                }
                let has_san = required_san
                    .as_deref()
                    .is_some_and(|v| !v.trim().is_empty());
                let has_ou = required_ou.as_deref().is_some_and(|v| !v.trim().is_empty());
                if !has_san && !has_ou {
                    return Err(
                        "mtls_bound_forwarded_identity requires a non-empty required_san or required_ou workload pin"
                            .into(),
                    );
                }
                if tls
                    .and_then(|cfg| cfg.ca_cert.as_deref())
                    .map_or(true, |path| path.trim().is_empty())
                {
                    return Err(
                        "mtls_bound_forwarded_identity requires tls.ca_cert so the gRPC layer verifies client certificates"
                            .into(),
                    );
                }
                Ok(())
            }
            Self::Chain { authenticators } => {
                for authenticator in authenticators {
                    authenticator.validate_delegated_mtls_contract(tls)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
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
            pdp: Some(PdpConfig::AlwaysAllow),
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
            audit_signing_key_ephemeral: false,
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed = ServiceConfig::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.grpc_addr, "0.0.0.0:50051");
        assert!(matches!(parsed.resolved_pdp(), Ok(PdpConfig::AlwaysAllow)));
    }

    #[test]
    fn omitting_the_pdp_block_is_rejected() {
        let yaml = "storage:\n  type: memory\nprovider:\n  type: software\n";
        let config = ServiceConfig::from_yaml(yaml).unwrap();

        assert!(config.pdp.is_none(), "there must be no implicit PDP");
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("`pdp:` is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn built_in_defaults_do_not_grant_an_implicit_pdp() {
        // `keyrack-service` falls back to `ServiceConfig::default()` when no
        // KEYRACK_CONFIG is set; that path must fail closed too.
        let err = ServiceConfig::default().validate().unwrap_err();
        assert!(
            err.contains("`pdp:` is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn explicit_always_allow_is_accepted() {
        let yaml = "pdp:\n  type: always_allow\n";
        let config = ServiceConfig::from_yaml(yaml).unwrap();

        config.validate().unwrap();
        assert!(matches!(config.resolved_pdp(), Ok(PdpConfig::AlwaysAllow)));
    }

    #[test]
    fn signing_without_a_persistent_key_is_rejected() {
        let yaml = "pdp:\n  type: always_allow\nsign_audit_events: true\n";
        let config = ServiceConfig::from_yaml(yaml).unwrap();

        let err = config.validate().unwrap_err();
        assert!(
            err.contains("audit_signing_key_path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn signing_accepts_a_key_path_or_an_explicit_ephemeral_opt_in() {
        let persistent = ServiceConfig::from_yaml(
            "pdp:\n  type: always_allow\nsign_audit_events: true\naudit_signing_key_path: /data/k\n",
        )
        .unwrap();
        persistent.validate().unwrap();

        let ephemeral = ServiceConfig::from_yaml(
            "pdp:\n  type: always_allow\nsign_audit_events: true\naudit_signing_key_ephemeral: true\n",
        )
        .unwrap();
        ephemeral.validate().unwrap();
    }

    #[test]
    fn unsigned_audit_config_is_valid_and_still_chains() {
        // Chaining is unconditional, so an unsigned config needs no signing
        // key and must not be rejected.
        let config = ServiceConfig::from_yaml("pdp:\n  type: always_deny\n").unwrap();
        assert!(!config.sign_audit_events);
        config.validate().unwrap();
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
        let yaml = r"
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
";
        let config = ServiceConfig::from_yaml(yaml).unwrap();
        let (providers, default) = config.resolved_providers().unwrap();
        assert_eq!(providers.len(), 2);
        assert_eq!(default, "default");
        assert_eq!(config.provider_routing.len(), 1);
        assert_eq!(
            config.provider_routing[0].match_tags.get("tenant"),
            Some(&"acme".to_string())
        );
        assert_eq!(
            config.provider_routing[0].provider.as_deref(),
            Some("tenant-b")
        );
    }

    #[test]
    fn resolved_providers_requires_default_for_multiple() {
        let yaml = r"
providers:
  - name: a
    type: software
  - name: b
    type: in_memory
";
        let config = ServiceConfig::from_yaml(yaml).unwrap();
        assert!(config.resolved_providers().is_err());
    }

    #[test]
    fn resolved_providers_rejects_unknown_default() {
        let yaml = r"
providers:
  - name: a
    type: software
default_provider: missing
";
        let config = ServiceConfig::from_yaml(yaml).unwrap();
        assert!(config.resolved_providers().is_err());
    }

    #[test]
    fn mtls_bound_forwarded_identity_config_parses() {
        let yaml = r"
authn:
  type: mtls_bound_forwarded_identity
  trusted_ca_cert_path: /etc/keyrack/tls/delegator-ca.pem
  required_san: spiffe://cluster.local/ns/essentials/sa/essentials
";
        let config = ServiceConfig::from_yaml(yaml).unwrap();
        match config.authn {
            AuthnConfig::MtlsBoundForwardedIdentity {
                trusted_ca_cert_path,
                required_san,
                required_ou,
            } => {
                assert_eq!(trusted_ca_cert_path, "/etc/keyrack/tls/delegator-ca.pem");
                assert_eq!(
                    required_san.as_deref(),
                    Some("spiffe://cluster.local/ns/essentials/sa/essentials")
                );
                assert!(required_ou.is_none());
            }
            other => panic!("unexpected authn config: {other:?}"),
        }
    }

    #[test]
    fn delegated_mtls_requires_server_client_ca_and_workload_pin() {
        let unpinned = AuthnConfig::MtlsBoundForwardedIdentity {
            trusted_ca_cert_path: "/etc/keyrack/tls/delegator-ca.pem".into(),
            required_san: None,
            required_ou: None,
        };
        let tls = TlsConfig {
            server_cert: "/etc/keyrack/tls/server.crt".into(),
            server_key: "/etc/keyrack/tls/server.key".into(),
            ca_cert: Some("/etc/keyrack/tls/delegator-ca.pem".into()),
        };
        assert!(unpinned
            .validate_delegated_mtls_contract(Some(&tls))
            .unwrap_err()
            .contains("required_san or required_ou"));

        let pinned = AuthnConfig::MtlsBoundForwardedIdentity {
            trusted_ca_cert_path: "/etc/keyrack/tls/delegator-ca.pem".into(),
            required_san: Some("spiffe://cluster.local/ns/essentials/sa/essentials".into()),
            required_ou: None,
        };
        assert!(pinned
            .validate_delegated_mtls_contract(None)
            .unwrap_err()
            .contains("tls.ca_cert"));
        pinned.validate_delegated_mtls_contract(Some(&tls)).unwrap();
    }

    #[test]
    fn delegated_mtls_validation_recurses_through_chain() {
        let chain = AuthnConfig::Chain {
            authenticators: vec![
                AuthnConfig::Jwt {
                    jwks_url: "https://idp.example/.well-known/jwks.json".into(),
                    issuer: None,
                    audience: None,
                    claims_namespace: None,
                },
                AuthnConfig::MtlsBoundForwardedIdentity {
                    trusted_ca_cert_path: "/etc/keyrack/tls/delegator-ca.pem".into(),
                    required_san: None,
                    required_ou: None,
                },
            ],
        };

        assert!(chain
            .validate_delegated_mtls_contract(None)
            .unwrap_err()
            .contains("required_san or required_ou"));
    }
}
