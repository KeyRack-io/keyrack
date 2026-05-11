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

    #[serde(default)]
    pub authn: AuthnConfig,

    #[serde(default)]
    pub provider_deny: Vec<String>,

    #[serde(default = "default_max_plaintext_bytes")]
    pub max_plaintext_bytes: usize,

    #[serde(default)]
    pub nats_notify: Option<NatsNotifyConfig>,
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
            authn: AuthnConfig::default(),
            provider_deny: Vec::new(),
            max_plaintext_bytes: default_max_plaintext_bytes(),
            nats_notify: None,
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
    },
    Grpc {
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
    File { path: String },
    Nats { url: String },
}

/// Authentication configuration.
///
/// Multiple authenticators are tried in order (mTLS first, then JWT, then
/// bootstrap token).  `Insecure` accepts all requests as a system
/// principal — suitable only for local development.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthnConfig {
    /// mTLS + optional JWT.  Production default.
    #[default]
    Mtls,
    /// JWT bearer token only (no mTLS).
    Jwt {
        jwks_url: String,
    },
    /// OSS fallback: bootstrap bearer token, time-bounded.
    BootstrapToken {
        #[serde(default = "default_bootstrap_max_age_secs")]
        max_age_secs: u64,
    },
    /// Skip authentication entirely (dev/test only).
    Insecure,
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
            authn: AuthnConfig::Insecure,
            provider_deny: Vec::new(),
            max_plaintext_bytes: default_max_plaintext_bytes(),
            nats_notify: None,
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed = ServiceConfig::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.grpc_addr, "0.0.0.0:50051");
    }
}
