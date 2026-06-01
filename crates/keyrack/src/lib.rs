// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: Apache-2.0
//
// This crate is the permissive (Apache-2.0) client SDK for KeyRack.
//
// It MUST NOT depend on `keyrack-core` or any AGPL-licensed crate. It contains
// no orchestration algorithms — no LID derivation/canonicalization, no
// resolver, no rule engine, no cascade logic, no ciphertext codec. It exposes
// only opaque identifiers, plain DTOs, and the network client. Key identity is
// computed server-side; the SDK treats identifiers as opaque handles. This
// boundary is enforced in CI by `scripts/check-sdk-no-agpl.sh`.

//! High-level Rust client library for KeyRack KMS (Apache-2.0).

/// Opaque key identifier returned by the KeyRack service.
///
/// The SDK never derives, parses, or canonicalizes this value client-side; it
/// is an opaque handle minted by the server. This keeps the crown-jewel LID
/// derivation logic exclusively in the AGPL core.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

pub type Attributes = std::collections::BTreeMap<String, String>;

#[macro_export]
macro_rules! attrs {
    ($($key:ident : $val:expr),* $(,)?) => {{
        let mut map = std::collections::BTreeMap::<String, String>::new();
        $(map.insert(stringify!($key).to_string(), $val.to_string());)*
        map
    }};
}

// ── Builder & Client ────────────────────────────────────────────────────────

pub struct KeyRackBuilder {
    service_url: Option<String>,
}

pub struct KeyRack {
    #[allow(dead_code)]
    service_url: String,
}

impl KeyRack {
    pub fn builder() -> KeyRackBuilder {
        KeyRackBuilder { service_url: None }
    }
}

impl KeyRackBuilder {
    pub fn service_url(mut self, url: &str) -> Self {
        self.service_url = Some(url.to_string());
        self
    }

    pub async fn build(self) -> Result<KeyRack, KeyRackError> {
        let url = self
            .service_url
            .ok_or(KeyRackError::Config("service_url is required".into()))?;
        Ok(KeyRack { service_url: url })
    }
}

// ── Domain Types ────────────────────────────────────────────────────────────

pub struct Namespace {
    pub name: String,
    pub attachment: Attributes,
    pub rules: Vec<RoutingRule>,
}

pub struct RoutingRule {
    pub match_attrs: Attributes,
    pub parent_attrs: Option<Attributes>,
}

impl RoutingRule {
    pub fn new(match_attrs: Attributes, parent_attrs: Option<Attributes>) -> Self {
        Self {
            match_attrs,
            parent_attrs,
        }
    }
}

pub struct ResolvedKey {
    lid: KeyId,
    version: u32,
}

impl ResolvedKey {
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn lid(&self) -> &KeyId {
        &self.lid
    }
}

pub struct ReEncryptionEvent {
    id: String,
    attributes: Attributes,
    old_version: u32,
    new_version: u32,
}

impl ReEncryptionEvent {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }
    pub fn old_version(&self) -> u32 {
        self.old_version
    }
    pub fn new_version(&self) -> u32 {
        self.new_version
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum KeyRackError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("connection error: {0}")]
    Connection(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("service error: {0}")]
    Service(String),
}

// ── Stub Methods ────────────────────────────────────────────────────────────

impl KeyRack {
    pub async fn register_namespace(&self, _ns: Namespace) -> Result<(), KeyRackError> {
        // TODO: wire to gRPC RegisterNamespace
        Ok(())
    }

    pub async fn resolve(&self, _attrs: &Attributes) -> Result<ResolvedKey, KeyRackError> {
        // TODO: wire to gRPC ResolveKey
        Err(KeyRackError::Service(
            "not yet connected to service".into(),
        ))
    }

    pub async fn resolve_at_version(
        &self,
        _attrs: &Attributes,
        _version: u32,
    ) -> Result<ResolvedKey, KeyRackError> {
        // TODO: wire to gRPC ResolveKeyAtVersion
        Err(KeyRackError::Service(
            "not yet connected to service".into(),
        ))
    }

    pub async fn poll_data_reencryption_jobs(
        &self,
        _namespace: &str,
    ) -> Result<Vec<ReEncryptionEvent>, KeyRackError> {
        // TODO: wire to gRPC ListRotationJobs
        Ok(vec![])
    }

    pub async fn acknowledge_reencryption_job(&self, _job_id: &str) -> Result<(), KeyRackError> {
        Ok(())
    }

    pub async fn complete_reencryption_job(&self, _job_id: &str) -> Result<(), KeyRackError> {
        Ok(())
    }
}
