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

//! Dynamic HSM connection registration (HSM PIN custody, Stage 2).
//!
//! Turns a persisted [`HsmConnection`] into a live PKCS#11 [`CryptoProvider`]
//! and registers it in the runtime [`ProviderRegistry`], so a connection that
//! was created via `CreateHsmConnection` (or persisted from a previous boot)
//! becomes a routing target. The PIN is **re-resolved from the mount** on every
//! construction/rehydration via [`crate::secret_ref`] — `KeyRack` persists only
//! the `pin_ref`, never the PIN bytes.
//!
//! Idempotency/conflict policy (ADR-0001 §8) is a pure decision —
//! [`classify_registration`] — separated from the side-effecting provider
//! construction so it can be unit-tested without a live HSM.

use std::sync::Arc;

use keyrack_core::audit::AuditSink;
use keyrack_core::error::KeyRackError;
use keyrack_core::hsm::{HsmConnection, HsmConnectionStatus, HsmProviderType};
use keyrack_core::key::{ProviderClass, ProviderRef};
use keyrack_core::provider::CryptoProvider;
use keyrack_core::registry::{ProviderEntry, ProviderRegistry};
use keyrack_core::storage::StorageBackend;

/// Outcome of comparing a registration request against the persisted state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationOutcome {
    /// No connection with this id exists yet — register fresh.
    Fresh,
    /// A connection with this id and an **identical** binding already exists —
    /// re-registration is an idempotent no-op (safe under retry / migration).
    Idempotent,
    /// A connection with this id exists but with a **different** binding —
    /// a conflict; the caller must reject (fail-closed), never silently
    /// overwrite (ADR-0001 §8).
    Conflict,
}

/// Classify a registration request against the persisted connection (if any).
///
/// Keyed by `connection_id`; the binding compared is
/// `provider_type + endpoint(lib_path) + token_label + pin_ref` (see
/// [`HsmConnection::same_binding`]) — the human-readable `description` is not
/// part of the identity, so re-registering with a new description is still
/// idempotent.
#[must_use]
pub fn classify_registration(
    existing: Option<&HsmConnection>,
    candidate: &HsmConnection,
) -> RegistrationOutcome {
    match existing {
        None => RegistrationOutcome::Fresh,
        Some(e) if e.same_binding(candidate) => RegistrationOutcome::Idempotent,
        Some(_) => RegistrationOutcome::Conflict,
    }
}

/// Maximum normalized `token_label` length: the PKCS#11 `CK_TOKEN_INFO.label`
/// field is 32 bytes.
pub const MAX_TOKEN_LABEL_BYTES: usize = 32;

/// Maximum `connection_id` length (it becomes a routing key + storage id).
pub const MAX_CONNECTION_ID_BYTES: usize = 128;

/// Normalize an operator-provided `token_label` (ADR-0001 §2, R1).
///
/// Trims trailing whitespace (PKCS#11 labels are space-padded; the read side
/// trims before matching), requires it to be non-empty and `<= 32` bytes when
/// UTF-8 encoded. The returned value is the canonical persisted/compared form.
pub fn normalize_token_label(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim_end();
    if trimmed.is_empty() {
        return Err("token_label must not be empty".to_string());
    }
    if trimmed.len() > MAX_TOKEN_LABEL_BYTES {
        return Err(format!(
            "token_label exceeds {MAX_TOKEN_LABEL_BYTES} bytes (got {})",
            trimmed.len()
        ));
    }
    Ok(trimmed.to_string())
}

/// Scheme-normalize a `pin_ref` so equivalent `file:` forms compare equal
/// (ADR-0001 §8.1, Q11): `file:///a/b` and `file:/a/b` both canonicalize to
/// `file:/a/b`. Non-`file:` references pass through unchanged; resolution
/// rejects them later (`FailedPrecondition`). Symlink/`..` resolution is NOT
/// part of identity — that is a resolution-time allowlist concern.
#[must_use]
pub fn normalize_pin_ref(raw: &str) -> String {
    match raw.strip_prefix("file:") {
        Some(rest) => {
            let path = rest.strip_prefix("//").unwrap_or(rest);
            format!("file:{path}")
        }
        None => raw.to_string(),
    }
}

/// Validate a caller-supplied `connection_id` (ADR-0001 §1.2, Q8): non-empty,
/// no surrounding/only whitespace, `<= 128` bytes, no control characters.
pub fn validate_connection_id(id: &str) -> Result<(), String> {
    if id.trim().is_empty() {
        return Err("connection_id must not be empty".to_string());
    }
    if id != id.trim() {
        return Err("connection_id must not have leading or trailing whitespace".to_string());
    }
    if id.len() > MAX_CONNECTION_ID_BYTES {
        return Err(format!(
            "connection_id exceeds {MAX_CONNECTION_ID_BYTES} bytes"
        ));
    }
    if id.chars().any(char::is_control) {
        return Err("connection_id must not contain control characters".to_string());
    }
    Ok(())
}

/// Failure registering a connection, classified for gRPC status mapping
/// (ADR-0001 §8.2, Q9).
#[derive(Debug)]
pub enum RegisterError {
    /// Malformed request (id/label validation, `oneof`/`provider_type` mismatch).
    /// → `InvalidArgument`.
    Invalid(String),
    /// Same id, different normalized binding. → `AlreadyExists`.
    Conflict(String),
    /// `pin_ref` resolution failure or token-not-found at construction.
    /// → `FailedPrecondition`.
    Precondition(String),
    /// Storage/registry failure. → `Internal`.
    Internal(String),
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::Conflict(m) | Self::Precondition(m) | Self::Internal(m) => {
                f.write_str(m)
            }
        }
    }
}

/// Register (or idempotently re-register) a PKCS#11 HSM connection.
///
/// Validates + normalizes the request, classifies it against the persisted
/// state (ADR-0001 §8), and on a fresh registration constructs the provider
/// (failing closed before persisting anything), persists the canonical record,
/// and registers it as a routing target. Returns the canonical connection
/// record (its `token_label`/`pin_ref` are the normalized forms to echo back).
#[allow(clippy::too_many_arguments)]
pub async fn register_pkcs11_connection(
    storage: &Arc<dyn StorageBackend>,
    registry: &Arc<dyn ProviderRegistry>,
    audit: &Arc<dyn AuditSink>,
    connection_id: &str,
    lib_path: &str,
    token_label_raw: &str,
    pin_ref_raw: &str,
    description: &str,
) -> Result<HsmConnection, RegisterError> {
    validate_connection_id(connection_id).map_err(RegisterError::Invalid)?;
    let token_label = normalize_token_label(token_label_raw).map_err(RegisterError::Invalid)?;
    let pin_ref = normalize_pin_ref(pin_ref_raw);

    let candidate = HsmConnection::new(connection_id, HsmProviderType::Hsm, lib_path, description)
        .with_pkcs11(token_label, pin_ref);

    // No dedicated NotFound variant exists for HSM connections; the storage
    // backends signal a missing row via `Other("hsm connection not found: …")`.
    let existing = match storage.get_hsm_connection(connection_id).await {
        Ok(c) => Some(c),
        Err(KeyRackError::Other(msg)) if msg.contains("not found") => None,
        Err(e) => return Err(RegisterError::Internal(e.to_string())),
    };

    match classify_registration(existing.as_ref(), &candidate) {
        RegistrationOutcome::Idempotent => {
            // Identical normalized binding already registered — return existing
            // without reconstructing (safe under retry / cutover migration).
            return Ok(existing.expect("idempotent outcome implies an existing record"));
        }
        RegistrationOutcome::Conflict => {
            return Err(RegisterError::Conflict(format!(
                "hsm connection '{connection_id}' already exists with a different binding"
            )));
        }
        RegistrationOutcome::Fresh => {}
    }

    // Construct BEFORE persisting: an unresolvable pin_ref or unreachable token
    // fails closed (FailedPrecondition) leaving nothing persisted or registered
    // (ADR-0001 §3). This also emits the secret_access(construct) event carrying
    // the caller's connection_id, before this RPC responds (ADR-0001 §5.2, Q10).
    let provider = build_pkcs11_provider_from_connection(&candidate, "construct", audit)
        .await
        .map_err(|e| RegisterError::Precondition(e.to_string()))?;

    storage
        .create_hsm_connection(&candidate)
        .await
        .map_err(|e| RegisterError::Internal(e.to_string()))?;

    registry
        .register(
            ProviderRef::new(candidate.connection_id.clone()),
            ProviderEntry {
                provider,
                class: ProviderClass::Pkcs11,
            },
        )
        .map_err(|e| RegisterError::Internal(e.to_string()))?;

    tracing::info!(
        connection_id = %candidate.connection_id,
        "registered HSM connection provider"
    );
    Ok(candidate)
}

/// Construct a live PKCS#11 provider from a persisted connection record.
///
/// Resolves the connection's `pin_ref` `KeyRack`-side (emitting a `secret_access`
/// audit event for `phase`) and opens the PKCS#11 token. Returns an error
/// (never a panic) if the connection isn't a PKCS#11 connection, the `pin_ref`
/// is unresolvable, or the token can't be opened — callers fail closed.
pub async fn build_pkcs11_provider_from_connection(
    conn: &HsmConnection,
    phase: &str,
    audit: &Arc<dyn AuditSink>,
) -> Result<Arc<dyn CryptoProvider>, Box<dyn std::error::Error>> {
    let (lib_path, token_label, pin_ref) =
        conn.pkcs11_params()
            .ok_or_else(|| -> Box<dyn std::error::Error> {
                format!(
                    "hsm connection '{}' is not a PKCS#11 connection with token_label + pin_ref",
                    conn.connection_id
                )
                .into()
            })?;

    // Re-resolve the PIN from the mount; never persisted. Emits secret_access.
    let resolved_pin = crate::secret_ref::resolve_pkcs11_pin(
        &conn.connection_id,
        None,
        Some(pin_ref),
        phase,
        audit,
    )
    .await?;

    let cfg = keyrack_pkcs11::Pkcs11ProviderConfig {
        lib_path: lib_path.to_string(),
        token_label: token_label.to_string(),
        pin: resolved_pin.expose().to_string(),
    };
    Ok(Arc::new(keyrack_pkcs11::Pkcs11Provider::new(&cfg)?))
}

/// Rehydrate persisted HSM connections into the runtime registry at boot.
///
/// For each PKCS#11 connection (HYOK/legacy interim records are skipped — they
/// aren't dynamically routed in Stage 2), reconstruct the provider and register
/// it under `ProviderRef(connection_id)`. A connection that fails to rehydrate
/// is **fail-closed for that connection only**: it is marked `Degraded` and the
/// process keeps serving every other connection (ADR-0001 §3, window 3).
///
/// Returns the number of connections successfully registered.
pub async fn rehydrate_hsm_connections(
    storage: &Arc<dyn StorageBackend>,
    registry: &Arc<dyn ProviderRegistry>,
    audit: &Arc<dyn AuditSink>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let connections = storage.list_hsm_connections().await?;
    let mut registered = 0usize;

    for conn in connections {
        if conn.pkcs11_params().is_none() {
            // HYOK and legacy interim records carry no PKCS#11 binding to
            // rehydrate; they remain accepted-but-unrouted metadata.
            continue;
        }

        match build_pkcs11_provider_from_connection(&conn, "rehydrate", audit).await {
            Ok(provider) => {
                registry.register(
                    ProviderRef::new(conn.connection_id.clone()),
                    ProviderEntry {
                        provider,
                        class: ProviderClass::Pkcs11,
                    },
                )?;
                registered += 1;
                tracing::info!(
                    connection_id = %conn.connection_id,
                    "rehydrated HSM connection provider"
                );
            }
            Err(e) => {
                tracing::error!(
                    connection_id = %conn.connection_id,
                    error = %e,
                    "failed to rehydrate HSM connection; marking degraded"
                );
                let mut degraded = conn.clone();
                degraded.update_status(HsmConnectionStatus::Degraded);
                if let Err(ue) = storage.update_hsm_connection(&degraded).await {
                    tracing::error!(
                        connection_id = %degraded.connection_id,
                        error = %ue,
                        "failed to persist degraded status after rehydration failure"
                    );
                }
            }
        }
    }

    Ok(registered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrack_core::hsm::HsmProviderType;

    fn pkcs11_conn(id: &str, pin_ref: &str) -> HsmConnection {
        HsmConnection::new(
            id,
            HsmProviderType::Hsm,
            "/usr/lib/softhsm/libsofthsm2.so",
            "",
        )
        .with_pkcs11("tenant", pin_ref)
    }

    #[test]
    fn classify_fresh_when_absent() {
        let cand = pkcs11_conn("c1", "file:a.pin");
        assert_eq!(
            classify_registration(None, &cand),
            RegistrationOutcome::Fresh
        );
    }

    #[test]
    fn classify_idempotent_on_identical_binding() {
        let existing = pkcs11_conn("c1", "file:a.pin");
        // Same binding, different description -> still idempotent.
        let mut cand = pkcs11_conn("c1", "file:a.pin");
        cand.description = "re-registered".into();
        assert_eq!(
            classify_registration(Some(&existing), &cand),
            RegistrationOutcome::Idempotent
        );
    }

    #[test]
    fn classify_conflict_on_changed_binding() {
        let existing = pkcs11_conn("c1", "file:a.pin");
        let cand = pkcs11_conn("c1", "file:b.pin");
        assert_eq!(
            classify_registration(Some(&existing), &cand),
            RegistrationOutcome::Conflict
        );
    }

    // --- rehydration (no live HSM needed) ---

    use keyrack_core::audit::{AuditEvent, AuditSink};

    fn in_memory_storage() -> Arc<dyn StorageBackend> {
        Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"))
    }

    struct NullSink;
    #[async_trait::async_trait]
    impl AuditSink for NullSink {
        async fn emit(&self, _event: &AuditEvent) -> keyrack_core::error::Result<()> {
            Ok(())
        }
    }

    fn dynamic_registry() -> Arc<dyn ProviderRegistry> {
        use keyrack_core::provider::inmem::InMemoryProvider;
        use keyrack_core::registry::DynamicProviderRegistry;
        Arc::new(
            DynamicProviderRegistry::new(
                [(
                    ProviderRef::new("default"),
                    ProviderEntry {
                        provider: Arc::new(InMemoryProvider::new()),
                        class: ProviderClass::InMemory,
                    },
                )],
                ProviderRef::new("default"),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn rehydration_skips_hyok_and_legacy() {
        let storage = in_memory_storage();
        // HYOK: no PKCS#11 binding.
        storage
            .create_hsm_connection(&HsmConnection::new(
                "hyok-1",
                HsmProviderType::Hyok,
                "kmip://x:5696",
                "",
            ))
            .await
            .unwrap();
        // Legacy HSM: no token_label/pin_ref.
        storage
            .create_hsm_connection(&HsmConnection::new(
                "legacy-1",
                HsmProviderType::Hsm,
                "/lib.so",
                "",
            ))
            .await
            .unwrap();

        let registry = dynamic_registry();
        let audit: Arc<dyn AuditSink> = Arc::new(NullSink);
        let n = rehydrate_hsm_connections(&storage, &registry, &audit)
            .await
            .unwrap();
        assert_eq!(n, 0, "no PKCS#11 connections to rehydrate");
        assert!(!registry.contains(&ProviderRef::new("hyok-1")));
        assert!(!registry.contains(&ProviderRef::new("legacy-1")));
    }

    #[tokio::test]
    async fn rehydration_marks_unresolvable_connection_degraded() {
        let storage = in_memory_storage();
        // A PKCS#11 connection whose pin_ref cannot resolve (no such mount):
        // construction fails -> fail-closed for this connection only.
        storage
            .create_hsm_connection(&pkcs11_conn("c-bad", "file:does-not-exist.pin"))
            .await
            .unwrap();

        let registry = dynamic_registry();
        let audit: Arc<dyn AuditSink> = Arc::new(NullSink);
        let n = rehydrate_hsm_connections(&storage, &registry, &audit)
            .await
            .unwrap();
        assert_eq!(n, 0, "the connection failed to rehydrate");
        assert!(!registry.contains(&ProviderRef::new("c-bad")));

        // The process kept serving; the connection is now Degraded.
        let after = storage.get_hsm_connection("c-bad").await.unwrap();
        assert_eq!(after.status, HsmConnectionStatus::Degraded);
    }

    // --- normalization / validation (pure) ---

    #[test]
    fn token_label_trims_trailing_and_rejects_empty() {
        assert_eq!(normalize_token_label("tenant-a   ").unwrap(), "tenant-a");
        assert_eq!(normalize_token_label("tenant-a").unwrap(), "tenant-a");
        assert!(normalize_token_label("   ").is_err());
        assert!(normalize_token_label("").is_err());
    }

    #[test]
    fn token_label_enforces_32_byte_limit() {
        let max = "a".repeat(MAX_TOKEN_LABEL_BYTES);
        assert_eq!(normalize_token_label(&max).unwrap(), max);
        let over = "a".repeat(MAX_TOKEN_LABEL_BYTES + 1);
        assert!(normalize_token_label(&over).is_err());
        // Trailing whitespace is trimmed before the length check.
        let padded = format!("{}{}", "a".repeat(MAX_TOKEN_LABEL_BYTES), "    ");
        assert_eq!(normalize_token_label(&padded).unwrap(), max);
    }

    #[test]
    fn pin_ref_scheme_normalizes_equivalent_file_forms() {
        // file:///a/b and file:/a/b both canonicalize to file:/a/b (Q11).
        assert_eq!(normalize_pin_ref("file:///a/b"), "file:/a/b");
        assert_eq!(normalize_pin_ref("file:/a/b"), "file:/a/b");
        // Relative reference under the allowlist root is preserved.
        assert_eq!(normalize_pin_ref("file:tenant.pin"), "file:tenant.pin");
        // Non-file references pass through unchanged (rejected at resolution).
        assert_eq!(normalize_pin_ref("env:PIN"), "env:PIN");
    }

    #[test]
    fn connection_id_validation() {
        assert!(validate_connection_id("conn-1").is_ok());
        assert!(validate_connection_id("").is_err());
        assert!(validate_connection_id("   ").is_err());
        assert!(validate_connection_id(" conn-1").is_err());
        assert!(validate_connection_id("conn-1 ").is_err());
        assert!(validate_connection_id(&"a".repeat(MAX_CONNECTION_ID_BYTES + 1)).is_err());
        assert!(validate_connection_id("conn\n1").is_err());
    }

    // --- register_pkcs11_connection (error paths reachable without a live HSM) ---

    fn lib_path() -> &'static str {
        "/usr/lib/softhsm/libsofthsm2.so"
    }

    #[tokio::test]
    async fn register_rejects_invalid_connection_id() {
        let storage = in_memory_storage();
        let registry = dynamic_registry();
        let audit: Arc<dyn AuditSink> = Arc::new(NullSink);
        let err = register_pkcs11_connection(
            &storage,
            &registry,
            &audit,
            "",
            lib_path(),
            "tenant",
            "file:a.pin",
            "",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterError::Invalid(_)));
    }

    #[tokio::test]
    async fn register_rejects_oversized_token_label() {
        let storage = in_memory_storage();
        let registry = dynamic_registry();
        let audit: Arc<dyn AuditSink> = Arc::new(NullSink);
        let huge = "a".repeat(MAX_TOKEN_LABEL_BYTES + 1);
        let err = register_pkcs11_connection(
            &storage,
            &registry,
            &audit,
            "c1",
            lib_path(),
            &huge,
            "file:a.pin",
            "",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterError::Invalid(_)));
    }

    #[tokio::test]
    async fn register_idempotent_returns_existing_without_construction() {
        let storage = in_memory_storage();
        // Pre-insert the canonical record (as a prior registration would leave it).
        storage
            .create_hsm_connection(&pkcs11_conn("c1", "file:a.pin"))
            .await
            .unwrap();
        let registry = dynamic_registry();
        let audit: Arc<dyn AuditSink> = Arc::new(NullSink);
        // Raw inputs normalizing to the same binding (trailing ws on the label).
        let conn = register_pkcs11_connection(
            &storage,
            &registry,
            &audit,
            "c1",
            lib_path(),
            "tenant   ",
            "file:a.pin",
            "ignored-description",
        )
        .await
        .unwrap();
        assert_eq!(conn.connection_id, "c1");
        assert_eq!(conn.token_label.as_deref(), Some("tenant"));
        // No new provider was constructed/registered (idempotent no-op).
        assert!(!registry.contains(&ProviderRef::new("c1")));
    }

    #[tokio::test]
    async fn register_conflict_on_changed_binding() {
        let storage = in_memory_storage();
        storage
            .create_hsm_connection(&pkcs11_conn("c1", "file:a.pin"))
            .await
            .unwrap();
        let registry = dynamic_registry();
        let audit: Arc<dyn AuditSink> = Arc::new(NullSink);
        let err = register_pkcs11_connection(
            &storage,
            &registry,
            &audit,
            "c1",
            lib_path(),
            "tenant",
            "file:b.pin",
            "",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterError::Conflict(_)));
    }

    #[tokio::test]
    async fn register_fresh_unresolvable_pin_is_precondition_and_persists_nothing() {
        let storage = in_memory_storage();
        let registry = dynamic_registry();
        let audit: Arc<dyn AuditSink> = Arc::new(NullSink);
        let err = register_pkcs11_connection(
            &storage,
            &registry,
            &audit,
            "c-new",
            lib_path(),
            "tenant",
            "file:definitely-missing-pin-file.pin",
            "",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterError::Precondition(_)));
        // Fail-closed: nothing persisted, nothing registered.
        assert!(matches!(
            storage.get_hsm_connection("c-new").await,
            Err(KeyRackError::Other(_))
        ));
        assert!(!registry.contains(&ProviderRef::new("c-new")));
    }
}
