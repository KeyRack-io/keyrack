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
use keyrack_core::hsm::{HsmConnection, HsmConnectionStatus};
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
}
