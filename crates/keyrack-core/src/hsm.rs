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

//! HSM connection lifecycle data model per `KEYRACK_SPEC.md` §5.8.
//!
//! Two provider variants:
//!
//! - **`Hsm`** — operator-managed hardware HSM (PKCS#11).
//! - **`Hyok`** — tenant-managed, true Hold-Your-Own-Key (KMIP).
//!
//! Three-value health status:
//!
//! - **`Healthy`** — reachable and operational.
//! - **`Degraded`** — reachable but rejecting requests (e.g.
//!   tenant-revoked KMIP policy).
//! - **`Down`** — unreachable; periodic health checks restore when
//!   connectivity recovers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// HSM connection provider variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HsmProviderType {
    /// Operator-managed hardware HSM (PKCS#11).
    Hsm,
    /// Tenant-managed HYOK (KMIP).
    Hyok,
}

/// Health status of an HSM connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HsmConnectionStatus {
    Healthy,
    Degraded,
    Down,
}

impl std::fmt::Display for HsmConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => f.write_str("healthy"),
            Self::Degraded => f.write_str("degraded"),
            Self::Down => f.write_str("down"),
        }
    }
}

/// An HSM connection record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConnection {
    pub connection_id: String,
    pub provider_type: HsmProviderType,
    pub status: HsmConnectionStatus,

    /// KMIP endpoint for HYOK connections; PKCS#11 lib path for HSM.
    pub endpoint: String,
    pub description: String,

    /// PKCS#11 token label (`HSM` provider type, Stage 2 dynamic registration).
    /// `None` for HYOK and for legacy/interim records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_label: Option<String>,

    /// Reference to the PKCS#11 PIN (`"file:<path>"`), resolved KeyRack-side
    /// under the `KEYRACK_SECRET_ROOT` allowlist root. **Never** the resolved
    /// PIN bytes — only the reference is persisted; the PIN is re-resolved from
    /// the mount on every construction/rehydration. `None` for HYOK / legacy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_ref: Option<String>,

    /// Scope owner for tenant isolation (ADR-0001 A1.4). Values: "platform",
    /// "tenant:<id>". When set, operations referencing this connection must
    /// carry a principal whose scope attribute matches (exact string equality);
    /// mismatch → `PermissionDenied`. When unset → platform-scoped (no check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_owner: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_health_check_at: Option<DateTime<Utc>>,
}

impl HsmConnection {
    /// Create a new connection in `Healthy` state.
    #[must_use]
    pub fn new(
        connection_id: impl Into<String>,
        provider_type: HsmProviderType,
        endpoint: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            connection_id: connection_id.into(),
            provider_type,
            status: HsmConnectionStatus::Healthy,
            endpoint: endpoint.into(),
            description: description.into(),
            token_label: None,
            pin_ref: None,
            scope_owner: None,
            created_at: now,
            updated_at: now,
            last_health_check_at: None,
        }
    }

    /// Attach PKCS#11 token label + PIN reference (Stage 2 `HSM` connections).
    ///
    /// `endpoint` carries the PKCS#11 `lib_path`; `pin_ref` is a reference
    /// (`"file:<path>"`), never the PIN itself.
    #[must_use]
    pub fn with_pkcs11(
        mut self,
        token_label: impl Into<String>,
        pin_ref: impl Into<String>,
    ) -> Self {
        self.token_label = Some(token_label.into());
        self.pin_ref = Some(pin_ref.into());
        self
    }

    /// Set the scope owner for tenant isolation (ADR-0001 A1.4).
    #[must_use]
    pub fn with_scope_owner(mut self, scope_owner: impl Into<String>) -> Self {
        self.scope_owner = Some(scope_owner.into());
        self
    }

    /// PKCS#11 connection parameters `(lib_path, token_label, pin_ref)` if this
    /// is an `HSM`-type connection with the Stage 2 fields populated.
    ///
    /// `lib_path` is [`Self::endpoint`]. Returns `None` for HYOK connections or
    /// legacy records that predate dynamic PKCS#11 registration.
    #[must_use]
    pub fn pkcs11_params(&self) -> Option<(&str, &str, &str)> {
        if self.provider_type != HsmProviderType::Hsm {
            return None;
        }
        match (self.token_label.as_deref(), self.pin_ref.as_deref()) {
            (Some(label), Some(reference)) => Some((self.endpoint.as_str(), label, reference)),
            _ => None,
        }
    }

    /// Whether two connections describe the *same* underlying PKCS#11 binding.
    /// Used by `CreateHsmConnection` idempotency: a re-registration with the
    /// same id but a different binding is a conflict (ADR-0001 §8).
    #[must_use]
    pub fn same_binding(&self, other: &Self) -> bool {
        self.provider_type == other.provider_type
            && self.endpoint == other.endpoint
            && self.token_label == other.token_label
            && self.pin_ref == other.pin_ref
            && self.scope_owner == other.scope_owner
    }

    /// Update connection status from a health check probe.
    pub fn update_status(&mut self, new_status: HsmConnectionStatus) {
        self.status = new_status;
        self.updated_at = Utc::now();
        self.last_health_check_at = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_connection_starts_healthy() {
        let conn = HsmConnection::new(
            "conn-1",
            HsmProviderType::Hsm,
            "/usr/lib/softhsm/libsofthsm2.so",
            "Dev SoftHSM",
        );
        assert_eq!(conn.status, HsmConnectionStatus::Healthy);
        assert_eq!(conn.provider_type, HsmProviderType::Hsm);
    }

    #[test]
    fn hyok_connection() {
        let conn = HsmConnection::new(
            "conn-hyok",
            HsmProviderType::Hyok,
            "kmip://tenant-hsm.example.com:5696",
            "Tenant HYOK HSM",
        );
        assert_eq!(conn.provider_type, HsmProviderType::Hyok);
    }

    #[test]
    fn status_transitions() {
        let mut conn = HsmConnection::new("conn-2", HsmProviderType::Hsm, "/dev/hsm", "test");

        conn.update_status(HsmConnectionStatus::Degraded);
        assert_eq!(conn.status, HsmConnectionStatus::Degraded);
        assert!(conn.last_health_check_at.is_some());

        conn.update_status(HsmConnectionStatus::Down);
        assert_eq!(conn.status, HsmConnectionStatus::Down);

        conn.update_status(HsmConnectionStatus::Healthy);
        assert_eq!(conn.status, HsmConnectionStatus::Healthy);
    }

    #[test]
    fn display_status() {
        assert_eq!(HsmConnectionStatus::Healthy.to_string(), "healthy");
        assert_eq!(HsmConnectionStatus::Degraded.to_string(), "degraded");
        assert_eq!(HsmConnectionStatus::Down.to_string(), "down");
    }

    #[test]
    fn serde_round_trip() {
        let conn = HsmConnection::new(
            "conn-rt",
            HsmProviderType::Hyok,
            "kmip://localhost:5696",
            "RT test",
        );
        let json = serde_json::to_string(&conn).unwrap();
        let parsed: HsmConnection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connection_id, "conn-rt");
        assert_eq!(parsed.provider_type, HsmProviderType::Hyok);
    }

    #[test]
    fn provider_type_serde() {
        let hsm_json = serde_json::to_string(&HsmProviderType::Hsm).unwrap();
        assert_eq!(hsm_json, r#""HSM""#);
        let hyok_json = serde_json::to_string(&HsmProviderType::Hyok).unwrap();
        assert_eq!(hyok_json, r#""HYOK""#);
    }

    #[test]
    fn pkcs11_params_present_for_hsm_with_fields() {
        let conn = HsmConnection::new(
            "conn-pk",
            HsmProviderType::Hsm,
            "/usr/lib/softhsm/libsofthsm2.so",
            "tenant-a HSM",
        )
        .with_pkcs11("tenant-a", "file:tenant-a.pin");
        assert_eq!(
            conn.pkcs11_params(),
            Some((
                "/usr/lib/softhsm/libsofthsm2.so",
                "tenant-a",
                "file:tenant-a.pin"
            ))
        );
    }

    #[test]
    fn pkcs11_params_none_for_hyok_and_legacy() {
        // HYOK never has PKCS#11 params.
        let hyok = HsmConnection::new("h", HsmProviderType::Hyok, "kmip://x:5696", "")
            .with_pkcs11("ignored", "file:ignored.pin");
        assert_eq!(hyok.pkcs11_params(), None);
        // Legacy HSM record without the Stage 2 fields.
        let legacy = HsmConnection::new("l", HsmProviderType::Hsm, "/lib.so", "");
        assert_eq!(legacy.pkcs11_params(), None);
    }

    #[test]
    fn same_binding_detects_conflict() {
        let a = HsmConnection::new("c", HsmProviderType::Hsm, "/lib.so", "")
            .with_pkcs11("tok", "file:a.pin");
        let same = HsmConnection::new("c", HsmProviderType::Hsm, "/lib.so", "desc differs")
            .with_pkcs11("tok", "file:a.pin");
        let diff_pin = HsmConnection::new("c", HsmProviderType::Hsm, "/lib.so", "")
            .with_pkcs11("tok", "file:b.pin");
        assert!(
            a.same_binding(&same),
            "description is not part of the binding"
        );
        assert!(
            !a.same_binding(&diff_pin),
            "different pin_ref is a conflict"
        );
    }

    #[test]
    fn pin_ref_redacted_field_is_a_reference_not_a_secret() {
        // The persisted field is a reference; serializing the record is safe.
        let conn = HsmConnection::new("c", HsmProviderType::Hsm, "/lib.so", "")
            .with_pkcs11("tok", "file:tenant.pin");
        let json = serde_json::to_string(&conn).unwrap();
        assert!(json.contains("file:tenant.pin"));
        // It must never carry resolved PIN bytes — only the reference.
        assert!(!json.contains("\"pin\""));
    }

    #[test]
    fn legacy_record_without_new_fields_deserializes() {
        // A record persisted before Stage 2 (no token_label/pin_ref keys).
        let legacy = r#"{
            "connection_id": "old",
            "provider_type": "HSM",
            "status": "healthy",
            "endpoint": "/usr/lib/pkcs11.so",
            "description": "legacy",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "last_health_check_at": null
        }"#;
        let parsed: HsmConnection = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.connection_id, "old");
        assert!(parsed.token_label.is_none());
        assert!(parsed.pin_ref.is_none());
        assert_eq!(parsed.pkcs11_params(), None);
    }
}
