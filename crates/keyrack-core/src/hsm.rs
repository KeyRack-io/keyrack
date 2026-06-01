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
            created_at: now,
            updated_at: now,
            last_health_check_at: None,
        }
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
        let mut conn = HsmConnection::new(
            "conn-2",
            HsmProviderType::Hsm,
            "/dev/hsm",
            "test",
        );

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
}
