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

//! Shared application state injected into every gRPC handler.

use keyrack_core::audit::AuditSink;
use keyrack_core::authn::AuthenticatorChain;
use keyrack_core::pdp::PolicyDecisionPoint;
use keyrack_core::provider::CryptoProvider;
use keyrack_core::storage::StorageBackend;
use keyrack_nats::NatsStateChangedPublisher;
use std::sync::Arc;

/// Shared state available to all RPC handlers.
///
/// Each field is trait-object-based so the service can be configured
/// with different backends (`SQLite` vs `Postgres`, Software vs PKCS#11, etc.)
/// at startup.
pub struct ServiceState {
    pub storage: Arc<dyn StorageBackend>,
    pub provider: Arc<dyn CryptoProvider>,
    pub pdp: Arc<dyn PolicyDecisionPoint>,
    pub audit: Arc<dyn AuditSink>,
    pub authn: Arc<AuthenticatorChain>,
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    pub max_plaintext_bytes: usize,
    pub nats_publisher: Option<Arc<NatsStateChangedPublisher>>,
    pub provider_class: keyrack_core::key::ProviderClass,
}

impl ServiceState {
    /// Emit an audit event for internal operations (e.g. cascade disable).
    pub async fn emit_audit_event(&self, resource_id: &str, detail: &str) {
        use keyrack_core::audit::{
            AuditAction, AuditEvent, AuditPrincipal, AuditResource, AuditResult, EventType,
        };

        let mut event = AuditEvent::new(
            EventType::CascadeDisable,
            AuditAction::CascadeDisable,
            AuditPrincipal {
                id: "keyrack:system".to_string(),
                principal_type: "system".to_string(),
            },
            AuditResource {
                id: resource_id.to_string(),
                resource_type: "key".to_string(),
            },
            AuditResult::Success,
        );
        event.metadata.insert(
            "detail".to_string(),
            serde_json::Value::String(detail.to_string()),
        );
        if let Err(e) = self.audit.emit(&event).await {
            tracing::warn!(resource_id, error = %e, "failed to emit cascade audit event");
        }
    }
}
