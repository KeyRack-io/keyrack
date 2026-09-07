// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Default-deny lifecycle enforcement and explicitly dangerous legacy decrypt.
//! This does not authorize callers: the ordinary PDP/scope gates still apply.

use crate::{domain::DomainError, ops::OpContext, state::ServiceState};
use keyrack_core::audit::{AuditEvent, AuditPrincipal, AuditResource, AuditResult, EventType};
use keyrack_core::key::{KeyRecord, KeyState};

/// A state check's result, retained until immediately before provider dispatch.
/// The legacy case must be recorded even when the provider subsequently fails.
#[must_use]
pub struct DecryptPermission {
    legacy: bool,
}

/// Check the logical key, not just its current enum or current key version.
pub fn check_decrypt(
    state: &ServiceState,
    record: &KeyRecord,
) -> Result<DecryptPermission, DomainError> {
    if record.permits_decrypt() {
        return Ok(DecryptPermission { legacy: false });
    }
    if state.legacy_compromised_key_decrypt && record.state == KeyState::Compromised {
        return Ok(DecryptPermission { legacy: true });
    }
    Err(DomainError::FailedPrecondition(format!(
        "key {} is in state {} (compromise history: {}) — decrypt not permitted",
        record.lid,
        record.state,
        record.has_compromise_history()
    )))
}

impl DecryptPermission {
    /// Record actual use of the legacy override, after all other gates and
    /// immediately before dispatch. Success means the override was exercised;
    /// the enclosing operation's audit event records the crypto result.
    /// Audit delivery is best-effort: errors are logged, not release-suppressed.
    pub async fn record_use(self, state: &ServiceState, record: &KeyRecord, ctx: &OpContext) {
        if !self.legacy {
            return;
        }
        tracing::warn!(
            legacy_compromised_key_decrypt = true,
            key_id = %record.lid,
            principal_id = %ctx.principal.id,
            request_id = %ctx.request_id,
            action = %ctx.action,
            "SECURITY: dangerous legacy compromised-key decrypt override exercised"
        );
        let mut event = AuditEvent::new(
            EventType::CryptoOperation,
            ctx.action.clone(),
            AuditPrincipal {
                id: ctx.principal.id.clone(),
                principal_type: ctx.principal.principal_type.clone(),
            },
            AuditResource::key(&record.lid),
            AuditResult::Success,
        )
        .with_request_id(ctx.request_id.clone());
        event.add_metadata("legacy_compromised_key_decrypt", "true");
        event.add_metadata("phase", "provider_dispatch");
        event.add_metadata("key_state", record.state.to_string());
        if let Err(error) = state.audit.emit(&event).await {
            tracing::warn!(
                legacy_compromised_key_decrypt = true,
                key_id = %record.lid,
                request_id = %ctx.request_id,
                %error,
                "failed to deliver legacy compromised-key decrypt audit marker (best-effort)"
            );
        }
    }
}
