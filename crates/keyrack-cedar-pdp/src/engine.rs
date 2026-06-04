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

//! Cedar policy evaluation engine with hot-reload support.

use cedar_policy::{Authorizer, Context, Entities, PolicySet, Request, Schema};
use keyrack_core::pdp::{AuthzRequest, AuthzResponse, Decision, PolicyReason};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CedarEngine {
    authorizer: Authorizer,
    policy_set: Arc<RwLock<PolicySet>>,
    schema: Option<Schema>,
}

impl CedarEngine {
    /// Load policies from Cedar text.
    pub fn new(policies_src: &str, schema_src: Option<&str>) -> Result<Self, String> {
        let policy_set: PolicySet = policies_src
            .parse()
            .map_err(|e| format!("failed to parse policies: {e}"))?;

        let schema = if let Some(src) = schema_src {
            let (schema, _warnings) = Schema::from_cedarschema_str(src)
                .map_err(|e| format!("failed to parse schema: {e}"))?;
            Some(schema)
        } else {
            None
        };

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            schema,
        })
    }

    /// Hot-reload policies from new source text.
    pub async fn reload_policies(&self, policies_src: &str) -> Result<usize, String> {
        let new_set: PolicySet = policies_src
            .parse()
            .map_err(|e| format!("failed to parse policies: {e}"))?;
        let count = new_set.policies().count();
        *self.policy_set.write().await = new_set;
        tracing::info!(count, "hot-reloaded Cedar policies");
        Ok(count)
    }

    /// Evaluate a `KeyRack` authz request against the loaded policies.
    pub async fn evaluate(&self, req: &AuthzRequest) -> Result<AuthzResponse, String> {
        let principal = format!("KeyRack::Principal::\"{}\"", req.principal.id)
            .parse()
            .map_err(|e| format!("bad principal: {e}"))?;
        let action = format!("KeyRack::Action::\"{}\"", req.action.action_name())
            .parse()
            .map_err(|e| format!("bad action: {e}"))?;
        let resource = format!("KeyRack::Resource::\"{}\"", req.resource.id)
            .parse()
            .map_err(|e| format!("bad resource: {e}"))?;
        let context = Context::empty();
        let entities = Entities::empty();

        let cedar_request =
            Request::new(principal, action, resource, context, self.schema.as_ref())
                .map_err(|e| format!("invalid request: {e}"))?;

        let ps = self.policy_set.read().await;
        let response = self
            .authorizer
            .is_authorized(&cedar_request, &ps, &entities);

        let decision = match response.decision() {
            cedar_policy::Decision::Allow => Decision::Permit,
            cedar_policy::Decision::Deny => Decision::Forbid,
        };

        let reasons: Vec<PolicyReason> = response
            .diagnostics()
            .reason()
            .map(|pid| PolicyReason {
                policy_id: pid.to_string(),
                reason_code: None,
                human_message: None,
            })
            .collect();

        Ok(AuthzResponse {
            request_id: req.request_id.clone(),
            decision,
            reasons,
            obligations: vec![],
            policy_version: None,
        })
    }

    pub async fn policy_count(&self) -> usize {
        self.policy_set.read().await.policies().count()
    }
}

/// Extension trait to get a stable action name from `AuditAction`.
trait ActionName {
    fn action_name(&self) -> String;
}

impl ActionName for keyrack_core::audit::AuditAction {
    fn action_name(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{self:?}"))
    }
}
