// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded live provider readiness, independent of advertised capabilities.

use keyrack_core::key::{ProviderClass, ProviderRef};
use keyrack_core::provider::CryptoProvider;
use keyrack_core::registry::ProviderRegistry;
use keyrack_core::storage::StorageBackend;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

/// Total provider readiness budget, independent of the number of providers.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCustody {
    #[default]
    Platform,
    Customer,
}

/// Only explicitly configured instances are exempt. Runtime registration under
/// the same name must not inherit another instance's readiness exemption.
#[derive(Clone, Default)]
pub struct CustodyReadiness {
    optional: HashMap<ProviderRef, Arc<dyn CryptoProvider>>,
    required: HashMap<ProviderRef, Arc<dyn CryptoProvider>>,
}

impl CustodyReadiness {
    pub fn insert(&mut self, name: ProviderRef, provider: Arc<dyn CryptoProvider>) {
        self.optional.insert(name, provider);
    }

    pub fn configure(
        &mut self,
        name: ProviderRef,
        provider: Arc<dyn CryptoProvider>,
        custody: ProviderCustody,
    ) {
        match custody {
            ProviderCustody::Customer => self.insert(name, provider),
            ProviderCustody::Platform => {
                self.required.insert(name, provider);
            }
        }
    }

    fn is_configured(&self, name: &ProviderRef, provider: &Arc<dyn CryptoProvider>) -> bool {
        self.optional
            .get(name)
            .or_else(|| self.required.get(name))
            .is_some_and(|configured| Arc::ptr_eq(configured, provider))
    }

    fn custody(&self, name: &ProviderRef, provider: &Arc<dyn CryptoProvider>) -> ProviderCustody {
        if self
            .optional
            .get(name)
            .is_some_and(|configured| Arc::ptr_eq(configured, provider))
        {
            ProviderCustody::Customer
        } else {
            ProviderCustody::Platform
        }
    }
}

#[derive(Serialize)]
pub struct ProviderState {
    pub custody: ProviderCustody,
    pub status: &'static str,
}

#[derive(Default)]
pub struct ProviderReadiness {
    pub ready: bool,
    pub states: BTreeMap<String, ProviderState>,
    pub connections: BTreeMap<String, ProviderState>,
}

/// Probe every registered backend, retaining the persisted PKCS#11 connection
/// guard. Neither probe failures nor timeouts of explicitly exempt instances
/// change readiness of the remaining providers. Raw backend errors stay private.
pub async fn provider_readiness(
    providers: Arc<dyn ProviderRegistry>,
    storage: Arc<dyn StorageBackend>,
    custody: &CustodyReadiness,
) -> ProviderReadiness {
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    let Ok(entries) = providers.entries() else {
        return ProviderReadiness::default();
    };
    if entries.is_empty() {
        return ProviderReadiness::default();
    }
    let mut report = ProviderReadiness::default();
    let mut probes = tokio::task::JoinSet::new();
    for (name, entry) in entries.iter().cloned() {
        report.states.insert(
            name.to_string(),
            ProviderState {
                custody: custody.custody(&name, &entry.provider),
                status: "unavailable",
            },
        );
        probes.spawn(async move {
            let ready = matches!(
                tokio::time::timeout_at(deadline, entry.provider.check_readiness()).await,
                Ok(Ok(()))
            );
            (name, ready)
        });
    }
    let connections = tokio::time::timeout_at(deadline, storage.list_hsm_connections()).await;
    let metadata_ok = connections.as_ref().is_ok_and(Result::is_ok);
    let connections = connections.ok().and_then(Result::ok).unwrap_or_default();
    for connection in &connections {
        if connection.pkcs11_params().is_some() {
            let name = ProviderRef::new(&connection.connection_id);
            let owner = if connection.scope_owner.as_deref().is_some_and(|owner| {
                owner
                    .strip_prefix("tenant:")
                    .is_some_and(|tenant| !tenant.is_empty())
            }) {
                ProviderCustody::Customer
            } else {
                ProviderCustody::Platform
            };
            report.connections.insert(
                connection.connection_id.clone(),
                ProviderState {
                    custody: owner,
                    status: "unavailable",
                },
            );
            if let Some((_, entry)) = entries.iter().find(|(entry_name, entry)| {
                *entry_name == name && entry.class == ProviderClass::Pkcs11
            }) {
                if !custody.is_configured(&name, &entry.provider) {
                    if let Some(state) = report.states.get_mut(&connection.connection_id) {
                        state.custody = owner;
                    }
                }
            }
        }
    }
    while let Some(result) = probes.join_next().await {
        if let Ok((name, ready)) = result {
            if ready {
                if let Some(state) = report.states.get_mut(&name.to_string()) {
                    state.status = "available";
                }
            }
        }
    }
    for (name, state) in &mut report.connections {
        if entries.iter().any(|(entry_name, entry)| {
            entry_name.as_str() == name
                && entry.class == ProviderClass::Pkcs11
                && !custody.is_configured(entry_name, &entry.provider)
        }) {
            if let Some(provider) = report.states.get(name) {
                state.status = provider.status;
            }
        }
    }
    report.ready = metadata_ok
        && report
            .states
            .values()
            .chain(report.connections.values())
            .all(|state| state.custody == ProviderCustody::Customer || state.status == "available");
    report
}

pub async fn providers_ready(
    providers: Arc<dyn ProviderRegistry>,
    storage: Arc<dyn StorageBackend>,
) -> bool {
    provider_readiness(providers, storage, &CustodyReadiness::default())
        .await
        .ready
}
