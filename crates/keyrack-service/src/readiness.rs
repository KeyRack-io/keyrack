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
}

impl CustodyReadiness {
    pub fn insert(&mut self, name: ProviderRef, provider: Arc<dyn CryptoProvider>) {
        self.optional.insert(name, provider);
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
    let metadata_ok = if let Ok(Ok(connections)) = connections {
        let mut complete = true;
        for connection in connections {
            if connection.pkcs11_params().is_some()
                && !entries.iter().any(|(name, entry)| {
                    *name == ProviderRef::new(&connection.connection_id)
                        && entry.class == ProviderClass::Pkcs11
                })
            {
                complete = false;
                report.states.insert(
                    connection.connection_id,
                    ProviderState {
                        custody: ProviderCustody::Platform,
                        status: "missing",
                    },
                );
            }
        }
        complete
    } else {
        false
    };
    while let Some(result) = probes.join_next().await {
        if let Ok((name, ready)) = result {
            if ready {
                if let Some(state) = report.states.get_mut(&name.to_string()) {
                    if state.status != "missing" {
                        state.status = "available";
                    }
                }
            }
        }
    }
    report.ready = metadata_ok
        && report
            .states
            .values()
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
