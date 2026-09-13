// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded live provider readiness, independent of advertised capabilities.

use keyrack_core::key::{ProviderClass, ProviderRef};
use keyrack_core::registry::ProviderRegistry;
use keyrack_core::storage::StorageBackend;
use std::sync::Arc;
use std::time::Duration;

/// Total provider readiness budget, independent of the number of providers.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Probe every registered backend and reject missing persisted PKCS#11
/// connections (including failed boot rehydration). This reads connection
/// metadata and authenticates sessions, without reading or changing key material.
pub async fn providers_ready(
    providers: Arc<dyn ProviderRegistry>,
    storage: Arc<dyn StorageBackend>,
) -> bool {
    tokio::time::timeout(PROBE_TIMEOUT, async {
        let Ok(connections) = storage.list_hsm_connections().await else {
            return false;
        };
        let Ok(entries) = providers.entries() else {
            return false;
        };
        if entries.is_empty() {
            return false;
        }
        for connection in connections {
            if connection.pkcs11_params().is_some()
                && !entries.iter().any(|(name, entry)| {
                    *name == ProviderRef::new(&connection.connection_id)
                        && entry.class == ProviderClass::Pkcs11
                })
            {
                return false;
            }
        }
        let mut probes = tokio::task::JoinSet::new();
        for (_, entry) in entries {
            probes.spawn(async move { entry.provider.check_readiness().await });
        }
        let mut ready = true;
        while let Some(result) = probes.join_next().await {
            ready &= matches!(result, Ok(Ok(())));
        }
        ready
    })
    .await
    .unwrap_or(false)
}
