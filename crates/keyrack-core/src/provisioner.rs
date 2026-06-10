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

//! Lazy provisioner with single-flight deduplication.
//!
//! Given an attribute set, the provisioner resolves the key hierarchy
//! chain and ensures every key in the chain exists in storage. Keys
//! that already exist are skipped; missing keys are created bottom-up
//! (root first) through the configured `CryptoProvider`.
//!
//! **Single-flight** guarantees that concurrent requests for the same
//! LID coalesce: only one task generates the key material and writes
//! the record; all other waiters receive the result once the first
//! completes.

use crate::attr::{AttributeSet, AttributeValue};
use crate::error::{KeyRackError, Result};
use crate::key::{KeyOrigin, KeyRecord, KeySpec, KeyState, KeyUsage, KeyVersionRecord};
use crate::lid::Lid;
use crate::registry::ProviderRegistry;
use crate::resolver::{resolve_chain, ResolverConfig};
use crate::routing::ProviderRouter;
use crate::rule::RuleRegistry;
use crate::storage::StorageBackend;
use crate::tags::{IdentityTags, UserTags};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

/// Outcome of a lazy-provision call.
#[derive(Debug, Clone)]
pub struct ProvisionResult {
    /// Full chain from leaf to root.
    pub chain: Vec<Lid>,
    /// LIDs that were newly created during this call.
    pub created: Vec<Lid>,
    /// LIDs that already existed.
    pub existed: Vec<Lid>,
}

/// Configuration for lazy provisioning.
#[derive(Debug, Clone)]
pub struct ProvisionConfig {
    /// Default key spec for auto-provisioned keys when the matched rule
    /// does not specify one.
    pub default_key_spec: KeySpec,
    /// Default key usage for auto-provisioned keys.
    pub default_key_usage: KeyUsage,
    /// Resolver config (max depth, canonicalization version).
    pub resolver: ResolverConfig,
}

impl Default for ProvisionConfig {
    fn default() -> Self {
        Self {
            default_key_spec: KeySpec::Aes256,
            default_key_usage: KeyUsage::EncryptDecrypt,
            resolver: ResolverConfig::default(),
        }
    }
}

type Waiter = broadcast::Sender<std::result::Result<(), String>>;

struct InflightGuard<'a> {
    inflight: &'a Mutex<HashMap<Lid, Waiter>>,
    lid: Lid,
    removed: bool,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        if !self.removed {
            if let Ok(mut map) = self.inflight.try_lock() {
                map.remove(&self.lid);
            }
        }
    }
}

/// Lazy provisioner with single-flight coalescing.
pub struct LazyProvisioner {
    storage: Arc<dyn StorageBackend>,
    providers: Arc<dyn ProviderRegistry>,
    rules: Arc<RuleRegistry>,
    config: ProvisionConfig,
    inflight: Mutex<HashMap<Lid, Waiter>>,
    router: ProviderRouter,
}

impl LazyProvisioner {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        providers: Arc<dyn ProviderRegistry>,
        rules: Arc<RuleRegistry>,
        config: ProvisionConfig,
        router: ProviderRouter,
    ) -> Self {
        Self {
            storage,
            providers,
            rules,
            config,
            inflight: Mutex::new(HashMap::new()),
            router,
        }
    }

    /// Resolve an attribute set to a key chain, provisioning any
    /// missing keys. Returns the full chain and which keys were
    /// newly created.
    pub async fn resolve_and_provision(
        &self,
        attrs: &BTreeMap<String, String>,
    ) -> Result<ProvisionResult> {
        let chain = resolve_chain(&self.rules, attrs, &self.config.resolver)?;

        let mut created = Vec::new();
        let mut existed = Vec::new();

        // Walk the chain root-first so parent keys exist before children.
        let reversed: Vec<_> = chain.iter().rev().copied().collect();

        for (i, lid) in reversed.iter().enumerate() {
            let parent_lid = if i > 0 { Some(&reversed[i - 1]) } else { None };

            match self.ensure_key(lid, parent_lid, attrs).await? {
                KeyProvisionOutcome::Created => created.push(*lid),
                KeyProvisionOutcome::Existed => existed.push(*lid),
            }
        }

        Ok(ProvisionResult {
            chain,
            created,
            existed,
        })
    }

    /// Ensure a single key exists, using single-flight deduplication.
    async fn ensure_key(
        &self,
        lid: &Lid,
        parent_lid: Option<&Lid>,
        attrs: &BTreeMap<String, String>,
    ) -> Result<KeyProvisionOutcome> {
        match self.storage.get_key(lid).await {
            Ok(_) => return Ok(KeyProvisionOutcome::Existed),
            Err(KeyRackError::KeyNotFound(_)) => {}
            Err(e) => return Err(e),
        }

        let mut rx = {
            let mut inflight = self.inflight.lock().await;

            if let Some(tx) = inflight.get(lid) {
                tx.subscribe()
            } else {
                let (tx, _) = broadcast::channel(1);
                inflight.insert(*lid, tx);
                // We are the leader — drop the lock and do the work.
                drop(inflight);
                return self.provision_as_leader(lid, parent_lid, attrs).await;
            }
        };

        // Wait for the leader to finish.
        match rx.recv().await {
            Ok(Ok(())) => Ok(KeyProvisionOutcome::Existed),
            Ok(Err(e)) => Err(KeyRackError::Other(format!(
                "single-flight leader failed for {lid}: {e}"
            ))),
            Err(_) => Err(KeyRackError::Other(format!(
                "single-flight channel closed for {lid}"
            ))),
        }
    }

    /// The leader task: create the key and notify waiters.
    async fn provision_as_leader(
        &self,
        lid: &Lid,
        parent_lid: Option<&Lid>,
        attrs: &BTreeMap<String, String>,
    ) -> Result<KeyProvisionOutcome> {
        let mut guard = InflightGuard {
            inflight: &self.inflight,
            lid: *lid,
            removed: false,
        };

        let result = self.do_provision(lid, parent_lid, attrs).await;

        let mut inflight = self.inflight.lock().await;
        if let Some(tx) = inflight.remove(lid) {
            let broadcast_val = match &result {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(broadcast_val);
        }
        guard.removed = true;

        result
    }

    async fn do_provision(
        &self,
        lid: &Lid,
        parent_lid: Option<&Lid>,
        attrs: &BTreeMap<String, String>,
    ) -> Result<KeyProvisionOutcome> {
        // Double-check: another task may have created the key between
        // our initial check and acquiring the leader slot.
        match self.storage.get_key(lid).await {
            Ok(_) => return Ok(KeyProvisionOutcome::Existed),
            Err(KeyRackError::KeyNotFound(_)) => {}
            Err(e) => return Err(e),
        }

        let rule_match = self.rules.match_rule(attrs);
        let key_spec = rule_match
            .as_ref()
            .and_then(|m| m.rule.key_spec.clone())
            .unwrap_or_else(|| self.config.default_key_spec.clone());

        let now = chrono::Utc::now();
        let mut identity_attrs = AttributeSet::new();
        for (k, v) in attrs {
            identity_attrs.insert(k, AttributeValue::String(v.clone()));
        }
        let identity_tags = IdentityTags::from_attribute_set(&identity_attrs);

        // Route the new key to the appropriate provider based on identity tags.
        let provider_name = self.router.select(&identity_tags);
        let entry = self
            .providers
            .resolve(&provider_name)
            .map_err(|e| KeyRackError::Other(format!("provider routing failed: {e}")))?;
        let key_handle = entry.provider.generate_key(&key_spec).await?;

        let record = KeyRecord {
            lid: *lid,
            canonicalization_version: self.config.resolver.canonicalization_version,
            parent_lid: parent_lid.copied(),
            occ_version: 1,
            current_key_version: 1,
            state: KeyState::Enabled,
            key_usage: self.config.default_key_usage,
            key_spec,
            origin: KeyOrigin::KeyRack,
            provider_class: entry.class,
            provider_ref: Some(provider_name.clone()),
            identity_tags,
            user_tags: UserTags::new(),
            created_at: now,
            updated_at: now,
            scheduled_deletion_at: None,
            description: "auto-provisioned by lazy resolver".into(),
            key_versions: vec![KeyVersionRecord {
                version_number: 1,
                key_handle,
                provider_ref: Some(provider_name.clone()),
                created_at: now,
                is_primary: true,
            }],
        };

        match self.storage.create_key(&record).await {
            Ok(()) => {
                tracing::info!(lid = %lid, "lazy-provisioned key");
                Ok(KeyProvisionOutcome::Created)
            }
            Err(_) => {
                // Another task may have created the key concurrently.
                match self.storage.get_key(lid).await {
                    Ok(_) => Ok(KeyProvisionOutcome::Existed),
                    Err(_) => Err(KeyRackError::Other(format!(
                        "failed to provision key {lid}"
                    ))),
                }
            }
        }
    }
}

impl std::fmt::Debug for LazyProvisioner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyProvisioner")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyProvisionOutcome {
    Created,
    Existed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ProviderRef;
    use crate::provider::inmem::InMemoryProvider;
    use crate::routing::ProviderRouter;
    use crate::rule::*;
    use crate::storage::StorageBackend;
    use std::sync::Arc;

    fn test_registry() -> RuleRegistry {
        let mut reg = RuleRegistry::new();

        reg.register(Namespace {
            name: "_infrastructure_".into(),
            attachment: None,
            max_depth: DEFAULT_MAX_DEPTH,
            routing_rules: vec![
                RoutingRule {
                    match_pattern: BTreeMap::from([("kind".into(), "root".into())]),
                    parent: ParentRef::Root,
                    priority: 0,
                    key_spec: None,
                },
                RoutingRule {
                    match_pattern: BTreeMap::from([
                        ("kind".into(), "tenant-root".into()),
                        ("tenant".into(), "$T".into()),
                    ]),
                    parent: ParentRef::Pattern(BTreeMap::from([("kind".into(), "root".into())])),
                    priority: 0,
                    key_spec: None,
                },
            ],
        });

        reg.register(Namespace {
            name: "app".into(),
            attachment: Some(BTreeMap::from([
                ("kind".into(), "tenant-root".into()),
                ("tenant".into(), "acme".into()),
            ])),
            max_depth: DEFAULT_MAX_DEPTH,
            routing_rules: vec![
                RoutingRule {
                    match_pattern: BTreeMap::from([
                        ("kind".into(), "dek".into()),
                        ("user".into(), "$U".into()),
                    ]),
                    parent: ParentRef::Pattern(BTreeMap::from([("kind".into(), "kek".into())])),
                    priority: 0,
                    key_spec: None,
                },
                RoutingRule {
                    match_pattern: BTreeMap::from([("kind".into(), "kek".into())]),
                    parent: ParentRef::Attachment,
                    priority: 0,
                    key_spec: None,
                },
            ],
        });

        reg
    }

    fn build_memory_storage() -> Arc<dyn StorageBackend> {
        // Use the same MemoryStorage from storage tests — replicate a
        // minimal version here for self-containment.
        use crate::error::KeyRackError;
        use crate::hsm::HsmConnection;
        use crate::rotation::{RotationJob, RotationJobState};
        use async_trait::async_trait;
        use std::sync::Mutex as StdMutex;

        struct Mem {
            keys: StdMutex<HashMap<String, KeyRecord>>,
        }

        impl Mem {
            fn new() -> Self {
                Self {
                    keys: StdMutex::new(HashMap::new()),
                }
            }
        }

        #[async_trait]
        impl StorageBackend for Mem {
            async fn create_key(&self, record: &KeyRecord) -> Result<()> {
                let mut keys = self.keys.lock().unwrap();
                let lid = record.lid.to_string();
                if keys.contains_key(&lid) {
                    return Err(KeyRackError::Other("key already exists".into()));
                }
                keys.insert(lid, record.clone());
                Ok(())
            }
            async fn get_key(&self, lid: &Lid) -> Result<KeyRecord> {
                let keys = self.keys.lock().unwrap();
                keys.get(&lid.to_string())
                    .cloned()
                    .ok_or_else(|| KeyRackError::KeyNotFound(lid.clone()))
            }
            async fn update_key(&self, record: &KeyRecord) -> Result<()> {
                let mut keys = self.keys.lock().unwrap();
                keys.insert(record.lid.to_string(), record.clone());
                Ok(())
            }
            async fn list_keys(
                &self,
                _filter: &crate::storage::KeyFilter,
            ) -> Result<crate::storage::Page<KeyRecord>> {
                Ok(crate::storage::Page {
                    items: vec![],
                    next_cursor: None,
                })
            }
            async fn list_children(&self, parent: &Lid) -> Result<Vec<KeyRecord>> {
                let keys = self.keys.lock().unwrap();
                Ok(keys
                    .values()
                    .filter(|r| r.parent_lid.as_ref() == Some(parent))
                    .cloned()
                    .collect())
            }
            async fn create_alias(&self, _: &crate::storage::AliasRecord) -> Result<()> {
                Ok(())
            }
            async fn resolve_alias(&self, name: &str) -> Result<Lid> {
                Err(KeyRackError::Other(format!("alias not found: {name}")))
            }
            async fn delete_alias(&self, _: &str) -> Result<()> {
                Ok(())
            }
            async fn list_aliases(&self) -> Result<Vec<crate::storage::AliasRecord>> {
                Ok(vec![])
            }
            async fn create_hsm_connection(&self, _: &HsmConnection) -> Result<()> {
                Ok(())
            }
            async fn get_hsm_connection(&self, id: &str) -> Result<HsmConnection> {
                Err(KeyRackError::Other(format!("not found: {id}")))
            }
            async fn update_hsm_connection(&self, _: &HsmConnection) -> Result<()> {
                Ok(())
            }
            async fn list_hsm_connections(&self) -> Result<Vec<HsmConnection>> {
                Ok(vec![])
            }
            async fn delete_hsm_connection(&self, _: &str) -> Result<()> {
                Ok(())
            }
            async fn create_rotation_job(&self, _: &RotationJob) -> Result<()> {
                Ok(())
            }
            async fn get_rotation_job(&self, id: &str) -> Result<RotationJob> {
                Err(KeyRackError::Other(format!("not found: {id}")))
            }
            async fn update_rotation_job(&self, _: &RotationJob) -> Result<()> {
                Ok(())
            }
            async fn list_rotation_jobs(
                &self,
                _: Option<RotationJobState>,
            ) -> Result<Vec<RotationJob>> {
                Ok(vec![])
            }
            async fn ping(&self) -> Result<()> {
                Ok(())
            }
        }

        Arc::new(Mem::new())
    }

    #[tokio::test]
    async fn provision_creates_full_chain() {
        use crate::key::ProviderClass;
        use crate::registry::{ProviderEntry, StaticProviderRegistry};
        use crate::key::ProviderRef;
        let storage = build_memory_storage();
        let provider = Arc::new(InMemoryProvider::new());
        let registry = Arc::new(StaticProviderRegistry::single(provider, ProviderClass::InMemory));
        let rules = Arc::new(test_registry());

        let prov = LazyProvisioner::new(
            Arc::clone(&storage),
            registry,
            rules,
            ProvisionConfig::default(),
            ProviderRouter::new(vec![], ProviderRef::new("default")),
        );

        let attrs = BTreeMap::from([
            ("kind".into(), "dek".into()),
            ("user".into(), "alice".into()),
        ]);

        let result = prov.resolve_and_provision(&attrs).await.unwrap();

        // dek → kek → tenant-root:acme → root = 4 keys
        assert_eq!(result.chain.len(), 4);
        assert_eq!(result.created.len(), 4);
        assert!(result.existed.is_empty());

        // All keys should now exist in storage.
        for lid in &result.chain {
            assert!(storage.get_key(lid).await.is_ok());
        }
    }

    #[tokio::test]
    async fn provision_idempotent() {
        use crate::key::ProviderClass;
        use crate::registry::StaticProviderRegistry;
        let storage = build_memory_storage();
        let provider = Arc::new(InMemoryProvider::new());
        let registry = Arc::new(StaticProviderRegistry::single(provider, ProviderClass::InMemory));
        let rules = Arc::new(test_registry());

        let prov = LazyProvisioner::new(
            Arc::clone(&storage),
            registry,
            rules,
            ProvisionConfig::default(),
            ProviderRouter::new(vec![], ProviderRef::new("default")),
        );

        let attrs = BTreeMap::from([
            ("kind".into(), "dek".into()),
            ("user".into(), "alice".into()),
        ]);

        let r1 = prov.resolve_and_provision(&attrs).await.unwrap();
        assert_eq!(r1.created.len(), 4);

        let r2 = prov.resolve_and_provision(&attrs).await.unwrap();
        assert!(r2.created.is_empty());
        assert_eq!(r2.existed.len(), 4);
    }

    #[tokio::test]
    async fn provision_shares_parent_keys() {
        use crate::key::ProviderClass;
        use crate::registry::StaticProviderRegistry;
        let storage = build_memory_storage();
        let provider = Arc::new(InMemoryProvider::new());
        let registry = Arc::new(StaticProviderRegistry::single(provider, ProviderClass::InMemory));
        let rules = Arc::new(test_registry());

        let prov = LazyProvisioner::new(
            Arc::clone(&storage),
            registry,
            rules,
            ProvisionConfig::default(),
            ProviderRouter::new(vec![], ProviderRef::new("default")),
        );

        let alice_attrs = BTreeMap::from([
            ("kind".into(), "dek".into()),
            ("user".into(), "alice".into()),
        ]);

        let bob_attrs =
            BTreeMap::from([("kind".into(), "dek".into()), ("user".into(), "bob".into())]);

        let r1 = prov.resolve_and_provision(&alice_attrs).await.unwrap();
        assert_eq!(r1.created.len(), 4);

        let r2 = prov.resolve_and_provision(&bob_attrs).await.unwrap();
        // Bob gets a new DEK but shares kek + tenant-root + root with Alice
        assert_eq!(r2.chain.len(), 4);
        assert_eq!(r2.created.len(), 1, "only bob's DEK should be new");
        assert_eq!(
            r2.existed.len(),
            3,
            "kek + tenant-root + root already exist"
        );
    }

    #[tokio::test]
    async fn concurrent_provision_single_flight() {
        use crate::key::ProviderClass;
        use crate::registry::StaticProviderRegistry;
        let storage = build_memory_storage();
        let provider = Arc::new(InMemoryProvider::new());
        let registry = Arc::new(StaticProviderRegistry::single(provider, ProviderClass::InMemory));
        let rules = Arc::new(test_registry());

        let prov = Arc::new(LazyProvisioner::new(
            Arc::clone(&storage),
            registry,
            rules,
            ProvisionConfig::default(),
            ProviderRouter::new(vec![], ProviderRef::new("default")),
        ));

        let attrs = BTreeMap::from([
            ("kind".into(), "dek".into()),
            ("user".into(), "charlie".into()),
        ]);

        let mut handles = Vec::new();
        for _ in 0..10 {
            let p = Arc::clone(&prov);
            let a = attrs.clone();
            handles.push(tokio::spawn(
                async move { p.resolve_and_provision(&a).await },
            ));
        }

        let mut total_created = 0;
        for h in handles {
            let r = h.await.unwrap().unwrap();
            total_created += r.created.len();
        }

        // Exactly 4 keys should have been created, no matter how many
        // concurrent callers there were.
        assert_eq!(total_created, 4);
    }

    #[tokio::test]
    async fn parent_lid_is_set_correctly() {
        use crate::key::ProviderClass;
        use crate::registry::StaticProviderRegistry;
        let storage = build_memory_storage();
        let provider = Arc::new(InMemoryProvider::new());
        let registry = Arc::new(StaticProviderRegistry::single(provider, ProviderClass::InMemory));
        let rules = Arc::new(test_registry());

        let prov = LazyProvisioner::new(
            Arc::clone(&storage),
            registry,
            rules,
            ProvisionConfig::default(),
            ProviderRouter::new(vec![], ProviderRef::new("default")),
        );

        let attrs = BTreeMap::from([
            ("kind".into(), "dek".into()),
            ("user".into(), "alice".into()),
        ]);

        let result = prov.resolve_and_provision(&attrs).await.unwrap();
        let chain = &result.chain;

        // chain[0] = dek (leaf), chain[3] = root
        let root = storage.get_key(&chain[3]).await.unwrap();
        assert!(root.parent_lid.is_none());

        let tenant_root = storage.get_key(&chain[2]).await.unwrap();
        assert_eq!(tenant_root.parent_lid, Some(chain[3]));

        let kek = storage.get_key(&chain[1]).await.unwrap();
        assert_eq!(kek.parent_lid, Some(chain[2]));

        let dek = storage.get_key(&chain[0]).await.unwrap();
        assert_eq!(dek.parent_lid, Some(chain[1]));
    }
}
