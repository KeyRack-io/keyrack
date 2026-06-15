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

//! Provider registry: resolves which [`CryptoProvider`] backs a given key
//! version.
//!
//! `KeyRack` can be configured with several named providers (e.g. a software
//! default plus one HSM per tenant). Each [`KeyRecord`]/[`KeyVersionRecord`]
//! carries an optional [`ProviderRef`] selecting one of them; `None` means
//! "use the default". The registry turns that binding into a concrete
//! provider at call time.
//!
//! Resolution order for a version (see [`KeyRecord::effective_provider_ref`]):
//! `version.provider_ref` -> `record.provider_ref` -> registry default.
//!
//! This is the routing layer that lets a single service front multiple
//! backends (multi-tenant HYOK, per-node hierarchy backends) and lets a key
//! straddle two providers during an HSM-to-HSM migration.

use crate::error::{KeyRackError, Result};
use crate::key::{KeyRecord, ProviderClass, ProviderRef};
use crate::provider::CryptoProvider;
use std::collections::HashMap;
use std::sync::Arc;

/// A configured provider together with its class metadata.
#[derive(Clone)]
pub struct ProviderEntry {
    pub provider: Arc<dyn CryptoProvider>,
    pub class: ProviderClass,
}

/// Resolves the crypto provider that backs a key or key version.
///
/// Object-safe: used behind `Arc<dyn ProviderRegistry>` in the service.
pub trait ProviderRegistry: Send + Sync {
    /// Resolve a provider by explicit name. Errors if the name is unknown.
    fn resolve(&self, name: &ProviderRef) -> Result<ProviderEntry>;

    /// The default provider entry, used when a key/version has no binding.
    fn default_entry(&self) -> ProviderEntry;

    /// The name of the default provider.
    fn default_ref(&self) -> &ProviderRef;

    /// Resolve the effective provider for a specific key version, applying
    /// the `version -> record -> default` precedence.
    fn resolve_for_version(
        &self,
        record: &KeyRecord,
        version_number: u64,
    ) -> Result<ProviderEntry> {
        match record.effective_provider_ref(version_number) {
            Some(name) => self.resolve(name),
            None => Ok(self.default_entry()),
        }
    }

    /// Resolve the provider for the record's current (primary) version.
    fn resolve_for_primary(&self, record: &KeyRecord) -> Result<ProviderEntry> {
        self.resolve_for_version(record, record.current_key_version)
    }

    /// Register (or replace) a provider at runtime, keyed by name.
    ///
    /// Static registries reject this — runtime registration is a Stage 2
    /// capability used by `CreateHsmConnection` for self-service HSM
    /// onboarding. Idempotency/conflict policy lives in the caller (it compares
    /// the persisted connection record); the registry itself is last-write-wins.
    fn register(&self, _name: ProviderRef, _entry: ProviderEntry) -> Result<()> {
        Err(KeyRackError::Other(
            "provider registry is static; runtime registration is not supported".into(),
        ))
    }

    /// Remove a runtime-registered provider. Static registries reject this.
    fn remove(&self, _name: &ProviderRef) -> Result<()> {
        Err(KeyRackError::Other(
            "provider registry is static; runtime removal is not supported".into(),
        ))
    }

    /// Whether a provider with this name is currently registered.
    fn contains(&self, name: &ProviderRef) -> bool {
        self.resolve(name).is_ok()
    }
}

/// A registry built once at startup from a fixed set of named providers.
pub struct StaticProviderRegistry {
    providers: HashMap<ProviderRef, ProviderEntry>,
    default: ProviderRef,
}

impl StaticProviderRegistry {
    /// Build from named providers and the name of the default.
    ///
    /// Errors if there are no providers, or if `default` does not name one
    /// of them.
    pub fn new(
        providers: impl IntoIterator<Item = (ProviderRef, ProviderEntry)>,
        default: ProviderRef,
    ) -> Result<Self> {
        let providers: HashMap<ProviderRef, ProviderEntry> = providers.into_iter().collect();
        if providers.is_empty() {
            return Err(KeyRackError::Other(
                "provider registry must contain at least one provider".into(),
            ));
        }
        if !providers.contains_key(&default) {
            return Err(KeyRackError::Other(format!(
                "default provider '{default}' is not among the configured providers"
            )));
        }
        Ok(Self { providers, default })
    }

    /// Convenience for the single-provider (back-compat) case: one provider
    /// named `"default"`.
    #[must_use]
    pub fn single(provider: Arc<dyn CryptoProvider>, class: ProviderClass) -> Self {
        let name = ProviderRef::new("default");
        let mut providers = HashMap::new();
        providers.insert(name.clone(), ProviderEntry { provider, class });
        Self {
            providers,
            default: name,
        }
    }

    /// Names of all configured providers (diagnostics, capabilities).
    pub fn names(&self) -> impl Iterator<Item = &ProviderRef> {
        self.providers.keys()
    }

    /// Number of configured providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether the registry has no providers (never true post-construction).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

impl ProviderRegistry for StaticProviderRegistry {
    fn resolve(&self, name: &ProviderRef) -> Result<ProviderEntry> {
        self.providers
            .get(name)
            .cloned()
            .ok_or_else(|| KeyRackError::ProviderUnavailable(format!("unknown provider '{name}'")))
    }

    fn default_entry(&self) -> ProviderEntry {
        self.providers
            .get(&self.default)
            .cloned()
            .expect("default provider present by construction")
    }

    fn default_ref(&self) -> &ProviderRef {
        &self.default
    }
}

/// A registry whose provider set can grow at runtime.
///
/// Seeded at startup from the static config (so the default and any
/// deploy-time providers are present from boot), then extended by
/// `CreateHsmConnection` (Stage 2 self-service HSM registration) and by boot
/// rehydration of persisted connections. Reads take a shared lock; runtime
/// registration takes an exclusive lock.
pub struct DynamicProviderRegistry {
    providers: std::sync::RwLock<HashMap<ProviderRef, ProviderEntry>>,
    default: ProviderRef,
}

impl DynamicProviderRegistry {
    /// Build from the seed (static-config) providers and the default name.
    ///
    /// Errors if the seed is empty or `default` does not name one of them.
    pub fn new(
        providers: impl IntoIterator<Item = (ProviderRef, ProviderEntry)>,
        default: ProviderRef,
    ) -> Result<Self> {
        let providers: HashMap<ProviderRef, ProviderEntry> = providers.into_iter().collect();
        if providers.is_empty() {
            return Err(KeyRackError::Other(
                "provider registry must contain at least one provider".into(),
            ));
        }
        if !providers.contains_key(&default) {
            return Err(KeyRackError::Other(format!(
                "default provider '{default}' is not among the configured providers"
            )));
        }
        Ok(Self {
            providers: std::sync::RwLock::new(providers),
            default,
        })
    }

    /// Names of all currently-registered providers (snapshot).
    #[must_use]
    pub fn names(&self) -> Vec<ProviderRef> {
        self.providers
            .read()
            .expect("provider registry lock poisoned")
            .keys()
            .cloned()
            .collect()
    }

    /// Number of currently-registered providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers
            .read()
            .expect("provider registry lock poisoned")
            .len()
    }

    /// Whether the registry has no providers (never true post-construction).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers
            .read()
            .expect("provider registry lock poisoned")
            .is_empty()
    }
}

impl ProviderRegistry for DynamicProviderRegistry {
    fn resolve(&self, name: &ProviderRef) -> Result<ProviderEntry> {
        self.providers
            .read()
            .expect("provider registry lock poisoned")
            .get(name)
            .cloned()
            .ok_or_else(|| KeyRackError::ProviderUnavailable(format!("unknown provider '{name}'")))
    }

    fn default_entry(&self) -> ProviderEntry {
        self.providers
            .read()
            .expect("provider registry lock poisoned")
            .get(&self.default)
            .cloned()
            .expect("default provider present by construction")
    }

    fn default_ref(&self) -> &ProviderRef {
        &self.default
    }

    fn register(&self, name: ProviderRef, entry: ProviderEntry) -> Result<()> {
        self.providers
            .write()
            .expect("provider registry lock poisoned")
            .insert(name, entry);
        Ok(())
    }

    fn remove(&self, name: &ProviderRef) -> Result<()> {
        if name == &self.default {
            return Err(KeyRackError::Other(
                "cannot remove the default provider".into(),
            ));
        }
        self.providers
            .write()
            .expect("provider registry lock poisoned")
            .remove(name);
        Ok(())
    }

    fn contains(&self, name: &ProviderRef) -> bool {
        self.providers
            .read()
            .expect("provider registry lock poisoned")
            .contains_key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::make_test_record;
    use crate::key::KeyState;
    use crate::provider::inmem::InMemoryProvider;

    fn entry() -> ProviderEntry {
        ProviderEntry {
            provider: Arc::new(InMemoryProvider::new()),
            class: ProviderClass::InMemory,
        }
    }

    fn registry() -> StaticProviderRegistry {
        StaticProviderRegistry::new(
            [
                (ProviderRef::new("default"), entry()),
                (ProviderRef::new("tenant-a"), entry()),
            ],
            ProviderRef::new("default"),
        )
        .unwrap()
    }

    #[test]
    fn rejects_empty() {
        let r = StaticProviderRegistry::new(std::iter::empty(), ProviderRef::new("x"));
        assert!(r.is_err());
    }

    #[test]
    fn rejects_default_not_present() {
        let r = StaticProviderRegistry::new(
            [(ProviderRef::new("a"), entry())],
            ProviderRef::new("missing"),
        );
        assert!(r.is_err());
    }

    #[test]
    fn resolve_known_and_unknown() {
        let reg = registry();
        assert!(reg.resolve(&ProviderRef::new("tenant-a")).is_ok());
        let err = reg.resolve(&ProviderRef::new("nope"));
        assert!(matches!(err, Err(KeyRackError::ProviderUnavailable(_))));
    }

    #[test]
    fn default_resolution() {
        let reg = registry();
        assert_eq!(reg.default_ref(), &ProviderRef::new("default"));
        assert_eq!(reg.default_entry().class, ProviderClass::InMemory);
    }

    #[test]
    fn resolve_for_version_precedence() {
        let reg = registry();
        let mut record = make_test_record(KeyState::Enabled);

        // No binding => default.
        assert!(reg.resolve_for_version(&record, 1).is_ok());

        // Version-level binding to a known provider resolves.
        record.key_versions[0].provider_ref = Some(ProviderRef::new("tenant-a"));
        assert!(reg.resolve_for_version(&record, 1).is_ok());

        // Version-level binding to an unknown provider errors.
        record.key_versions[0].provider_ref = Some(ProviderRef::new("ghost"));
        assert!(matches!(
            reg.resolve_for_version(&record, 1),
            Err(KeyRackError::ProviderUnavailable(_))
        ));
    }

    #[test]
    fn single_provider_back_compat() {
        let reg = StaticProviderRegistry::single(
            Arc::new(InMemoryProvider::new()),
            ProviderClass::Software,
        );
        assert_eq!(reg.default_ref(), &ProviderRef::new("default"));
        let record = make_test_record(KeyState::Enabled);
        // A legacy record with no binding resolves to the single default.
        assert!(reg.resolve_for_primary(&record).is_ok());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn static_registry_rejects_runtime_registration() {
        let reg = registry();
        let err = reg.register(ProviderRef::new("late"), entry());
        assert!(matches!(err, Err(KeyRackError::Other(_))));
        assert!(reg.remove(&ProviderRef::new("tenant-a")).is_err());
    }

    fn dynamic_registry() -> DynamicProviderRegistry {
        DynamicProviderRegistry::new(
            [(ProviderRef::new("default"), entry())],
            ProviderRef::new("default"),
        )
        .unwrap()
    }

    #[test]
    fn dynamic_rejects_empty_and_missing_default() {
        assert!(DynamicProviderRegistry::new(std::iter::empty(), ProviderRef::new("x")).is_err());
        assert!(DynamicProviderRegistry::new(
            [(ProviderRef::new("a"), entry())],
            ProviderRef::new("missing"),
        )
        .is_err());
    }

    #[test]
    fn dynamic_register_then_resolve() {
        let reg = dynamic_registry();
        let name = ProviderRef::new("tenant-x-hsm");
        assert!(!reg.contains(&name));
        assert!(reg.resolve(&name).is_err());

        reg.register(name.clone(), entry()).unwrap();
        assert!(reg.contains(&name));
        assert!(reg.resolve(&name).is_ok());
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn dynamic_register_is_last_write_wins() {
        // Idempotency/conflict policy lives in the caller; the registry itself
        // simply replaces. Re-registering the same name must not error or grow.
        let reg = dynamic_registry();
        let name = ProviderRef::new("tenant-y-hsm");
        reg.register(name.clone(), entry()).unwrap();
        reg.register(name.clone(), entry()).unwrap();
        assert_eq!(reg.len(), 2);
        assert!(reg.contains(&name));
    }

    #[test]
    fn dynamic_remove_non_default_but_not_default() {
        let reg = dynamic_registry();
        let name = ProviderRef::new("ephemeral");
        reg.register(name.clone(), entry()).unwrap();
        assert!(reg.contains(&name));

        reg.remove(&name).unwrap();
        assert!(!reg.contains(&name));

        // The default cannot be removed.
        assert!(reg.remove(&ProviderRef::new("default")).is_err());
        assert!(reg.contains(&ProviderRef::new("default")));
    }

    #[test]
    fn dynamic_resolves_for_version_after_registration() {
        let reg = dynamic_registry();
        reg.register(ProviderRef::new("tenant-a"), entry()).unwrap();
        let mut record = make_test_record(KeyState::Enabled);
        record.key_versions[0].provider_ref = Some(ProviderRef::new("tenant-a"));
        assert!(reg.resolve_for_version(&record, 1).is_ok());
    }
}
