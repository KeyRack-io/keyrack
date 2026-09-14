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

//! `CreateKey` with a parent: what gets created, and what gets refused.
//!
//! From 0.5.0 a `parent_key_id` means the child's material is wrapped under
//! that parent. These tests drive the real service creation path against real
//! `SQLite` storage and a real provider, so every refusal here is the refusal
//! a caller would receive.

use keyrack_core::key::{
    Exportability, KeyMaterial, KeyRecord, KeySpec, KeyState, KeyVersionRecord, ProviderClass,
    ProviderRef,
};
use keyrack_core::provider::software::{SoftwareProvider, SOFTWARE_WRAPPING_MECHANISM};
use keyrack_core::provider::CryptoProvider;
use keyrack_core::provider::KeyHandle;
use keyrack_core::registry::{ProviderEntry, ProviderRegistry, StaticProviderRegistry};
use keyrack_core::storage::StorageBackend;
use keyrack_core::wrapping::WrappingIdentifier;
use keyrack_service::domain::{self, CreateKeyInput, DomainError};
use keyrack_service::hierarchy::{WrappingProfile, WrappingProfiles};
use keyrack_service::routing::ProviderRouter;
use keyrack_service::state::ServiceState;
use std::collections::BTreeMap;
use std::sync::Arc;

const DOMAIN: &str = "test-single-process";
const PARENT_PROVIDER: &str = "default";
const OTHER_PROVIDER: &str = "other";

/// These tests assert on refusals, not on audit output.
struct SilentAudit;

#[async_trait::async_trait]
impl keyrack_core::audit::AuditSink for SilentAudit {
    async fn emit(
        &self,
        _event: &keyrack_core::audit::AuditEvent,
    ) -> keyrack_core::error::Result<()> {
        Ok(())
    }
}

/// A provider that declares the wrapping profile but cannot evidence closure.
///
/// This is the shape a partial implementation takes: the capability dump looks
/// right, and nothing would notice until a creation needed to be resolved.
/// Only the capability questions are answered; this stub is never asked to do
/// cryptography, and says so rather than pretending to.
struct NoClosureEvidence(Arc<dyn CryptoProvider>);

#[async_trait::async_trait]
impl CryptoProvider for NoClosureEvidence {
    fn wrapping_capabilities(&self) -> keyrack_core::wrapping::WrappingCapabilities {
        self.0.wrapping_capabilities()
    }

    fn wrapping_closure_verifier(
        &self,
    ) -> Option<Arc<dyn keyrack_core::creation::A2ClosureVerifier>> {
        None
    }

    fn capabilities(&self) -> keyrack_core::provider::ProviderCapabilities {
        self.0.capabilities()
    }

    async fn generate_key(&self, _spec: &KeySpec) -> keyrack_core::error::Result<KeyHandle> {
        unreachable!("capability stub")
    }

    async fn encrypt(
        &self,
        _handle: &KeyHandle,
        _plaintext: &[u8],
        _aad: &[u8],
    ) -> keyrack_core::error::Result<keyrack_core::provider::EncryptOutput> {
        unreachable!("capability stub")
    }

    async fn decrypt(
        &self,
        _handle: &KeyHandle,
        _ciphertext: &[u8],
        _aad: &[u8],
    ) -> keyrack_core::error::Result<keyrack_core::sensitive::Sensitive<Vec<u8>>> {
        unreachable!("capability stub")
    }

    async fn sign(
        &self,
        _handle: &KeyHandle,
        _algorithm: keyrack_core::provider::SigningAlgorithm,
        _message: &[u8],
    ) -> keyrack_core::error::Result<Vec<u8>> {
        unreachable!("capability stub")
    }

    async fn verify(
        &self,
        _handle: &KeyHandle,
        _algorithm: keyrack_core::provider::SigningAlgorithm,
        _message: &[u8],
        _signature: &[u8],
    ) -> keyrack_core::error::Result<bool> {
        unreachable!("capability stub")
    }

    async fn generate_random(
        &self,
        _length: usize,
    ) -> keyrack_core::error::Result<keyrack_core::sensitive::Sensitive<Vec<u8>>> {
        unreachable!("capability stub")
    }

    async fn destroy_key(&self, _handle: &KeyHandle) -> keyrack_core::error::Result<()> {
        unreachable!("capability stub")
    }
}

fn identifier(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).expect("valid identifier")
}

fn profile(mechanism: &str) -> WrappingProfile {
    WrappingProfile {
        mechanism: identifier(mechanism),
        security_domain: identifier(DOMAIN),
    }
}

/// A provider scoped exactly as startup would scope it for `name`.
fn scoped(name: &str) -> Arc<dyn CryptoProvider> {
    Arc::new(SoftwareProvider::scoped(
        ProviderRef::new(name),
        identifier(DOMAIN),
    ))
}

fn entry(provider: Arc<dyn CryptoProvider>) -> ProviderEntry {
    ProviderEntry {
        provider,
        class: ProviderClass::Software,
    }
}

/// A service with real `SQLite` storage, one or two software providers, and the
/// wrapping profiles an operator would have configured.
fn state(
    providers: Vec<(&str, Arc<dyn CryptoProvider>)>,
    wrapping: Vec<(&str, WrappingProfile)>,
) -> Arc<ServiceState> {
    let storage: Arc<dyn StorageBackend> =
        Arc::new(keyrack_sqlite::SqliteStorage::in_memory().expect("in-memory SQLite"));
    let registry: Arc<dyn ProviderRegistry> = Arc::new(
        StaticProviderRegistry::new(
            providers
                .into_iter()
                .map(|(name, provider)| (ProviderRef::new(name), entry(provider))),
            ProviderRef::new(PARENT_PROVIDER),
        )
        .expect("registry"),
    );
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    Arc::new(ServiceState {
        storage,
        providers: registry,
        provider_router: ProviderRouter::new(vec![], ProviderRef::new(PARENT_PROVIDER)).unwrap(),
        pdp: Arc::new(keyrack_core::pdp::AlwaysAllow),
        audit: Arc::new(SilentAudit),
        authn: Arc::new(keyrack_core::authn::AuthenticatorChain::new(vec![
            Box::new(keyrack_core::authn::InsecureAuthenticator),
        ])),
        metrics_handle: recorder.handle(),
        max_plaintext_bytes: 4096,
        legacy_compromised_key_decrypt: false,
        nats_publisher: None,
        wrapping: WrappingProfiles::new(
            wrapping
                .into_iter()
                .map(|(name, profile)| (ProviderRef::new(name), profile)),
        ),
    })
}

/// The default deployment: one software provider, wrapping activated on it.
fn activated() -> Arc<ServiceState> {
    state(
        vec![(PARENT_PROVIDER, scoped(PARENT_PROVIDER))],
        vec![(PARENT_PROVIDER, profile(SOFTWARE_WRAPPING_MECHANISM))],
    )
}

fn input(spec: KeySpec, parent: Option<&KeyRecord>) -> CreateKeyInput {
    CreateKeyInput {
        key_spec: spec,
        attributes: BTreeMap::new(),
        namespace: String::new(),
        description: None,
        exportable: Exportability::NonExportable,
        parent_key_id: parent.map(|p| p.lid.to_string()),
        hsm_connection_id: None,
        backend_id: None,
    }
}

async fn parent_key(state: &Arc<ServiceState>) -> KeyRecord {
    domain::create_key(state, input(KeySpec::Aes256, None))
        .await
        .expect("parent creation")
}

async fn child_error(state: &Arc<ServiceState>, input: CreateKeyInput) -> String {
    domain::create_key(state, input)
        .await
        .map(|record| record.lid)
        .expect_err("child creation must be refused")
        .to_string()
}

#[tokio::test]
async fn a_child_is_created_wrapped_under_its_parent() {
    let state = activated();
    let parent = parent_key(&state).await;

    let child = domain::create_key(&state, input(KeySpec::Aes256, Some(&parent)))
        .await
        .expect("child creation");

    assert_eq!(child.parent_lid, Some(parent.lid));
    let version = child.primary_version().expect("primary version");
    let KeyMaterial::ParentWrapped(material) = &version.material else {
        panic!("a child of a parent must be wrapped, not independently resident");
    };
    // The descriptor records exactly what the deployment declared, so a later
    // reader knows which backend and construction to ask for.
    assert_eq!(material.mechanism().as_str(), SOFTWARE_WRAPPING_MECHANISM);
    assert_eq!(material.security_domain().as_str(), DOMAIN);
    assert_eq!(material.provider_ref().as_str(), PARENT_PROVIDER);
    assert_eq!(material.parent().lid, parent.lid);
    assert_eq!(material.parent().version.get(), parent.current_key_version);

    // The child is durable and readable as what it is.
    let stored = state.storage.get_key(&child.lid).await.expect("stored");
    assert!(matches!(
        stored.primary_version().unwrap().material,
        KeyMaterial::ParentWrapped(_)
    ));
    assert!(!stored.has_legacy_parent_semantics());
    assert_eq!(stored.state, KeyState::Enabled);
}

#[tokio::test]
async fn the_wrapped_envelope_is_retained_where_the_descriptor_points() {
    let state = activated();
    let parent = parent_key(&state).await;
    let child = domain::create_key(&state, input(KeySpec::Aes256, Some(&parent)))
        .await
        .expect("child creation");

    let KeyMaterial::ParentWrapped(material) = &child.primary_version().unwrap().material else {
        panic!("expected wrapped material");
    };
    let reference = material.wrapped_material_ref().as_str();
    let operation: uuid::Uuid = reference
        .strip_prefix("creation:")
        .expect("material reference names a creation")
        .parse()
        .expect("creation identifier");
    let envelope = state
        .storage
        .read_creation_envelope(operation)
        .await
        .expect("the wrapped material the descriptor points at must exist");
    assert!(!envelope.is_empty());
}

#[tokio::test]
async fn a_provider_without_a_configured_profile_refuses_child_creation() {
    // Same provider, same capability: the only difference is that no operator
    // activated wrapping on it.
    let state = state(vec![(PARENT_PROVIDER, scoped(PARENT_PROVIDER))], vec![]);
    let parent = parent_key(&state).await;

    let error = child_error(&state, input(KeySpec::Aes256, Some(&parent))).await;
    assert!(
        error.contains("not configured to wrap child keys"),
        "unexpected error: {error}"
    );
    assert_eq!(
        state
            .storage
            .list_keys(&filter())
            .await
            .unwrap()
            .items
            .len(),
        1,
        "a refused child must leave nothing behind"
    );
}

#[tokio::test]
async fn a_provider_that_does_not_implement_wrapping_refuses_child_creation() {
    // The in-memory provider declares no wrapping tuples and has no closure
    // verifier: this is the PKCS#11 and Vault position until they implement it.
    let state = state(
        vec![(
            PARENT_PROVIDER,
            Arc::new(keyrack_core::provider::inmem::InMemoryProvider::new()),
        )],
        vec![(PARENT_PROVIDER, profile(SOFTWARE_WRAPPING_MECHANISM))],
    );
    let parent = parent_key(&state).await;

    let error = child_error(&state, input(KeySpec::Aes256, Some(&parent))).await;
    assert!(
        error.contains("cannot wrap child keys"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn a_declared_profile_the_provider_does_not_implement_refuses_at_startup() {
    let provider = scoped(PARENT_PROVIDER);
    let name = ProviderRef::new(PARENT_PROVIDER);

    keyrack_service::hierarchy::verify_wrapping_profile(
        &name,
        &profile(SOFTWARE_WRAPPING_MECHANISM),
        provider.as_ref(),
    )
    .expect("the mechanism this provider declares must be accepted");

    let error = keyrack_service::hierarchy::verify_wrapping_profile(
        &name,
        &profile("pkcs11:aes-key-wrap-pad:v1"),
        provider.as_ref(),
    )
    .expect_err("a mechanism the provider does not declare must refuse to start");
    assert!(
        error.contains("does not declare it"),
        "unexpected error: {error}"
    );

    let error = keyrack_service::hierarchy::verify_wrapping_profile(
        &name,
        &profile(SOFTWARE_WRAPPING_MECHANISM),
        &keyrack_core::provider::inmem::InMemoryProvider::new(),
    )
    .expect_err("a provider that declares nothing must refuse to start");
    assert!(
        error.contains("does not declare it"),
        "unexpected error: {error}"
    );

    // Declaring the mechanism is not enough: without closure evidence a
    // journaled creation on this provider could never be resolved, and the
    // operator should learn that at startup rather than mid-creation.
    let error = keyrack_service::hierarchy::verify_wrapping_profile(
        &name,
        &profile(SOFTWARE_WRAPPING_MECHANISM),
        &NoClosureEvidence(scoped(PARENT_PROVIDER)),
    )
    .expect_err("a provider that cannot evidence closure must refuse to start");
    assert!(
        error.contains("cannot evidence wrapped-key closure"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn a_child_must_be_in_the_same_security_domain_as_its_parent() {
    // Two providers, both able to wrap, both activated. The parent lives on one
    // of them, so the other cannot hold its children (ADR-0004 A2).
    let mut state = state(
        vec![
            (PARENT_PROVIDER, scoped(PARENT_PROVIDER)),
            (OTHER_PROVIDER, scoped(OTHER_PROVIDER)),
        ],
        vec![
            (PARENT_PROVIDER, profile(SOFTWARE_WRAPPING_MECHANISM)),
            (OTHER_PROVIDER, profile(SOFTWARE_WRAPPING_MECHANISM)),
        ],
    );
    // Routing that lets the caller pick a backend, so the refusal under test is
    // the security-domain rule and not the routing policy in front of it.
    Arc::get_mut(&mut state)
        .expect("sole reference")
        .provider_router = ProviderRouter::with_rules(
        vec![keyrack_core::routing::RoutingRule {
            match_tags: BTreeMap::new(),
            action: keyrack_core::routing::RuleAction::DelegateAny,
        }],
        ProviderRef::new(PARENT_PROVIDER),
    )
    .unwrap();
    let parent = parent_key(&state).await;

    let mut child = input(KeySpec::Aes256, Some(&parent));
    child.backend_id = Some(OTHER_PROVIDER.into());
    let error = child_error(&state, child).await;
    assert!(
        error.contains("same security domain as its parent"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn only_symmetric_encryption_keys_can_be_children() {
    let state = activated();
    let parent = parent_key(&state).await;

    for spec in [KeySpec::Hmac256, KeySpec::EcdsaP256Sha256] {
        let error = child_error(&state, input(spec.clone(), Some(&parent))).await;
        assert!(
            error.contains("cannot be a child"),
            "unexpected error for {spec:?}: {error}"
        );
    }
}

#[tokio::test]
async fn a_child_cannot_be_exportable() {
    let state = activated();
    let parent = parent_key(&state).await;

    let mut child = input(KeySpec::Aes256, Some(&parent));
    child.exportable = Exportability::Exportable;
    let error = child_error(&state, child).await;
    assert!(
        error.contains("cannot be exportable"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn an_exportable_parent_cannot_wrap_children() {
    let state = activated();
    let mut parent = parent_key(&state).await;
    parent.exportability = Exportability::Exportable;
    parent.occ_version += 1;
    state.storage.update_key(&parent).await.unwrap();

    let error = child_error(&state, input(KeySpec::Aes256, Some(&parent))).await;
    assert!(
        error.contains("is exportable and cannot wrap child keys"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn a_wrapped_key_cannot_itself_wrap_children() {
    let state = activated();
    let parent = parent_key(&state).await;
    let child = domain::create_key(&state, input(KeySpec::Aes256, Some(&parent)))
        .await
        .expect("child creation");

    let error = child_error(&state, input(KeySpec::Aes256, Some(&child))).await;
    assert!(
        error.contains("not an independently resident key"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn a_disabled_or_compromised_parent_cannot_wrap_children() {
    for state_after in [KeyState::Disabled, KeyState::Compromised] {
        let state = activated();
        let mut parent = parent_key(&state).await;
        parent.transition_to(state_after).expect("transition");
        state.storage.update_key(&parent).await.unwrap();

        let error = child_error(&state, input(KeySpec::Aes256, Some(&parent))).await;
        assert!(
            error.contains("not an eligible wrapping key"),
            "unexpected error for {state_after:?}: {error}"
        );
    }
}

#[tokio::test]
async fn a_parent_created_before_0_5_0_is_refused_by_name() {
    let state = activated();
    let grandparent = parent_key(&state).await;

    // A pre-0.5.0 child: a parent binding alongside independently resident
    // material, which is what the earlier lineage-only meaning produced.
    let mut legacy = parent_key(&state).await;
    legacy.parent_lid = Some(grandparent.lid);
    legacy.occ_version += 1;
    state.storage.update_key(&legacy).await.unwrap();
    let stored = state.storage.get_key(&legacy.lid).await.unwrap();
    assert!(
        stored.has_legacy_parent_semantics(),
        "the fixture must be detectable as pre-0.5.0"
    );

    let error = child_error(&state, input(KeySpec::Aes256, Some(&legacy))).await;
    assert!(
        error.contains("require migration before use in 0.5 and later"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn a_parent_with_no_explicit_provider_binding_cannot_wrap_children() {
    let state = activated();
    let mut parent = parent_key(&state).await;

    // Strip every binding: what remains resolves only through the registry
    // default, which is not a record of where the material actually is.
    parent.provider_ref = None;
    parent.key_versions = parent
        .key_versions
        .iter()
        .map(|version| {
            let KeyMaterial::ProviderResident { key_handle, .. } = &version.material else {
                panic!("expected resident material");
            };
            KeyVersionRecord {
                version_number: version.version_number,
                material: KeyMaterial::ProviderResident {
                    key_handle: key_handle.clone(),
                    provider_ref: None,
                },
                created_at: version.created_at,
                is_primary: version.is_primary,
            }
        })
        .collect();
    parent.occ_version += 1;
    state.storage.update_key(&parent).await.unwrap();

    let error = child_error(&state, input(KeySpec::Aes256, Some(&parent))).await;
    assert!(
        error.contains("no explicit provider binding"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn a_refused_child_is_a_precondition_failure_not_an_internal_error() {
    let state = state(vec![(PARENT_PROVIDER, scoped(PARENT_PROVIDER))], vec![]);
    let parent = parent_key(&state).await;

    let error = domain::create_key(&state, input(KeySpec::Aes256, Some(&parent)))
        .await
        .map(|record| record.lid)
        .expect_err("must be refused");
    assert!(
        matches!(error, DomainError::FailedPrecondition(_)),
        "a caller must be told this cannot be done here, not that something broke: {error:?}"
    );
}

fn filter() -> keyrack_core::storage::KeyFilter {
    keyrack_core::storage::KeyFilter {
        user_tags: vec![],
        state: None,
        owner_principal_id: None,
        limit: Some(100),
        cursor: None,
    }
}
