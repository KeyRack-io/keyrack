// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conformance for the software wrapping profile: the ADR-0005 operations
//! exercised against real AES-256-GCM, and every refusal they owe.
//!
//! What passes here is a mechanism, not custody. Parent, envelope and unwrapped
//! child all live in this process's heap, so nothing in this file establishes
//! that a software-wrapped child is provider-contained. It is not.

use keyrack_core::canon::CanonicalizationVersion;
use keyrack_core::creation::{
    creation_correlation, CreationBinding, CreationOwner, CreationRequest,
};
use keyrack_core::key::{
    Exportability, KeyOrigin, KeyRecord, KeySpec, KeyState, KeyUsage, KeyVersionRecord,
    ProviderClass, ProviderRef,
};
use keyrack_core::lid::Lid;
use keyrack_core::material::{KeyMaterial, ParentWrappedMaterial};
use keyrack_core::provider::inmem::InMemoryProvider;
use keyrack_core::provider::software::{SoftwareProvider, SOFTWARE_WRAPPING_MECHANISM};
use keyrack_core::provider::{CryptoProvider, KeyHandle, WrappedKeyLease};
use keyrack_core::tags::{IdentityTags, UserTags};
use keyrack_core::wrapping::{
    VersionedKeyId, WrappedKeyFormat, WrappedKeyLifecycle, WrappingCapability, WrappingContext,
    WrappingContextVersion, WrappingError, WrappingIdentifier, WrappingKeyPurpose,
    WrappingOperation,
};
use uuid::Uuid;

/// 12-byte nonce, 32-byte wrapped child, 16-byte tag.
const ENVELOPE_BYTES: usize = 60;

fn name(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).unwrap()
}

fn context(parent: &KeyHandle) -> WrappingContext {
    WrappingContext {
        version: WrappingContextVersion::V1,
        child: VersionedKeyId::new(Lid::from_bytes([7; 32]), 1).unwrap(),
        parent: VersionedKeyId::new(Lid::from_bytes([9; 32]), 3).unwrap(),
        parent_spec: parent.key_spec.clone(),
        child_spec: KeySpec::Aes256,
        key_format: WrappedKeyFormat::RawSecret,
        purpose: WrappingKeyPurpose::EncryptDecrypt,
        provider_ref: ProviderRef::new("software-test"),
        security_domain: name("software-test-domain"),
        mechanism: name(SOFTWARE_WRAPPING_MECHANISM),
        public_material_sha256: None,
    }
}

/// A creation whose context is the one above, so a binding taken from it is a
/// real one rather than a shape a test invented for the provider.
fn creation(context: &WrappingContext) -> CreationRequest {
    let material = ParentWrappedMaterial::new(
        context.provider_ref.clone(),
        context.security_domain.clone(),
        context.parent,
        context.version,
        context.key_format.clone(),
        context.mechanism.clone(),
        name("kr-a2-envelope-software-test"),
    )
    .unwrap();
    let record = KeyRecord {
        lid: context.child.lid,
        canonicalization_version: CanonicalizationVersion::V2,
        parent_lid: Some(context.parent.lid),
        occ_version: 1,
        current_key_version: context.child.version.get(),
        state: KeyState::Enabled,
        was_compromised: false,
        key_usage: KeyUsage::EncryptDecrypt,
        key_spec: context.child_spec.clone(),
        origin: KeyOrigin::KeyRack,
        provider_class: ProviderClass::Software,
        provider_ref: Some(context.provider_ref.clone()),
        exportability: Exportability::NonExportable,
        first_exported_at: None,
        owner_principal_id: None,
        identity_tags: IdentityTags::from_map(std::collections::BTreeMap::new()).unwrap(),
        user_tags: UserTags::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        scheduled_deletion_at: None,
        description: String::new(),
        key_versions: vec![KeyVersionRecord {
            version_number: context.child.version.get(),
            material: KeyMaterial::ParentWrapped(material),
            created_at: chrono::Utc::now(),
            is_primary: true,
        }],
    };
    let operation = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let mut request = CreationRequest {
        operation,
        attempt,
        owner: CreationOwner {
            instance: Uuid::new_v4(),
            generation: 1,
        },
        correlation: creation_correlation(operation, attempt),
        record,
        expected_key_occ: None,
        expected_parent_occ: 1,
        parent_spec: context.parent_spec.clone(),
        context_bytes: Vec::new(),
    };
    request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
    request.validate().unwrap();
    request
}

/// The binding of one creation of that child, for the operations that need to
/// know which creation they are having an effect for.
fn binding(context: &WrappingContext) -> CreationBinding {
    CreationBinding::of(&creation(context)).unwrap()
}

async fn parented() -> (SoftwareProvider, KeyHandle, WrappingContext) {
    let provider = SoftwareProvider::new();
    let parent = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let context = context(&parent);
    (provider, parent, context)
}

#[tokio::test]
async fn a_wrapped_child_is_generated_opened_used_and_closed() {
    let (provider, parent, ctx) = parented().await;

    let generated = provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap();
    assert_eq!(generated.envelope.len(), ENVELOPE_BYTES);

    // Encrypt under the creation lease, then decrypt under a separately opened
    // lease: the same child has to come back out of the envelope for this to
    // pass, which is what makes the child usable rather than merely recorded.
    let sealed = provider
        .encrypt(generated.lease.handle(), b"child payload", b"aad")
        .await
        .unwrap();
    provider.close_wrapped_key(&generated.lease).await.unwrap();

    let lease = provider
        .open_wrapped_key(&ctx, &parent, &generated.envelope)
        .await
        .unwrap();
    let opened = provider
        .decrypt(lease.handle(), &sealed.ciphertext, b"aad")
        .await
        .unwrap();
    assert_eq!(opened.expose(), b"child payload");

    // The child is its own key, not an alias for the parent that wraps it.
    assert!(provider
        .decrypt(&parent, &sealed.ciphertext, b"aad")
        .await
        .is_err());
    assert_ne!(lease.handle().key_id, parent.key_id);
    provider.close_wrapped_key(&lease).await.unwrap();
}

#[tokio::test]
async fn a_closed_lease_stops_operating_and_closes_idempotently() {
    let (provider, parent, ctx) = parented().await;
    let generated = provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap();
    let lease = generated.lease;

    let first = provider.close_wrapped_key(&lease).await.unwrap();
    assert!(provider
        .encrypt(lease.handle(), b"after close", b"aad")
        .await
        .is_err());

    // A repeated close reports the same fact, so a lost response can be
    // reconciled instead of being retried as fresh work.
    let second = provider.close_wrapped_key(&lease).await.unwrap();
    assert_eq!(first, second);
}

#[tokio::test]
async fn a_predicted_next_lease_cannot_close_material_that_is_not_yet_issued() {
    let (provider, parent, ctx) = parented().await;
    let generated = provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap();
    let issued = generated.lease.object().as_str();
    let (prefix, n) = issued.rsplit_once('-').expect("issued object identity");
    let next = n.parse::<u64>().expect("issued counter") + 1;
    let predicted = format!("{prefix}-{next}");
    let predicted_lease = WrappedKeyLease::new(
        KeyHandle {
            key_id: predicted.clone(),
            key_spec: KeySpec::Aes256,
        },
        name(&predicted),
        &ctx,
    )
    .unwrap();
    assert!(
        provider.close_wrapped_key(&predicted_lease).await.is_err(),
        "a lease that was never issued must not certify closure"
    );
    provider
        .encrypt(generated.lease.handle(), b"still live", b"aad")
        .await
        .expect("the real child must still operate after a predicted close");
    provider
        .close_wrapped_key(&generated.lease)
        .await
        .expect("the real lease still closes");
}

/// Idempotent close is bounded by what the provider still remembers, and the
/// boundary is an error rather than a success. A caller that is told "closed"
/// about an object nobody can account for would be entitled to conclude the
/// creation was cleaned up, and to create the child again.
#[tokio::test]
async fn a_forgotten_closure_is_unresolved_rather_than_successful() {
    let (provider, parent, ctx) = parented().await;
    let creation = binding(&ctx);
    let first = provider
        .generate_wrapped_key(&ctx, &parent, &creation)
        .await
        .unwrap();
    provider.close_wrapped_key(&first.lease).await.unwrap();
    assert_eq!(
        provider.close_wrapped_key(&first.lease).await.unwrap(),
        provider.close_wrapped_key(&first.lease).await.unwrap()
    );

    // Enough closures after it to push the first one out of the bounded record.
    for _ in 0..4096 {
        let next = provider
            .generate_wrapped_key(&ctx, &parent, &creation)
            .await
            .unwrap();
        provider.close_wrapped_key(&next.lease).await.unwrap();
    }
    let error = provider
        .close_wrapped_key(&first.lease)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown wrapping lease"), "{error}");
}

#[tokio::test]
async fn closing_under_another_context_is_refused_and_destroys_nothing() {
    let (provider, parent, ctx) = parented().await;
    let generated = provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap();

    // Same object identity, different bindings. Closing must refuse rather than
    // destroy an object on a claim that does not describe it.
    let mut other = ctx.clone();
    other.child.lid = Lid::from_bytes([8; 32]);
    let misbound = WrappedKeyLease::new(
        generated.lease.handle().clone(),
        generated.lease.object().clone(),
        &other,
    )
    .unwrap();
    assert!(provider.close_wrapped_key(&misbound).await.is_err());

    // Untouched: the real lease still operates, and still closes.
    provider
        .encrypt(generated.lease.handle(), b"still open", b"aad")
        .await
        .unwrap();
    provider.close_wrapped_key(&generated.lease).await.unwrap();

    // The recorded closure is bound too, so a misbound repeat is also refused.
    assert!(provider.close_wrapped_key(&misbound).await.is_err());
}

#[tokio::test]
async fn a_lease_from_another_provider_is_not_closeable_here() {
    let (provider, parent, ctx) = parented().await;
    let generated = provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap();

    let (other, _, _) = parented().await;
    assert!(other.close_wrapped_key(&generated.lease).await.is_err());
    // The real holder can still close it: a foreign refusal destroys nothing.
    provider.close_wrapped_key(&generated.lease).await.unwrap();
}

#[tokio::test]
async fn an_undeclared_tuple_is_refused_for_every_operation() {
    let (provider, parent, ctx) = parented().await;
    let envelope = provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap()
        .envelope;

    let mut refused = Vec::new();
    let mut changed = ctx.clone();
    changed.child_spec = KeySpec::Aes128;
    refused.push(changed);
    let mut changed = ctx.clone();
    changed.parent_spec = KeySpec::Aes128;
    refused.push(changed);
    let mut changed = ctx.clone();
    changed.purpose = WrappingKeyPurpose::WrapUnwrap;
    refused.push(changed);
    let mut changed = ctx.clone();
    changed.key_format = WrappedKeyFormat::ProviderNative(name("native"));
    refused.push(changed);
    let mut changed = ctx.clone();
    changed.mechanism = name("software:aes-256-gcm:v2");
    refused.push(changed);
    let mut changed = ctx.clone();
    changed.mechanism = name("pkcs11:aes-key-wrap-pad:v1");
    refused.push(changed);

    for changed in refused {
        let generate = provider
            .generate_wrapped_key(&changed, &parent, &binding(&ctx))
            .await
            .unwrap_err()
            .to_string();
        assert!(generate.contains("refused"), "{generate}");
        let open = provider
            .open_wrapped_key(&changed, &parent, &envelope)
            .await
            .unwrap_err()
            .to_string();
        assert!(open.contains("refused"), "{open}");
    }
}

#[tokio::test]
async fn a_parent_handle_that_is_not_the_bound_spec_is_refused() {
    let (provider, parent, ctx) = parented().await;
    let smaller = provider.generate_key(&KeySpec::Aes128).await.unwrap();
    let error = provider
        .generate_wrapped_key(&ctx, &smaller, &binding(&ctx))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("parent handle"), "{error}");

    // The bound parent still works, so the refusal is about this handle only.
    provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap();
}

#[tokio::test]
async fn the_authenticated_context_refuses_every_other_binding() {
    let (provider, parent, ctx) = parented().await;
    let envelope = provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap()
        .envelope;

    // Bindings that the declared tuple permits, so they reach the wrapping
    // itself and must fail there: the canonical context is the AES-GCM AAD.
    let mut rebound = Vec::new();
    let mut changed = ctx.clone();
    changed.child.lid = Lid::from_bytes([8; 32]);
    rebound.push(changed);
    let mut changed = ctx.clone();
    changed.child.version = VersionedKeyId::new(ctx.child.lid, 2).unwrap().version;
    rebound.push(changed);
    let mut changed = ctx.clone();
    changed.parent.lid = Lid::from_bytes([10; 32]);
    rebound.push(changed);
    let mut changed = ctx.clone();
    changed.parent.version = VersionedKeyId::new(ctx.parent.lid, 4).unwrap().version;
    rebound.push(changed);
    let mut changed = ctx.clone();
    changed.provider_ref = ProviderRef::new("another-backend");
    rebound.push(changed);
    let mut changed = ctx.clone();
    changed.security_domain = name("another-domain");
    rebound.push(changed);

    for changed in rebound {
        assert!(provider
            .open_wrapped_key(&changed, &parent, &envelope)
            .await
            .is_err());
    }

    // Another parent of the same spec cannot open it either.
    let other_parent = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    assert!(provider
        .open_wrapped_key(&ctx, &other_parent, &envelope)
        .await
        .is_err());

    // Nor can a tampered, truncated or padded envelope.
    let mut flipped = envelope.clone();
    flipped[20] ^= 1;
    for bad in [
        flipped,
        envelope[..ENVELOPE_BYTES - 1].to_vec(),
        [envelope.clone(), vec![0]].concat(),
        Vec::new(),
    ] {
        assert!(provider
            .open_wrapped_key(&ctx, &parent, &bad)
            .await
            .is_err());
    }

    // The unaltered request still opens, so the refusals above are the bindings.
    provider
        .open_wrapped_key(&ctx, &parent, &envelope)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_scoped_provider_refuses_a_context_naming_another_backend() {
    let provider = SoftwareProvider::scoped(
        ProviderRef::new("software-test"),
        name("software-test-domain"),
    );
    let parent = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let ctx = context(&parent);
    provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap();

    for changed in [
        WrappingContext {
            provider_ref: ProviderRef::new("hsm-backend"),
            ..ctx.clone()
        },
        WrappingContext {
            security_domain: name("hsm-domain"),
            ..ctx.clone()
        },
    ] {
        let error = provider
            .generate_wrapped_key(&changed, &parent, &binding(&ctx))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("another provider or security domain"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn the_declared_profile_covers_only_the_operations_implemented() {
    let provider = SoftwareProvider::new();
    let parent = KeyHandle {
        key_id: "unused".into(),
        key_spec: KeySpec::Aes256,
    };
    let ctx = context(&parent);
    let capabilities = provider.wrapping_capabilities();

    // One profile, declared for exactly the three operations that exist.
    assert_eq!(capabilities.tuples().len(), 3);
    for operation in [
        WrappingOperation::Generate,
        WrappingOperation::Open,
        WrappingOperation::Close,
    ] {
        assert_eq!(
            capabilities.require(&WrappingCapability::requested(
                &ctx,
                operation,
                WrappedKeyLifecycle::SessionObject
            )),
            Ok(())
        );
    }
    // Rewrap is not implemented, so it is not declared and cannot be requested.
    assert_eq!(
        capabilities.require(&WrappingCapability::requested(
            &ctx,
            WrappingOperation::Rewrap,
            WrappedKeyLifecycle::SessionObject
        )),
        Err(WrappingError::UnsupportedCapability)
    );
    // The lifetime declared is the one that is true. A caller that needs a
    // journaled temporary object in a backend is refused, not downgraded.
    assert_eq!(
        capabilities.require(&WrappingCapability::requested(
            &ctx,
            WrappingOperation::Generate,
            WrappedKeyLifecycle::JournaledTemporaryObject
        )),
        Err(WrappingError::UnsupportedCapability)
    );

    // The mechanism identity says what it is on sight: software, and which
    // algorithm. A capability dump cannot read as contained custody.
    assert_eq!(SOFTWARE_WRAPPING_MECHANISM, "software:aes-256-gcm:v1");
    for tuple in capabilities.tuples() {
        assert!(tuple.mechanism.as_str().starts_with("software"));
        assert!(tuple.mechanism.as_str().contains("aes-256-gcm"));
    }
}

#[tokio::test]
async fn a_provider_without_the_profile_refuses_all_three_operations() {
    let provider = InMemoryProvider::new();
    let parent = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let ctx = context(&parent);

    assert!(provider.wrapping_capabilities().tuples().is_empty());
    let error = provider
        .generate_wrapped_key(&ctx, &parent, &binding(&ctx))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("not supported by this provider"), "{error}");
    let error = provider
        .open_wrapped_key(&ctx, &parent, &[0; ENVELOPE_BYTES])
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("not supported by this provider"), "{error}");

    // Nothing to close, and nothing that could evidence a closure: a provider
    // inheriting the defaults cannot drive journaled creation at all.
    assert!(provider.wrapping_closure_verifier().is_none());
    assert!(SoftwareProvider::new()
        .wrapping_closure_verifier()
        .is_some());
}
