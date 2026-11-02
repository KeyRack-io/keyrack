// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::Pkcs11ProviderConfig;
use keyrack_core::creation::VerifiedA2Closure;
use keyrack_core::key::{KeyMaterial, ParentWrappedMaterial};
use keyrack_core::provider::CryptoProvider;
use std::num::NonZeroU64;

fn identifier(value: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(value).unwrap()
}

fn config() -> Pkcs11ProviderConfig {
    let token_label = std::env::var("KMS_PKCS11_TOKEN_LABEL").expect("fresh token required");
    assert_eq!(token_label, "keyrack-wrapping-probe");
    Pkcs11ProviderConfig {
        lib_path: std::env::var("KMS_PKCS11_LIB").unwrap(),
        token_label,
        pin: std::env::var("KMS_PKCS11_PIN").unwrap(),
    }
}

fn configured(config: &Pkcs11ProviderConfig) -> Pkcs11Provider {
    Pkcs11Provider::new_with_wrapping(
        config,
        ProviderRef::new("wrapping"),
        identifier(CONTEXT_DERIVED_WRAPPING_MECHANISM),
        identifier("token-domain"),
    )
    .unwrap()
}

fn request(parent: Option<VersionedKeyId>, spec: KeySpec) -> CreationRequest {
    let (_, mut request) = keyrack_test_support::creation_conformance::fixture();
    let material = request.material().unwrap();
    let parent = parent.unwrap_or(material.parent());
    let reference = material.wrapped_material_ref().clone();
    request.record.key_spec = spec;
    request.record.parent_lid = Some(parent.lid);
    request.record.key_versions[0].material = KeyMaterial::ParentWrapped(
        ParentWrappedMaterial::new(
            ProviderRef::new("wrapping"),
            identifier("token-domain"),
            parent,
            WrappingContextVersion::V1,
            WrappedKeyFormat::RawSecret,
            identifier(CONTEXT_DERIVED_WRAPPING_MECHANISM),
            reference,
        )
        .unwrap(),
    );
    request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
    request.validate().unwrap();
    request
}

async fn object_count(provider: &Pkcs11Provider) -> usize {
    provider
        .run(|session| {
            session
                .find_objects(&[])
                .map(|objects| objects.len())
                .map_err(|e| crate::provider::map_pkcs11_error("test object inventory", &e))
        })
        .await
        .unwrap()
}

struct ReleaseMigration(Arc<native::MigrationPause>);
impl Drop for ReleaseMigration {
    fn drop(&mut self) {
        self.0.release();
    }
}

async fn generate(
    provider: &Pkcs11Provider,
    parent: &KeyHandle,
    request: &CreationRequest,
) -> Vec<u8> {
    let context = request.context().unwrap();
    let generated = provider
        .generate_wrapped_key(&context, parent, &CreationBinding::of(request).unwrap())
        .await
        .unwrap();
    assert!(provider
        .encrypt(
            generated.lease.handle(),
            b"creation must not be usable",
            b""
        )
        .await
        .is_err());
    let verifier = provider.wrapping_closure_verifier().unwrap();
    let claim = A2ClosureClaim {
        intent_fingerprint: request.fingerprint().unwrap(),
        envelope_digest: *blake3::hash(&generated.envelope).as_bytes(),
        fact: A2ClosureFact::SessionClosed {
            session: generated.lease.object().as_str().into(),
        },
    };
    assert!(
        verifier.verify(request, &claim).is_err(),
        "live session must not certify closure"
    );
    let closed = provider.close_wrapped_key(&generated.lease).await.unwrap();
    assert_eq!(closed.fact, claim.fact);
    VerifiedA2Closure::verify(
        request,
        &generated.envelope,
        claim.clone(),
        verifier.as_ref(),
    )
    .unwrap();
    let mut different = request.clone();
    different.expected_parent_occ += 1;
    let mut rebound = claim.clone();
    rebound.intent_fingerprint = different.fingerprint().unwrap();
    assert!(
        verifier.verify(&different, &rebound).is_err(),
        "closed session cannot rebind another intent"
    );
    assert_eq!(
        provider
            .close_wrapped_key(&generated.lease)
            .await
            .unwrap()
            .fact,
        closed.fact
    );
    assert!(
        provider
            .generate_wrapped_key(&context, parent, &CreationBinding::of(request).unwrap())
            .await
            .is_err(),
        "closed evidence cannot authorize redispatch"
    );
    generated.envelope
}

#[tokio::test]
async fn context_wrapped_provider_roundtrip_swap_restart_and_exact_closure() {
    let config = config();
    let ordinary = Pkcs11Provider::new(&config).unwrap();
    assert!(ordinary.wrapping_capabilities().tuples().is_empty());
    assert!(!ordinary.rewrap_is_retry_safe());
    let ordinary_root = ordinary.generate_key(&KeySpec::Aes256).await.unwrap();
    let ordinary_cipher = ordinary
        .encrypt(&ordinary_root, b"ordinary semantics", b"aad")
        .await
        .unwrap();
    assert!(ordinary
        .decrypt(&ordinary_root, &ordinary_cipher.ciphertext, b"aad")
        .await
        .unwrap()
        .expose()
        .as_slice()
        .eq(b"ordinary semantics"));
    let provider = configured(&config);
    assert_eq!(provider.wrapping_capabilities().tuples().len(), 8);
    assert!(provider.rewrap_is_retry_safe());
    assert!(provider
        .capabilities()
        .key_specs
        .iter()
        .all(|entry| matches!(entry.key_spec, KeySpec::Aes128 | KeySpec::Aes256)));
    assert!(provider.generate_key(&KeySpec::Aes128).await.is_err());
    let parent = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let wrong_parent = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    assert!(provider
        .encrypt(&parent, b"derive-only root", b"")
        .await
        .is_err());
    let mut retained = None;
    for spec in [KeySpec::Aes128, KeySpec::Aes256] {
        let first = request(None, spec.clone());
        let context = first.context().unwrap();
        let second = request(Some(context.parent), spec);
        let first_bytes = generate(&provider, &parent, &first).await;
        let second_bytes = generate(&provider, &parent, &second).await;
        let engine = provider.wrapping.as_ref().unwrap();
        let baseline = object_count(&provider).await;
        let failed = request(Some(context.parent), context.child_spec.clone());
        *engine.next_fault.lock().unwrap() = Some(native::Fault::AfterGenerate);
        let failure = provider
            .generate_wrapped_key(
                &failed.context().unwrap(),
                &parent,
                &CreationBinding::of(&failed).unwrap(),
            )
            .await
            .unwrap_err();
        assert!(failure
            .to_string()
            .contains("injected after child generation"));
        assert_eq!(object_count(&provider).await, baseline);
        {
            let state = engine.state.lock().unwrap();
            let id = &state.attempts[&(failed.operation, failed.attempt)];
            let evidence = &state.entries[id];
            assert!(evidence.owner.as_ref().unwrap().closed);
            assert!(evidence.envelope_digest.is_none() && evidence.issued.is_none());
        }
        *engine.next_fault.lock().unwrap() = Some(native::Fault::AfterOpen);
        let failure = provider
            .open_wrapped_key(&context, &parent, &first_bytes)
            .await
            .unwrap_err();
        assert!(failure.to_string().contains("injected after native unwrap"));
        assert_eq!(object_count(&provider).await, baseline);
        // The current binding API is opaque before effects. Publication must
        // reject a binding for a different request/context, even after close.
        let mismatched_request = request(Some(context.parent), context.child_spec.clone());
        let mismatched = provider
            .generate_wrapped_key(
                &context,
                &parent,
                &CreationBinding::of(&mismatched_request).unwrap(),
            )
            .await
            .unwrap();
        let mismatch_close = provider.close_wrapped_key(&mismatched.lease).await.unwrap();
        let mismatch_claim = A2ClosureClaim {
            intent_fingerprint: mismatched_request.fingerprint().unwrap(),
            envelope_digest: *blake3::hash(&mismatched.envelope).as_bytes(),
            fact: mismatch_close.fact,
        };
        assert!(VerifiedA2Closure::verify(
            &mismatched_request,
            &mismatched.envelope,
            mismatch_claim,
            provider.wrapping_closure_verifier().unwrap().as_ref()
        )
        .is_err());
        let lease = provider
            .open_wrapped_key(&context, &parent, &first_bytes)
            .await
            .unwrap();
        assert!(provider
            .destroy_key(lease.handle())
            .await
            .unwrap_err()
            .to_string()
            .contains("original session owner"));
        let output = provider
            .encrypt(lease.handle(), b"wrapped application data", b"associated")
            .await
            .unwrap();
        assert!(provider
            .decrypt(lease.handle(), &output.ciphertext, b"associated")
            .await
            .unwrap()
            .expose()
            .as_slice()
            .eq(b"wrapped application data"));
        assert!(provider
            .decrypt(lease.handle(), &output.ciphertext, b"tampered")
            .await
            .is_err());
        provider.close_wrapped_key(&lease).await.unwrap();
        assert!(provider
            .encrypt(lease.handle(), b"stale", b"")
            .await
            .is_err());
        for (label, bytes, parent_handle) in [
            ("sibling swap", &second_bytes, &parent),
            ("wrong parent", &first_bytes, &wrong_parent),
        ] {
            let error = provider
                .open_wrapped_key(&context, parent_handle, bytes)
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("context-derived child unwrap (not retried)"),
                "{label}: {error}"
            );
        }
        let mut changed = context.clone();
        changed.parent.version = NonZeroU64::new(2).unwrap();
        assert!(provider
            .open_wrapped_key(&changed, &parent, &first_bytes)
            .await
            .unwrap_err()
            .to_string()
            .contains("child unwrap"));
        let mut changed = context.clone();
        changed.child.version = NonZeroU64::new(2).unwrap();
        assert!(provider
            .open_wrapped_key(&changed, &parent, &first_bytes)
            .await
            .unwrap_err()
            .to_string()
            .contains("child unwrap"));
        let mut changed = context.clone();
        changed.child.lid = Lid::from_bytes([77; 32]);
        assert!(provider
            .open_wrapped_key(&changed, &parent, &first_bytes)
            .await
            .unwrap_err()
            .to_string()
            .contains("child unwrap"));
        let mut changed = context.clone();
        changed.parent.lid = Lid::from_bytes([88; 32]);
        assert!(provider
            .open_wrapped_key(&changed, &parent, &first_bytes)
            .await
            .unwrap_err()
            .to_string()
            .contains("child unwrap"));
        let current = provider
            .open_wrapped_key(&context, &parent, &first_bytes)
            .await
            .unwrap();
        provider.close_wrapped_key(&current).await.unwrap();
        let mut destination = context.clone();
        destination.parent.version = NonZeroU64::new(2).unwrap();
        let engine = provider.wrapping.as_ref().unwrap();
        let mut migration_owner = native::Owner::new(&provider).unwrap();
        let migrated_raw = migration_owner
            .rewrap_closed(
                &engine.profile,
                &context,
                &parent,
                &destination,
                &wrong_parent,
                &first_bytes[FRAME.len()..],
            )
            .unwrap();
        assert!(
            migration_owner.closed,
            "original session closes before output returns"
        );
        let mut migrated = FRAME.to_vec();
        migrated.extend(migrated_raw);
        let api_migrated = provider
            .rewrap_wrapped_key(&context, &parent, &first_bytes, &destination, &wrong_parent)
            .await
            .unwrap();
        assert_eq!(
            api_migrated, migrated,
            "deterministic native KW preserves the same child"
        );
        assert!(ordinary
            .rewrap_wrapped_key(&context, &parent, &first_bytes, &destination, &wrong_parent)
            .await
            .is_err());
        let migrated_lease = provider
            .open_wrapped_key(&destination, &wrong_parent, &migrated)
            .await
            .unwrap();
        assert!(provider
            .decrypt(migrated_lease.handle(), &output.ciphertext, b"associated")
            .await
            .unwrap()
            .expose()
            .as_slice()
            .eq(b"wrapped application data"));
        provider.close_wrapped_key(&migrated_lease).await.unwrap();
        // Pause with a real temporary child and old KEK already in the token.
        let pause = Arc::new(native::MigrationPause::default());
        let release = ReleaseMigration(Arc::clone(&pause));
        *engine.next_migration_pause.lock().unwrap() = Some(Arc::clone(&pause));
        let baseline = object_count(&provider).await;
        let (cloned_provider, old, old_parent, old_bytes, new, new_parent) = (
            provider.clone(),
            context.clone(),
            parent.clone(),
            first_bytes.clone(),
            destination.clone(),
            wrong_parent.clone(),
        );
        let cancelled = tokio::spawn(async move {
            cloned_provider
                .rewrap_wrapped_key(&old, &old_parent, &old_bytes, &new, &new_parent)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), pause.entered.notified())
            .await
            .unwrap();
        assert_eq!(
            object_count(&provider).await,
            baseline + 2,
            "temporary migration child and old KEK exist"
        );
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        release.0.release();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            engine.serialized(|_, _| Ok(())),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            object_count(&provider).await,
            baseline,
            "cancelled migration owner completed cleanup"
        );
        let retried = provider
            .rewrap_wrapped_key(&context, &parent, &first_bytes, &destination, &wrong_parent)
            .await
            .unwrap();
        assert_eq!(retried, migrated);
        // Separately retained old envelopes remain usable under the old parent.
        let old_again = provider
            .open_wrapped_key(&context, &parent, &first_bytes)
            .await
            .unwrap();
        provider.close_wrapped_key(&old_again).await.unwrap();
        let mut rejected_destination = destination.clone();
        rejected_destination.child.version = NonZeroU64::new(2).unwrap();
        let mut refused_owner = native::Owner::new(&provider).unwrap();
        assert!(refused_owner
            .rewrap_closed(
                &engine.profile,
                &context,
                &parent,
                &rejected_destination,
                &wrong_parent,
                &first_bytes[FRAME.len()..]
            )
            .is_err());
        assert!(
            refused_owner.closed,
            "refused migration also explicitly closes its original session"
        );
        assert!(provider
            .rewrap_wrapped_key(
                &context,
                &parent,
                &first_bytes,
                &rejected_destination,
                &wrong_parent
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("other than the exact parent"));
        let mut changed_domain = destination.clone();
        changed_domain.security_domain = identifier("foreign-domain");
        assert!(provider
            .rewrap_wrapped_key(
                &context,
                &parent,
                &first_bytes,
                &changed_domain,
                &wrong_parent
            )
            .await
            .is_err());
        let mut corrupt = first_bytes[FRAME.len()..].to_vec();
        corrupt[0] ^= 1;
        let baseline = object_count(&provider).await;
        let mut failed_owner = native::Owner::new(&provider).unwrap();
        assert!(failed_owner
            .rewrap_closed(
                &engine.profile,
                &context,
                &parent,
                &destination,
                &wrong_parent,
                &corrupt
            )
            .unwrap_err()
            .to_string()
            .contains("temporary migration child unwrap"));
        assert!(
            failed_owner.closed,
            "native migration failure closes original session"
        );
        assert_eq!(object_count(&provider).await, baseline);
        retained = Some((context, first_bytes, current, output));
    }
    let (context, bytes, old_lease, output) = retained.unwrap();
    let restarted = configured(&config);
    assert!(restarted.close_wrapped_key(&old_lease).await.is_err());
    let reopened = restarted
        .open_wrapped_key(&context, &parent, &bytes)
        .await
        .unwrap();
    assert!(restarted
        .decrypt(reopened.handle(), &output.ciphertext, b"associated")
        .await
        .unwrap()
        .expose()
        .as_slice()
        .eq(b"wrapped application data"));
    restarted.close_wrapped_key(&reopened).await.unwrap();
    drop(restarted);
    let failed_creation = request(Some(context.parent), KeySpec::Aes256);
    let generated = provider
        .generate_wrapped_key(
            &failed_creation.context().unwrap(),
            &parent,
            &CreationBinding::of(&failed_creation).unwrap(),
        )
        .await
        .unwrap();
    let failed_open = provider
        .open_wrapped_key(&context, &parent, &bytes)
        .await
        .unwrap();
    let mut admitted_migration = native::Owner::new(&provider).unwrap();
    let engine = provider.wrapping.as_ref().unwrap();
    let mut release_migration = native::Owner::new(&provider).unwrap();
    let mut competing_close = native::Owner::new(&provider).unwrap();
    competing_close.fault = Some(native::Fault::CloseBeforeNative);
    release_migration.release_close_failure = Some(Box::new(competing_close));
    assert!(!provider
        .module
        .wrapping_cleanup_unconfirmed
        .load(std::sync::atomic::Ordering::Acquire));
    let before_release = object_count(&provider).await;
    let release_error = release_migration
        .rewrap_closed(
            &engine.profile,
            &context,
            &parent,
            &context,
            &parent,
            &bytes[FRAME.len()..],
        )
        .unwrap_err();
    assert!(release_error.to_string().contains("process restart"));
    assert!(
        provider.rewrap_is_retry_safe(),
        "cleanup uncertainty must not poison durable retry semantics"
    );
    assert!(
        release_migration.closed,
        "real rewrap and original close finished before release fence"
    );
    assert_eq!(object_count(&provider).await, before_release);
    for _ in 0..2 {
        assert!(provider
            .rewrap_wrapped_key(&context, &parent, &bytes, &context, &parent)
            .await
            .unwrap_err()
            .to_string()
            .contains("process restart"));
        assert_eq!(
            object_count(&provider).await,
            before_release,
            "retry qualification cannot bypass the pre-effect cleanup fence"
        );
    }
    let attempts = {
        let mut state = engine.state.lock().unwrap();
        [&generated.lease, &failed_open].map(|lease| {
            let owner = state
                .entries
                .get_mut(lease.object().as_str())
                .unwrap()
                .owner
                .as_mut()
                .unwrap();
            owner.fault = Some(native::Fault::CloseBeforeNative);
            Arc::clone(&owner.close_attempts)
        })
    };
    let live_count = object_count(&provider).await;
    for lease in [&generated.lease, &failed_open] {
        let closed = provider.close_wrapped_key(lease).await.map(|_| ());
        let error = finish::<()>(Err(failure("original operation failure")), closed).unwrap_err();
        assert!(error.to_string().contains("original operation failure"));
        assert!(error.to_string().contains("injected close failure"));
        assert!(
            provider.close_wrapped_key(lease).await.is_err(),
            "unconfirmed close cannot become success"
        );
    }
    for count in &attempts {
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    let migration_error = admitted_migration
        .rewrap_closed(
            &engine.profile,
            &context,
            &parent,
            &context,
            &parent,
            &bytes[FRAME.len()..],
        )
        .unwrap_err();
    assert!(migration_error.to_string().contains("process restart"));
    assert!(
        admitted_migration.closed,
        "already admitted owners may still close while fenced"
    );
    // A destructor retry would remove the opened child. Its continued presence
    // distinguishes no-drop sessions from cryptoki's default automatic close.
    assert_eq!(object_count(&provider).await, live_count);
    let claim = A2ClosureClaim {
        intent_fingerprint: failed_creation.fingerprint().unwrap(),
        envelope_digest: *blake3::hash(&generated.envelope).as_bytes(),
        fact: A2ClosureFact::SessionClosed {
            session: generated.lease.object().as_str().into(),
        },
    };
    assert!(provider
        .wrapping_closure_verifier()
        .unwrap()
        .verify(&failed_creation, &claim)
        .is_err());
    {
        let mut state = engine.state.lock().unwrap();
        for lease in [&generated.lease, &failed_open] {
            let owner = state
                .entries
                .get_mut(lease.object().as_str())
                .unwrap()
                .owner
                .take()
                .unwrap();
            assert!(!owner.closed);
            drop(owner);
        }
    }
    for count in &attempts {
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    assert_eq!(
        object_count(&provider).await,
        live_count,
        "owner Drop must not retry consumed close"
    );
    assert!(provider
        .open_wrapped_key(&context, &parent, &bytes)
        .await
        .unwrap_err()
        .to_string()
        .contains("process restart"));
    let reconstruction = Pkcs11Provider::new_with_wrapping(
        &config,
        ProviderRef::new("wrapping"),
        identifier(CONTEXT_DERIVED_WRAPPING_MECHANISM),
        identifier("token-domain"),
    );
    assert!(reconstruction
        .err()
        .unwrap()
        .to_string()
        .contains("process restart"));
    // Terminal fixture recovery clears the intentionally unresolved native
    // session. It is never original-session closure evidence.
    assert!(provider
        .module
        .recover(provider.module.generation())
        .permits_retry());
    assert!(
        provider.rewrap_is_retry_safe(),
        "repeatability remains a profile property across ordinary recovery"
    );
    assert!(!ordinary.rewrap_is_retry_safe());
    assert_eq!(object_count(&provider).await, live_count - 1);
    assert!(provider
        .wrapping_closure_verifier()
        .unwrap()
        .verify(&failed_creation, &claim)
        .is_err());
    assert!(provider
        .open_wrapped_key(&context, &parent, &bytes)
        .await
        .unwrap_err()
        .to_string()
        .contains("process restart"));
    let reconstruction = Pkcs11Provider::new_with_wrapping(
        &config,
        ProviderRef::new("wrapping"),
        identifier(CONTEXT_DERIVED_WRAPPING_MECHANISM),
        identifier("token-domain"),
    );
    assert!(reconstruction
        .err()
        .unwrap()
        .to_string()
        .contains("process restart"));
    drop(provider);
    ordinary.destroy_key(&parent).await.unwrap();
    ordinary.destroy_key(&wrong_parent).await.unwrap();
    ordinary.destroy_key(&ordinary_root).await.unwrap();
    let guard = ordinary.module.gate.enter().unwrap();
    let observer = ordinary
        .module
        .ctx
        .open_rw_session(ordinary.current_slot().unwrap())
        .unwrap();
    assert!(
        observer.find_objects(&[]).unwrap().is_empty(),
        "all owners closed and owned roots removed"
    );
    observer.close().unwrap();
    drop(guard);
    println!("CONTEXT_WRAPPED_PROVIDER_PASS startup_kat_aes128=true startup_kat_aes256=true sibling_swap_native_refusal=true same_token_ordinary=true original_closure=true restart=true baseline_restored=true");
}
