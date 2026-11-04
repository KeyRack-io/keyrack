// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-token tests. Readable fixture keys exist only in this test module.

use super::super::tests::{config, configured, request};
use super::super::CONTEXT_DERIVED_WRAPPING_MECHANISM;
use super::*;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use keyrack_core::creation::CreationBinding;
use keyrack_core::key::ProviderRef;
use keyrack_core::provider::CryptoProvider;
use keyrack_core::wrapping::WrappingIdentifier;
use std::sync::atomic::Ordering;

fn profile() -> Profile {
    Profile::new(
        ProviderRef::new("wrapping"),
        WrappingIdentifier::new(CONTEXT_DERIVED_WRAPPING_MECHANISM).unwrap(),
        WrappingIdentifier::new("token-domain").unwrap(),
    )
    .unwrap()
}

fn inventory(owner: &Owner) -> Vec<ObjectHandle> {
    owner.session().unwrap().find_objects(&[]).unwrap()
}

fn same_inventory(owner: &Owner, expected: &[ObjectHandle]) {
    assert!(
        !owner.closed,
        "inventory must precede original-session close"
    );
    let actual = inventory(owner);
    assert_eq!(actual.len(), expected.len());
    assert!(expected.iter().all(|key| actual.contains(key)));
}

fn readable_parent(owner: &Owner, token: bool, label: &str) -> ObjectHandle {
    let mut attrs = template(Role::Parent, 32, token, label);
    for attribute in &mut attrs {
        match attribute {
            Attribute::Sensitive(value) => *value = false,
            Attribute::Extractable(value) | Attribute::Modifiable(value) => *value = true,
            _ => (),
        }
    }
    owner
        .session()
        .unwrap()
        .generate_key(&Mechanism::AesKeyGen, &attrs)
        .unwrap()
}

// This independent calculation deliberately does not call context_digest,
// C_DeriveKey, or a token AES operation. CBC has exactly two unpadded blocks.
fn expected_payload(parent: &[u8; 32], context: &WrappingContext, child: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"KeyRack-PKCS11-CBC32-KW-v1\0");
    digest.update(context.canonical_bytes().unwrap());
    let digest: [u8; 32] = digest.finalize().into();
    let cipher = aes::Aes256::new_from_slice(parent).unwrap();
    let mut previous = [0_u8; 16];
    let mut kek = [0_u8; 32];
    for (input, output) in digest.chunks_exact(16).zip(kek.chunks_exact_mut(16)) {
        let mut block = Block::<aes::Aes256>::default();
        for (index, byte) in input.iter().enumerate() {
            block[index] = byte ^ previous[index];
        }
        cipher.encrypt_block(&mut block);
        output.copy_from_slice(&block);
        previous.copy_from_slice(&block);
    }
    let mut wrapped = vec![0; child.len() + 8];
    aes_kw::KekAes256::new(&kek.into())
        .wrap(child, &mut wrapped)
        .unwrap();
    wrapped
}

#[tokio::test]
async fn native_provider_envelope_matches_independent_cbc_and_kw() {
    let provider = configured(&config());
    let mut fixture = Owner::new(&provider).unwrap();
    let baseline = inventory(&fixture);
    let readable_label = format!("readable-test-parent-{}", uuid::Uuid::new_v4());
    let readable = readable_parent(&fixture, false, &readable_label);
    let attributes = fixture
        .session()
        .unwrap()
        .get_attributes(readable, &[AttributeType::Value])
        .unwrap();
    let [Attribute::Value(value)] = attributes.as_slice() else {
        panic!("test parent must provide its public fixture value");
    };
    let parent_value: [u8; 32] = value.as_slice().try_into().unwrap();
    // SoftHSM's CKA_MODIFIABLE is creation-only. Import the same public fixture
    // bytes into a separate strict object instead of relaxing production policy.
    // This copy exists only in the test: production never reads a parent value.
    let label = format!("strict-test-parent-{}", uuid::Uuid::new_v4());
    let mut strict = template(Role::Parent, 32, true, &label);
    strict.retain(|attribute| !matches!(attribute, Attribute::ValueLen(_)));
    strict.push(Attribute::Value(parent_value.to_vec()));
    let parent = fixture.session().unwrap().create_object(&strict).unwrap();
    policy(
        fixture.session().unwrap(),
        parent,
        &template(Role::Parent, 32, true, &label),
    )
    .unwrap();
    unreadable(fixture.session().unwrap(), parent).unwrap();
    let handle = KeyHandle {
        key_id: label,
        key_spec: KeySpec::Aes256,
    };
    for spec in [KeySpec::Aes128, KeySpec::Aes256] {
        let request = request(None, spec);
        let context = request.context().unwrap();
        let child: Vec<u8> =
            (0..u8::try_from(key_size(&context.child_spec).unwrap()).unwrap()).collect();
        let expected_wrapped = expected_payload(&parent_value, &context, &child);
        // Exercise the real derivation with the readable fixture as well as
        // the strict provider path, using identical parent and child bytes.
        fixture.fault = Some(Fault::KnownGeneratedValue);
        let readable_wrapped = fixture
            .generate_under(&context, readable, "readable-parent-known-child")
            .unwrap();
        fixture.fault = None;
        assert_eq!(readable_wrapped, expected_wrapped);
        *provider
            .wrapping
            .as_ref()
            .unwrap()
            .next_fault
            .lock()
            .unwrap() = Some(Fault::KnownGeneratedValue);
        let generated = provider
            .generate_wrapped_key(&context, &handle, &CreationBinding::of(&request).unwrap())
            .await
            .unwrap();
        let mut expected = b"KRCBKW01".to_vec();
        expected.extend(expected_wrapped);
        assert_eq!(
            generated.envelope, expected,
            "full provider envelope differs from independent CBC/KW construction"
        );
        provider.close_wrapped_key(&generated.lease).await.unwrap();
    }
    fixture.session().unwrap().destroy_object(parent).unwrap();
    fixture.session().unwrap().destroy_object(readable).unwrap();
    same_inventory(&fixture, &baseline);
    fixture.close().unwrap();
}

#[test]
fn native_failure_cleanup_precedes_original_session_close() {
    let provider = configured(&config());
    let mut owner = Owner::new(&provider).unwrap();
    let label = format!("cleanup-parent-{}", uuid::Uuid::new_v4());
    let parent = owner
        .session()
        .unwrap()
        .generate_key(
            &Mechanism::AesKeyGen,
            &template(Role::Parent, 32, false, &label),
        )
        .unwrap();
    let context = profile().self_test_context(KeySpec::Aes256).unwrap();
    let baseline = inventory(&owner);
    for (fault, cause, destroyed) in [
        (
            Fault::DerivedPolicy,
            "injected derived KEK policy rejection",
            1,
        ),
        (
            Fault::DerivedUnreadable,
            "injected derived KEK unreadable rejection",
            1,
        ),
        (
            Fault::DerivedSensitiveFalse,
            "strict Sensitive policy readback mismatch",
            1,
        ),
        (
            Fault::DerivedExtractableTrue,
            "strict Extractable policy readback mismatch",
            1,
        ),
        (Fault::AfterGenerate, "injected after child generation", 2),
        (
            Fault::WrapLengthMismatch,
            "native AES-KW output length mismatch",
            2,
        ),
    ] {
        owner.fault = Some(fault);
        let attempts = owner.destroy_attempts.load(Ordering::SeqCst);
        let error = owner
            .generate_under(&context, parent, "failed-child")
            .unwrap_err();
        assert!(
            error.to_string().contains(cause),
            "unexpected refusal: {error}"
        );
        same_inventory(&owner, &baseline);
        assert_eq!(owner.close_attempts.load(Ordering::SeqCst), 0);
        assert_eq!(
            owner.destroy_attempts.load(Ordering::SeqCst) - attempts,
            destroyed
        );
        owner.fault = None;
        assert_eq!(
            owner
                .generate_under(&context, parent, "unchanged-control")
                .unwrap()
                .len(),
            40
        );
        same_inventory(&owner, &baseline);
    }
    owner.session().unwrap().destroy_object(parent).unwrap();
    owner.close().unwrap();

    let mut setup = Owner::new(&provider).unwrap();
    let initial = inventory(&setup);
    let old_label = format!("old-parent-{}", uuid::Uuid::new_v4());
    let new_label = format!("new-parent-{}", uuid::Uuid::new_v4());
    setup.generate_root(&old_label).unwrap();
    setup.generate_root(&new_label).unwrap();
    let old_parent = KeyHandle {
        key_id: old_label,
        key_spec: KeySpec::Aes256,
    };
    let new_parent = KeyHandle {
        key_id: new_label,
        key_spec: KeySpec::Aes256,
    };
    let wrapped = setup
        .generate(&context, &old_parent, "migration-input")
        .unwrap();
    let mut new_context = context.clone();
    new_context.parent.version = std::num::NonZeroU64::new(2).unwrap();
    let baseline = inventory(&setup);
    for (fault, cause, destroyed) in [
        (
            Fault::RewrapAfterUnwrap,
            "injected after migration unwrap",
            2,
        ),
        (
            Fault::RewrapAfterDerive,
            "injected after migration derivation",
            3,
        ),
        (
            Fault::WrapLengthMismatch,
            "rewrap output length mismatch",
            3,
        ),
    ] {
        let mut migration = Owner::new(&provider).unwrap();
        migration.fault = Some(fault);
        let error = migration
            .rewrap_closed(
                &profile(),
                &context,
                &old_parent,
                &new_context,
                &new_parent,
                &wrapped,
            )
            .unwrap_err();
        assert!(
            error.to_string().contains(cause),
            "unexpected migration refusal: {error}"
        );
        assert_eq!(migration.destroy_attempts.load(Ordering::SeqCst), destroyed);
        assert_eq!(migration.close_attempts.load(Ordering::SeqCst), 1);
        assert!(migration.closed);
        same_inventory(&setup, &baseline);
    }
    for handle in [&old_parent, &new_parent] {
        let object = setup.parent(handle).unwrap();
        setup.session().unwrap().destroy_object(object).unwrap();
    }
    same_inventory(&setup, &initial);
    setup.close().unwrap();
}

#[test]
fn native_startup_refuses_failed_self_test_and_preserves_inventory() {
    let config = config();
    let ordinary = Pkcs11Provider::new(&config).unwrap();
    let mut observer = Owner::new(&ordinary).unwrap();
    let baseline = inventory(&observer);
    let advertised = ordinary
        .module
        .ctx
        .get_mechanism_list(ordinary.current_slot().unwrap())
        .unwrap();
    assert!(advertised.contains(&cryptoki::mechanism::MechanismType::AES_CBC_ENCRYPT_DATA));
    assert!(advertised.contains(&cryptoki::mechanism::MechanismType::AES_KEY_WRAP));
    let inspect = || {
        match observer
            .session()
            .unwrap()
            .login(UserType::User, Some(&make_auth_pin(&config.pin)))
        {
            Ok(()) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => (),
            Err(error) => panic!("inventory observer login failed: {error}"),
        }
        same_inventory(&observer, &baseline);
    };
    for (fault, cause) in [
        (
            Fault::DerivedSensitiveFalse,
            "strict Sensitive policy readback mismatch",
        ),
        (
            Fault::DerivedExtractableTrue,
            "strict Extractable policy readback mismatch",
        ),
        (Fault::AfterGenerate, "injected after child generation"),
        (
            Fault::WrapLengthMismatch,
            "native AES-KW output length mismatch",
        ),
    ] {
        // Constructor authentication intentionally refuses an ambient login.
        // Log out before the operation, but keep this observation session open.
        // Do not log out after the operation until its inventory is checked:
        // logout could itself discard private session objects and hide a leak.
        observer.session().unwrap().logout().unwrap();
        let result = with_self_test_fault(fault, || {
            Pkcs11Provider::new_with_wrapping(
                &config,
                ProviderRef::new("wrapping"),
                WrappingIdentifier::new(CONTEXT_DERIVED_WRAPPING_MECHANISM).unwrap(),
                WrappingIdentifier::new("token-domain").unwrap(),
            )
        });
        let error = result
            .err()
            .expect("advertised mechanisms cannot bypass failed self-test");
        assert!(
            error.to_string().contains(cause),
            "unexpected startup refusal: {error}"
        );
        inspect();
        observer.session().unwrap().logout().unwrap();
        let qualified = configured(&config);
        assert_eq!(qualified.wrapping_capabilities().tuples().len(), 8);
        inspect();
    }
    observer.close().unwrap();
}

#[tokio::test]
async fn native_parent_roles_refuse_ordinary_use_and_wrong_parent() {
    let config = config();
    let ordinary = Pkcs11Provider::new(&config).unwrap();
    let provider = configured(&config);
    let ordinary_parent = ordinary.generate_key(&KeySpec::Aes256).await.unwrap();
    let ordinary_cipher = ordinary
        .encrypt(&ordinary_parent, b"ordinary control", b"aad")
        .await
        .unwrap();
    assert!(ordinary
        .decrypt(&ordinary_parent, &ordinary_cipher.ciphertext, b"aad")
        .await
        .unwrap()
        .expose()
        .as_slice()
        .eq(b"ordinary control"));
    let request = request(None, KeySpec::Aes256);
    let context = request.context().unwrap();
    let mut owner = Owner::new(&provider).unwrap();
    let baseline = inventory(&owner);
    let error = provider
        .generate_wrapped_key(
            &context,
            &ordinary_parent,
            &CreationBinding::of(&request).unwrap(),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("policy readback mismatch"),
        "unexpected parent refusal: {error}"
    );
    same_inventory(&owner, &baseline);
    owner.close().unwrap();
    let parent = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    let error = provider
        .encrypt(&parent, b"not an ordinary key", b"aad")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("derive-only roots cannot encrypt"),
        "unexpected encrypt refusal: {error}"
    );
    let error = provider
        .decrypt(&parent, &ordinary_cipher.ciphertext, b"aad")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("derive-only roots cannot decrypt"),
        "unexpected decrypt refusal: {error}"
    );
    ordinary.destroy_key(&ordinary_parent).await.unwrap();
    provider.destroy_key(&parent).await.unwrap();
}

#[test]
fn native_destroy_failure_attempts_remaining_objects_and_fences_admission() {
    let config = config();
    let provider = configured(&config);
    let mut owner = Owner::new(&provider).unwrap();
    let baseline = inventory(&owner);
    let create = || {
        owner
            .session()
            .unwrap()
            .generate_key(
                &Mechanism::AesKeyGen,
                &template(Role::Kek, 32, false, &uuid::Uuid::new_v4().to_string()),
            )
            .unwrap()
    };
    let control = create();
    owner.destroy_objects(&[control]).unwrap();
    assert!(ensure_cleanup_confirmed(&provider.module).is_ok());
    // Allocate both handles before invalidating one, so the token cannot reuse
    // the destroyed handle for the object whose cleanup must still be tried.
    let stale = create();
    let live = create();
    owner.session().unwrap().destroy_object(stale).unwrap();
    let before = owner.destroy_attempts.load(Ordering::SeqCst);
    let error = owner.destroy_objects(&[stale, live]).unwrap_err();
    let expected = map_pkcs11_error(
        "context-derived temporary object destruction",
        &Error::Pkcs11(RvError::ObjectHandleInvalid, Function::DestroyObject),
    );
    assert_eq!(error.to_string(), expected.to_string());
    assert_eq!(owner.destroy_attempts.load(Ordering::SeqCst) - before, 2);
    assert_eq!(owner.close_attempts.load(Ordering::SeqCst), 0);
    same_inventory(&owner, &baseline);
    let refused = Owner::new(&provider)
        .err()
        .expect("failed destruction must fence new owners");
    assert!(refused.to_string().contains("cleanup is unconfirmed"));
    owner.close().unwrap();
    assert!(
        ensure_cleanup_confirmed(&provider.module).is_err(),
        "successful close must not erase failed-destruction evidence"
    );
    let refused = Pkcs11Provider::new_with_wrapping(
        &config,
        ProviderRef::new("wrapping"),
        WrappingIdentifier::new(CONTEXT_DERIVED_WRAPPING_MECHANISM).unwrap(),
        WrappingIdentifier::new("token-domain").unwrap(),
    )
    .err()
    .expect("reconstruction must preserve the cleanup fence");
    assert!(refused.to_string().contains("cleanup is unconfirmed"));
    // The dedicated wrapping fence does not disable ordinary token operation.
    Pkcs11Provider::new(&config).unwrap();
}
