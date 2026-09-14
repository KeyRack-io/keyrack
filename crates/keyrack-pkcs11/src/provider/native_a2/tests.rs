// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One process/one disposable token: native calls, not a scripted provider.

use super::*;
use crate::Pkcs11ProviderConfig;
use keyrack_core::provider::CryptoProvider;
use keyrack_test_support::creation_conformance::fixture;

fn named(session: &Session, label: &str) -> Vec<ObjectHandle> {
    session
        .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])
        .unwrap()
}

fn parent(session: &Session, label: &str) -> KeyHandle {
    session
        .generate_key(
            &Mechanism::AesKeyGen,
            &[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::ValueLen(32.into()),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(false),
                Attribute::Decrypt(false),
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
                Attribute::Copyable(false),
                Attribute::Modifiable(false),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Id(label.as_bytes().to_vec()),
            ],
        )
        .unwrap();
    KeyHandle {
        key_id: label.into(),
        key_spec: KeySpec::Aes256,
    }
}

#[test]
fn native_a2_soft_hsm() {
    let label = std::env::var("KMS_PKCS11_TOKEN_LABEL").expect("disposable token label required");
    assert_eq!(label, "keyrack-wrapping-probe", "refuse an arbitrary token");
    let library = std::env::var("KMS_PKCS11_LIB").expect("explicit native library required");
    let module = super::super::shared_module(&library).unwrap();
    let check = module.gate.enter().unwrap();
    assert!(
        module
            .ctx
            .get_library_info()
            .unwrap()
            .manufacturer_id()
            .to_ascii_lowercase()
            .contains("softhsm"),
        "this live test is restricted to SoftHSM, before login or creation"
    );
    let slots: Vec<_> = module
        .ctx
        .get_slots_with_initialized_token()
        .unwrap()
        .into_iter()
        .filter(|slot| module.ctx.get_token_info(*slot).unwrap().label() == label)
        .collect();
    assert_eq!(
        slots.len(),
        1,
        "one exact initialized dedicated token required"
    );
    let token = module.ctx.get_token_info(slots[0]).unwrap();
    assert!(
        token
            .manufacturer_id()
            .to_ascii_lowercase()
            .contains("softhsm")
            && token.model().to_ascii_lowercase().contains("softhsm")
    );
    drop(check);
    let provider = Pkcs11Provider::new(&Pkcs11ProviderConfig {
        lib_path: library,
        token_label: label,
        pin: std::env::var("KMS_PKCS11_PIN").expect("test PIN required"),
    })
    .unwrap();
    assert!(
        provider.wrapping_capabilities().tuples().is_empty(),
        "mechanism success must not advertise custody"
    );
    let admission = LifetimeAdmission::acquire(Arc::clone(&provider.module)).unwrap();
    let control = provider
        .module
        .ctx
        .open_rw_session(provider.current_slot().unwrap())
        .unwrap();
    control
        .login(UserType::User, Some(&make_auth_pin(&provider.pin)))
        .unwrap();
    assert!(
        control.find_objects(&[]).unwrap().is_empty(),
        "disposable token must be empty"
    );
    let good_parent = parent(&control, "native-a2-parent");
    let wrong_parent = parent(&control, "native-a2-wrong-parent");
    let (_, request) = fixture();
    let original_generation = provider.module.generation();
    journal_rejects_unqualified_provider(provider.clone());
    assert!(named(&control, &request.correlation).is_empty());

    let acquire = |parent: &KeyHandle, mode| {
        provider
            .native_a2_conformance_session(parent.clone(), request.clone(), mode)
            .unwrap()
    };

    // Unsupported native context wrapping is an exact refusal, no KW fallback.
    let mut rejected = acquire(&good_parent, NativeWrapMode::GcmCandidate);
    let Err(error) = rejected.generate_wrapped_key(&request) else {
        panic!("SoftHSM unexpectedly accepted GCM wrap; re-triage qualification");
    };
    let expected = map_pkcs11_error(
        "native child wrap (no fallback)",
        &cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::MechanismInvalid,
            cryptoki::context::Function::WrapKey,
        ),
    );
    assert_eq!(
        error.to_string(),
        expected.to_string(),
        "only the precise mechanism refusal counts"
    );
    assert!(
        error
            .to_string()
            .contains("native child wrap (no fallback)"),
        "must reach the wrapping call: {error}"
    );
    assert_eq!(named(&control, &request.correlation).len(), 1);
    assert!(rejected.generate_wrapped_key(&request).is_err());
    assert_eq!(
        named(&control, &request.correlation).len(),
        1,
        "no repeated Generate after error"
    );
    assert!(rejected.closed_session().is_none());
    rejected.close_wrapped_key().unwrap();
    assert!(named(&control, &request.correlation).is_empty());
    // Synthetic bytes exercise native mechanism refusal only; they are not a
    // valid GCM envelope or evidence of successful context authentication.
    let mut rejected_open = acquire(&good_parent, NativeWrapMode::GcmCandidate);
    let gcm_input = NativeEnvelope {
        mode: NativeWrapMode::GcmCandidate,
        iv: [0; 12],
        ciphertext: vec![0x42; 48],
        intent: request.fingerprint().unwrap(),
    };
    let Err(error) = rejected_open.open_wrapped_key(&request, &gcm_input) else {
        panic!("SoftHSM unexpectedly accepted native GCM unwrap");
    };
    let expected = map_pkcs11_error(
        "native child unwrap (not retried)",
        &cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::MechanismInvalid,
            cryptoki::context::Function::UnwrapKey,
        ),
    );
    assert_eq!(error.to_string(), expected.to_string());
    assert!(rejected_open
        .open_wrapped_key(&request, &gcm_input)
        .is_err());
    rejected_open.close_wrapped_key().unwrap();
    assert!(named(&control, &request.correlation).is_empty());
    println!(
        "NATIVE_A2_PASS gcm_wrap_refused=true gcm_unwrap_refused=true fallback=false retry=false"
    );

    // Positive KW mechanism evidence is explicitly unqualified for context custody.
    let mut creation = acquire(&good_parent, NativeWrapMode::KwMechanicsOnly);
    let envelope = creation.generate_wrapped_key(&request).unwrap();
    assert_eq!(envelope.ciphertext().len(), 40);
    assert!(creation.generate_wrapped_key(&request).is_err());
    assert!(creation
        .encrypt(b"must not use generation object", b"")
        .is_err());
    assert!(creation.closed_session().is_none());
    let held = provider.module.gate.inner.lock().unwrap().in_flight;
    assert_eq!(held, 2, "control + idle creation session retain admission");
    creation.close_wrapped_key().unwrap();
    let closure = creation.closed_session().unwrap();
    creation.close_wrapped_key().unwrap();
    assert_eq!(creation.closed_session(), Some(closure));
    assert_eq!(provider.module.gate.inner.lock().unwrap().in_flight, 1);
    assert!(named(&control, &request.correlation).is_empty());

    let mut opened = acquire(&good_parent, NativeWrapMode::KwMechanicsOnly);
    opened.open_wrapped_key(&request, &envelope).unwrap();
    assert_eq!(
        opened
            .session()
            .unwrap()
            .get_attributes(
                opened.opened.unwrap(),
                &[cryptoki::object::AttributeType::ValueLen]
            )
            .unwrap(),
        vec![Attribute::ValueLen(0.into())],
        "record SoftHSM's missing positive size readback, not an independent size proof"
    );
    assert!(
        check_opened_policy(
            opened.session().unwrap(),
            opened.opened.unwrap(),
            &request,
            NativeWrapMode::GcmCandidate
        )
        .is_err(),
        "the mechanics exception must not weaken GCM policy"
    );
    assert!(opened.open_wrapped_key(&request, &envelope).is_err());
    let encrypted = opened
        .encrypt(b"public native lease payload", b"caller-application-aad")
        .unwrap();
    assert!(opened.decrypt(&encrypted.ciphertext, b"wrong-aad").is_err());
    assert_eq!(
        opened
            .decrypt(&encrypted.ciphertext, b"caller-application-aad")
            .unwrap()
            .expose(),
        b"public native lease payload"
    );
    assert_eq!(
        provider.module.generation(),
        original_generation,
        "native refusals never invoke module recovery"
    );
    opened.close_wrapped_key().unwrap();
    assert!(opened.encrypt(b"closed", b"").is_err());
    assert!(opened
        .decrypt(&encrypted.ciphertext, b"caller-application-aad")
        .is_err());
    assert!(named(&control, &request.correlation).is_empty());
    println!("NATIVE_A2_PASS kw_roundtrip=true explicit_original_close=true application_aad=true custody_qualified=false");

    let (_, mut aes128) = fixture();
    aes128.record.key_spec = KeySpec::Aes128;
    aes128.context_bytes = aes128.context().unwrap().canonical_bytes().unwrap();
    let mut generated128 = provider
        .native_a2_conformance_session(
            good_parent.clone(),
            aes128.clone(),
            NativeWrapMode::KwMechanicsOnly,
        )
        .unwrap();
    let wrapped128 = generated128.generate_wrapped_key(&aes128).unwrap();
    assert_eq!(wrapped128.ciphertext().len(), 24);
    generated128.close_wrapped_key().unwrap();
    let mut opened128 = provider
        .native_a2_conformance_session(
            good_parent.clone(),
            aes128.clone(),
            NativeWrapMode::KwMechanicsOnly,
        )
        .unwrap();
    opened128.open_wrapped_key(&aes128, &wrapped128).unwrap();
    let cipher128 = opened128.encrypt(b"public AES128 payload", b"aad").unwrap();
    assert_eq!(
        opened128
            .decrypt(&cipher128.ciphertext, b"aad")
            .unwrap()
            .expose(),
        b"public AES128 payload"
    );
    opened128.close_wrapped_key().unwrap();
    assert!(named(&control, &aes128.correlation).is_empty());

    // Changed intent, wrong wrapping parent, corrupted bytes and wrong mechanism
    // never yield usable leases, and cannot retry the consumed native attempt.
    let mut changed_request = request.clone();
    changed_request.expected_parent_occ += 1;
    let mut changed = acquire(&good_parent, NativeWrapMode::KwMechanicsOnly);
    assert!(changed
        .open_wrapped_key(&changed_request, &envelope)
        .is_err());
    assert!(named(&control, &request.correlation).is_empty());
    changed.close_wrapped_key().unwrap();
    for (parent_handle, mode, corrupt) in [
        (&wrong_parent, NativeWrapMode::KwMechanicsOnly, false),
        (&good_parent, NativeWrapMode::GcmCandidate, false),
        (&good_parent, NativeWrapMode::KwMechanicsOnly, true),
    ] {
        let mut candidate = acquire(parent_handle, mode);
        let mut input = envelope.clone();
        if corrupt {
            input.ciphertext[0] ^= 1;
        }
        assert!(candidate.open_wrapped_key(&request, &input).is_err());
        assert!(candidate.open_wrapped_key(&request, &envelope).is_err());
        assert!(candidate.encrypt(b"refused", b"").is_err());
        candidate.close_wrapped_key().unwrap();
        assert!(named(&control, &request.correlation).is_empty());
    }
    println!(
        "NATIVE_A2_PASS changed_intent=true wrong_parent=true corrupt_wrap=true wrong_mode=true"
    );

    // Last session Drop closes before its module admission is released, but is
    // not observable closure evidence and cannot publish a creation journal.
    {
        let mut dropped = acquire(&good_parent, NativeWrapMode::KwMechanicsOnly);
        dropped.open_wrapped_key(&request, &envelope).unwrap();
        assert_eq!(named(&control, &request.correlation).len(), 1);
        assert_eq!(provider.module.gate.inner.lock().unwrap().in_flight, 2);
    }
    assert!(named(&control, &request.correlation).is_empty());
    assert_eq!(provider.module.gate.inner.lock().unwrap().in_flight, 1);

    // Cold parent loss cannot open another lease. A previously opened child
    // continues to work until explicit closure: do not claim a stronger fence.
    let mut warm = acquire(&good_parent, NativeWrapMode::KwMechanicsOnly);
    warm.open_wrapped_key(&request, &envelope).unwrap();
    control
        .destroy_object(named(&control, &good_parent.key_id)[0])
        .unwrap();
    let mut cold = acquire(&good_parent, NativeWrapMode::KwMechanicsOnly);
    assert!(cold.open_wrapped_key(&request, &envelope).is_err());
    cold.close_wrapped_key().unwrap();
    control
        .destroy_object(named(&control, &wrong_parent.key_id)[0])
        .unwrap();
    control.close().unwrap();
    drop(admission);
    // No other session/admission remains: this exercises an IDLE owned lease,
    // not a control session accidentally preventing module recovery for us.
    assert_eq!(provider.module.gate.inner.lock().unwrap().in_flight, 1);
    assert!(provider.module.gate.quiesce().is_none());
    assert!(warm.encrypt(b"warm lifetime limit", b"").is_ok());
    warm.close_wrapped_key().unwrap();
    assert_eq!(provider.module.gate.inner.lock().unwrap().in_flight, 0);
    assert!(provider.module.gate.quiesce().is_some());
    let check = provider.module.gate.enter().unwrap();
    let control = provider
        .module
        .ctx
        .open_rw_session(provider.current_slot().unwrap())
        .unwrap();
    control
        .login(UserType::User, Some(&make_auth_pin(&provider.pin)))
        .unwrap();
    assert!(control.find_objects(&[]).unwrap().is_empty());
    control.close().unwrap();
    drop(check);
    assert!(provider.wrapping_capabilities().tuples().is_empty());
    println!("NATIVE_A2_PASS cold_parent_loss=true warm_until_close=true idle_lease_blocks_recovery=true token_empty=true custody_qualified=false");
}

/// Test-only rejection bridge: it cannot produce or verify creation evidence.
/// This is NOT the pending production creation adapter.
struct UnqualifiedJournalProbe(Pkcs11Provider);

impl keyrack_core::creation::A2ClosureVerifier for UnqualifiedJournalProbe {
    fn verify(
        &self,
        _: &CreationRequest,
        _: &keyrack_core::creation::A2ClosureClaim,
    ) -> Result<()> {
        Err(refused("no qualified creation provenance"))
    }
}

#[async_trait::async_trait]
impl keyrack_core::creation_driver::A2CreationProvider for UnqualifiedJournalProbe {
    async fn preflight(&self, request: &CreationRequest) -> Result<()> {
        use keyrack_core::wrapping::{WrappedKeyLifecycle, WrappingCapability, WrappingOperation};
        let context = request.context()?;
        self.0
            .wrapping_capabilities()
            .require(&WrappingCapability {
                parent_spec: context.parent_spec,
                child_spec: context.child_spec,
                key_format: context.key_format,
                purpose: context.purpose,
                mechanism: context.mechanism,
                context_version: context.version,
                operation: WrappingOperation::Generate,
                lifecycle: WrappedKeyLifecycle::SessionObject,
            })
            .map_err(|_| refused("unqualified token cannot enter creation dispatch"))
    }

    async fn generate_and_wrap(&self, _: &CreationRequest) -> Result<Vec<u8>> {
        panic!("journal dispatched an unqualified provider")
    }

    async fn close_creation(
        &self,
        _: &CreationRequest,
    ) -> Result<keyrack_core::creation::A2ClosureClaim> {
        panic!("unqualified mechanism work cannot mint journal closure")
    }
}

fn journal_rejects_unqualified_provider(provider: Pkcs11Provider) {
    use keyrack_core::creation::CreationPhase;
    use keyrack_core::creation_driver::A2CreationDriver;
    use keyrack_core::storage::StorageBackend;
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async move {
            let store = Arc::new(keyrack_sqlite::SqliteStorage::in_memory().unwrap());
            let (parent, request) = fixture();
            store.create_key(&parent).await.unwrap();
            let driver =
                A2CreationDriver::new(store.clone(), Arc::new(UnqualifiedJournalProbe(provider)));
            assert!(driver.run(request.clone()).await.is_err());
            let reservation = store.get_creation(request.operation).await.unwrap();
            assert_eq!(reservation.phase, CreationPhase::Reserved);
            assert!(!reservation.dispatch_started);
            assert!(store.get_key(&request.record.lid).await.is_err());
            assert!(store
                .read_creation_envelope(request.operation)
                .await
                .is_err());
            assert!(store
                .publish_creation(request.operation, request.owner, reservation.revision)
                .await
                .is_err());
            assert!(driver.run(request.clone()).await.is_err());
            assert!(
                !store
                    .get_creation(request.operation)
                    .await
                    .unwrap()
                    .dispatch_started
            );
        });
    println!("NATIVE_A2_PASS journal_preflight_refuses_unqualified=true native_dispatch=false publication=false");
}
