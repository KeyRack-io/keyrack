// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
#[cfg(feature = "softhsm-tests")]
use cryptoki::{object::Attribute, session::Session};
#[cfg(feature = "softhsm-tests")]
use keyrack_core::creation::{creation_correlation, CreationRequest};
use keyrack_core::key::KeySpec;
#[cfg(feature = "softhsm-tests")]
use keyrack_core::provider::CryptoProvider;
use keyrack_test_support::creation_conformance::fixture;
use std::sync::mpsc;
use std::time::Duration;

pub(super) struct Pause {
    generated: bool,
    entered: mpsc::Sender<String>,
    resume: mpsc::Receiver<()>,
}

pub(super) fn pause(adapter: &NativeA2ConformanceAdapter, generated: bool, id: &str) {
    let mut hook = adapter.pause.lock().unwrap();
    if hook.as_ref().is_some_and(|p| p.generated == generated) {
        let p = hook.take().unwrap();
        p.entered.send(id.to_owned()).unwrap();
        p.resume
            .recv_timeout(Duration::from_secs(10))
            .expect("test pause bounded");
    }
}

#[cfg(feature = "softhsm-tests")]
fn arm(
    adapter: &NativeA2ConformanceAdapter,
    generated: bool,
) -> (mpsc::Receiver<String>, mpsc::Sender<()>) {
    let (entered, received) = mpsc::channel();
    let (resume, release) = mpsc::channel();
    *adapter.pause.lock().unwrap() = Some(Pause {
        generated,
        entered,
        resume: release,
    });
    (received, resume)
}

#[cfg(feature = "softhsm-tests")]
fn fresh(request: &CreationRequest) -> CreationRequest {
    let mut request = request.clone();
    request.operation = Uuid::new_v4();
    request.attempt = Uuid::new_v4();
    request.correlation = creation_correlation(request.operation, request.attempt);
    request
}

#[cfg(feature = "softhsm-tests")]
fn count(control: &Session, request: &CreationRequest) -> usize {
    control
        .find_objects(&[Attribute::Label(request.correlation.as_bytes().to_vec())])
        .unwrap()
        .len()
}

#[test]
fn conformance_frame_is_bounded_and_preserves_nonce() {
    let (_, request) = fixture();
    let context = request.context().unwrap();
    for mode in [
        NativeWrapMode::GcmCandidate,
        NativeWrapMode::KwMechanicsOnly,
    ] {
        let envelope = NativeEnvelope {
            mode,
            iv: if mode == NativeWrapMode::GcmCandidate {
                [7; 12]
            } else {
                [0; 12]
            },
            context_sha256: context.context_sha256().unwrap(),
            ciphertext: vec![
                9;
                if mode == NativeWrapMode::GcmCandidate {
                    48
                } else {
                    40
                }
            ],
        };
        let bytes = encode(&envelope);
        assert!(decode(&bytes, mode, &context).unwrap() == envelope);
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len], mode, &context).is_err());
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode(&longer, mode, &context).is_err());
        let opposite = if mode == NativeWrapMode::GcmCandidate {
            NativeWrapMode::KwMechanicsOnly
        } else {
            NativeWrapMode::GcmCandidate
        };
        assert!(decode(&bytes, opposite, &context).is_err());
        for index in 0..9 {
            let mut corrupt = bytes.clone();
            corrupt[index] ^= 1;
            assert!(decode(&corrupt, mode, &context).is_err());
        }
        let mut changed = context.clone();
        changed.child.version = std::num::NonZeroU64::new(2).unwrap();
        assert!(decode(&bytes, mode, &changed).is_err());
    }
}

#[test]
fn reserved_identity_is_not_an_issued_lease_and_capacity_does_not_evict() {
    let (_, request) = fixture();
    let context = request.context().unwrap();
    let parent = KeyHandle {
        key_id: "parent".into(),
        key_spec: KeySpec::Aes256,
    };
    let mut state = State::default();
    for i in 0..MAX_OWNERS {
        state.entries.insert(
            format!("reserved-{i}"),
            Entry {
                context: context.clone(),
                parent: parent.clone(),
                creation: None,
                owner: None,
                envelope: None,
                issued: None,
            },
        );
    }
    assert!(state.capacity().is_err());
    let synthetic = WrappedKeyLease::new(
        KeyHandle {
            key_id: "reserved-0".into(),
            key_spec: KeySpec::Aes256,
        },
        WrappingIdentifier::new("reserved-0").unwrap(),
        &context,
    )
    .unwrap();
    assert!(state.lease_entry(&synthetic).is_err());
    assert!(state.handle_entry(synthetic.handle()).is_err());
    assert_eq!(state.entries.len(), MAX_OWNERS);
}

/// Invoked by the existing exact-name disposable `SoftHSM` test; no new stack.
#[cfg(feature = "softhsm-tests")]
pub(crate) fn live(
    provider: &Pkcs11Provider,
    parent: &KeyHandle,
    base: &CreationRequest,
    control: &Session,
) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let adapter = provider.native_a2_conformance_adapter(NativeWrapMode::KwMechanicsOnly);
        let request = fresh(base);
        let context = request.context().unwrap();
        let binding = CreationBinding::of(&request).unwrap();
        let generated: GeneratedWrappedKey = adapter
            .generate_wrapped_key(&context, parent, &binding)
            .await
            .unwrap();
        assert_eq!(count(control, &request), 1);
        assert!(adapter
            .verify_closed_creation(&binding, &generated.envelope)
            .await
            .is_err());
        assert!(adapter
            .encrypt(
                generated.lease.handle(),
                b"not an operational creation key",
                b""
            )
            .await
            .is_err());
        // Same operation/attempt cannot dispatch twice, even with altered owner.
        assert!(adapter
            .generate_wrapped_key(&context, parent, &binding)
            .await
            .is_err());
        let mut changed = request.clone();
        changed.owner.generation += 1;
        let changed_binding = CreationBinding::of(&changed).unwrap();
        assert!(adapter
            .generate_wrapped_key(&context, parent, &changed_binding)
            .await
            .is_err());
        assert!(adapter
            .close_creation_attempt(&changed_binding)
            .await
            .is_err());
        assert_eq!(count(control, &request), 1);
        let closed: WrappedKeyClosure = adapter.close_wrapped_key(&generated.lease).await.unwrap();
        assert_eq!(
            adapter.close_wrapped_key(&generated.lease).await.unwrap(),
            closed
        );
        assert_eq!(count(control, &request), 0);
        adapter
            .verify_closed_creation(&binding, &generated.envelope)
            .await
            .unwrap();
        let mut wrong_output = generated.envelope.clone();
        *wrong_output.last_mut().unwrap() ^= 1;
        assert!(adapter
            .verify_closed_creation(&binding, &wrong_output)
            .await
            .is_err());

        // Cold Open carries no CreationBinding. Only the exact issuing adapter
        // accepts its random opaque lease; it never interprets a token handle.
        let opened: WrappedKeyLease = adapter
            .open_wrapped_key(&context, parent, &generated.envelope)
            .await
            .unwrap();
        let encrypted = adapter
            .encrypt(opened.handle(), b"native shared shapes", b"data-aad")
            .await
            .unwrap();
        assert_eq!(
            adapter
                .decrypt(opened.handle(), &encrypted.ciphertext, b"data-aad")
                .await
                .unwrap()
                .expose(),
            b"native shared shapes"
        );
        assert!(adapter
            .decrypt(opened.handle(), &encrypted.ciphertext, b"wrong-aad")
            .await
            .is_err());
        let other = provider.native_a2_conformance_adapter(NativeWrapMode::KwMechanicsOnly);
        assert!(other.close_wrapped_key(&opened).await.is_err());
        assert!(other.encrypt(opened.handle(), b"x", b"").await.is_err());
        let altered_handle = KeyHandle {
            key_id: opened.handle().key_id.clone(),
            key_spec: KeySpec::Aes128,
        };
        let altered =
            WrappedKeyLease::new(altered_handle.clone(), opened.object().clone(), &context)
                .unwrap();
        assert!(adapter.close_wrapped_key(&altered).await.is_err());
        assert!(adapter.encrypt(&altered_handle, b"x", b"").await.is_err());
        let mut wrong_context = context.clone();
        wrong_context.child.version = std::num::NonZeroU64::new(2).unwrap();
        let altered = WrappedKeyLease::new(
            opened.handle().clone(),
            opened.object().clone(),
            &wrong_context,
        )
        .unwrap();
        assert!(adapter.close_wrapped_key(&altered).await.is_err());
        assert!(adapter
            .encrypt(opened.handle(), b"still open after refused close", b"")
            .await
            .is_ok());
        adapter.close_wrapped_key(&opened).await.unwrap();
        assert!(adapter
            .encrypt(opened.handle(), b"closed", b"")
            .await
            .is_err());
        // Successful local mechanics never supplies a qualified journal verifier.
        assert!(provider.wrapping_capabilities().tuples().is_empty());
        assert!(provider.wrapping_closure_verifier().is_none());
        assert!(
            keyrack_core::creation_driver::WrappingCreationProvider::new(
                Arc::new(provider.clone()),
                parent.clone(),
                keyrack_core::wrapping::WrappedKeyLifecycle::SessionObject,
            )
            .is_err(),
            "the real shared journal adapter cannot promote this profile"
        );
        assert!(
            CryptoProvider::generate_wrapped_key(provider, &context, parent, &binding)
                .await
                .is_err()
        );
        assert!(
            CryptoProvider::open_wrapped_key(provider, &context, parent, &generated.envelope)
                .await
                .is_err()
        );
        assert!(CryptoProvider::close_wrapped_key(provider, &opened)
            .await
            .is_err());
        println!("NATIVE_A2_ADAPTER_PASS binding/lease/use/closure/refusals; no qualification");

        let gcm = provider.native_a2_conformance_adapter(NativeWrapMode::GcmCandidate);
        let failed = fresh(base);
        let failed_binding = CreationBinding::of(&failed).unwrap();
        let error = gcm
            .generate_wrapped_key(&context, parent, &failed_binding)
            .await
            .unwrap_err();
        let expected = super::super::super::map_pkcs11_error(
            "native child wrap (no fallback)",
            &cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::MechanismInvalid,
                cryptoki::context::Function::WrapKey,
            ),
        );
        assert_eq!(
            error.to_string(),
            expected.to_string(),
            "precise SoftHSM refusal"
        );
        assert_eq!(
            count(control, &failed),
            1,
            "native Generate acted before Wrap refused"
        );
        assert!(gcm
            .generate_wrapped_key(&context, parent, &failed_binding)
            .await
            .is_err());
        gcm.close_creation_attempt(&failed_binding).await.unwrap();
        assert_eq!(count(control, &failed), 0);
        assert!(gcm
            .verify_closed_creation(&failed_binding, &generated.envelope)
            .await
            .is_err());
        assert!(
            gcm.open_wrapped_key(&context, parent, &generated.envelope)
                .await
                .is_err(),
            "no KW fallback"
        );
        println!("NATIVE_A2_ADAPTER_PASS failed Generate retains original cleanup owner");

        // Deterministic interleavings against real native sessions, not fake
        // providers. Before and after material creation, the same lock fences
        // close until issuance; no close-before-insert resurrection is possible.
        for material_created in [false, true] {
            let request = fresh(base);
            let binding = CreationBinding::of(&request).unwrap();
            let (entered, resume) = arm(&adapter, material_created);
            let a = adapter.clone();
            let c = context.clone();
            let p = parent.clone();
            let b = binding.clone();
            let generate = tokio::spawn(async move { a.generate_wrapped_key(&c, &p, &b).await });
            let id = entered.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(count(control, &request), usize::from(material_created));
            assert!(
                adapter.state.try_lock().is_err(),
                "original owner and effect share serialization"
            );
            // The test-only hook leaks a normally private random ID on purpose.
            let guessed = WrappedKeyLease::new(
                KeyHandle {
                    key_id: id.clone(),
                    key_spec: context.child_spec.clone(),
                },
                WrappingIdentifier::new(id).unwrap(),
                &context,
            )
            .unwrap();
            let a = adapter.clone();
            let mut close = tokio::spawn(async move { a.close_wrapped_key(&guessed).await });
            assert!(tokio::time::timeout(Duration::from_millis(30), &mut close)
                .await
                .is_err());
            resume.send(()).unwrap();
            let result = generate.await.unwrap().unwrap();
            close.await.unwrap().unwrap();
            adapter.close_wrapped_key(&result.lease).await.unwrap();
            assert_eq!(count(control, &request), 0);
            assert!(adapter
                .encrypt(result.lease.handle(), b"no resurrection", b"")
                .await
                .is_err());
            adapter
                .verify_closed_creation(&binding, &result.envelope)
                .await
                .unwrap();
        }
        println!("NATIVE_A2_ADAPTER_PASS close serialized before/after native effect");

        let cancelled = fresh(base);
        let binding = CreationBinding::of(&cancelled).unwrap();
        let (entered, resume) = arm(&adapter, false);
        let a = adapter.clone();
        let c = context.clone();
        let p = parent.clone();
        let b = binding.clone();
        let generate = tokio::spawn(async move { a.generate_wrapped_key(&c, &p, &b).await });
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        generate.abort();
        assert!(generate.await.unwrap_err().is_cancelled());
        resume.send(()).unwrap();
        adapter.close_creation_attempt(&binding).await.unwrap();
        assert_eq!(count(control, &cancelled), 0);
        assert!(adapter
            .generate_wrapped_key(&context, parent, &binding)
            .await
            .is_err());
        println!("NATIVE_A2_ADAPTER_PASS cancelled caller retains owner and cannot regenerate");

        let orphan = provider.native_a2_conformance_adapter(NativeWrapMode::KwMechanicsOnly);
        let before = control.find_objects(&[]).unwrap().len();
        let (entered, resume) = arm(&orphan, true);
        let a = orphan.clone();
        let c = context.clone();
        let p = parent.clone();
        let bytes = generated.envelope.clone();
        let open = tokio::spawn(async move { a.open_wrapped_key(&c, &p, &bytes).await });
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(control.find_objects(&[]).unwrap().len(), before + 1);
        open.abort();
        assert!(open.await.unwrap_err().is_cancelled());
        resume.send(()).unwrap();
        // No returned lease to invent or guess. Adapter teardown owns cleanup.
        orphan.close_all().await.unwrap();
        orphan.close_all().await.unwrap();
        assert_eq!(control.find_objects(&[]).unwrap().len(), before);
        assert!(orphan
            .open_wrapped_key(&context, parent, &generated.envelope)
            .await
            .is_err());
        let fresh_request = fresh(base);
        let fresh_binding = CreationBinding::of(&fresh_request).unwrap();
        assert!(orphan
            .generate_wrapped_key(&context, parent, &fresh_binding)
            .await
            .is_err());
        assert_eq!(count(control, &fresh_request), 0);
        println!("NATIVE_A2_ADAPTER_PASS cancelled Open settled by fenced owner-wide teardown");
        adapter.close_all().await.unwrap();
        gcm.close_all().await.unwrap();
        other.close_all().await.unwrap();
    });
}
