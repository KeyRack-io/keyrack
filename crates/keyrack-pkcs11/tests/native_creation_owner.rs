// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scripted ownership/fault tests, NOT provider qualification or cryptography.

#[path = "support/native_creation.rs"]
mod native_creation;

use cryptoki::object::{Attribute, AttributeType};
use keyrack_test_support::creation_conformance::fixture;
use native_creation::{CreationSession, NativeCreation, NativeCreationError, Result};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    ParentPolicy,
    Generate,
    GeneratePanic,
    ChildPolicy,
    ChildRead,
    Wrap,
    WrapPanic,
    Length,
    Close,
    ClosePanic,
}

#[derive(Default)]
struct Calls {
    generates: usize,
    wraps: usize,
    closes: usize,
    drops: usize,
    aad: Vec<u8>,
    input_iv: [u8; 12],
    read_types: Vec<AttributeType>,
}

struct ScriptedSession {
    fault: Fault,
    calls: Arc<Mutex<Calls>>,
    template: Vec<Attribute>,
}

fn failure() -> NativeCreationError {
    NativeCreationError::Invalid("scripted fault, not a native result".into())
}

impl CreationSession for ScriptedSession {
    type Key = u8;

    fn generate(&mut self, template: &[Attribute]) -> Result<u8> {
        self.calls.lock().unwrap().generates += 1;
        // The mock records effects BEFORE error/panic to exercise ambiguity.
        self.template = template.to_vec();
        assert!(
            self.fault != Fault::GeneratePanic,
            "scripted Generate panic"
        );
        if self.fault == Fault::Generate {
            return Err(failure());
        }
        Ok(2)
    }

    fn attributes(&mut self, key: u8, types: &[AttributeType]) -> Result<Vec<Attribute>> {
        self.calls
            .lock()
            .unwrap()
            .read_types
            .extend_from_slice(types);
        assert!(!types.contains(&AttributeType::Value));
        assert!(!types.contains(&AttributeType::AllowedMechanisms));
        if key == 1 {
            return Ok(vec![Attribute::Wrap(self.fault != Fault::ParentPolicy)]);
        }
        assert_eq!(key, 2);
        if self.fault == Fault::ChildRead {
            return Err(failure());
        }
        let mut result = self.template.clone();
        if self.fault == Fault::ChildPolicy {
            result.retain(|a| !matches!(a, Attribute::Sensitive(_)));
            result.push(Attribute::Sensitive(false));
        }
        Ok(result)
    }

    fn wrap_gcm(
        &mut self,
        parent: u8,
        child: u8,
        iv: &mut [u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        assert_eq!((parent, child), (1, 2));
        {
            let mut calls = self.calls.lock().unwrap();
            calls.wraps += 1;
            calls.aad = aad.to_vec();
            calls.input_iv = *iv;
        }
        assert!(self.fault != Fault::WrapPanic, "scripted Wrap panic");
        if self.fault == Fault::Wrap {
            return Err(failure());
        }
        // Emulate a provider returning an IV, rather than silently persisting
        // the caller's original buffer. This does not qualify such a provider.
        *iv = [0x55; 12];
        let wrapped_len = if self.template.contains(&Attribute::ValueLen(16.into())) {
            32
        } else {
            48
        };
        Ok(vec![
            0x42;
            if self.fault == Fault::Length {
                wrapped_len - 1
            } else {
                wrapped_len
            }
        ])
    }

    fn close(self) -> Result<()> {
        self.calls.lock().unwrap().closes += 1;
        assert!(self.fault != Fault::ClosePanic, "scripted Close panic");
        if self.fault == Fault::Close {
            Err(failure())
        } else {
            Ok(())
        }
    }
}

impl Drop for ScriptedSession {
    fn drop(&mut self) {
        // Model a destructor that may clean up, but reports no observable proof.
        self.calls.lock().unwrap().drops += 1;
    }
}

fn session(fault: Fault) -> (ScriptedSession, Arc<Mutex<Calls>>) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    (
        ScriptedSession {
            fault,
            calls: calls.clone(),
            template: Vec::new(),
        },
        calls,
    )
}

#[test]
fn exact_output_requires_original_explicit_close() {
    let (_, request) = fixture();
    let (session, calls) = session(Fault::None);
    let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
    let output = owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
        .unwrap();
    assert!(owner.closed_session().is_none());
    assert!(owner.verify_closed_output(&request, &output).is_err());
    owner.close().unwrap();
    let identity = owner.closed_session().unwrap();
    owner.close().unwrap();
    assert_eq!(owner.closed_session(), Some(identity));
    owner.verify_closed_output(&request, &output).unwrap();
    assert_eq!(calls.lock().unwrap().closes, 1);
    assert_eq!(output.iv, [0x55; 12]);
    assert_eq!(calls.lock().unwrap().input_iv, [7; 12]);
    assert_eq!(calls.lock().unwrap().aad, request.context_bytes);
    let mut forged = output.clone();
    forged.iv[0] ^= 1;
    assert!(owner.verify_closed_output(&request, &forged).is_err());
    let mut forged = output.clone();
    forged.ciphertext[0] ^= 1;
    assert!(owner.verify_closed_output(&request, &forged).is_err());
    let mut changed = request.clone();
    changed.owner.generation += 1;
    assert!(owner.verify_closed_output(&changed, &output).is_err());
}

#[test]
fn generation_is_one_shot_before_and_after_close() {
    let (_, request) = fixture();
    let (session, calls) = session(Fault::None);
    let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
    owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
        .unwrap();
    assert!(owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], false, [8; 12])
        .is_err());
    owner.close().unwrap();
    assert!(owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [9; 12])
        .is_err());
    assert_eq!(calls.lock().unwrap().generates, 1);
    assert_eq!(calls.lock().unwrap().wraps, 1);
}

#[test]
fn changed_intent_and_malformed_context_have_no_provider_effects() {
    let (_, request) = fixture();
    let (session, calls) = session(Fault::None);
    let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
    let mut changed = request.clone();
    changed.owner.generation += 1;
    assert!(owner
        .generate_and_wrap(&changed, &[Attribute::Wrap(true)], true, [7; 12])
        .is_err());
    let mut malformed = request.clone();
    malformed.context_bytes[0] ^= 1;
    assert!(owner
        .generate_and_wrap(&malformed, &[Attribute::Wrap(true)], true, [7; 12])
        .is_err());
    assert!(calls.lock().unwrap().read_types.is_empty());
    assert_eq!(calls.lock().unwrap().generates, 0);
    // Rejected requests did not turn into a different accepted intent.
    owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
        .unwrap();
    owner.close().unwrap();
}

#[test]
fn parent_policy_denies_before_generate_and_cannot_be_retried() {
    let (_, request) = fixture();
    let (session, calls) = session(Fault::ParentPolicy);
    let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
    assert!(owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
        .is_err());
    assert!(owner
        .generate_and_wrap(&request, &[Attribute::Wrap(false)], false, [8; 12])
        .is_err());
    owner.close().unwrap();
    assert_eq!(calls.lock().unwrap().generates, 0);
    assert_eq!(calls.lock().unwrap().closes, 1);
}

#[test]
fn secret_or_collection_attribute_queries_are_refused_locally() {
    for policy in [
        vec![],
        vec![Attribute::Value(vec![0])],
        vec![Attribute::AllowedMechanisms(vec![])],
        vec![Attribute::VendorDefined((AttributeType::Value, vec![0]))],
        vec![Attribute::VendorDefined((
            AttributeType::AllowedMechanisms,
            vec![],
        ))],
        vec![Attribute::Wrap(true), Attribute::Wrap(true)],
        vec![Attribute::Wrap(true), Attribute::Wrap(false)],
    ] {
        let (_, request) = fixture();
        let (session, calls) = session(Fault::None);
        let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
        assert!(owner
            .generate_and_wrap(&request, &policy, true, [7; 12])
            .is_err());
        assert!(calls.lock().unwrap().read_types.is_empty());
        owner.close().unwrap();
    }
}

#[test]
fn creation_template_has_independent_custody_and_usage_assertions() {
    use cryptoki::object::{KeyType, ObjectClass};
    use keyrack_core::key::KeySpec;
    for (spec, bytes) in [(KeySpec::Aes128, 16), (KeySpec::Aes256, 32)] {
        let (_, mut request) = fixture();
        request.record.key_spec = spec;
        request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
        let expected = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(bytes.into()),
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
            Attribute::WrapWithTrusted(true),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
            Attribute::Derive(false),
            Attribute::Modifiable(false),
            Attribute::Copyable(false),
            Attribute::Destroyable(true),
            Attribute::Label(request.correlation.as_bytes().to_vec()),
            Attribute::Id(request.correlation.as_bytes().to_vec()),
        ];
        let actual = native_creation::creation_template(&request, true).unwrap();
        assert_eq!(actual.len(), expected.len());
        assert!(expected.iter().all(|a| actual.contains(a)));
        let (session, _) = session(Fault::None);
        let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
        let output = owner
            .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
            .unwrap();
        assert_eq!(
            output.ciphertext.len(),
            usize::try_from(bytes).unwrap() + 16
        );
        owner.close().unwrap();
        owner.verify_closed_output(&request, &output).unwrap();
    }
}

#[test]
fn generation_readback_and_wrap_errors_remain_one_shot_but_cleanup_runs() {
    for fault in [
        Fault::Generate,
        Fault::ChildRead,
        Fault::ChildPolicy,
        Fault::Wrap,
        Fault::Length,
    ] {
        let (_, request) = fixture();
        let (session, calls) = session(fault);
        let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
        assert!(owner
            .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
            .is_err());
        assert!(owner
            .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [8; 12])
            .is_err());
        owner.close().unwrap();
        assert!(owner.closed_session().is_some());
        assert_eq!(calls.lock().unwrap().generates, 1);
        assert_eq!(calls.lock().unwrap().closes, 1);
        assert_eq!(
            calls.lock().unwrap().wraps,
            usize::from(matches!(fault, Fault::Wrap | Fault::Length))
        );
    }
}

#[test]
fn provider_unwind_does_not_restore_generate_or_lose_cleanup_owner() {
    for fault in [Fault::GeneratePanic, Fault::WrapPanic] {
        let (_, request) = fixture();
        let (session, calls) = session(fault);
        let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            owner.generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
        }));
        assert!(outcome.is_err());
        assert!(owner
            .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [8; 12])
            .is_err());
        owner.close().unwrap();
        assert_eq!(calls.lock().unwrap().generates, 1);
        assert_eq!(calls.lock().unwrap().closes, 1);
    }
}

#[test]
fn close_error_and_destructor_cannot_mint_closure_or_retry_a_consumed_session() {
    let (_, request) = fixture();
    let (session, calls) = session(Fault::Close);
    let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
    let output = owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
        .unwrap();
    assert!(owner.close().is_err());
    assert_eq!(calls.lock().unwrap().drops, 1);
    assert!(owner.close().is_err());
    assert_eq!(calls.lock().unwrap().closes, 1);
    assert!(owner.closed_session().is_none());
    assert!(owner.verify_closed_output(&request, &output).is_err());
    assert!(owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [8; 12])
        .is_err());
}

#[test]
fn close_unwind_remains_unconfirmed() {
    let (_, request) = fixture();
    let (session, calls) = session(Fault::ClosePanic);
    let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
    let output = owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
        .unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| owner.close())).is_err());
    assert!(owner.close().is_err());
    assert!(owner.closed_session().is_none());
    assert!(owner.verify_closed_output(&request, &output).is_err());
    assert_eq!(calls.lock().unwrap().closes, 1);
}

#[test]
fn empty_replacement_session_never_verifies_original_output() {
    let (_, request) = fixture();
    let (session, _) = session(Fault::None);
    let mut original = NativeCreation::new(session, 1, request.clone()).unwrap();
    let output = original
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
        .unwrap();
    original.close().unwrap();
    let (replacement, _) = self::session(Fault::None);
    let mut replacement = NativeCreation::new(replacement, 1, request.clone()).unwrap();
    replacement.close().unwrap();
    assert_ne!(original.closed_session(), replacement.closed_session());
    assert!(replacement.verify_closed_output(&request, &output).is_err());
}

#[test]
fn cleanup_does_not_require_a_still_eligible_request() {
    let (_, mut request) = fixture();
    let (session, calls) = session(Fault::None);
    let mut owner = NativeCreation::new(session, 1, request.clone()).unwrap();
    owner
        .generate_and_wrap(&request, &[Attribute::Wrap(true)], true, [7; 12])
        .unwrap();
    request.record.state = keyrack_core::key::KeyState::Disabled;
    assert!(request.validate().is_err());
    owner.close().unwrap();
    assert_eq!(calls.lock().unwrap().closes, 1);
}
