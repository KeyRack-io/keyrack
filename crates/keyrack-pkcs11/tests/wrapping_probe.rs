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

//! Provider-local AES-KW primitive and session-lifecycle probe for `SoftHSM2`.
//!
//! This is NOT a completed A2 hierarchy implementation, an authenticated
//! hierarchy-context format, a trusted-wrapping policy, or an HYOK proof.
//! AES-KW authenticates wrapped key bytes, but has no external AAD interface.
//! AES-GCM below operates on application data; its AAD does not bind the wrap.
//! Stock `SoftHSM2` rejects AES-GCM wrapping, which this profile must demonstrate.
//!
//! Requires `softhsm-tests`, `KMS_PKCS11_LIB`, `KMS_PKCS11_PIN`, and
//! `KMS_PKCS11_TOKEN_LABEL=keyrack-wrapping-probe`. The initialized token must
//! be empty and disposable. One combined test avoids independent initialization
//! and token-wide login races. It does not use the production provider API.

#![cfg(feature = "softhsm-tests")]

#[path = "support/native_creation.rs"]
mod native_creation;

use std::error::Error as StdError;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use uuid::Uuid;

type ProbeResult<T> = Result<T, Box<dyn StdError>>;

const TOKEN_LABEL: &str = "keyrack-wrapping-probe";
const APPLICATION_AAD: &[u8] = b"wrapping-probe/application-data/v1";
const APPLICATION_PLAINTEXT: &[u8] = b"public lifecycle probe payload, not key material";

fn check(condition: bool, message: &str) -> ProbeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn at_stage<T>(stage: &str, result: ProbeResult<T>) -> ProbeResult<T> {
    result.map_err(|error| format!("{stage}: {error}").into())
}

/// Preserve both the operation failure and any explicit cleanup failure.
fn finish<T>(outcome: ProbeResult<T>, cleanup: ProbeResult<()>) -> ProbeResult<T> {
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => {
            Err(format!("{error}; cleanup also failed: {cleanup_error}").into())
        }
    }
}

fn required_env(name: &str) -> ProbeResult<String> {
    let value = std::env::var(name).map_err(|_| format!("{name} must be set"))?;
    check(!value.is_empty(), &format!("{name} must not be empty"))?;
    Ok(value)
}

fn expected_error<T>(
    result: cryptoki::error::Result<T>,
    allowed: &[RvError],
    operation: &str,
) -> ProbeResult<()> {
    match result {
        Err(Error::Pkcs11(code, _)) if allowed.contains(&code) => Ok(()),
        Err(error) => Err(format!("{operation}: unexpected error: {error}").into()),
        // Do not debug-print an unexpected successful result: it might contain
        // sensitive bytes if a provider regresses.
        Ok(_) => Err(format!("{operation}: unexpectedly succeeded").into()),
    }
}

fn with_session<T>(
    module: &Pkcs11,
    slot: Slot,
    operation: impl FnOnce(&Session) -> ProbeResult<T>,
) -> ProbeResult<T> {
    let session = module.open_rw_session(slot)?;
    let outcome = operation(&session);
    finish(outcome, session.close().map_err(Into::into))
}

/// A session-created handle must travel with its owning session, not by itself.
struct SessionKey {
    session: Session,
    handle: ObjectHandle,
}

impl SessionKey {
    fn create(
        module: &Pkcs11,
        slot: Slot,
        create: impl FnOnce(&Session) -> ProbeResult<ObjectHandle>,
    ) -> ProbeResult<Self> {
        let session = module.open_rw_session(slot)?;
        match create(&session) {
            Ok(handle) => Ok(Self { session, handle }),
            Err(error) => finish(Err(error), session.close().map_err(Into::into)),
        }
    }

    fn encrypt(&self) -> ProbeResult<([u8; 12], Vec<u8>)> {
        let mut nonce = [0_u8; 12];
        self.session.generate_random_slice(&mut nonce)?;
        let params = GcmParams::new(&mut nonce, APPLICATION_AAD, 128.into())?;
        let ciphertext = self.session.encrypt(
            &Mechanism::AesGcm(params),
            self.handle,
            APPLICATION_PLAINTEXT,
        )?;
        Ok((nonce, ciphertext))
    }

    fn verify_decryption(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> ProbeResult<()> {
        let mut nonce = *nonce;
        let params = GcmParams::new(&mut nonce, APPLICATION_AAD, 128.into())?;
        let plaintext =
            self.session
                .decrypt(&Mechanism::AesGcm(params), self.handle, ciphertext)?;
        // This API returns application plaintext, never the key's CKA_VALUE.
        check(
            plaintext == APPLICATION_PLAINTEXT,
            "direct-handle application decryption did not recover the payload",
        )
    }

    fn finish<T>(self, outcome: ProbeResult<T>, destroy: bool) -> ProbeResult<T> {
        let destroyed = if destroy {
            self.session.destroy_object(self.handle).map_err(Into::into)
        } else {
            // Deliberately test destruction by closing the creating session.
            Ok(())
        };
        let outcome = finish(outcome, destroyed);
        finish(outcome, self.session.close().map_err(Into::into))
    }
}

fn attributes(label: &str, token: bool, extractable: bool) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(token),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(extractable),
        Attribute::Encrypt(!token),
        Attribute::Decrypt(!token),
        Attribute::Wrap(token),
        Attribute::Unwrap(token),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(label.as_bytes().to_vec()),
        Attribute::AllowedMechanisms(vec![if token {
            MechanismType::AES_KEY_WRAP
        } else {
            MechanismType::AES_GCM
        }]),
    ]
}

fn generate(session: &Session, label: &str, token: bool) -> ProbeResult<ObjectHandle> {
    let mut template = attributes(label, token, !token);
    template.push(Attribute::ValueLen(32.into()));
    Ok(session.generate_key(&Mechanism::AesKeyGen, &template)?)
}

fn generate_gcm_probe_parent(session: &Session, label: &str) -> ProbeResult<ObjectHandle> {
    let mut template = attributes(label, true, false);
    // Omission selects SoftHSM's default empty set, which places no extra
    // mechanism restriction on this wrapping-only experimental parent.
    template.retain(|attribute| attribute.attribute_type() != AttributeType::AllowedMechanisms);
    template.push(Attribute::ValueLen(32.into()));
    Ok(session.generate_key(&Mechanism::AesKeyGen, &template)?)
}

fn find_label(session: &Session, label: &str) -> ProbeResult<Vec<ObjectHandle>> {
    Ok(session.find_objects(&[Attribute::Label(label.as_bytes().to_vec())])?)
}

fn empty_token(session: &Session, message: &str) -> ProbeResult<()> {
    check(session.find_objects(&[])?.is_empty(), message)
}

fn parent_handle(session: &Session, label: &str) -> ProbeResult<ObjectHandle> {
    let objects = session.find_objects(&[
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ])?;
    check(objects.len() == 1, "expected exactly one labeled parent")?;
    Ok(objects[0])
}

fn verify_attributes(
    session: &Session,
    handle: ObjectHandle,
    token: bool,
    extractable: bool,
) -> ProbeResult<()> {
    let expected = [
        Attribute::Token(token),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(extractable),
        Attribute::Encrypt(!token),
        Attribute::Decrypt(!token),
        Attribute::Wrap(token),
        Attribute::Unwrap(token),
    ];
    let types: Vec<_> = expected.iter().map(Attribute::attribute_type).collect();
    let actual = session.get_attributes(handle, &types)?;
    check(
        expected.iter().all(|attribute| actual.contains(attribute)),
        "provider did not retain the requested custody/use attributes",
    )?;
    let info = session.get_attribute_info(handle, &[AttributeType::Value])?;
    check(
        matches!(info.as_slice(), [AttributeInfo::Sensitive]),
        "raw key CKA_VALUE was not reported sensitive",
    )?;
    // cryptoki omits sensitive/unavailable attributes rather than returning
    // CKR_ATTRIBUTE_SENSITIVE from get_attributes.
    check(
        session
            .get_attributes(handle, &[AttributeType::Value])?
            .is_empty(),
        "raw key CKA_VALUE was unexpectedly readable",
    )
}

struct Labels {
    parent: String,
    wrong_parent: String,
    generated: String,
    opened: String,
    rejected: String,
    warm: String,
}

impl Labels {
    fn new() -> Self {
        let prefix = format!("wrapping-probe-{}", Uuid::new_v4());
        Self {
            parent: format!("{prefix}-parent"),
            wrong_parent: format!("{prefix}-wrong-parent"),
            generated: format!("{prefix}-generated"),
            opened: format!("{prefix}-opened"),
            rejected: format!("{prefix}-rejected"),
            warm: format!("{prefix}-warm"),
        }
    }

    fn cleanup(&self, session: &Session) -> ProbeResult<()> {
        let mut result = Ok(());
        // Only this invocation's exact UUID labels are cleanup targets.
        for label in [
            &self.parent,
            &self.wrong_parent,
            &self.generated,
            &self.opened,
            &self.rejected,
            &self.warm,
        ] {
            let cleaned = (|| {
                for handle in find_label(session, label)? {
                    session.destroy_object(handle)?;
                }
                Ok(())
            })();
            result = finish(result, cleaned);
        }
        result
    }
}

fn check_mechanisms(module: &Pkcs11, slot: Slot) -> ProbeResult<()> {
    let kw = module.get_mechanism_info(slot, MechanismType::AES_KEY_WRAP)?;
    check(kw.wrap() && kw.unwrap(), "AES-KW wrap/unwrap unavailable")?;
    let gcm = module.get_mechanism_info(slot, MechanismType::AES_GCM)?;
    check(
        gcm.encrypt() && gcm.decrypt(),
        "AES-GCM application encrypt/decrypt unavailable",
    )?;
    check(
        !gcm.wrap() && !gcm.unwrap(),
        "SoftHSM profile changed: review AES-GCM wrapping support explicitly",
    )
}

fn verify_gcm_parent_policy(session: &Session, handle: ObjectHandle) -> ProbeResult<()> {
    // SoftHSM treats its default empty set as unrestricted; a size-only query
    // verifies that no per-key mechanism allow-list can explain GCM refusal.
    let info = session.get_attribute_info(handle, &[AttributeType::AllowedMechanisms])?;
    check(
        matches!(info.as_slice(), [AttributeInfo::Available(0)]),
        "GCM probe parent unexpectedly has a mechanism allow-list restriction",
    )
}

/// Exercise the candidate's real Generate/readback/GCM-Wrap/Close path on the
/// disposable token. This is an UNQUALIFIED mechanism probe: its parent lacks a
/// trusted-wrap policy and the deliberate `false` is not an A2 profile fallback.
fn native_creation_owner_probe(
    module: &Pkcs11,
    slot: Slot,
    control: &Session,
    parent_label: &str,
) -> ProbeResult<()> {
    use keyrack_test_support::creation_conformance::fixture;
    use native_creation::{NativeCreation, NativeCreationError, NativeWrapOutput};

    let (_, request) = fixture();
    let session = module.open_rw_session(slot)?;
    let parent = parent_handle(&session, parent_label)?;
    let mut owner = NativeCreation::new(session, parent, request.clone())?;
    let outcome = (|| {
        let policy = [
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Wrap(true),
            Attribute::Unwrap(true),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
        ];
        let mut iv = [0; 12];
        control.generate_random_slice(&mut iv)?;
        match owner.generate_and_wrap(&request, &policy, false, iv) {
            Err(NativeCreationError::Native(Error::Pkcs11(
                RvError::MechanismInvalid,
                cryptoki::context::Function::WrapKey,
            ))) => {}
            Err(error) => {
                return Err(
                    format!("native owner: expected GCM mechanism refusal, got {error}").into(),
                )
            }
            Ok(_) => {
                return Err(
                    "native owner: unexpected successful GCM wrapping; review qualification".into(),
                )
            }
        }
        // The original child exists after the failed Wrap and is still owed
        // cleanup. This observation is a probe assertion, NEVER closure proof.
        check(
            find_label(control, &request.correlation)?.len() == 1,
            "native owner lost its creation child before explicit close",
        )?;
        check(
            owner
                .generate_and_wrap(&request, &policy, false, iv)
                .is_err(),
            "native owner repeated Generate after failure",
        )?;
        check(
            owner.closed_session().is_none(),
            "native owner claimed premature closure",
        )
    })();
    let outcome = finish(outcome, owner.close().map_err(Into::into));
    outcome?;
    let identity = owner.closed_session();
    check(
        identity.is_some(),
        "native owner did not observe explicit session close",
    )?;
    owner.close()?;
    check(
        owner.closed_session() == identity,
        "native owner changed closure identity on retry",
    )?;
    check(
        find_label(control, &request.correlation)?.is_empty(),
        "native creation child survived original session close",
    )?;
    let forged = NativeWrapOutput {
        iv: [0; 12],
        ciphertext: vec![0; 48],
    };
    check(
        owner.verify_closed_output(&request, &forged).is_err(),
        "native owner certified an output after failed wrapping",
    )
}

fn probe(module: &Pkcs11, slot: Slot, control: &Session, labels: &Labels) -> ProbeResult<()> {
    at_stage("mechanism profile", check_mechanisms(module, slot))?;
    let parent = at_stage(
        "KW-only parent generation",
        generate(control, &labels.parent, true),
    )?;
    // This second parent also probes mechanism dispatch. No mechanism allow-
    // list avoids confusing a key-policy refusal with missing module support.
    let gcm_probe_parent = at_stage(
        "GCM probe parent generation",
        generate_gcm_probe_parent(control, &labels.wrong_parent),
    )?;
    at_stage(
        "KW-only parent attributes",
        verify_attributes(control, parent, true, false),
    )?;
    at_stage(
        "GCM probe parent attributes",
        verify_attributes(control, gcm_probe_parent, true, false),
    )?;
    at_stage(
        "GCM probe parent unrestricted mechanism policy",
        verify_gcm_parent_policy(control, gcm_probe_parent),
    )?;
    at_stage(
        "native creation owner",
        native_creation_owner_probe(module, slot, control, &labels.wrong_parent),
    )?;

    let generated = SessionKey::create(module, slot, |session| {
        generate(session, &labels.generated, false)
    })?;
    let wrapped_and_payload = (|| {
        verify_attributes(&generated.session, generated.handle, false, true)?;
        let parent = parent_handle(&generated.session, &labels.parent)?;
        let wrapped =
            generated
                .session
                .wrap_key(&Mechanism::AesKeyWrap, parent, generated.handle)?;
        check(
            wrapped.len() == 40,
            "unexpected AES-256 KW ciphertext length",
        )?;
        let (nonce, ciphertext) = generated.encrypt()?;
        let gcm_probe_parent = parent_handle(&generated.session, &labels.wrong_parent)?;
        // Both KW operations succeed with precisely the parent used for GCM
        // refusal tests. It is wrapping-only, never a data-decryption oracle.
        let control_wrapped = generated.session.wrap_key(
            &Mechanism::AesKeyWrap,
            gcm_probe_parent,
            generated.handle,
        )?;
        let control_child = generated.session.unwrap_key(
            &Mechanism::AesKeyWrap,
            gcm_probe_parent,
            &control_wrapped,
            &attributes(&labels.rejected, false, false),
        )?;
        let checked = verify_attributes(&generated.session, control_child, false, false);
        finish(
            checked,
            generated
                .session
                .destroy_object(control_child)
                .map_err(Into::into),
        )?;
        let mut wrap_nonce = [0_u8; 12];
        generated.session.generate_random_slice(&mut wrap_nonce)?;
        let params = GcmParams::new(&mut wrap_nonce, b"not-bound-by-KW", 128.into())?;
        expected_error(
            generated.session.wrap_key(
                &Mechanism::AesGcm(params),
                gcm_probe_parent,
                generated.handle,
            ),
            &[RvError::MechanismInvalid],
            "SoftHSM AES-GCM C_WrapKey refusal",
        )?;
        let params = GcmParams::new(&mut wrap_nonce, b"not-bound-by-KW", 128.into())?;
        expected_error(
            generated.session.unwrap_key(
                &Mechanism::AesGcm(params),
                gcm_probe_parent,
                &control_wrapped,
                &attributes(&labels.rejected, false, false),
            ),
            &[RvError::MechanismInvalid],
            "SoftHSM AES-GCM C_UnwrapKey refusal",
        )?;
        Ok((wrapped, nonce, ciphertext))
    })();
    let (wrapped, nonce, ciphertext) = generated.finish(wrapped_and_payload, true)?;
    check(
        find_label(control, &labels.generated)?.is_empty(),
        "generated child survived explicit destruction/session close",
    )?;

    let opened = SessionKey::create(module, slot, |session| {
        Ok(session.unwrap_key(
            &Mechanism::AesKeyWrap,
            parent_handle(session, &labels.parent)?,
            &wrapped,
            &attributes(&labels.opened, false, false),
        )?)
    })?;
    let opened_result = (|| {
        verify_attributes(&opened.session, opened.handle, false, false)?;
        opened.verify_decryption(&nonce, &ciphertext)?;
        expected_error(
            opened.session.wrap_key(
                &Mechanism::AesKeyWrap,
                parent_handle(&opened.session, &labels.parent)?,
                opened.handle,
            ),
            &[RvError::KeyUnextractable],
            "rewrap of a nonextractable opened child",
        )?;
        let invalid_wrap_errors = [
            // SoftHSM 2.6.x returns GENERAL_ERROR for AES-KW integrity failure.
            RvError::GeneralError,
            RvError::WrappedKeyInvalid,
            RvError::EncryptedDataInvalid,
        ];
        let template = attributes(&labels.rejected, false, false);
        expected_error(
            opened.session.unwrap_key(
                &Mechanism::AesKeyWrap,
                parent_handle(&opened.session, &labels.wrong_parent)?,
                &wrapped,
                &template,
            ),
            &invalid_wrap_errors,
            "AES-KW unwrap under the wrong parent",
        )?;
        let mut tampered = wrapped.clone();
        tampered[0] ^= 1;
        expected_error(
            opened.session.unwrap_key(
                &Mechanism::AesKeyWrap,
                parent_handle(&opened.session, &labels.parent)?,
                &tampered,
                &template,
            ),
            &invalid_wrap_errors,
            "AES-KW unwrap of tampered ciphertext",
        )?;
        check(
            find_label(&opened.session, &labels.rejected)?.is_empty(),
            "a refused unwrap created an object",
        )?;
        // Positive control uses the same session and template after failures.
        let positive = opened.session.unwrap_key(
            &Mechanism::AesKeyWrap,
            parent_handle(&opened.session, &labels.parent)?,
            &wrapped,
            &template,
        )?;
        let checked = verify_attributes(&opened.session, positive, false, false);
        finish(
            checked,
            opened.session.destroy_object(positive).map_err(Into::into),
        )
    })();
    opened.finish(opened_result, true)?;
    check(
        find_label(control, &labels.opened)?.is_empty(),
        "opened child survived explicit destruction/session close",
    )?;

    let warm = SessionKey::create(module, slot, |session| {
        Ok(session.unwrap_key(
            &Mechanism::AesKeyWrap,
            parent_handle(session, &labels.parent)?,
            &wrapped,
            &attributes(&labels.warm, false, false),
        )?)
    })?;
    let warm_result = (|| {
        verify_attributes(&warm.session, warm.handle, false, false)?;
        warm.verify_decryption(&nonce, &ciphertext)?;
        with_session(module, slot, |cold| {
            // Resolve while it exists: a later handle error is due to deletion,
            // not an invented handle or a pre-existing lookup failure.
            let old_parent = parent_handle(cold, &labels.parent)?;
            verify_attributes(cold, old_parent, true, false)?;
            with_session(module, slot, |destroyer| {
                let parent = parent_handle(destroyer, &labels.parent)?;
                destroyer.destroy_object(parent)?;
                Ok(())
            })?;
            check(
                find_label(cold, &labels.parent)?.is_empty(),
                "parent survived destruction from a fresh session",
            )?;
            expected_error(
                cold.unwrap_key(
                    &Mechanism::AesKeyWrap,
                    old_parent,
                    &wrapped,
                    &attributes(&labels.rejected, false, false),
                ),
                &[
                    RvError::UnwrappingKeyHandleInvalid,
                    RvError::KeyHandleInvalid,
                ],
                "cold unwrap after parent destruction",
            )
        })?;
        // Important limitation: deleting a parent does NOT revoke a previously
        // opened session key. Local lease invalidation still has to close it.
        warm.verify_decryption(&nonce, &ciphertext)
    })();
    warm.finish(warm_result, false)?;
    with_session(module, slot, |observer| {
        for label in [
            &labels.parent,
            &labels.generated,
            &labels.opened,
            &labels.rejected,
            &labels.warm,
        ] {
            check(
                find_label(observer, label)?.is_empty(),
                "deleted parent or session child remains visible after close",
            )?;
        }
        Ok(())
    })
}

#[test]
fn softhsm_wrapping_lifecycle_probe() -> ProbeResult<()> {
    let library = required_env("KMS_PKCS11_LIB")?;
    let label = required_env("KMS_PKCS11_TOKEN_LABEL")?;
    check(
        label == TOKEN_LABEL,
        "refusing any token except the dedicated keyrack-wrapping-probe token",
    )?;
    let pin = AuthPin::new(required_env("KMS_PKCS11_PIN")?.into_boxed_str());
    let module = Pkcs11::new(library)?;
    module.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let outcome = (|| {
        check(
            module
                .get_library_info()?
                .manufacturer_id()
                .to_ascii_lowercase()
                .contains("softhsm"),
            "this mechanism profile is restricted to SoftHSM",
        )?;
        let mut matching_slots = Vec::new();
        for slot in module.get_slots_with_initialized_token()? {
            if module.get_token_info(slot)?.label() == label {
                matching_slots.push(slot);
            }
        }
        check(
            matching_slots.len() == 1,
            "expected exactly one initialized dedicated probe token",
        )?;
        let slot = matching_slots[0];
        let token = module.get_token_info(slot)?;
        check(
            token
                .manufacturer_id()
                .to_ascii_lowercase()
                .contains("softhsm")
                && token.model().to_ascii_lowercase().contains("softhsm"),
            "refusing a token without the expected SoftHSM manufacturer/model",
        )?;
        with_session(&module, slot, |control| {
            // Login state is token-wide. Keep this session alive and do not
            // perform per-lease logouts, which would invalidate sibling state.
            control.login(UserType::User, Some(&pin))?;
            empty_token(
                control,
                "refusing a nonempty probe token; initialize a disposable token",
            )?;
            let labels = Labels::new();
            let outcome = probe(&module, slot, control, &labels);
            let outcome = finish(outcome, labels.cleanup(control));
            finish(
                outcome,
                empty_token(control, "probe left objects on the disposable token"),
            )
        })
    })();
    finish(outcome, module.finalize().map_err(Into::into))
}
