// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact native context-derived wrapping qualification on an empty disposable token.
#![cfg(feature = "softhsm-tests")]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::ekdf::AesCbcDeriveParams;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use keyrack_core::wrapping::WrappingIdentifier;
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn policy(session: &Session, object: ObjectHandle, expected: &[Attribute]) -> Result<()> {
    for wanted in expected {
        let actual = session.get_attributes(object, &[wanted.attribute_type()])?;
        require(
            actual.as_slice() == [wanted.clone()],
            &format!(
                "strict scalar readback failed for {:?}",
                wanted.attribute_type()
            ),
        )?;
    }
    Ok(())
}

fn unreadable(session: &Session, object: ObjectHandle) -> Result<()> {
    require(
        matches!(
            session
                .get_attribute_info(object, &[AttributeType::Value])?
                .as_slice(),
            [AttributeInfo::Sensitive]
        ),
        "CKA_VALUE must be sensitive",
    )?;
    require(
        session
            .get_attributes(object, &[AttributeType::Value])?
            .is_empty(),
        "CKA_VALUE unexpectedly readable",
    )
}

#[derive(Clone, Copy)]
enum Role {
    Parent,
    Kek,
    Generated,
    Opened,
}

fn template(size: usize, role: Role) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(size.try_into().unwrap()),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(matches!(role, Role::Generated)),
        Attribute::Encrypt(matches!(role, Role::Opened)),
        Attribute::Decrypt(matches!(role, Role::Opened)),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Wrap(matches!(role, Role::Kek)),
        Attribute::Unwrap(matches!(role, Role::Kek)),
        Attribute::Derive(matches!(role, Role::Parent)),
        Attribute::Copyable(false),
        Attribute::Destroyable(true),
        Attribute::Modifiable(false),
    ]
}

fn derive(session: &Session, parent: ObjectHandle, digest: &[u8; 32]) -> Result<ObjectHandle> {
    let expected = template(32, Role::Kek);
    let object = session.derive_key(
        &Mechanism::AesCbcEncryptData(AesCbcDeriveParams::new([0; 16], digest)),
        parent,
        &expected,
    )?;
    policy(session, object, &expected)?;
    unreadable(session, object)?;
    Ok(object)
}

fn digest(context: &keyrack_core::wrapping::WrappingContext) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"KeyRack-PKCS11-CBC32-KW-v1\0");
    hash.update(context.canonical_bytes()?);
    Ok(hash.finalize().into())
}

fn exercise(session: &Session) -> Result<()> {
    require(
        session.find_objects(&[])?.is_empty(),
        "fresh owner must see empty token",
    )?;
    let parent_template = template(32, Role::Parent);
    let parent = session.generate_key(&Mechanism::AesKeyGen, &parent_template)?;
    policy(session, parent, &parent_template)?;
    unreadable(session, parent)?;
    // Positive control distinguishes value-read denial from a broken attribute API.
    let mut readable_template = template(32, Role::Generated);
    let sensitive = readable_template
        .iter_mut()
        .find(|a| matches!(a, Attribute::Sensitive(_)))
        .unwrap();
    *sensitive = Attribute::Sensitive(false);
    let readable = session.generate_key(&Mechanism::AesKeyGen, &readable_template)?;
    let value = session.get_attributes(readable, &[AttributeType::Value])?;
    require(
        matches!(value.as_slice(), [Attribute::Value(bytes)] if bytes.len() == 32),
        "positive control value read failed",
    )?;
    session.destroy_object(readable)?;

    let (_, request) = keyrack_test_support::creation_conformance::fixture();
    let mut context = request.context()?;
    context.mechanism = WrappingIdentifier::new("pkcs11:aes256-cbc-sha256-kw:v1")?;
    for (spec, size) in [
        (keyrack_core::key::KeySpec::Aes128, 16),
        (keyrack_core::key::KeySpec::Aes256, 32),
    ] {
        context.child_spec = spec;
        let context_digest = digest(&context)?;
        let kek = derive(session, parent, &context_digest)?;
        let generated_template = template(size, Role::Generated);
        let child = session.generate_key(&Mechanism::AesKeyGen, &generated_template)?;
        policy(session, child, &generated_template)?;
        let wrapped = session.wrap_key(&Mechanism::AesKeyWrap, kek, child)?;
        require(wrapped.len() == size + 8, "RFC3394 length mismatch")?;
        let mut opened_template = template(size, Role::Opened);
        opened_template.retain(|a| !matches!(a, Attribute::ValueLen(_)));
        let opened = session.unwrap_key(&Mechanism::AesKeyWrap, kek, &wrapped, &opened_template)?;
        policy(session, opened, &opened_template)?;
        let size_readback = session.get_attributes(opened, &[AttributeType::ValueLen])?;
        require(
            size_readback == [Attribute::ValueLen(size.try_into()?)]
                || size_readback == [Attribute::ValueLen(0.into())],
            "unwrapped size inconsistent",
        )?;
        unreadable(session, opened)?;
        // Independently repeat derivation for the same complete context.
        let repeated = derive(session, parent, &context_digest)?;
        let again =
            session.unwrap_key(&Mechanism::AesKeyWrap, repeated, &wrapped, &opened_template)?;
        policy(session, again, &opened_template)?;
        unreadable(session, again)?;
        let mut wrong_context = context.clone();
        wrong_context.security_domain = WrappingIdentifier::new("different-security-domain")?;
        let wrong = derive(session, parent, &digest(&wrong_context)?)?;
        let before_refusal = session.find_objects(&[])?.len();
        match session.unwrap_key(&Mechanism::AesKeyWrap, wrong, &wrapped, &opened_template) {
            // SoftHSM 2.7.0 SoftHSM.cpp:6634-6638 maps the AES-KW
            // backend's unwrap failure to GENERAL_ERROR. This is not a
            // generic error allowance: matching controls bracket the call.
            Err(Error::Pkcs11(RvError::GeneralError, cryptoki::context::Function::UnwrapKey)) => (),
            Err(error) => {
                return Err(format!("wrong context returned unexpected cause: {error}").into())
            }
            Ok(_) => return Err("wrong context unexpectedly unwrapped".into()),
        }
        require(
            session.find_objects(&[])?.len() == before_refusal,
            "refused unwrap created an object",
        )?;
        let after_refusal =
            session.unwrap_key(&Mechanism::AesKeyWrap, kek, &wrapped, &opened_template)?;
        policy(session, after_refusal, &opened_template)?;
        unreadable(session, after_refusal)?;
        for object in [after_refusal, wrong, again, repeated, opened, child, kek] {
            session.destroy_object(object)?;
        }
        require(
            session.find_objects(&[])?.len() == 1,
            "objects leaked after child cleanup",
        )?;
        println!("CONTEXT_DERIVED_PASS aes_bits={} kek_sensitive=true kek_extractable=false opened_sensitive=true opened_extractable=false wrong_context=CKR_GENERAL_ERROR matching_after_refusal=true refusal_created_objects=false values_unreadable=true", size * 8);
    }
    session.destroy_object(parent)?;
    require(
        session.find_objects(&[])?.is_empty(),
        "session object cleanup did not restore baseline",
    )
}

#[test]
fn context_derived_soft_hsm_strict_policy_and_cleanup() -> Result<()> {
    let label = std::env::var("KMS_PKCS11_TOKEN_LABEL")?;
    require(label == "keyrack-wrapping-probe", "refuse arbitrary token")?;
    let module = Pkcs11::new(std::env::var("KMS_PKCS11_LIB")?)?;
    module.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    require(
        module
            .get_library_info()?
            .manufacturer_id()
            .to_ascii_lowercase()
            .contains("softhsm"),
        "only SoftHSM is admitted for this probe",
    )?;
    let slots: Vec<_> = module
        .get_slots_with_initialized_token()?
        .into_iter()
        .filter(|slot| {
            module
                .get_token_info(*slot)
                .is_ok_and(|info| info.label() == label)
        })
        .collect();
    require(slots.len() == 1, "one exact disposable token required")?;
    let observer = module.open_rw_session(slots[0])?;
    observer.login(
        UserType::User,
        Some(&AuthPin::new(std::env::var("KMS_PKCS11_PIN")?.into())),
    )?;
    require(
        observer.find_objects(&[])?.is_empty(),
        "disposable token must be empty",
    )?;
    let owner = module.open_rw_session(slots[0])?;
    let outcome = exercise(&owner);
    // Close the original session even when any strict readback/native call fails.
    let closed = owner.close();
    let remaining = observer.find_objects(&[]);
    let observer_closed = observer.close();
    closed?;
    require(
        remaining?.is_empty(),
        "original-session close left objects behind",
    )?;
    observer_closed?;
    outcome?;
    println!("CONTEXT_DERIVED_CLEANUP explicit_original_close=true all_objects_session=true baseline_restored=true");
    Ok(())
}
