// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Original-session native operations. No call in this module is retried.

use super::{failure, key_size, Profile};
use crate::provider::{make_auth_pin, map_pkcs11_error, Pkcs11Provider, SharedModule};
use cryptoki::context::Function;
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::ekdf::AesCbcDeriveParams;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use keyrack_core::error::Result;
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{EncryptOutput, KeyHandle};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::wrapping::WrappingContext;
use sha2::{Digest, Sha256};
use std::sync::Arc;

struct Admission(Arc<SharedModule>);

pub(super) fn ensure_cleanup_confirmed(module: &SharedModule) -> Result<()> {
    if module
        .wrapping_cleanup_unconfirmed
        .load(std::sync::atomic::Ordering::Acquire)
    {
        Err(failure("native cleanup is unconfirmed; wrapping is disabled for this module until process restart"))
    } else {
        Ok(())
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        self.0.gate.leave();
    }
}

/// Cryptoki automatic close is disabled. This owner attempts close at most
/// once, including unwind cleanup, before releasing module admission.
pub(super) struct Owner {
    module: Arc<SharedModule>,
    session: Option<Session>,
    admission: Option<Admission>,
    pub(super) closed: bool,
    opened: Option<ObjectHandle>,
    #[cfg(test)]
    pub(super) fault: Option<Fault>,
    #[cfg(test)]
    pub(super) close_attempts: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    pub(super) release_close_failure: Option<Box<Owner>>,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    AfterGenerate,
    AfterOpen,
    CloseBeforeNative,
}

impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            // Destructor cleanup never sets `closed` or supplies a receipt.
            if let Err(error) = self.close_once(session) {
                tracing::error!(%error, "native original-session destructor cleanup unconfirmed");
            }
        }
        self.admission.take();
    }
}

#[derive(Clone, Copy)]
enum Role {
    Parent,
    Kek,
    Generated,
    Opened,
    Migration,
}

fn template(role: Role, size: usize, token: bool, label: &str) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(size.try_into().expect("bounded AES size")),
        Attribute::Token(token),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(matches!(role, Role::Generated | Role::Migration)),
        Attribute::Encrypt(matches!(role, Role::Opened)),
        Attribute::Decrypt(matches!(role, Role::Opened)),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Wrap(matches!(role, Role::Kek)),
        Attribute::Unwrap(matches!(role, Role::Kek)),
        Attribute::Derive(matches!(role, Role::Parent)),
        Attribute::Copyable(false),
        Attribute::Destroyable(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(label.as_bytes().to_vec()),
        Attribute::Modifiable(false),
    ]
}

fn policy(session: &Session, key: ObjectHandle, expected: &[Attribute]) -> Result<()> {
    for wanted in expected {
        let actual = session
            .get_attributes(key, &[wanted.attribute_type()])
            .map_err(|e| map_pkcs11_error("context-derived scalar policy readback", &e))?;
        if actual.as_slice() != [wanted.clone()] {
            return Err(failure(&format!(
                "strict {:?} policy readback mismatch",
                wanted.attribute_type()
            )));
        }
    }
    Ok(())
}

fn unreadable(session: &Session, key: ObjectHandle) -> Result<()> {
    let info = session
        .get_attribute_info(key, &[AttributeType::Value])
        .map_err(|e| map_pkcs11_error("context-derived value sensitivity", &e))?;
    if !matches!(info.as_slice(), [AttributeInfo::Sensitive]) {
        return Err(failure("CKA_VALUE not sensitive"));
    }
    let value = session
        .get_attributes(key, &[AttributeType::Value])
        .map_err(|e| map_pkcs11_error("context-derived value denial", &e))?;
    if !value.is_empty() {
        return Err(failure("CKA_VALUE unexpectedly readable"));
    }
    Ok(())
}

fn context_digest(context: &WrappingContext) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"KeyRack-PKCS11-CBC32-KW-v1\0");
    hash.update(
        context
            .canonical_bytes()
            .map_err(|e| failure(&e.to_string()))?,
    );
    Ok(hash.finalize().into())
}

fn derive(
    session: &Session,
    parent: ObjectHandle,
    context: &WrappingContext,
    label: &str,
) -> Result<ObjectHandle> {
    let digest = context_digest(context)?;
    let expected = template(Role::Kek, 32, false, label);
    let key = session
        .derive_key(
            &Mechanism::AesCbcEncryptData(AesCbcDeriveParams::new([0; 16], &digest)),
            parent,
            &expected,
        )
        .map_err(|e| map_pkcs11_error("context-derived KEK derive (not retried)", &e))?;
    policy(session, key, &expected)?;
    unreadable(session, key)?;
    Ok(key)
}

fn unwrapped_policy(
    session: &Session,
    key: ObjectHandle,
    size: usize,
    label: &str,
    role: Role,
) -> Result<()> {
    let mut expected = template(role, size, false, label);
    expected.retain(|a| !matches!(a, Attribute::ValueLen(_)));
    policy(session, key, &expected)?;
    let actual = session
        .get_attributes(key, &[AttributeType::ValueLen])
        .map_err(|e| map_pkcs11_error("context-derived unwrap size readback", &e))?;
    if actual != [Attribute::ValueLen(size.try_into().expect("AES size"))]
        && actual != [Attribute::ValueLen(0.into())]
    {
        return Err(failure("inconsistent unwrapped AES size"));
    }
    unreadable(session, key)
}

fn opened_policy(session: &Session, key: ObjectHandle, size: usize, label: &str) -> Result<()> {
    unwrapped_policy(session, key, size, label, Role::Opened)
}

impl Owner {
    pub(super) fn new(provider: &Pkcs11Provider) -> Result<Self> {
        ensure_cleanup_confirmed(&provider.module)?;
        provider.module.gate.admit()?;
        let admission = Admission(Arc::clone(&provider.module));
        // Admission can wait through recovery; the fast check may be stale by
        // the time it returns. Keep the RAII guard while rechecking the latch.
        ensure_cleanup_confirmed(&provider.module)?;
        let session = provider
            .module
            .ctx
            .open_rw_session_no_drop(provider.current_slot()?)
            .map_err(|e| map_pkcs11_error("context-derived original session open", &e))?;
        let mut owner = Self {
            module: Arc::clone(&provider.module),
            session: Some(session),
            admission: Some(admission),
            closed: false,
            opened: None,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            close_attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            release_close_failure: None,
        };
        match owner
            .session()?
            .login(UserType::User, Some(&make_auth_pin(&provider.pin)))
        {
            Ok(()) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => (),
            Err(e) => {
                let operation = Err(map_pkcs11_error("context-derived login", &e));
                return super::finish(operation, owner.close());
            }
        }
        Ok(owner)
    }

    fn session(&self) -> Result<&Session> {
        self.session
            .as_ref()
            .ok_or_else(|| failure("original session is unavailable"))
    }

    pub(super) fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.opened = None;
        let session = self
            .session
            .take()
            .ok_or_else(|| failure("original close remains unconfirmed"))?;
        let result = self.close_once(session);
        self.admission.take();
        result?;
        self.closed = true;
        Ok(())
    }

    fn record_close(&self, result: Result<()>) -> Result<()> {
        if result.is_err() {
            self.module
                .wrapping_cleanup_unconfirmed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }

    fn close_once(&mut self, session: Session) -> Result<()> {
        #[cfg(test)]
        {
            self.close_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fault == Some(Fault::CloseBeforeNative) {
                // A consumed no-drop Session cannot retry a failed close from
                // its destructor. The live regression observes the object.
                drop(session);
                return self
                    .record_close(Err(failure("injected close failure before native close")));
            }
        }
        let result = session
            .close()
            .map_err(|e| map_pkcs11_error("context-derived original session close", &e));
        self.record_close(result)
    }

    fn parent(&self, handle: &KeyHandle) -> Result<ObjectHandle> {
        let session = self.session()?;
        let found = session
            .find_objects(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Token(true),
                Attribute::Label(handle.key_id.as_bytes().to_vec()),
            ])
            .map_err(|e| map_pkcs11_error("context-derived exact parent lookup", &e))?;
        if found.len() != 1 {
            return Err(failure("exact resident parent missing or ambiguous"));
        }
        policy(
            session,
            found[0],
            &template(Role::Parent, 32, true, &handle.key_id),
        )?;
        Ok(found[0])
    }

    pub(super) fn generate_root(&self, label: &str) -> Result<()> {
        let session = self.session()?;
        let expected = template(Role::Parent, 32, true, label);
        let root = session
            .generate_key(&Mechanism::AesKeyGen, &expected)
            .map_err(|e| map_pkcs11_error("derive-only root generation (not retried)", &e))?;
        let checked = policy(session, root, &expected).and_then(|()| unreadable(session, root));
        if checked.is_err() {
            return super::finish(
                checked,
                session
                    .destroy_object(root)
                    .map_err(|e| map_pkcs11_error("rejected derive-only root cleanup", &e)),
            );
        }
        checked
    }

    pub(super) fn generate(
        &mut self,
        context: &WrappingContext,
        parent: &KeyHandle,
        label: &str,
    ) -> Result<Vec<u8>> {
        let parent = self.parent(parent)?;
        self.generate_under(context, parent, label)
    }

    fn generate_under(
        &self,
        context: &WrappingContext,
        parent: ObjectHandle,
        label: &str,
    ) -> Result<Vec<u8>> {
        let session = self.session()?;
        let size = key_size(&context.child_spec)?;
        let kek = derive(session, parent, context, label)?;
        let expected = template(Role::Generated, size, false, label);
        let child = session
            .generate_key(&Mechanism::AesKeyGen, &expected)
            .map_err(|e| map_pkcs11_error("context-derived child generation (not retried)", &e))?;
        #[cfg(test)]
        if self.fault == Some(Fault::AfterGenerate) {
            return Err(failure("injected after child generation"));
        }
        policy(session, child, &expected)?;
        let bytes = session
            .wrap_key(&Mechanism::AesKeyWrap, kek, child)
            .map_err(|e| map_pkcs11_error("context-derived child wrap (no fallback)", &e))?;
        if bytes.len() != size + 8 {
            return Err(failure("native AES-KW output length mismatch"));
        }
        for key in [child, kek] {
            session
                .destroy_object(key)
                .map_err(|e| map_pkcs11_error("context-derived temporary cleanup", &e))?;
        }
        Ok(bytes)
    }

    pub(super) fn open(
        &mut self,
        context: &WrappingContext,
        parent: &KeyHandle,
        wrapped: &[u8],
        label: &str,
    ) -> Result<()> {
        let parent = self.parent(parent)?;
        self.open_under(context, parent, wrapped, label)
    }

    fn open_under(
        &mut self,
        context: &WrappingContext,
        parent: ObjectHandle,
        wrapped: &[u8],
        label: &str,
    ) -> Result<()> {
        let session = self.session()?;
        let size = key_size(&context.child_spec)?;
        let kek = derive(session, parent, context, label)?;
        let mut expected = template(Role::Opened, size, false, label);
        expected.retain(|a| !matches!(a, Attribute::ValueLen(_)));
        let opened = session.unwrap_key(&Mechanism::AesKeyWrap, kek, wrapped, &expected);
        // No session KEK survives an ordinary successful open.
        let destroyed = session.destroy_object(kek);
        let child = super::finish(
            opened.map_err(|e| map_pkcs11_error("context-derived child unwrap (not retried)", &e)),
            destroyed.map_err(|e| map_pkcs11_error("context-derived KEK destruction", &e)),
        )?;
        #[cfg(test)]
        if self.fault == Some(Fault::AfterOpen) {
            return Err(failure("injected after native unwrap"));
        }
        opened_policy(session, child, size, label)?;
        self.opened = Some(child);
        Ok(())
    }

    /// Private native mechanics awaiting the shared migration contract. Returns
    /// only wrapped bytes, after explicit original-session closure; no receipt
    /// type or migration publication is invented here.
    #[allow(dead_code)]
    pub(super) fn rewrap_closed(
        &mut self,
        profile: &Profile,
        old: &WrappingContext,
        old_parent: &KeyHandle,
        new: &WrappingContext,
        new_parent: &KeyHandle,
        wrapped: &[u8],
    ) -> Result<Vec<u8>> {
        let label = format!("kr-wrap-migrate-{}", uuid::Uuid::new_v4());
        let label = label.as_str();
        let outcome = (|| {
            ensure_cleanup_confirmed(&self.module)?;
            profile.validate(
                old,
                old_parent,
                keyrack_core::wrapping::WrappingOperation::Open,
            )?;
            profile.validate(
                new,
                new_parent,
                keyrack_core::wrapping::WrappingOperation::Generate,
            )?;
            let mut allowed = old.clone();
            allowed.parent = new.parent;
            allowed.parent_spec = new.parent_spec.clone();
            if allowed != *new {
                return Err(failure(
                    "rewrap changes fields other than the exact parent identity/spec",
                ));
            }
            if old.child_spec != new.child_spec || wrapped.len() != key_size(&old.child_spec)? + 8 {
                return Err(failure(
                    "rewrap must preserve child algorithm and exact envelope length",
                ));
            }
            let old_parent = self.parent(old_parent)?;
            let new_parent = self.parent(new_parent)?;
            let session = self.session()?;
            let old_kek = derive(session, old_parent, old, label)?;
            let size = key_size(&old.child_spec)?;
            let mut attributes = template(Role::Migration, size, false, label);
            attributes.retain(|a| !matches!(a, Attribute::ValueLen(_)));
            let child = session
                .unwrap_key(&Mechanism::AesKeyWrap, old_kek, wrapped, &attributes)
                .map_err(|e| {
                    map_pkcs11_error("temporary migration child unwrap (not retried)", &e)
                })?;
            unwrapped_policy(session, child, size, label, Role::Migration)?;
            let new_kek = derive(session, new_parent, new, label)?;
            let output = session
                .wrap_key(&Mechanism::AesKeyWrap, new_kek, child)
                .map_err(|e| {
                    map_pkcs11_error("temporary migration child wrap (no fallback)", &e)
                })?;
            if output.len() != size + 8 {
                return Err(failure("rewrap output length mismatch"));
            }
            let mut cleanup = Ok(());
            for key in [old_kek, new_kek, child] {
                cleanup = super::finish(
                    cleanup,
                    session
                        .destroy_object(key)
                        .map_err(|e| map_pkcs11_error("rewrap temporary object destruction", &e)),
                );
            }
            cleanup?;
            Ok(output)
        })();
        let output = super::finish(outcome, self.close())?;
        #[cfg(test)]
        if let Some(other) = self.release_close_failure.as_mut() {
            // Real original owner, with deterministic failure at its native
            // close boundary. Only close_once's production failure path sets
            // the latch; this hook does not assume that transition happened.
            assert!(other.close().is_err(), "injected competing close must fail");
        }
        ensure_cleanup_confirmed(&self.module)?;
        Ok(output)
    }

    fn known_answer(
        &mut self,
        context: &WrappingContext,
        parent: ObjectHandle,
        label: &str,
    ) -> Result<()> {
        // Public FIPS 197 Appendix C vectors, never application key material.
        // This tests the actual unwrapped AES size when VALUE_LEN reports zero.
        let size = key_size(&context.child_spec)?;
        let public_key: Vec<u8> = (0..u8::try_from(size).expect("AES size")).collect();
        let plaintext: Vec<u8> = (0..16).map(|i| i * 0x11).collect();
        let expected: [u8; 16] = if size == 16 {
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a,
            ]
        } else {
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89,
            ]
        };
        let session = self.session()?;
        let mut attributes = template(Role::Generated, size, false, label);
        attributes.retain(|a| !matches!(a, Attribute::ValueLen(_) | Attribute::Modifiable(_)));
        attributes.push(Attribute::Value(public_key));
        attributes.push(Attribute::Modifiable(false));
        let known = session
            .create_object(&attributes)
            .map_err(|e| map_pkcs11_error("public AES known-answer fixture", &e))?;
        let kek = derive(session, parent, context, label)?;
        let wrapped = session
            .wrap_key(&Mechanism::AesKeyWrap, kek, known)
            .map_err(|e| map_pkcs11_error("known-answer wrap", &e))?;
        session
            .destroy_object(kek)
            .map_err(|e| map_pkcs11_error("known-answer KEK cleanup", &e))?;
        session
            .destroy_object(known)
            .map_err(|e| map_pkcs11_error("known-answer input cleanup", &e))?;
        self.open_under(context, parent, &wrapped, label)?;
        let opened = self.opened.take().expect("successful known-answer open");
        let session = self.session()?;
        let actual = session
            .encrypt(&Mechanism::AesEcb, opened, &plaintext)
            .map_err(|e| map_pkcs11_error("known-answer AES operation", &e))?;
        if actual != expected {
            return Err(failure("unwrapped AES known-answer size/key mismatch"));
        }
        session
            .destroy_object(opened)
            .map_err(|e| map_pkcs11_error("known-answer opened cleanup", &e))
    }

    pub(super) fn encrypt(
        &self,
        context: &WrappingContext,
        label: &str,
        data: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        let session = self.session()?;
        let key = self
            .opened
            .ok_or_else(|| failure("creation/closed owner cannot perform ordinary use"))?;
        opened_policy(session, key, key_size(&context.child_spec)?, label)?;
        let mut iv = [0; 12];
        session
            .generate_random_slice(&mut iv)
            .map_err(|e| map_pkcs11_error("native lease nonce", &e))?;
        let params = GcmParams::new(&mut iv, aad, 128.into())
            .map_err(|e| map_pkcs11_error("native lease GCM", &e))?;
        let encrypted = session
            .encrypt(&Mechanism::AesGcm(params), key, data)
            .map_err(|e| map_pkcs11_error("native lease encrypt", &e))?;
        let mut ciphertext = iv.to_vec();
        ciphertext.extend(encrypted);
        Ok(EncryptOutput { ciphertext })
    }

    pub(super) fn decrypt(
        &self,
        context: &WrappingContext,
        label: &str,
        data: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        if data.len() < 28 {
            return Err(failure("truncated application ciphertext"));
        }
        let session = self.session()?;
        let key = self
            .opened
            .ok_or_else(|| failure("creation/closed owner cannot perform ordinary use"))?;
        opened_policy(session, key, key_size(&context.child_spec)?, label)?;
        let mut iv: [u8; 12] = data[..12].try_into().expect("length checked");
        let params = GcmParams::new(&mut iv, aad, 128.into())
            .map_err(|e| map_pkcs11_error("native lease GCM", &e))?;
        session
            .decrypt(&Mechanism::AesGcm(params), key, &data[12..])
            .map(Sensitive::new)
            .map_err(|e| map_pkcs11_error("native lease decrypt", &e))
    }
}

/// Explicit profile admission: only the qualified software-token family, and
/// only session objects, including the parent. No broad mechanism fallback.
pub(super) fn self_test(provider: &Pkcs11Provider, profile: &Profile) -> Result<()> {
    let mut observer = Owner::new(provider)?;
    let outcome = self_test_observed(provider, profile, &observer);
    super::finish(outcome, observer.close())
}

fn self_test_observed(
    provider: &Pkcs11Provider,
    profile: &Profile,
    observer: &Owner,
) -> Result<()> {
    let info = provider
        .module
        .ctx
        .get_library_info()
        .map_err(|e| map_pkcs11_error("wrapping module identity", &e))?;
    if !info
        .manufacturer_id()
        .to_ascii_lowercase()
        .contains("softhsm")
        || info.library_version().major() != 2
        || info.library_version().minor() != 7
    {
        return Err(failure(
            "this experimental wrapping profile requires qualified SoftHSM 2.7",
        ));
    }
    let baseline = observer
        .session()?
        .find_objects(&[])
        .map_err(|e| map_pkcs11_error("self-test baseline", &e))?;
    let mut owner = Owner::new(provider)?;
    let outcome = (|| {
        let label = format!("kr-wrap-self-test-{}", uuid::Uuid::new_v4());
        let expected = template(Role::Parent, 32, false, &label);
        let parent = owner
            .session()?
            .generate_key(&Mechanism::AesKeyGen, &expected)
            .map_err(|e| map_pkcs11_error("session-only self-test parent", &e))?;
        policy(owner.session()?, parent, &expected)?;
        unreadable(owner.session()?, parent)?;
        for spec in [KeySpec::Aes128, KeySpec::Aes256] {
            let context = profile.self_test_context(spec)?;
            owner.known_answer(&context, parent, &label)?;
            let bytes = owner.generate_under(&context, parent, &label)?;
            owner.open_under(&context, parent, &bytes, &label)?;
            let encrypted =
                owner.encrypt(&context, &label, b"wrapping startup self-test", b"aad")?;
            let decrypted = owner.decrypt(&context, &label, &encrypted.ciphertext, b"aad")?;
            if decrypted.expose().as_slice() != b"wrapping startup self-test" {
                return Err(failure("startup crypto mismatch"));
            }
            let opened = owner.opened.take().expect("successful open");
            owner
                .session()?
                .destroy_object(opened)
                .map_err(|e| map_pkcs11_error("self-test opened cleanup", &e))?;
            let mut wrong = context.clone();
            wrong.child.version = std::num::NonZeroU64::new(2).expect("nonzero");
            let session = owner.session()?;
            let kek = derive(session, parent, &wrong, &label)?;
            let mut opened_template =
                template(Role::Opened, key_size(&context.child_spec)?, false, &label);
            opened_template.retain(|a| !matches!(a, Attribute::ValueLen(_)));
            let count = session
                .find_objects(&[])
                .map_err(|e| map_pkcs11_error("self-test refusal baseline", &e))?
                .len();
            match session.unwrap_key(&Mechanism::AesKeyWrap, kek, &bytes, &opened_template) {
                Err(Error::Pkcs11(RvError::GeneralError, Function::UnwrapKey)) => (),
                Err(e) => {
                    return Err(map_pkcs11_error(
                        "unexpected self-test wrong-context refusal",
                        &e,
                    ))
                }
                Ok(_) => return Err(failure("wrong context passed startup unwrap")),
            }
            if session
                .find_objects(&[])
                .map_err(|e| map_pkcs11_error("self-test refusal inventory", &e))?
                .len()
                != count
            {
                return Err(failure("failed startup unwrap created an object"));
            }
            session
                .destroy_object(kek)
                .map_err(|e| map_pkcs11_error("self-test wrong KEK cleanup", &e))?;
            owner.open_under(&context, parent, &bytes, &label)?;
            let opened = owner.opened.take().expect("successful control open");
            owner
                .session()?
                .destroy_object(opened)
                .map_err(|e| map_pkcs11_error("self-test control cleanup", &e))?;
        }
        owner
            .session()?
            .destroy_object(parent)
            .map_err(|e| map_pkcs11_error("self-test parent cleanup", &e))?;
        Ok(())
    })();
    let closed = owner.close();
    let remaining = observer
        .session()?
        .find_objects(&[])
        .map_err(|e| map_pkcs11_error("self-test final inventory", &e));
    let inventory = remaining.and_then(|after| {
        if baseline.len() != after.len() || !baseline.iter().all(|key| after.contains(key)) {
            Err(failure("self-test changed token object baseline"))
        } else {
            Ok(())
        }
    });
    super::finish(super::finish(outcome, closed), inventory)
}
