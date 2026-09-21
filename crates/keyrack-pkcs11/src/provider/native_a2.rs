// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native PKCS#11 candidate engine, exposed only for explicit conformance runs.
//!
//! This is NOT a qualified A2 provider or the shared wrapping trait. In particular,
//! AES-KW has no external AAD; comparing context in this host does not authenticate
//! it against a malicious coordinator. No method here mints `VerifiedA2Closure`,
//! registers a service capability, or routes to software/the crypto worker.
//! The authenticated GCM candidate never falls back to the KW mechanics path.
//!
//! Sessions own module admission until explicit close AND destructor fallback have
//! finished. No native effect goes through the ordinary retrying provider `run`.
//! Ambiguous Generate/Unwrap consumes its original attempt, including on unwind.
//! Scalar policy checks are not proof of trusted-template enforcement, transport
//! security, hardware isolation, nonce limits, current authority or all-holder
//! closure. Those remain per-token qualification requirements.

use super::{make_auth_pin, map_pkcs11_error, Pkcs11Provider, SharedModule};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use keyrack_core::creation::CreationBinding;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{EncryptOutput, KeyHandle};
use keyrack_core::sensitive::Sensitive;
use keyrack_core::wrapping::{WrappedKeyFormat, WrappingContext, WrappingKeyPurpose};
use std::sync::Arc;
use uuid::Uuid;

pub mod adapter;

fn refused(message: &str) -> KeyRackError {
    KeyRackError::Provider(format!("unqualified native A2 candidate: {message}"))
}

/// Mechanism choice is explicit and immutable, never negotiated after failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeWrapMode {
    /// Supplies the complete canonical context to native GCM wrapping. A native
    /// success alone does not qualify the token or its attribute enforcement.
    GcmCandidate,
    /// Exercises native key wrapping/lifetimes ONLY. There is no context binding.
    /// This must never satisfy a hierarchy authenticated-context admission gate.
    KwMechanicsOnly,
}

/// In-process primitive output, NOT a new persisted/shared envelope encoding.
/// No key bytes, numeric object handle, Debug or serde implementation is exposed.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeEnvelope {
    mode: NativeWrapMode,
    iv: [u8; 12],
    ciphertext: Vec<u8>,
    context_sha256: [u8; 32],
}

impl NativeEnvelope {
    /// Wrapped bytes only. The shared contract owner selects durable encoding.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Keeps the module alive and prevents process-wide finalization under a session.
struct LifetimeAdmission(Arc<SharedModule>);

impl LifetimeAdmission {
    fn acquire(module: Arc<SharedModule>) -> Result<Self> {
        module.gate.admit()?;
        Ok(Self(module))
    }
}

impl Drop for LifetimeAdmission {
    fn drop(&mut self) {
        self.0.gate.leave();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ready,
    Attempted,
    Open,
    CloseUnconfirmed,
    Closed,
}

/// One original native session and at most one Generate OR Unwrap attempt.
///
/// This synchronous owner is Send but not Sync. The conformance adapter serializes
/// use/close in a blocking owner and retains it through caller cancellation.
/// Durable dispatch/restart reconciliation is not supplied here: a fresh instance
/// is not proof that an earlier attempt had no effects. Cleanup does not require
/// fresh crypto authority. No Clone or serializable lease handle is supplied here.
pub struct NativeA2Session {
    // Drop order matters: cryptoki's destructor may call C_CloseSession again.
    // It must run before admission is released, even if explicit close failed.
    session: Option<Session>,
    admission: Option<LifetimeAdmission>,
    identity: Uuid,
    context: WrappingContext,
    context_bytes: Vec<u8>,
    context_sha256: [u8; 32],
    creation: Option<CreationBinding>,
    correlation: String,
    parent: KeyHandle,
    mode: NativeWrapMode,
    phase: Phase,
    opened: Option<ObjectHandle>,
    generated: Option<NativeEnvelope>,
}

impl Pkcs11Provider {
    /// Blocking conformance-only owner acquisition; never service admission.
    /// Session acquisition and later native effects are deliberately not retried.
    /// `Some(creation)` selects a generation owner; `None` selects an ordinary
    /// open owner with a fresh use-only correlation. The roles are immutable.
    pub fn native_a2_conformance_session(
        &self,
        parent: KeyHandle,
        context: WrappingContext,
        creation: Option<CreationBinding>,
        mode: NativeWrapMode,
    ) -> Result<NativeA2Session> {
        let context_bytes = validate_inputs(&context, &parent)?;
        let context_sha256 = context
            .context_sha256()
            .map_err(|_| refused("invalid wrapping context"))?;
        let identity = Uuid::new_v4();
        let correlation = creation.as_ref().map_or_else(
            || format!("kr-native-a2-use-{identity}"),
            |binding| binding.correlation().to_owned(),
        );
        let admission = LifetimeAdmission::acquire(Arc::clone(&self.module))?;
        let session = self
            .module
            .ctx
            .open_rw_session(self.current_slot()?)
            .map_err(|e| map_pkcs11_error("native owner open", &e))?;
        match session.login(UserType::User, Some(&make_auth_pin(&self.pin))) {
            Ok(())
            | Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::UserAlreadyLoggedIn,
                _,
            )) => {}
            Err(error) => return Err(map_pkcs11_error("native owner login", &error)),
        }
        Ok(NativeA2Session {
            session: Some(session),
            admission: Some(admission),
            identity,
            context,
            context_bytes,
            context_sha256,
            creation,
            correlation,
            parent,
            mode,
            phase: Phase::Ready,
            opened: None,
            generated: None,
        })
    }
}

impl NativeA2Session {
    fn session(&self) -> Result<&Session> {
        self.session
            .as_ref()
            .ok_or_else(|| refused("original session unavailable"))
    }

    fn check_binding(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: Option<&CreationBinding>,
    ) -> Result<()> {
        if context != &self.context || parent != &self.parent {
            return Err(refused("attempt context or exact parent changed"));
        }
        if self.creation.as_ref() != creation {
            return Err(refused("attempt creation binding or owner role changed"));
        }
        Ok(())
    }

    fn begin(
        &mut self,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: Option<&CreationBinding>,
    ) -> Result<()> {
        self.check_binding(context, parent, creation)?;
        if self.phase != Phase::Ready {
            return Err(refused("native attempt already consumed or closed"));
        }
        // Before any native effect or policy read. Failure/unwind cannot retry.
        self.phase = Phase::Attempted;
        Ok(())
    }

    fn parent(&self) -> Result<ObjectHandle> {
        let session = self.session()?;
        let handles = session
            .find_objects(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Token(true),
                Attribute::Label(self.parent.key_id.as_bytes().to_vec()),
            ])
            .map_err(|e| map_pkcs11_error("native parent lookup", &e))?;
        if handles.len() != 1 {
            return Err(refused("parent lookup must identify exactly one object"));
        }
        let parent = handles[0];
        let expected = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(
                key_length(&self.parent.key_spec)?
                    .try_into()
                    .map_err(|_| refused("parent AES size"))?,
            ),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Wrap(true),
            Attribute::Unwrap(true),
        ];
        check_attributes(session, parent, &expected)?;
        Ok(parent)
    }

    /// Native Generate -> Wrap. The caller must explicitly close the original
    /// creation owner before any legitimate journal publication. No closure proof
    /// or qualified envelope is returned by this candidate-only method.
    pub fn generate_wrapped_key(
        &mut self,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: &CreationBinding,
    ) -> Result<NativeEnvelope> {
        self.begin(context, parent, Some(creation))?;
        let parent = self.parent()?;
        let session = self.session()?;
        let template = child_template(context, &self.correlation, true)?;
        let child = session
            .generate_key(&Mechanism::AesKeyGen, &template)
            .map_err(|e| map_pkcs11_error("native child generate (not retried)", &e))?;
        check_attributes(session, child, &template)?;
        let mut iv = [0; 12];
        let ciphertext = match self.mode {
            NativeWrapMode::GcmCandidate => {
                session
                    .generate_random_slice(&mut iv)
                    .map_err(|e| map_pkcs11_error("candidate wrap nonce", &e))?;
                let params = GcmParams::new(&mut iv, &self.context_bytes, 128.into())
                    .map_err(|e| map_pkcs11_error("candidate GCM params", &e))?;
                // cryptoki makes a size query and an output C_WrapKey call.
                // Nonce/use accounting and returned-IV behavior need qualification.
                session.wrap_key(&Mechanism::AesGcm(params), parent, child)
            }
            NativeWrapMode::KwMechanicsOnly => {
                session.wrap_key(&Mechanism::AesKeyWrap, parent, child)
            }
        }
        .map_err(|e| map_pkcs11_error("native child wrap (no fallback)", &e))?;
        let overhead = if self.mode == NativeWrapMode::GcmCandidate {
            16
        } else {
            8
        };
        if ciphertext.len() != key_length(&context.child_spec)? + overhead {
            return Err(refused("unexpected native wrapped length"));
        }
        let envelope = NativeEnvelope {
            mode: self.mode,
            iv,
            ciphertext,
            context_sha256: self.context_sha256,
        };
        self.generated = Some(envelope.clone());
        Ok(envelope)
    }

    /// Unwrap into this original session only; never return an operable handle.
    /// Requires an ordinary-use owner. The stored envelope binds wrapping context,
    /// while creation provenance stays with the owner that originally generated it.
    /// Host-side equality here is not authentication for the KW mechanics path.
    pub fn open_wrapped_key(
        &mut self,
        context: &WrappingContext,
        parent: &KeyHandle,
        envelope: &NativeEnvelope,
    ) -> Result<()> {
        self.begin(context, parent, None)?;
        if envelope.context_sha256 != self.context_sha256 || envelope.mode != self.mode {
            return Err(refused("envelope context/mechanism mismatch"));
        }
        let expected = key_length(&context.child_spec)?
            + if self.mode == NativeWrapMode::GcmCandidate {
                16
            } else {
                8
            };
        if envelope.ciphertext.len() != expected {
            return Err(refused("invalid native wrapped length"));
        }
        let parent = self.parent()?;
        let session = self.session()?;
        let mut template = child_template(context, &self.correlation, false)?;
        // Unwrap infers secret length from the wrapped bytes. GCM readback below
        // requires exact AES size; the explicitly unqualified KW profile also
        // records SoftHSM's zero-length metadata behavior (see check_opened_policy).
        template.retain(|a| !matches!(a, Attribute::ValueLen(_)));
        let mut iv = envelope.iv;
        let opened = match self.mode {
            NativeWrapMode::GcmCandidate => {
                let params = GcmParams::new(&mut iv, &self.context_bytes, 128.into())
                    .map_err(|e| map_pkcs11_error("candidate GCM params", &e))?;
                session.unwrap_key(
                    &Mechanism::AesGcm(params),
                    parent,
                    &envelope.ciphertext,
                    &template,
                )
            }
            NativeWrapMode::KwMechanicsOnly => session.unwrap_key(
                &Mechanism::AesKeyWrap,
                parent,
                &envelope.ciphertext,
                &template,
            ),
        }
        .map_err(|e| map_pkcs11_error("native child unwrap (not retried)", &e))?;
        // No attribute repair. Even a returned handle remains unusable until all
        // exact scalar checks pass; on error explicit original-session close is owed.
        check_opened_policy(session, opened, context, &self.correlation, self.mode)?;
        self.opened = Some(opened);
        self.phase = Phase::Open;
        Ok(())
    }

    fn usable(&self) -> Result<(&Session, ObjectHandle)> {
        if self.phase != Phase::Open {
            return Err(refused("lease is not open"));
        }
        let key = self
            .opened
            .ok_or_else(|| refused("lease lost its original object"))?;
        let session = self.session()?;
        check_opened_policy(session, key, &self.context, &self.correlation, self.mode)?;
        Ok((session, key))
    }

    /// Native application crypto only, with caller AAD (not hierarchy-context AAD).
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptOutput> {
        let (session, key) = self.usable()?;
        let mut iv = [0; 12];
        session
            .generate_random_slice(&mut iv)
            .map_err(|e| map_pkcs11_error("lease nonce", &e))?;
        let params = GcmParams::new(&mut iv, aad, 128.into())
            .map_err(|e| map_pkcs11_error("lease GCM", &e))?;
        let ciphertext = session
            .encrypt(&Mechanism::AesGcm(params), key, plaintext)
            .map_err(|e| map_pkcs11_error("native lease encrypt", &e))?;
        let mut output = iv.to_vec();
        output.extend(ciphertext);
        Ok(EncryptOutput { ciphertext: output })
    }

    /// Returns application plaintext, never key material or `CKA_VALUE`.
    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Sensitive<Vec<u8>>> {
        if ciphertext.len() < 28 {
            return Err(refused("truncated application ciphertext"));
        }
        let (session, key) = self.usable()?;
        let mut iv: [u8; 12] = ciphertext[..12].try_into().expect("checked nonce length");
        let params = GcmParams::new(&mut iv, aad, 128.into())
            .map_err(|e| map_pkcs11_error("lease GCM", &e))?;
        session
            .decrypt(&Mechanism::AesGcm(params), key, &ciphertext[12..])
            .map(Sensitive::new)
            .map_err(|e| map_pkcs11_error("native lease decrypt", &e))
    }

    /// Explicit original-session closure. Repeat success is local/idempotent;
    /// consumed failure remains unconfirmed even if cryptoki's Drop later succeeds.
    /// This is neither creation-journal evidence nor a revocation receipt.
    pub fn close_wrapped_key(&mut self) -> Result<()> {
        if self.phase == Phase::Closed {
            return Ok(());
        }
        self.phase = Phase::CloseUnconfirmed;
        self.opened = None;
        let session = self
            .session
            .take()
            .ok_or_else(|| refused("closure unconfirmed"))?;
        let outcome = session
            .close()
            .map_err(|e| map_pkcs11_error("native original-session close", &e));
        // close() consumes Session; its destructor has completed before this line.
        self.admission.take();
        outcome?;
        self.phase = Phase::Closed;
        Ok(())
    }

    /// A local observation only; never reconstructable evidence after restart.
    pub fn closed_session(&self) -> Option<Uuid> {
        (self.phase == Phase::Closed).then_some(self.identity)
    }

    /// Match a successful generation's retained output after explicit original
    /// close. This local observation is not qualified creation-journal evidence.
    /// An empty, failed or ordinary-use owner cannot certify a creation here.
    pub fn verify_closed_creation(
        &self,
        context: &WrappingContext,
        parent: &KeyHandle,
        creation: &CreationBinding,
        envelope: &NativeEnvelope,
    ) -> Result<()> {
        self.check_binding(context, parent, Some(creation))?;
        if self.phase != Phase::Closed || self.generated.as_ref() != Some(envelope) {
            return Err(refused("no matching explicitly closed native generation"));
        }
        Ok(())
    }
}

fn validate_inputs(context: &WrappingContext, parent: &KeyHandle) -> Result<Vec<u8>> {
    if parent.key_spec != context.parent_spec
        || parent.key_id.is_empty()
        || parent.key_id.len() > 256
    {
        return Err(refused("invalid exact parent handle/spec"));
    }
    if context.purpose != WrappingKeyPurpose::EncryptDecrypt
        || context.key_format != WrappedKeyFormat::RawSecret
        || context.child.lid == context.parent.lid
    {
        return Err(refused(
            "candidate supports raw AES encrypt/decrypt leaves only",
        ));
    }
    key_length(&context.child_spec)?;
    context
        .canonical_bytes()
        .map_err(|_| refused("invalid wrapping context"))
}

fn key_length(spec: &KeySpec) -> Result<usize> {
    match spec {
        KeySpec::Aes128 => Ok(16),
        KeySpec::Aes256 => Ok(32),
        _ => Err(refused("candidate supports AES leaves only")),
    }
}

fn child_template(
    context: &WrappingContext,
    correlation: &str,
    creation: bool,
) -> Result<Vec<Attribute>> {
    Ok(vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(
            key_length(&context.child_spec)?
                .try_into()
                .map_err(|_| refused("AES size"))?,
        ),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(creation),
        Attribute::Copyable(false),
        Attribute::Destroyable(true),
        Attribute::Encrypt(!creation),
        Attribute::Decrypt(!creation),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Wrap(false),
        Attribute::Unwrap(false),
        Attribute::Derive(false),
        Attribute::Label(correlation.as_bytes().to_vec()),
        Attribute::Id(correlation.as_bytes().to_vec()),
        // SoftHSM 2.6.1 applies the template in caller order and forbids further
        // unwrap attributes after immutability. Set it last in the SAME native
        // call; never omit it, repair afterward, or retry a weaker template.
        Attribute::Modifiable(false),
    ])
}

fn check_attributes(session: &Session, key: ObjectHandle, expected: &[Attribute]) -> Result<()> {
    // Fixed scalar/identifier inputs only, never CKA_VALUE or unsafe collection
    // decoders. Missing, sensitive, unavailable, duplicate or weaker reads fail.
    for wanted in expected {
        let actual = session
            .get_attributes(key, &[wanted.attribute_type()])
            .map_err(|e| map_pkcs11_error("native exact policy readback", &e))?;
        if actual.as_slice() != [wanted.clone()] {
            return Err(refused(&format!(
                "native exact policy readback mismatch for {:?}",
                wanted.attribute_type()
            )));
        }
    }
    Ok(())
}

fn check_opened_policy(
    session: &Session,
    key: ObjectHandle,
    context: &WrappingContext,
    correlation: &str,
    mode: NativeWrapMode,
) -> Result<()> {
    let mut expected = child_template(context, correlation, false)?;
    if mode == NativeWrapMode::KwMechanicsOnly {
        // SoftHSM 2.7.0 C_UnwrapKey stores CKA_VALUE without updating VALUE_LEN.
        // This MECHANICS-ONLY profile checks the originally generated AES length
        // and exact RFC3394 ciphertext length (key bytes + 8), but cannot claim
        // an independent positive token size readback when it returns zero.
        // Do not carry this exception into GCM/custody qualification or silently
        // accept another nonzero size, missing attribute or provider read error.
        expected.retain(|a| !matches!(a, Attribute::ValueLen(_)));
        let actual = session
            .get_attributes(key, &[cryptoki::object::AttributeType::ValueLen])
            .map_err(|e| map_pkcs11_error("KW mechanics size observation", &e))?;
        let wanted = Attribute::ValueLen(
            key_length(&context.child_spec)?
                .try_into()
                .map_err(|_| refused("AES size"))?,
        );
        if !kw_size_observation_matches(&actual, &wanted) {
            return Err(refused("KW mechanics returned inconsistent key size"));
        }
    }
    check_attributes(session, key, &expected)
}

fn kw_size_observation_matches(actual: &[Attribute], wanted: &Attribute) -> bool {
    actual == [wanted.clone()] || actual == [Attribute::ValueLen(0.into())]
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn immutability_is_last_without_omitting_any_policy() {
        let (_, request) = keyrack_test_support::creation_conformance::fixture();
        let context = request.context().unwrap();
        for creation in [true, false] {
            let template = child_template(&context, &request.correlation, creation).unwrap();
            assert_eq!(template.last(), Some(&Attribute::Modifiable(false)));
            assert_eq!(
                template
                    .iter()
                    .filter(|a| matches!(a, Attribute::Modifiable(_)))
                    .count(),
                1
            );
            for attribute in [
                Attribute::Token(false),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(creation),
                Attribute::Copyable(false),
                Attribute::Destroyable(true),
                Attribute::Encrypt(!creation),
                Attribute::Decrypt(!creation),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
            ] {
                assert!(template.contains(&attribute));
            }
        }
    }

    #[test]
    fn kw_unknown_size_exception_is_exact_and_bounded() {
        for expected in [16, 32] {
            let wanted = Attribute::ValueLen(expected.into());
            assert!(kw_size_observation_matches(
                std::slice::from_ref(&wanted),
                &wanted
            ));
            assert!(kw_size_observation_matches(
                &[Attribute::ValueLen(0.into())],
                &wanted
            ));
            for wrong in [1, 24, 64] {
                assert!(!kw_size_observation_matches(
                    &[Attribute::ValueLen(wrong.into())],
                    &wanted
                ));
            }
            assert!(!kw_size_observation_matches(&[], &wanted));
            assert!(!kw_size_observation_matches(
                &[wanted.clone(), wanted.clone()],
                &wanted
            ));
            assert!(!kw_size_observation_matches(
                &[Attribute::Token(false)],
                &wanted
            ));
        }
    }

    #[test]
    fn generated_policy_keeps_positive_size_and_forbids_child_use() {
        let (_, mut request) = keyrack_test_support::creation_conformance::fixture();
        for (spec, size) in [(KeySpec::Aes128, 16), (KeySpec::Aes256, 32)] {
            request.record.key_spec = spec;
            let context = request.context().unwrap();
            let generated = child_template(&context, &request.correlation, true).unwrap();
            assert!(generated.contains(&Attribute::ValueLen(size.into())));
            assert!(!generated.contains(&Attribute::ValueLen(0.into())));
            for policy in [
                Attribute::Token(false),
                Attribute::Sensitive(true),
                Attribute::Copyable(false),
                Attribute::Modifiable(false),
                Attribute::Encrypt(false),
                Attribute::Decrypt(false),
            ] {
                assert!(generated.contains(&policy));
            }
            let opened = child_template(&context, "kr-native-a2-use-policy-test", false).unwrap();
            assert!(opened.contains(&Attribute::Extractable(false)));
            assert!(opened.contains(&Attribute::ValueLen(size.into())));
            assert!(generated.contains(&Attribute::Id(request.correlation.as_bytes().to_vec())));
            assert!(opened.contains(&Attribute::Id(b"kr-native-a2-use-policy-test".to_vec())));
        }
    }

    // No native session exists in this negative-test owner. Every invalid input
    // must be rejected while Ready, before the first native policy read/effect.
    fn owner(creation: Option<CreationBinding>) -> NativeA2Session {
        let (_, request) = keyrack_test_support::creation_conformance::fixture();
        let context = request.context().unwrap();
        let identity = Uuid::new_v4();
        let correlation = creation.as_ref().map_or_else(
            || format!("kr-native-a2-use-{identity}"),
            |binding| binding.correlation().to_owned(),
        );
        NativeA2Session {
            session: None,
            admission: None,
            identity,
            context_bytes: context.canonical_bytes().unwrap(),
            context_sha256: context.context_sha256().unwrap(),
            context,
            creation,
            correlation,
            parent: KeyHandle {
                key_id: "native-parent".into(),
                key_spec: KeySpec::Aes256,
            },
            mode: NativeWrapMode::GcmCandidate,
            phase: Phase::Ready,
            opened: None,
            generated: None,
        }
    }

    #[test]
    fn changed_creation_context_and_exact_parent_are_refused_before_effects() {
        let (_, request) = keyrack_test_support::creation_conformance::fixture();
        let creation = CreationBinding::of(&request).unwrap();
        let mut owner = owner(Some(creation.clone()));
        let context = owner.context.clone();
        let parent = owner.parent.clone();
        for (case, mut changed) in [
            request.clone(),
            request.clone(),
            request.clone(),
            request.clone(),
        ]
        .into_iter()
        .enumerate()
        {
            // Every new attempt, including one with identical wrapping context,
            // has independent provenance and cannot take over this owner.
            match case {
                0 => changed.operation = Uuid::new_v4(),
                1 => changed.attempt = Uuid::new_v4(),
                2 => changed.owner.instance = Uuid::new_v4(),
                _ => changed.expected_parent_occ += 1,
            }
            changed.correlation =
                keyrack_core::creation::creation_correlation(changed.operation, changed.attempt);
            let changed = CreationBinding::of(&changed).unwrap();
            assert!(owner
                .generate_wrapped_key(&context, &parent, &changed)
                .is_err());
            assert!(owner.phase == Phase::Ready);
        }
        let mut changed = request;
        changed.owner.generation += 1;
        let changed = CreationBinding::of(&changed).unwrap();
        assert!(owner
            .generate_wrapped_key(&context, &parent, &changed)
            .is_err());
        let mut changed_context = context.clone();
        changed_context.child_spec = KeySpec::Aes128;
        assert!(owner
            .generate_wrapped_key(&changed_context, &parent, &creation)
            .is_err());
        let mut changed_parent = parent.clone();
        changed_parent.key_id.push_str("-other");
        assert!(owner
            .generate_wrapped_key(&context, &changed_parent, &creation)
            .is_err());
        changed_parent = parent;
        changed_parent.key_spec = KeySpec::Aes128;
        assert!(owner
            .generate_wrapped_key(&context, &changed_parent, &creation)
            .is_err());
        assert!(owner.phase == Phase::Ready);
        assert!(owner.generated.is_none());
    }

    #[test]
    fn creation_and_use_roles_cannot_be_interchanged() {
        let (_, request) = keyrack_test_support::creation_conformance::fixture();
        let creation = CreationBinding::of(&request).unwrap();
        let mut generated = owner(Some(creation.clone()));
        let mut opened = owner(None);
        let context = generated.context.clone();
        let parent = generated.parent.clone();
        let envelope = NativeEnvelope {
            mode: NativeWrapMode::GcmCandidate,
            iv: [0; 12],
            ciphertext: vec![0; 48],
            context_sha256: generated.context_sha256,
        };
        assert!(generated
            .open_wrapped_key(&context, &parent, &envelope)
            .is_err());
        assert!(opened
            .generate_wrapped_key(&context, &parent, &creation)
            .is_err());
        assert!(generated.phase == Phase::Ready);
        assert!(opened.phase == Phase::Ready);
        assert_eq!(generated.correlation, creation.correlation());
        assert!(opened.correlation.starts_with("kr-native-a2-use-"));
        assert_ne!(opened.correlation, creation.correlation());
    }

    #[test]
    fn empty_failed_or_use_owner_cannot_verify_a_closed_creation() {
        let (_, request) = keyrack_test_support::creation_conformance::fixture();
        let creation = CreationBinding::of(&request).unwrap();
        let mut generated = owner(Some(creation.clone()));
        let context = generated.context.clone();
        let parent = generated.parent.clone();
        let envelope = NativeEnvelope {
            mode: NativeWrapMode::GcmCandidate,
            iv: [0; 12],
            ciphertext: vec![0; 48],
            context_sha256: generated.context_sha256,
        };
        for phase in [
            Phase::Ready,
            Phase::Attempted,
            Phase::CloseUnconfirmed,
            Phase::Closed,
        ] {
            generated.phase = phase;
            assert!(generated
                .verify_closed_creation(&context, &parent, &creation, &envelope)
                .is_err());
        }
        let mut opened = owner(None);
        opened.phase = Phase::Closed;
        assert!(opened
            .verify_closed_creation(&context, &parent, &creation, &envelope)
            .is_err());
    }

    #[test]
    fn unsupported_leaf_profiles_are_refused_before_session_acquisition() {
        let owner = owner(None);
        let mut context = owner.context.clone();
        assert!(validate_inputs(&context, &owner.parent).is_ok());
        context.purpose = WrappingKeyPurpose::WrapUnwrap;
        assert!(validate_inputs(&context, &owner.parent).is_err());
        context = owner.context.clone();
        context.key_format = WrappedKeyFormat::ProviderNative(
            keyrack_core::wrapping::WrappingIdentifier::new("other-format").unwrap(),
        );
        assert!(validate_inputs(&context, &owner.parent).is_err());
        context = owner.context;
        context.child = context.parent;
        assert!(validate_inputs(&context, &owner.parent).is_err());
    }
}

#[cfg(all(test, feature = "softhsm-tests"))]
mod tests;
