// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Qualification-only native creation owner. Not linked into the provider.
//!
//! This deliberately does not implement `A2CreationProvider` or mint an A2 closure
//! claim: a qualified tuple, trusted parent resolution, native policy, bounded
//! nonce allocation, authority admission and an agreed envelope are still needed.
//! Its narrower job is to own the ORIGINAL session across Generate, native GCM
//! Wrap and explicit Close, including errors and unwinding. Tests supply policy;
//! accepting that policy here does not qualify it. There is no key-value read,
//! plaintext import, unwrap, attribute repair, object search or regeneration path.

use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use keyrack_core::creation::CreationRequest;
use keyrack_core::error::KeyRackError;
use keyrack_core::key::KeySpec;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum NativeCreationError {
    #[error("native creation candidate: {0}")]
    Invalid(String),
    #[error("native PKCS#11 call: {0}")]
    Native(#[from] cryptoki::error::Error),
    #[error("invalid creation request: {0}")]
    Request(#[from] KeyRackError),
}

pub type Result<T> = std::result::Result<T, NativeCreationError>;

fn invalid(message: &str) -> NativeCreationError {
    NativeCreationError::Invalid(message.into())
}

/// Private test seam. The real implementation below only calls native PKCS#11.
pub trait CreationSession {
    type Key: Copy;

    fn generate(&mut self, template: &[Attribute]) -> Result<Self::Key>;
    fn attributes(&mut self, key: Self::Key, types: &[AttributeType]) -> Result<Vec<Attribute>>;
    fn wrap_gcm(
        &mut self,
        parent: Self::Key,
        child: Self::Key,
        iv: &mut [u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>>;
    fn close(self) -> Result<()>;
}

impl CreationSession for Session {
    type Key = ObjectHandle;

    fn generate(&mut self, template: &[Attribute]) -> Result<Self::Key> {
        Ok(self.generate_key(&Mechanism::AesKeyGen, template)?)
    }

    fn attributes(&mut self, key: Self::Key, types: &[AttributeType]) -> Result<Vec<Attribute>> {
        Ok(self.get_attributes(key, types)?)
    }

    fn wrap_gcm(
        &mut self,
        parent: Self::Key,
        child: Self::Key,
        iv: &mut [u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let params = GcmParams::new(iv, aad, 128.into())?;
        // cryptoki performs a length query followed by an output C_WrapKey call.
        // A future qualification must cover BOTH calls and the returned IV, not
        // assume that one Rust call means one native nonce consumption.
        Ok(self.wrap_key(&Mechanism::AesGcm(params), parent, child)?)
    }

    fn close(self) -> Result<()> {
        Ok(Session::close(self)?)
    }
}

/// Scalar custody/use policy only. Neither this type nor scalar readback proves
/// that a provider enforces a trusted wrapping/unwrapping template atomically.
/// `trusted_wrap = false` exists ONLY for the visibly unqualified mechanism probe.
pub fn creation_template(request: &CreationRequest, trusted_wrap: bool) -> Result<Vec<Attribute>> {
    request.validate()?;
    let size = match request.record.key_spec {
        KeySpec::Aes128 => 16,
        KeySpec::Aes256 => 32,
        _ => return Err(invalid("unsupported child spec")),
    };
    Ok(vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(size.into()),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        // Generation must permit native wrap; raw reads must remain sensitive.
        Attribute::Extractable(true),
        Attribute::WrapWithTrusted(trusted_wrap),
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
    ])
}

/// In-memory primitive output; NOT an envelope encoding or shared custody frame.
/// No Debug/Serialize implementation: avoid accidental output in error reports.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeWrapOutput {
    pub iv: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ready,
    Attempted,
    CloseUnconfirmed,
    Closed,
}

/// No Clone/Deserialize and no accessor for the original session or child handle.
/// Exclusive mutable access serializes use/close. The future async adapter must
/// retain this owner in a blocking task/serialized holder, not drop it on timeout.
pub struct NativeCreation<S: CreationSession> {
    session: Option<S>,
    parent: S::Key,
    request: CreationRequest,
    fingerprint: [u8; 32],
    // Opaque process-local correlation, never a recyclable numeric PKCS#11 handle.
    session_identity: Uuid,
    phase: Phase,
    child: Option<S::Key>,
    output: Option<NativeWrapOutput>,
}

impl<S: CreationSession> NativeCreation<S> {
    /// Caller supplies an original, otherwise empty session and its resolved
    /// parent handle. This is NOT a trusted resolver or a permission to dispatch;
    /// no runtime constructor/export/registration is provided.
    pub fn new(session: S, parent: S::Key, request: CreationRequest) -> Result<Self> {
        let fingerprint = request.fingerprint()?;
        Ok(Self {
            session: Some(session),
            parent,
            request,
            fingerprint,
            session_identity: Uuid::new_v4(),
            phase: Phase::Ready,
            child: None,
            output: None,
        })
    }

    fn check_request(&self, request: &CreationRequest) -> Result<()> {
        if request.fingerprint()? != self.fingerprint {
            return Err(invalid("attempt intent changed"));
        }
        Ok(())
    }

    /// One attempt, including failed policy checks, ambiguous calls and panics.
    /// IV allocation/use bounds are deliberately NOT inferred from an attempt ID
    /// or random bytes here. The qualification harness supplies the IV buffer.
    pub fn generate_and_wrap(
        &mut self,
        request: &CreationRequest,
        parent_policy: &[Attribute],
        trusted_wrap: bool,
        mut iv: [u8; 12],
    ) -> Result<NativeWrapOutput> {
        self.check_request(request)?;
        if self.phase != Phase::Ready {
            return Err(invalid("attempt already consumed or closed"));
        }
        // Set before any provider call so an unwind never restores permission.
        self.phase = Phase::Attempted;
        let session = self.session.as_mut().ok_or_else(|| invalid("lost owner"))?;
        check_attributes(session, self.parent, parent_policy)?;
        let template = creation_template(&self.request, trusted_wrap)?;
        let child = session.generate(&template)?;
        self.child = Some(child);
        check_attributes(session, child, &template)?;
        let ciphertext =
            session.wrap_gcm(self.parent, child, &mut iv, &self.request.context_bytes)?;
        // This candidate exercises raw AES key octets + a 128-bit GCM tag only.
        // Different native key formats require a different reviewed profile.
        let expected = match self.request.record.key_spec {
            KeySpec::Aes128 => 32,
            KeySpec::Aes256 => 48,
            _ => return Err(invalid("unsupported child spec")),
        };
        if ciphertext.len() != expected {
            return Err(invalid("unexpected native wrap length"));
        }
        let output = NativeWrapOutput { iv, ciphertext };
        self.output = Some(output.clone());
        Ok(output)
    }

    /// Explicitly close the original session even after Generate/Wrap failure.
    /// No policy/currentness check may prevent cleanup. Only explicit Ok confirms
    /// closure. cryptoki consumes Session on error and Drop may retry silently;
    /// neither that retry, a replacement session nor a handle search is evidence.
    pub fn close(&mut self) -> Result<()> {
        if self.phase == Phase::Closed {
            return Ok(());
        }
        self.phase = Phase::CloseUnconfirmed;
        let session = self
            .session
            .take()
            .ok_or_else(|| invalid("closure unconfirmed"))?;
        session.close()?;
        self.phase = Phase::Closed;
        Ok(())
    }

    /// Local observation only. No conversion to creation/lease/revocation evidence.
    /// Missing original owner after process loss cannot be recreated from this ID.
    pub fn closed_session(&self) -> Option<Uuid> {
        (self.phase == Phase::Closed).then_some(self.session_identity)
    }

    /// Verify exact retained primitive output and intent only after explicit close.
    /// This is not a provenance verifier for a persisted A2 envelope/closure claim.
    pub fn verify_closed_output(
        &self,
        request: &CreationRequest,
        output: &NativeWrapOutput,
    ) -> Result<()> {
        self.check_request(request)?;
        if self.phase != Phase::Closed || self.output.as_ref() != Some(output) {
            return Err(invalid("no matching closed native output"));
        }
        Ok(())
    }
}

fn check_attributes<S: CreationSession>(
    session: &mut S,
    key: S::Key,
    expected: &[Attribute],
) -> Result<()> {
    // Do not read CKA_VALUE or collection-valued attributes. These are scalar
    // template assertions, not an attempt to repair a weaker returned object.
    if expected.is_empty()
        || expected.iter().any(|a| {
            !matches!(
                a,
                Attribute::Class(_)
                    | Attribute::KeyType(_)
                    | Attribute::ValueLen(_)
                    | Attribute::Token(_)
                    | Attribute::Private(_)
                    | Attribute::Sensitive(_)
                    | Attribute::Extractable(_)
                    | Attribute::WrapWithTrusted(_)
                    | Attribute::Trusted(_)
                    | Attribute::Encrypt(_)
                    | Attribute::Decrypt(_)
                    | Attribute::Sign(_)
                    | Attribute::Verify(_)
                    | Attribute::Wrap(_)
                    | Attribute::Unwrap(_)
                    | Attribute::Derive(_)
                    | Attribute::Modifiable(_)
                    | Attribute::Copyable(_)
                    | Attribute::Destroyable(_)
                    | Attribute::Label(_)
                    | Attribute::Id(_)
            )
        })
    {
        return Err(invalid("invalid scalar policy"));
    }
    let types: Vec<_> = expected.iter().map(Attribute::attribute_type).collect();
    for (index, attribute_type) in types.iter().enumerate() {
        if types[..index].contains(attribute_type) {
            return Err(invalid("duplicate policy attribute"));
        }
    }
    let actual = session.attributes(key, &types)?;
    if actual.len() != expected.len() || !expected.iter().all(|a| actual.contains(a)) {
        return Err(invalid("provider template mismatch"));
    }
    Ok(())
}
