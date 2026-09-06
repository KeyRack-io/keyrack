// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    AuthorityGrant, AuthorityIdentity, AuthorityScope, ClockDomain, ContractError, CreationOutcome,
    CreationOwner, CreationResult, CryptoOperation, CustodyContext, CustodyMaterialDescriptor,
    CustodyProfile, ExecutionBoundary, ExecutorIncarnation, InFlightDisposition,
    LeaseCleanupReason, LeaseCleanupResult, LeaseIdentity, LeaseRecord, NonZeroU64, ProviderRef,
    RequestBinding, Result, RevocationCommand, RevocationResult, Uuid, Validity, VersionedKeyId,
    WrappingContext, WrappingIdentifier, MAX_CONTRACT_BYTES, MAX_RECEIPT_LEASES,
};
use crate::key::KeySpec;
use crate::lid::Lid;
use crate::wrapping::{WrappedKeyFormat, WrappingContextVersion, WrappingKeyPurpose};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"KeyRack:CustodyContract\0";

mod sealed {
    pub trait Sealed {}
    impl<T: super::Wire> Sealed for T {}
}

/// One strict encoding, including a message-kind tag. No serde/JSON fallback,
/// ignored fields, trailing bytes, enum-layout dependency or unbounded allocation.
pub trait Canonical: sealed::Sealed + Sized {
    fn canonical_bytes(&self) -> Result<Vec<u8>>;
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self>;
    fn sha256(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

impl<T: Wire> Canonical for T {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer(DOMAIN.to_vec());
        w.u16(1);
        w.u8(T::KIND);
        self.write(&mut w)?;
        if w.0.len() > MAX_CONTRACT_BYTES {
            return Err(ContractError::Encoding("message too large"));
        }
        Ok(w.0)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CONTRACT_BYTES {
            return Err(ContractError::Encoding("message too large"));
        }
        let mut r = Reader(bytes);
        r.literal(DOMAIN)?;
        if r.u16()? != 1 || r.u8()? != T::KIND {
            return Err(ContractError::Encoding(
                "unknown version or wrong message kind",
            ));
        }
        let value = T::read(&mut r)?;
        if !r.0.is_empty() {
            return Err(ContractError::Encoding("trailing bytes"));
        }
        // Re-encoding validates every semantic invariant, and ensures that no
        // accepted byte string has an alternative noncanonical representation.
        if value.canonical_bytes()? != bytes {
            return Err(ContractError::Encoding("noncanonical message"));
        }
        Ok(value)
    }
}

pub(super) trait Wire: Sized {
    const KIND: u8;
    fn write(&self, w: &mut Writer) -> Result<()>;
    fn read(r: &mut Reader<'_>) -> Result<Self>;
}

pub(super) struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u8(&mut self, n: u8) {
        self.0.push(n);
    }
    pub fn u16(&mut self, n: u16) {
        self.0.extend(n.to_be_bytes());
    }
    pub fn u32(&mut self, n: u32) {
        self.0.extend(n.to_be_bytes());
    }
    pub fn u64(&mut self, n: u64) {
        self.0.extend(n.to_be_bytes());
    }
    pub fn fixed(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub fn id(&mut self, id: &WrappingIdentifier) {
        self.u16(u16::try_from(id.as_str().len()).expect("bounded identifier"));
        self.fixed(id.as_str().as_bytes());
    }
    pub fn uuid(&mut self, id: Uuid) -> Result<()> {
        if id.is_nil() {
            return Err(ContractError::Binding("nil identity"));
        }
        self.fixed(id.as_bytes());
        Ok(())
    }
    pub fn blob(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_CONTRACT_BYTES {
            return Err(ContractError::Encoding("nested message too large"));
        }
        self.u32(u32::try_from(bytes.len()).expect("bounded message"));
        self.fixed(bytes);
        Ok(())
    }
    pub fn message<T: Canonical>(&mut self, value: &T) -> Result<()> {
        self.blob(&value.canonical_bytes()?)
    }
    fn executor(&mut self, id: ExecutorIncarnation) {
        self.fixed(id.as_bytes());
    }
    fn validity(&mut self, value: Validity) -> Result<()> {
        value.validate()?;
        match value.clock {
            ClockDomain::UnixMilliseconds => self.u8(1),
            ClockDomain::ExecutorMonotonicMilliseconds(id) => {
                self.u8(2);
                self.executor(id);
            }
        }
        self.u64(value.not_before);
        self.u64(value.not_after);
        Ok(())
    }
}

pub(super) struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(ContractError::Encoding("truncated field"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn literal(&mut self, value: &[u8]) -> Result<()> {
        if self.take(value.len())? != value {
            return Err(ContractError::Encoding("wrong domain"));
        }
        Ok(())
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| ContractError::Encoding("wrong field size"))
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn nonzero(&mut self) -> Result<NonZeroU64> {
        NonZeroU64::new(self.u64()?).ok_or(ContractError::Encoding("zero counter or generation"))
    }
    pub fn id(&mut self) -> Result<WrappingIdentifier> {
        let n = usize::from(self.u16()?);
        if n == 0 || n > 256 {
            return Err(ContractError::Encoding("identifier length"));
        }
        let text = std::str::from_utf8(self.take(n)?)
            .map_err(|_| ContractError::Encoding("identifier not ASCII"))?;
        Ok(WrappingIdentifier::new(text)?)
    }
    pub fn uuid(&mut self) -> Result<Uuid> {
        let id = Uuid::from_bytes(self.fixed()?);
        if id.is_nil() {
            return Err(ContractError::Encoding("nil identity"));
        }
        Ok(id)
    }
    pub fn blob(&mut self) -> Result<&'a [u8]> {
        let n =
            usize::try_from(self.u32()?).map_err(|_| ContractError::Encoding("length overflow"))?;
        if n > MAX_CONTRACT_BYTES {
            return Err(ContractError::Encoding("nested message too large"));
        }
        self.take(n)
    }
    pub fn message<T: Canonical>(&mut self) -> Result<T> {
        T::from_canonical_bytes(self.blob()?)
    }
    fn executor(&mut self) -> Result<ExecutorIncarnation> {
        ExecutorIncarnation::new(self.fixed()?)
    }
    fn validity(&mut self) -> Result<Validity> {
        let clock = match self.u8()? {
            1 => ClockDomain::UnixMilliseconds,
            2 => ClockDomain::ExecutorMonotonicMilliseconds(self.executor()?),
            _ => return Err(ContractError::Encoding("unknown clock")),
        };
        let value = Validity {
            clock,
            not_before: self.u64()?,
            not_after: self.u64()?,
        };
        value.validate()?;
        Ok(value)
    }
}

fn unknown() -> ContractError {
    ContractError::Encoding("unknown enum tag")
}

impl Wire for CustodyProfile {
    const KIND: u8 = 1;
    fn write(&self, w: &mut Writer) -> Result<()> {
        w.u8(match self.boundary {
            ExecutionBoundary::ProviderSessionObject => 1,
            ExecutionBoundary::ProviderJournaledTemporaryObject => 2,
            ExecutionBoundary::TrustedHostWorkerMemory => 3,
        });
        w.id(&self.id);
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let boundary = match r.u8()? {
            1 => ExecutionBoundary::ProviderSessionObject,
            2 => ExecutionBoundary::ProviderJournaledTemporaryObject,
            3 => ExecutionBoundary::TrustedHostWorkerMemory,
            _ => return Err(unknown()),
        };
        Ok(Self {
            boundary,
            id: r.id()?,
        })
    }
}

impl Wire for CustodyContext {
    const KIND: u8 = 2;
    fn write(&self, w: &mut Writer) -> Result<()> {
        self.validate()?;
        w.blob(&self.wrapping.canonical_bytes()?)?;
        w.message(&self.profile)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            wrapping: read_v1(r.blob()?)?,
            profile: r.message()?,
        })
    }
}

// This is a strict reader for the FROZEN V1 bytes, not a second V1 encoder.
// Re-encode using the original implementation to catch drift/noncanonical input.
fn read_v1(bytes: &[u8]) -> Result<WrappingContext> {
    let mut r = Reader(bytes);
    r.literal(b"KeyRack:ParentWrappedContext\0")?;
    let version = WrappingContextVersion::try_from(r.u16()?)?;
    let child = read_key(&mut r)?;
    let parent = read_key(&mut r)?;
    let parent_spec = read_spec(&mut r)?;
    let child_spec = read_spec(&mut r)?;
    let key_format = match r.u8()? {
        1 => WrappedKeyFormat::RawSecret,
        2 => WrappedKeyFormat::Pkcs8Der,
        3 => WrappedKeyFormat::ProviderNative(r.id()?),
        _ => return Err(unknown()),
    };
    let purpose = match r.u8()? {
        1 => WrappingKeyPurpose::EncryptDecrypt,
        2 => WrappingKeyPurpose::SignVerify,
        3 => WrappingKeyPurpose::GenerateVerifyMac,
        4 => WrappingKeyPurpose::WrapUnwrap,
        _ => return Err(unknown()),
    };
    let provider_ref = ProviderRef::new(r.id()?.as_str());
    let security_domain = r.id()?;
    let mechanism = r.id()?;
    let public_material_sha256 = match r.u8()? {
        0 => None,
        1 => Some(r.fixed()?),
        _ => return Err(unknown()),
    };
    let context = WrappingContext {
        version,
        child,
        parent,
        parent_spec,
        child_spec,
        key_format,
        purpose,
        provider_ref,
        security_domain,
        mechanism,
        public_material_sha256,
    };
    if !r.0.is_empty() || context.canonical_bytes()? != bytes {
        return Err(ContractError::Encoding("noncanonical V1 context"));
    }
    Ok(context)
}

fn read_key(r: &mut Reader<'_>) -> Result<VersionedKeyId> {
    Ok(VersionedKeyId::new(Lid::from_bytes(r.fixed()?), r.u64()?)?)
}

fn read_spec(r: &mut Reader<'_>) -> Result<KeySpec> {
    Ok(match r.u8()? {
        1 => KeySpec::Aes256,
        2 => KeySpec::Aes128,
        3 => KeySpec::Ed25519,
        4 => KeySpec::RsaPkcs1v15Sha256 { key_size: r.u32()? },
        5 => KeySpec::RsaPssSha256 { key_size: r.u32()? },
        6 => KeySpec::EcdsaP256Sha256,
        7 => KeySpec::EcdsaP384,
        8 => KeySpec::Hmac256,
        _ => return Err(unknown()),
    })
}

impl Wire for CustodyMaterialDescriptor {
    const KIND: u8 = 3;
    fn write(&self, w: &mut Writer) -> Result<()> {
        w.message(&self.context)?;
        w.id(&self.envelope_ref);
        w.fixed(&self.envelope_sha256);
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            context: r.message()?,
            envelope_ref: r.id()?,
            envelope_sha256: r.fixed()?,
        })
    }
}

impl Wire for RequestBinding {
    const KIND: u8 = 4;
    fn write(&self, w: &mut Writer) -> Result<()> {
        self.validate()?;
        w.uuid(self.operation)?;
        w.uuid(self.attempt)?;
        w.executor(self.executor);
        w.fixed(&self.context_sha256);
        w.fixed(&self.request_sha256);
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            operation: r.uuid()?,
            attempt: r.uuid()?,
            executor: r.executor()?,
            context_sha256: r.fixed()?,
            request_sha256: r.fixed()?,
        })
    }
}

impl Wire for AuthorityIdentity {
    const KIND: u8 = 5;
    fn write(&self, w: &mut Writer) -> Result<()> {
        w.id(&self.issuer);
        match &self.scope {
            AuthorityScope::Context(digest) => {
                w.u8(1);
                w.fixed(digest);
            }
            AuthorityScope::SecurityDomain {
                provider_ref,
                security_domain,
            } => {
                w.u8(2);
                w.id(&WrappingIdentifier::new(provider_ref.as_str())?);
                w.id(security_domain);
            }
        }
        w.u64(self.generation.get());
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let issuer = r.id()?;
        let scope = match r.u8()? {
            1 => AuthorityScope::Context(r.fixed()?),
            2 => AuthorityScope::SecurityDomain {
                provider_ref: ProviderRef::new(r.id()?.as_str()),
                security_domain: r.id()?,
            },
            _ => return Err(unknown()),
        };
        Ok(Self {
            issuer,
            scope,
            generation: r.nonzero()?,
        })
    }
}

impl Wire for AuthorityGrant {
    const KIND: u8 = 6;
    fn write(&self, w: &mut Writer) -> Result<()> {
        self.validate()?;
        w.message(&self.authority)?;
        w.message(&self.request)?;
        w.id(&self.principal);
        w.u8(match self.operation {
            CryptoOperation::GenerateWrapped => 1,
            CryptoOperation::Encrypt => 2,
            CryptoOperation::Decrypt => 3,
        });
        w.u64(self.sequence.get());
        w.validity(self.validity)?;
        w.u64(self.ancestor_not_after);
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let authority = r.message()?;
        let request = r.message()?;
        let principal = r.id()?;
        let operation = match r.u8()? {
            1 => CryptoOperation::GenerateWrapped,
            2 => CryptoOperation::Encrypt,
            3 => CryptoOperation::Decrypt,
            _ => return Err(unknown()),
        };
        Ok(Self {
            authority,
            request,
            principal,
            operation,
            sequence: r.nonzero()?,
            validity: r.validity()?,
            ancestor_not_after: r.u64()?,
        })
    }
}

impl Wire for LeaseIdentity {
    const KIND: u8 = 7;
    fn write(&self, w: &mut Writer) -> Result<()> {
        w.executor(self.executor);
        w.u64(self.counter.get());
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            executor: r.executor()?,
            counter: r.nonzero()?,
        })
    }
}

impl Wire for LeaseRecord {
    const KIND: u8 = 8;
    fn write(&self, w: &mut Writer) -> Result<()> {
        self.residency.check_executor(self.lease.executor)?;
        if matches!(self.authority.scope, AuthorityScope::Context(digest) if digest != self.context_sha256)
        {
            return Err(ContractError::Binding("lease scope/context mismatch"));
        }
        w.message(&self.lease)?;
        w.fixed(&self.context_sha256);
        w.message(&self.authority)?;
        w.validity(self.residency)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            lease: r.message()?,
            context_sha256: r.fixed()?,
            authority: r.message()?,
            residency: r.validity()?,
        })
    }
}

impl Wire for CreationResult {
    const KIND: u8 = 9;
    fn write(&self, w: &mut Writer) -> Result<()> {
        w.message(&self.request)?;
        w.uuid(self.owner.instance)?;
        if self.owner.generation == 0 {
            return Err(ContractError::Binding("zero creation owner generation"));
        }
        w.u64(self.owner.generation);
        w.fixed(&self.material_sha256);
        match &self.outcome {
            CreationOutcome::ProviderSessionClosed { session } => {
                w.u8(1);
                w.id(session);
            }
            CreationOutcome::ProviderTemporaryObjectDestroyed { object } => {
                w.u8(2);
                w.id(object);
            }
            CreationOutcome::NativeWrappedOnlyGenerated => w.u8(3),
        }
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let request = r.message()?;
        let owner = CreationOwner {
            instance: r.uuid()?,
            generation: r.nonzero()?.get(),
        };
        let material_sha256 = r.fixed()?;
        let outcome = match r.u8()? {
            1 => CreationOutcome::ProviderSessionClosed { session: r.id()? },
            2 => CreationOutcome::ProviderTemporaryObjectDestroyed { object: r.id()? },
            3 => CreationOutcome::NativeWrappedOnlyGenerated,
            _ => return Err(unknown()),
        };
        Ok(Self {
            request,
            owner,
            material_sha256,
            outcome,
        })
    }
}

impl Wire for LeaseCleanupResult {
    const KIND: u8 = 10;
    fn write(&self, w: &mut Writer) -> Result<()> {
        w.message(&self.record)?;
        w.u8(match self.reason {
            LeaseCleanupReason::Released => 1,
            LeaseCleanupReason::ResidencyExpired => 2,
            LeaseCleanupReason::AuthorityFenced => 3,
        });
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let record = r.message()?;
        let reason = match r.u8()? {
            1 => LeaseCleanupReason::Released,
            2 => LeaseCleanupReason::ResidencyExpired,
            3 => LeaseCleanupReason::AuthorityFenced,
            _ => return Err(unknown()),
        };
        Ok(Self { record, reason })
    }
}

impl Wire for RevocationCommand {
    const KIND: u8 = 11;
    fn write(&self, w: &mut Writer) -> Result<()> {
        self.validity.check_executor(self.executor)?;
        w.uuid(self.fence)?;
        w.executor(self.executor);
        w.message(&self.authority)?;
        w.validity(self.validity)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            fence: r.uuid()?,
            executor: r.executor()?,
            authority: r.message()?,
            validity: r.validity()?,
        })
    }
}

impl Wire for RevocationResult {
    const KIND: u8 = 12;
    fn write(&self, w: &mut Writer) -> Result<()> {
        w.uuid(self.fence)?;
        w.executor(self.executor);
        w.message(&self.authority)?;
        w.fixed(&self.command_sha256);
        w.u8(match self.in_flight {
            InFlightDisposition::Drained => 1,
            InFlightDisposition::OutputsSuppressed => 2,
        });
        if self.observed_leases.len() > MAX_RECEIPT_LEASES {
            return Err(ContractError::Binding("too many observed leases"));
        }
        w.u16(u16::try_from(self.observed_leases.len()).expect("bounded lease list"));
        let mut previous = 0;
        for lease in &self.observed_leases {
            if lease.executor != self.executor || lease.counter.get() <= previous {
                return Err(ContractError::Binding(
                    "leases must be unique, sorted and local",
                ));
            }
            w.message(lease)?;
            previous = lease.counter.get();
        }
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let fence = r.uuid()?;
        let executor = r.executor()?;
        let authority = r.message()?;
        let command_sha256 = r.fixed()?;
        let in_flight = match r.u8()? {
            1 => InFlightDisposition::Drained,
            2 => InFlightDisposition::OutputsSuppressed,
            _ => return Err(unknown()),
        };
        let n = usize::from(r.u16()?);
        if n > MAX_RECEIPT_LEASES {
            return Err(ContractError::Encoding("too many observed leases"));
        }
        let observed_leases = (0..n).map(|_| r.message()).collect::<Result<Vec<_>>>()?;
        Ok(Self {
            fence,
            executor,
            authority,
            command_sha256,
            in_flight,
            observed_leases,
        })
    }
}
