// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::codec::{Reader, Wire, Writer};
use super::{
    AuthorityGrant, Canonical, ContractError, CreationResult, LeaseCleanupResult, Result,
    RevocationCommand, RevocationResult, WrappingIdentifier, MAX_CONTRACT_BYTES,
};
use ed25519_dalek::{Signature, VerifyingKey};

mod sealed {
    pub trait Claims {}
}

/// Only these evidence families may be signed under this contract. In particular,
/// a descriptor or lease record alone is not authority or a cleanup receipt.
pub trait EvidenceClaims: Canonical + sealed::Claims {
    #[doc(hidden)]
    fn authority_issuer(&self) -> Option<&WrappingIdentifier> {
        None
    }
}

macro_rules! observation {
    ($($ty:ty),+ $(,)?) => { $(
        impl sealed::Claims for $ty {}
        impl EvidenceClaims for $ty {}
    )+ };
}
observation!(CreationResult, LeaseCleanupResult, RevocationResult);

impl sealed::Claims for AuthorityGrant {}
impl EvidenceClaims for AuthorityGrant {
    fn authority_issuer(&self) -> Option<&WrappingIdentifier> {
        Some(&self.authority.issuer)
    }
}
impl sealed::Claims for RevocationCommand {}
impl EvidenceClaims for RevocationCommand {
    fn authority_issuer(&self) -> Option<&WrappingIdentifier> {
        Some(&self.authority.issuer)
    }
}

/// Untrusted signed claim. Version 1 supports Ed25519 only (algorithm tag 1).
/// No public key is accepted from the message. Transport/authority integrations
/// which cannot supply this profile must propose a separately reviewed encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence<T: EvidenceClaims> {
    pub issuer: WrappingIdentifier,
    pub key_id: WrappingIdentifier,
    pub claims: T,
    pub signature: [u8; 64],
}

impl<T: EvidenceClaims> Evidence<T> {
    /// Domain, version, algorithm, signer names and the FULL typed canonical
    /// claim. Signs exact bytes, not JSON and not a caller-selected prehash.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        if self
            .claims
            .authority_issuer()
            .is_some_and(|issuer| issuer != &self.issuer)
        {
            return Err(ContractError::Binding(
                "authority issuer/evidence signer mismatch",
            ));
        }
        let mut w = Writer(b"KeyRack:CustodyEvidenceSignature\0".to_vec());
        w.u16(1);
        w.u8(1);
        w.id(&self.issuer);
        w.id(&self.key_id);
        w.message(&self.claims)?;
        if w.0.len() > MAX_CONTRACT_BYTES {
            return Err(ContractError::Encoding("signature transcript too large"));
        }
        Ok(w.0)
    }

    /// Authenticate against independently configured signer identity/key. This
    /// does NOT establish that the signer has current authority for this scope,
    /// that a receipt is truthful, or that the same signed grant was not replayed.
    pub fn authenticate(self, trusted: &EvidenceKey) -> Result<AuthenticatedEvidence<T>> {
        if self.issuer != trusted.issuer || self.key_id != trusted.key_id {
            return Err(ContractError::Authentication);
        }
        trusted
            .key
            .verify_strict(
                &self.signing_bytes()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ContractError::Authentication)?;
        Ok(AuthenticatedEvidence { evidence: self })
    }
}

/// Caller obtains this key from trusted configuration, not coordinator input.
/// Key identity/rotation and issuer-to-scope/executor authorization remain the
/// integrator's responsibility; this is not a key distribution mechanism.
pub struct EvidenceKey {
    pub issuer: WrappingIdentifier,
    pub key_id: WrappingIdentifier,
    pub key: VerifyingKey,
}

/// Signature authentication only. No public constructor, Deserialize, or implicit
/// conversion into an authorization, storage closure, or global-fence token.
pub struct AuthenticatedEvidence<T: EvidenceClaims> {
    evidence: Evidence<T>,
}

impl<T: EvidenceClaims> AuthenticatedEvidence<T> {
    pub fn claims(&self) -> &T {
        &self.evidence.claims
    }
    pub fn issuer(&self) -> &WrappingIdentifier {
        &self.evidence.issuer
    }
    pub fn key_id(&self) -> &WrappingIdentifier {
        &self.evidence.key_id
    }
}

impl<T: EvidenceClaims> Wire for Evidence<T> {
    const KIND: u8 = 13;
    fn write(&self, w: &mut Writer) -> Result<()> {
        self.signing_bytes()?;
        w.u8(1);
        w.id(&self.issuer);
        w.id(&self.key_id);
        w.message(&self.claims)?;
        w.fixed(&self.signature);
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        if r.u8()? != 1 {
            return Err(ContractError::Encoding("unknown signature algorithm"));
        }
        Ok(Self {
            issuer: r.id()?,
            key_id: r.id()?,
            claims: r.message()?,
            signature: r.fixed()?,
        })
    }
}
