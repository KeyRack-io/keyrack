// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

//! Self-describing ciphertext header.
//!
//! Every ciphertext blob produced by `KeyRack` is prefixed with a fixed-size
//! header that identifies the key, version, and encryption context used.
//! This allows automatic key/version selection at decrypt time without
//! any out-of-band metadata.
//!
//! See `docs/SPEC.md` §4 for the byte layout.
//!
//! ```text
//! Offset  Len  Field
//! ──────  ───  ─────
//!   0       4  Magic: 0x4B 0x52 0x43 0x4B ("KRCK")
//!   4       2  Header version (LE u16)
//!   6      32  Key LID (raw 32 bytes)
//!  38       8  Key version (LE u64)
//!  46      32  Encryption context hash (BLAKE3, or 32×0x00 if none)
//!  78       2  Reserved / payload-length prefix (LE u16, currently 0)
//!  80     ...  Ciphertext payload
//! ```

use crate::encryption_context::ZERO_CONTEXT_HASH;
use crate::error::KeyRackError;
use crate::lid::Lid;

/// Magic bytes: "KRCK" in ASCII.
pub const MAGIC: [u8; 4] = [0x4B, 0x52, 0x43, 0x4B];

/// Current header version.
pub const HEADER_VERSION: u16 = 1;

/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 80;

/// Parsed ciphertext header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextHeader {
    pub header_version: u16,
    pub lid: Lid,
    pub key_version: u64,
    pub encryption_context_hash: [u8; 32],
}

impl CiphertextHeader {
    /// Create a header for a new ciphertext.
    #[must_use]
    pub fn new(lid: Lid, key_version: u64, encryption_context_hash: [u8; 32]) -> Self {
        Self {
            header_version: HEADER_VERSION,
            lid,
            key_version,
            encryption_context_hash,
        }
    }

    /// Encode the header into an 80-byte fixed-size buffer.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];

        buf[0..4].copy_from_slice(&MAGIC);
        buf[4..6].copy_from_slice(&self.header_version.to_le_bytes());
        buf[6..38].copy_from_slice(self.lid.as_bytes());
        buf[38..46].copy_from_slice(&self.key_version.to_le_bytes());
        buf[46..78].copy_from_slice(&self.encryption_context_hash);
        // buf[78..80] is reserved, already zero.

        buf
    }

    /// Decode a header from the first 80 bytes of a buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, KeyRackError> {
        if buf.len() < HEADER_SIZE {
            return Err(KeyRackError::Provider(format!(
                "ciphertext too short for header: need {HEADER_SIZE}, got {}",
                buf.len()
            )));
        }

        if buf[0..4] != MAGIC {
            return Err(KeyRackError::Provider(
                "invalid ciphertext magic bytes".into(),
            ));
        }

        let header_version = u16::from_le_bytes([buf[4], buf[5]]);
        if header_version != HEADER_VERSION {
            return Err(KeyRackError::Provider(format!(
                "unsupported header version: {header_version}"
            )));
        }

        let mut lid_bytes = [0u8; 32];
        lid_bytes.copy_from_slice(&buf[6..38]);
        let lid = Lid::from_bytes(lid_bytes);

        let key_version = u64::from_le_bytes(buf[38..46].try_into().unwrap());

        let mut ec_hash = [0u8; 32];
        ec_hash.copy_from_slice(&buf[46..78]);

        Ok(Self {
            header_version,
            lid,
            key_version,
            encryption_context_hash: ec_hash,
        })
    }

    /// Whether this header carries an encryption context.
    #[must_use]
    pub fn has_encryption_context(&self) -> bool {
        self.encryption_context_hash != ZERO_CONTEXT_HASH
    }

    /// Pack header + ciphertext payload into a single blob.
    #[must_use]
    pub fn wrap_payload(&self, ciphertext_payload: &[u8]) -> Vec<u8> {
        let header = self.encode();
        let mut out = Vec::with_capacity(HEADER_SIZE + ciphertext_payload.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(ciphertext_payload);
        out
    }

    /// Split a blob into header + payload.
    pub fn unwrap_payload(blob: &[u8]) -> Result<(Self, &[u8]), KeyRackError> {
        let header = Self::decode(blob)?;
        Ok((header, &blob[HEADER_SIZE..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AttributeSet, AttributeValue};
    use crate::canon::{canonicalize, CanonicalizationVersion};
    use crate::encryption_context::EncryptionContext;

    fn test_lid() -> Lid {
        let mut attrs = AttributeSet::new();
        attrs.insert("tenant", AttributeValue::String("acme".into()));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        Lid::derive(CanonicalizationVersion::V1, &form)
    }

    #[test]
    fn encode_decode_round_trip() {
        let lid = test_lid();
        let header = CiphertextHeader::new(lid.clone(), 42, ZERO_CONTEXT_HASH);

        let encoded = header.encode();
        assert_eq!(encoded.len(), HEADER_SIZE);

        let decoded = CiphertextHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn magic_bytes_are_krck() {
        let header = CiphertextHeader::new(test_lid(), 1, ZERO_CONTEXT_HASH);
        let encoded = header.encode();
        assert_eq!(&encoded[0..4], b"KRCK");
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(b"NOPE");
        assert!(CiphertextHeader::decode(&buf).is_err());
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let buf = [0u8; 10];
        assert!(CiphertextHeader::decode(&buf).is_err());
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let header = CiphertextHeader::new(test_lid(), 1, ZERO_CONTEXT_HASH);
        let mut encoded = header.encode();
        encoded[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert!(CiphertextHeader::decode(&encoded).is_err());
    }

    #[test]
    fn encryption_context_hash_preserved() {
        let mut ctx = EncryptionContext::new();
        ctx.insert("purpose", "volume-dek");
        let hash = ctx.hash();

        let header = CiphertextHeader::new(test_lid(), 5, hash);
        assert!(header.has_encryption_context());

        let decoded = CiphertextHeader::decode(&header.encode()).unwrap();
        assert_eq!(decoded.encryption_context_hash, hash);
        assert!(decoded.has_encryption_context());
    }

    #[test]
    fn no_context_is_zero_hash() {
        let header = CiphertextHeader::new(test_lid(), 1, ZERO_CONTEXT_HASH);
        assert!(!header.has_encryption_context());
    }

    #[test]
    fn wrap_unwrap_payload() {
        let lid = test_lid();
        let header = CiphertextHeader::new(lid, 3, ZERO_CONTEXT_HASH);
        let payload = b"encrypted data here";

        let blob = header.wrap_payload(payload);
        assert_eq!(blob.len(), HEADER_SIZE + payload.len());

        let (decoded, extracted_payload) = CiphertextHeader::unwrap_payload(&blob).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(extracted_payload, payload);
    }

    #[test]
    fn key_version_round_trip() {
        let header = CiphertextHeader::new(test_lid(), u64::MAX, ZERO_CONTEXT_HASH);
        let decoded = CiphertextHeader::decode(&header.encode()).unwrap();
        assert_eq!(decoded.key_version, u64::MAX);
    }
}
