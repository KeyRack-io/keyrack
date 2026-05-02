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

//! Logical ID (LID) derivation.
//!
//! ```text
//! LID = BLAKE3(canonicalization_version_le32 || canonical_form_bytes)
//! ```
//!
//! Displayed as `lid_` followed by 64 lowercase hex characters.

use crate::canon::{CanonicalizationVersion, CanonicalForm};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

const LID_PREFIX: &str = "lid_";

/// A 32-byte logical identifier derived from a canonicalized attribute set.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Lid([u8; 32]);

impl Lid {
    /// Derive a LID from a canonicalization version and canonical form.
    #[must_use]
    pub fn derive(version: CanonicalizationVersion, form: &CanonicalForm) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&version.as_le_bytes());
        hasher.update(form.bytes());
        let hash = hasher.finalize();
        Self(*hash.as_bytes())
    }

    /// Construct a LID from raw bytes (e.g. when decoding from a
    /// ciphertext header or storage row).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}

impl fmt::Display for Lid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{LID_PREFIX}")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Lid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Lid({self})")
    }
}

/// Error returned when parsing a LID from a string fails.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LidParseError {
    #[error("LID must start with \"lid_\"")]
    MissingPrefix,

    #[error("LID hex portion must be exactly 64 characters, got {0}")]
    WrongLength(usize),

    #[error("invalid hex character at position {0}")]
    InvalidHex(usize),
}

impl FromStr for Lid {
    type Err = LidParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_part = s
            .strip_prefix(LID_PREFIX)
            .ok_or(LidParseError::MissingPrefix)?;

        if hex_part.len() != 64 {
            return Err(LidParseError::WrongLength(hex_part.len()));
        }

        let mut bytes = [0u8; 32];
        for (i, chunk) in hex_part.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0]).ok_or(LidParseError::InvalidHex(i * 2))?;
            let lo = hex_digit(chunk[1]).ok_or(LidParseError::InvalidHex(i * 2 + 1))?;
            bytes[i] = (hi << 4) | lo;
        }

        Ok(Self(bytes))
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AttributeSet, AttributeValue};
    use crate::canon::{canonicalize, CanonicalizationVersion};

    fn make_lid(key: &str, val: &str) -> Lid {
        let mut attrs = AttributeSet::new();
        attrs.insert(key, AttributeValue::String(val.into()));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        Lid::derive(CanonicalizationVersion::V1, &form)
    }

    #[test]
    fn deterministic() {
        let a = make_lid("tenant", "acme");
        let b = make_lid("tenant", "acme");
        assert_eq!(a, b);
    }

    #[test]
    fn different_input_different_lid() {
        let a = make_lid("tenant", "acme");
        let b = make_lid("tenant", "globex");
        assert_ne!(a, b);
    }

    #[test]
    fn display_format() {
        let lid = make_lid("tenant", "acme");
        let s = lid.to_string();
        assert!(s.starts_with("lid_"));
        assert_eq!(s.len(), 4 + 64);
        assert!(s[4..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn display_fromstr_round_trip() {
        let lid = make_lid("tenant", "acme");
        let s = lid.to_string();
        let parsed: Lid = s.parse().unwrap();
        assert_eq!(lid, parsed);
    }

    #[test]
    fn fromstr_rejects_missing_prefix() {
        let result = "deadbeef".repeat(8).parse::<Lid>();
        assert!(matches!(result, Err(LidParseError::MissingPrefix)));
    }

    #[test]
    fn fromstr_rejects_wrong_length() {
        let result = "lid_abcd".parse::<Lid>();
        assert!(matches!(result, Err(LidParseError::WrongLength(4))));
    }

    #[test]
    fn fromstr_rejects_invalid_hex() {
        let bad = format!("lid_{}", "zz".repeat(32));
        let result = bad.parse::<Lid>();
        assert!(matches!(result, Err(LidParseError::InvalidHex(_))));
    }

    #[test]
    fn different_version_different_lid() {
        let mut attrs = AttributeSet::new();
        attrs.insert("x", AttributeValue::I64(1));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);

        let lid_v1 = Lid::derive(CanonicalizationVersion::V1, &form);

        // Simulate V2 by manually hashing with a different version byte.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&2_u32.to_le_bytes());
        hasher.update(form.bytes());
        let lid_v2_bytes = *hasher.finalize().as_bytes();

        assert_ne!(lid_v1.as_bytes(), &lid_v2_bytes);
    }

    #[test]
    fn single_byte_flip_changes_lid() {
        let mut attrs = AttributeSet::new();
        attrs.insert("x", AttributeValue::I64(0));
        let form_a = canonicalize(CanonicalizationVersion::V1, &attrs);

        let mut attrs_b = AttributeSet::new();
        attrs_b.insert("x", AttributeValue::I64(1));
        let form_b = canonicalize(CanonicalizationVersion::V1, &attrs_b);

        let lid_a = Lid::derive(CanonicalizationVersion::V1, &form_a);
        let lid_b = Lid::derive(CanonicalizationVersion::V1, &form_b);
        assert_ne!(lid_a, lid_b);
    }

    #[test]
    fn serde_round_trip() {
        let lid = make_lid("tenant", "acme");
        let json = serde_json::to_string(&lid).unwrap();
        let parsed: Lid = serde_json::from_str(&json).unwrap();
        assert_eq!(lid, parsed);
    }
}
