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

//! `SecretString` — a serde-friendly secret string that is redacted by
//! construction.
//!
//! Unlike [`crate::sensitive::Sensitive`] (which has no serde impls),
//! `SecretString` deserializes transparently from a plain string but can
//! **never** be serialized back to its plaintext: its `Serialize` impl emits a
//! fixed mask, and its `Debug`/`Display` impls do the same. This makes it
//! impossible for a configured secret (e.g. a PKCS#11 PIN) to leak into config
//! dumps, error payloads, or audit metadata by accident — redaction is
//! structural, not a regex pass over message strings.
//!
//! The plaintext is held in a [`Zeroizing`] buffer (zeroized on drop) and is
//! reachable only via the conspicuous [`SecretString::expose`] accessor.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// The fixed token emitted in place of the secret by `Debug`/`Display`/
/// `Serialize`. Never contains secret bytes.
pub const REDACTED: &str = "***REDACTED***";

/// A string secret that is redacted by construction.
///
/// Deserializes from a plain string; serializes to [`REDACTED`].
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wrap a plaintext secret.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Access the plaintext. Named to be conspicuous in code review and grep.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl Eq for SecretString {}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl Serialize for SecretString {
    /// Always serializes to [`REDACTED`] — the plaintext is never emitted.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_are_redacted() {
        let s = SecretString::new("hunter2");
        assert_eq!(format!("{s:?}"), REDACTED);
        assert_eq!(format!("{s}"), REDACTED);
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn serialize_never_emits_plaintext() {
        let s = SecretString::new("hunter2");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, format!("\"{REDACTED}\""));
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn deserialize_reads_plaintext() {
        let s: SecretString = serde_json::from_str("\"hunter2\"").unwrap();
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn expose_returns_plaintext() {
        let s = SecretString::new("p1n");
        assert_eq!(s.expose(), "p1n");
    }

    #[test]
    fn redacted_in_enclosing_debug() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Cfg {
            label: String,
            pin: SecretString,
        }
        let c = Cfg {
            label: "tenant-a".into(),
            pin: SecretString::new("1234"),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("tenant-a"));
        assert!(dbg.contains(REDACTED));
        assert!(!dbg.contains("1234"));
    }
}
