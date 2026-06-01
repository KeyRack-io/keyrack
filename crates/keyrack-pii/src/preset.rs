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

//! PII preset types.

use serde::{Deserialize, Serialize};

/// Built-in PII presets.
///
/// Each preset applies type-specific normalization before hashing
/// to ensure consistent tokenization regardless of formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    /// Email address — lowercased before hashing.
    Email,
    /// US Social Security Number — digits only (strips dashes/spaces).
    Ssn,
    /// Phone number — digits only (strips formatting).
    Phone,
    /// Credit card number — digits only (strips spaces/dashes).
    CreditCard,
    /// IP address (v4 or v6) — normalized string representation.
    IpAddress,
    /// Raw value — no normalization applied.
    Raw,
}

impl Preset {
    /// Token prefix for this preset type.
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            Self::Email => "tok:email:",
            Self::Ssn => "tok:ssn:",
            Self::Phone => "tok:phone:",
            Self::CreditCard => "tok:cc:",
            Self::IpAddress => "tok:ip:",
            Self::Raw => "tok:raw:",
        }
    }

    /// Normalize the input value according to this preset's rules.
    pub(crate) fn normalize(self, value: &str) -> String {
        match self {
            Self::Email => value.trim().to_lowercase(),
            Self::Ssn | Self::Phone | Self::CreditCard => {
                value.chars().filter(|c| c.is_ascii_digit()).collect()
            }
            Self::IpAddress => normalize_ip(value),
            Self::Raw => value.to_string(),
        }
    }
}

fn normalize_ip(value: &str) -> String {
    let trimmed = value.trim();
    if let Ok(addr) = trimmed.parse::<std::net::IpAddr>() {
        addr.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_lowercased() {
        assert_eq!(Preset::Email.normalize("Alice@Example.COM"), "alice@example.com");
    }

    #[test]
    fn ssn_digits_only() {
        assert_eq!(Preset::Ssn.normalize("123-45-6789"), "123456789");
    }

    #[test]
    fn phone_digits_only() {
        assert_eq!(Preset::Phone.normalize("+1 (555) 123-4567"), "15551234567");
    }

    #[test]
    fn credit_card_digits_only() {
        assert_eq!(Preset::CreditCard.normalize("4111 1111 1111 1111"), "4111111111111111");
    }

    #[test]
    fn ip_v4_normalized() {
        assert_eq!(Preset::IpAddress.normalize("  192.168.1.1  "), "192.168.1.1");
    }

    #[test]
    fn ip_v6_normalized() {
        let norm = Preset::IpAddress.normalize("::1");
        assert_eq!(norm, "::1");
    }

    #[test]
    fn raw_no_change() {
        assert_eq!(Preset::Raw.normalize("Hello World!"), "Hello World!");
    }
}
