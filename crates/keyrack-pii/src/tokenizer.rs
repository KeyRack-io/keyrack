// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1

//! BLAKE3-based deterministic tokenizer.

use crate::Preset;

/// Deterministic PII tokenizer using BLAKE3 keyed hashing.
///
/// Each tokenizer is bound to a salt (typically per-tenant). The same
/// (salt, value, preset) triple always produces the same token.
/// Tokens are non-reversible — you cannot recover the original value.
///
/// The salt is used as the BLAKE3 key (first 32 bytes) and an
/// additional domain-separation context derived from the preset.
pub struct Tokenizer {
    key: [u8; 32],
}

impl Tokenizer {
    /// Create a new tokenizer with the given salt.
    ///
    /// If `salt` is shorter than 32 bytes, it is zero-padded. If
    /// longer, only the first 32 bytes are used.
    #[must_use]
    pub fn new(salt: &[u8]) -> Self {
        let mut key = [0u8; 32];
        let len = salt.len().min(32);
        key[..len].copy_from_slice(&salt[..len]);
        Self { key }
    }

    /// Tokenize a PII value using the given preset.
    ///
    /// Returns a deterministic, non-reversible token string with a
    /// type prefix (e.g. `tok:email:a1b2c3...`).
    #[must_use]
    pub fn tokenize(&self, value: &str, preset: Preset) -> String {
        let normalized = preset.normalize(value);
        let domain = preset.prefix();

        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(domain.as_bytes());
        hasher.update(normalized.as_bytes());
        let hash = hasher.finalize();

        let hex = hash.to_hex();
        format!("{domain}{hex}")
    }

    /// Tokenize a raw value without any preset normalization.
    #[must_use]
    pub fn tokenize_raw(&self, value: &str) -> String {
        self.tokenize(value, Preset::Raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"test-tenant-salt-exactly-32bytes!";

    #[test]
    fn deterministic() {
        let tok = Tokenizer::new(SALT);
        let t1 = tok.tokenize("alice@example.com", Preset::Email);
        let t2 = tok.tokenize("alice@example.com", Preset::Email);
        assert_eq!(t1, t2);
    }

    #[test]
    fn different_values_different_tokens() {
        let tok = Tokenizer::new(SALT);
        let t1 = tok.tokenize("alice@example.com", Preset::Email);
        let t2 = tok.tokenize("bob@example.com", Preset::Email);
        assert_ne!(t1, t2);
    }

    #[test]
    fn different_salts_different_tokens() {
        let tok1 = Tokenizer::new(b"salt-a-32-bytes-padding-here!!!!");
        let tok2 = Tokenizer::new(b"salt-b-32-bytes-padding-here!!!!");
        let t1 = tok1.tokenize("alice@example.com", Preset::Email);
        let t2 = tok2.tokenize("alice@example.com", Preset::Email);
        assert_ne!(t1, t2);
    }

    #[test]
    fn different_presets_different_tokens() {
        let tok = Tokenizer::new(SALT);
        let t1 = tok.tokenize("12345", Preset::Ssn);
        let t2 = tok.tokenize("12345", Preset::Phone);
        assert_ne!(t1, t2);
    }

    #[test]
    fn email_case_insensitive() {
        let tok = Tokenizer::new(SALT);
        let t1 = tok.tokenize("Alice@Example.COM", Preset::Email);
        let t2 = tok.tokenize("alice@example.com", Preset::Email);
        assert_eq!(t1, t2);
    }

    #[test]
    fn ssn_ignores_formatting() {
        let tok = Tokenizer::new(SALT);
        let t1 = tok.tokenize("123-45-6789", Preset::Ssn);
        let t2 = tok.tokenize("123456789", Preset::Ssn);
        assert_eq!(t1, t2);
    }

    #[test]
    fn phone_ignores_formatting() {
        let tok = Tokenizer::new(SALT);
        let t1 = tok.tokenize("+1 (555) 123-4567", Preset::Phone);
        let t2 = tok.tokenize("15551234567", Preset::Phone);
        assert_eq!(t1, t2);
    }

    #[test]
    fn credit_card_ignores_spaces() {
        let tok = Tokenizer::new(SALT);
        let t1 = tok.tokenize("4111 1111 1111 1111", Preset::CreditCard);
        let t2 = tok.tokenize("4111111111111111", Preset::CreditCard);
        assert_eq!(t1, t2);
    }

    #[test]
    fn token_has_prefix() {
        let tok = Tokenizer::new(SALT);
        assert!(tok.tokenize("x", Preset::Email).starts_with("tok:email:"));
        assert!(tok.tokenize("x", Preset::Ssn).starts_with("tok:ssn:"));
        assert!(tok.tokenize("x", Preset::Phone).starts_with("tok:phone:"));
        assert!(tok.tokenize("x", Preset::CreditCard).starts_with("tok:cc:"));
        assert!(tok.tokenize("x", Preset::IpAddress).starts_with("tok:ip:"));
        assert!(tok.tokenize("x", Preset::Raw).starts_with("tok:raw:"));
    }

    #[test]
    fn short_salt_padded() {
        let tok = Tokenizer::new(b"short");
        let t = tok.tokenize("test", Preset::Raw);
        assert!(t.starts_with("tok:raw:"));
        assert!(t.len() > 10);
    }

    #[test]
    fn raw_tokenize_shorthand() {
        let tok = Tokenizer::new(SALT);
        let t1 = tok.tokenize_raw("hello");
        let t2 = tok.tokenize("hello", Preset::Raw);
        assert_eq!(t1, t2);
    }
}
