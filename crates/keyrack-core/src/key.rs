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

//! Key record and state machine.
//!
//! The state machine matches `KEYRACK_SPEC.md` §5.4:
//!
//! ```text
//! creating ──► enabled ◄──► disabled
//!                 │              │
//!                 ▼              ▼
//!           pending_deletion ◄───┘
//!                 │
//!                 ▼
//!            destroyed
//! ```

use crate::canon::CanonicalizationVersion;
use crate::lid::Lid;
use crate::tags::{IdentityTags, UserTags};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Key lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Creating,
    Enabled,
    Disabled,
    PendingDeletion,
    Destroyed,
}

impl KeyState {
    /// Whether encrypt and sign operations are permitted.
    #[must_use]
    pub fn permits_encrypt(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Whether decrypt and verify operations are permitted.
    /// Disabled keys allow decrypt for data recovery.
    #[must_use]
    pub fn permits_decrypt(&self) -> bool {
        matches!(self, Self::Enabled | Self::Disabled)
    }

    /// Returns the set of states this state can transition to.
    #[must_use]
    pub fn valid_transitions(&self) -> &'static [KeyState] {
        match self {
            Self::Creating => &[Self::Enabled],
            Self::Enabled => &[Self::Disabled, Self::PendingDeletion],
            Self::Disabled => &[Self::Enabled, Self::PendingDeletion],
            Self::PendingDeletion => &[Self::Disabled, Self::Destroyed],
            Self::Destroyed => &[],
        }
    }

    /// Check whether transitioning to `target` is valid.
    #[must_use]
    pub fn can_transition_to(&self, target: Self) -> bool {
        self.valid_transitions().contains(&target)
    }
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => f.write_str("creating"),
            Self::Enabled => f.write_str("enabled"),
            Self::Disabled => f.write_str("disabled"),
            Self::PendingDeletion => f.write_str("pending_deletion"),
            Self::Destroyed => f.write_str("destroyed"),
        }
    }
}

/// What the key is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyUsage {
    EncryptDecrypt,
    SignVerify,
}

/// Cryptographic algorithm / key spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeySpec {
    Aes256,
    Ed25519,
    RsaPkcs1v15Sha256 { key_size: u32 },
    EcdsaP256Sha256,
}

/// Which provider class backs this key's material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderClass {
    Software,
    Pkcs11,
    Kmip,
    InMemory,
}

/// The primary key record. Stored in the storage backend.
///
/// `parent_lid` is stored, not recomputed — existing keys preserve their
/// parent relationships even when rules change (see `MIGRATION.md`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub lid: Lid,
    pub canonicalization_version: CanonicalizationVersion,
    pub parent_lid: Option<Lid>,
    pub version: u64,
    pub state: KeyState,
    pub key_usage: KeyUsage,
    pub key_spec: KeySpec,
    pub provider_class: ProviderClass,
    pub identity_tags: IdentityTags,
    pub user_tags: UserTags,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub scheduled_deletion_at: Option<DateTime<Utc>>,
    pub description: String,
}

impl KeyRecord {
    /// Attempt a state transition. Returns `Err` if the transition is invalid.
    pub fn transition_to(
        &mut self,
        target: KeyState,
    ) -> std::result::Result<KeyState, (KeyState, KeyState)> {
        let from = self.state;
        if from.can_transition_to(target) {
            self.state = target;
            self.version += 1;
            self.updated_at = Utc::now();
            Ok(target)
        } else {
            Err((from, target))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creating_can_only_go_to_enabled() {
        assert!(KeyState::Creating.can_transition_to(KeyState::Enabled));
        assert!(!KeyState::Creating.can_transition_to(KeyState::Disabled));
        assert!(!KeyState::Creating.can_transition_to(KeyState::PendingDeletion));
        assert!(!KeyState::Creating.can_transition_to(KeyState::Destroyed));
    }

    #[test]
    fn enabled_transitions() {
        assert!(KeyState::Enabled.can_transition_to(KeyState::Disabled));
        assert!(KeyState::Enabled.can_transition_to(KeyState::PendingDeletion));
        assert!(!KeyState::Enabled.can_transition_to(KeyState::Creating));
        assert!(!KeyState::Enabled.can_transition_to(KeyState::Destroyed));
    }

    #[test]
    fn disabled_transitions() {
        assert!(KeyState::Disabled.can_transition_to(KeyState::Enabled));
        assert!(KeyState::Disabled.can_transition_to(KeyState::PendingDeletion));
        assert!(!KeyState::Disabled.can_transition_to(KeyState::Creating));
        assert!(!KeyState::Disabled.can_transition_to(KeyState::Destroyed));
    }

    #[test]
    fn pending_deletion_transitions() {
        // CancelKeyDeletion returns to disabled, not enabled.
        assert!(KeyState::PendingDeletion.can_transition_to(KeyState::Disabled));
        assert!(KeyState::PendingDeletion.can_transition_to(KeyState::Destroyed));
        assert!(!KeyState::PendingDeletion.can_transition_to(KeyState::Enabled));
        assert!(!KeyState::PendingDeletion.can_transition_to(KeyState::Creating));
    }

    #[test]
    fn destroyed_is_terminal() {
        assert!(KeyState::Destroyed.valid_transitions().is_empty());
    }

    #[test]
    fn encrypt_permissions() {
        assert!(!KeyState::Creating.permits_encrypt());
        assert!(KeyState::Enabled.permits_encrypt());
        assert!(!KeyState::Disabled.permits_encrypt());
        assert!(!KeyState::PendingDeletion.permits_encrypt());
        assert!(!KeyState::Destroyed.permits_encrypt());
    }

    #[test]
    fn decrypt_permissions() {
        assert!(!KeyState::Creating.permits_decrypt());
        assert!(KeyState::Enabled.permits_decrypt());
        assert!(KeyState::Disabled.permits_decrypt());
        assert!(!KeyState::PendingDeletion.permits_decrypt());
        assert!(!KeyState::Destroyed.permits_decrypt());
    }

    #[test]
    fn key_record_transition() {
        let mut record = make_test_record(KeyState::Enabled);
        let v = record.version;
        assert!(record.transition_to(KeyState::Disabled).is_ok());
        assert_eq!(record.state, KeyState::Disabled);
        assert_eq!(record.version, v + 1);
    }

    #[test]
    fn key_record_invalid_transition() {
        let mut record = make_test_record(KeyState::Enabled);
        let result = record.transition_to(KeyState::Destroyed);
        assert!(result.is_err());
        assert_eq!(record.state, KeyState::Enabled);
    }

    #[test]
    fn cancel_deletion_returns_to_disabled() {
        let mut record = make_test_record(KeyState::PendingDeletion);
        assert!(record.transition_to(KeyState::Disabled).is_ok());
        assert_eq!(record.state, KeyState::Disabled);
        // Cannot go directly back to enabled.
        assert!(record.transition_to(KeyState::Enabled).is_ok());
    }

    #[test]
    fn serde_round_trip_key_state() {
        for state in &[
            KeyState::Creating,
            KeyState::Enabled,
            KeyState::Disabled,
            KeyState::PendingDeletion,
            KeyState::Destroyed,
        ] {
            let json = serde_json::to_string(state).unwrap();
            let parsed: KeyState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, parsed);
        }
    }

    fn make_test_record(state: KeyState) -> KeyRecord {
        use crate::attr::{AttributeSet, AttributeValue};
        use crate::canon::{canonicalize, CanonicalizationVersion};

        let mut attrs = AttributeSet::new();
        attrs.insert("tenant", AttributeValue::String("test".into()));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        let lid = Lid::derive(CanonicalizationVersion::V1, &form);

        KeyRecord {
            lid,
            canonicalization_version: CanonicalizationVersion::V1,
            parent_lid: None,
            version: 1,
            state,
            key_usage: KeyUsage::EncryptDecrypt,
            key_spec: KeySpec::Aes256,
            provider_class: ProviderClass::Software,
            identity_tags: IdentityTags::from_attribute_set(&attrs),
            user_tags: UserTags::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scheduled_deletion_at: None,
            description: String::new(),
        }
    }
}
