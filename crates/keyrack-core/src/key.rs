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

//! Key record, key version record, and state machine.
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
//!
//! Two distinct version concepts exist:
//!
//! - **`occ_version`**: monotonic storage counter for optimistic
//!   concurrency control (§9.2). Bumped on every mutation.
//! - **Key version** (`KeyVersionRecord`): per-rotation material.
//!   Rotation creates a new version; old versions are retained for
//!   decrypt. `current_key_version` identifies the active version
//!   for encrypt/sign operations.

use crate::canon::CanonicalizationVersion;
use crate::lid::Lid;
use crate::provider::KeyHandle;
use crate::tags::{IdentityTags, UserTags};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use crate::material::{KeyMaterial, ParentWrappedMaterial};

/// Key lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Creating,
    Enabled,
    Disabled,
    /// NIST SP 800-57: key material may have been exposed.
    /// Decrypt is denied by default; mathematical verification is unchanged.
    Compromised,
    PendingDeletion,
    Destroyed,
}

impl KeyState {
    /// Whether encrypt and sign operations are permitted by the live state.
    /// Use [`KeyRecord::permits_encrypt`] to enforce compromise history too.
    #[must_use]
    pub fn permits_encrypt(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Whether decrypt operations are permitted by the live state.
    /// Disabled keys allow decrypt for data recovery.
    /// Service callers must use [`KeyRecord::permits_decrypt`] so compromise
    /// history is also enforced after deletion cancellation.
    #[must_use]
    pub fn permits_decrypt(&self) -> bool {
        matches!(self, Self::Enabled | Self::Disabled)
    }

    /// Whether mathematical signature or MAC verification is permitted.
    /// This preserves existing behavior; it does not establish trustworthy
    /// provenance for a compromised key.
    #[must_use]
    pub fn permits_verify(&self) -> bool {
        matches!(self, Self::Enabled | Self::Disabled | Self::Compromised)
    }

    /// Whether raw key-material export is permitted. `Enabled` only.
    /// Use [`KeyRecord::permits_export`] to enforce compromise history too.
    ///
    /// Deliberately stricter than [`Self::permits_decrypt`], which grants
    /// `Disabled` latitude for data recovery. Export is not a
    /// data-recovery operation: it hands the caller the key itself, so it is a
    /// custody-boundary crossing and is strictly more powerful than decrypt —
    /// the holder of exported bytes can decrypt forever, outside `KeyRack`, with
    /// no further authorization. Disabling a key is how an operator withdraws
    /// its use, so continuing to hand out copies would defeat it, and export
    /// cannot be undone once the bytes have left. `PendingDeletion` and
    /// `Destroyed` must refuse for destruction to be real rather than a label
    /// on the record.
    #[must_use]
    pub fn permits_export(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Returns the set of states this state can transition to.
    #[must_use]
    pub fn valid_transitions(&self) -> &'static [KeyState] {
        match self {
            Self::Creating => &[Self::Enabled],
            Self::Enabled => &[Self::Disabled, Self::Compromised, Self::PendingDeletion],
            Self::Disabled => &[Self::Enabled, Self::Compromised, Self::PendingDeletion],
            Self::Compromised => &[Self::PendingDeletion],
            Self::PendingDeletion => &[Self::Disabled, Self::Destroyed],
            Self::Destroyed => &[],
        }
    }

    /// Check whether the live-state edge to `target` exists. This cannot check
    /// compromise history; mutations must use [`KeyRecord::transition_to`].
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
            Self::Compromised => f.write_str("compromised"),
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
    /// Symmetric MAC keys (HMAC). Used with `GenerateMac` / `VerifyMac`.
    GenerateVerifyMac,
}

/// Cryptographic algorithm / key spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeySpec {
    Aes256,
    Aes128,
    Ed25519,
    RsaPkcs1v15Sha256 {
        key_size: u32,
    },
    RsaPssSha256 {
        key_size: u32,
    },
    EcdsaP256Sha256,
    /// ECDSA over NIST P-384 (CNSA / PCI). Default digest SHA-384.
    EcdsaP384,
    /// HMAC-SHA-256 MAC key (32-byte secret).
    Hmac256,
}

/// Which provider class backs this key's material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderClass {
    Software,
    Pkcs11,
    Kmip,
    InMemory,
    VaultTransit,
}

/// Name of a configured crypto provider, used as a routing key.
///
/// This is a SIDE PROPERTY of a key/version: it selects which configured
/// [`CryptoProvider`](crate::provider::CryptoProvider) backs the material.
/// It MUST NOT participate in LID derivation — logical key identity stays
/// independent of the physical backend so that keys can migrate between
/// providers/HSMs (BYOK <-> HYOK) without their identity, or the LID
/// pinned into existing ciphertext headers, changing.
///
/// `None` on a record/version means "use the registry default provider".
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProviderRef(pub String);

impl ProviderRef {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProviderRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ProviderRef {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<String> for ProviderRef {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Where the key material originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrigin {
    /// Generated by `KeyRack` internally.
    KeyRack,
    /// Imported by the operator/tenant.
    External,
}

/// Whether this key's raw material may cross the trust boundary via an
/// explicit, audited export / KMIP Get. Default = `NonExportable`. Mutable
/// only via the two guarded transitions (never a public field setter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Exportability {
    #[default]
    NonExportable,
    Exportable,
}

/// Per-rotation key version record.
///
/// Each rotation creates a new `KeyVersionRecord` with fresh material.
/// Old versions are retained for decrypt/verify of existing ciphertext.
/// The `KeyRecord.current_key_version` field points to the active
/// version for encrypt/sign.
#[derive(Debug, Clone)]
pub struct KeyVersionRecord {
    /// Sequential version number (1, 2, 3, ...).
    pub version_number: u64,
    /// Exclusive durable representation; wrapped material has no resident handle.
    /// Serialization preserves the flat legacy shape for provider-resident keys.
    pub material: KeyMaterial,
    /// When this version was created (initial creation or rotation).
    pub created_at: DateTime<Utc>,
    /// Whether this version is the current primary for encrypt/sign.
    pub is_primary: bool,
}

impl KeyVersionRecord {
    /// Construct an independently provider-resident version without changing its
    /// legacy provider-inheritance or primary-selection semantics.
    pub fn provider_resident(
        version_number: u64,
        key_handle: KeyHandle,
        provider_ref: Option<ProviderRef>,
        created_at: DateTime<Utc>,
        is_primary: bool,
    ) -> Self {
        Self {
            version_number,
            material: KeyMaterial::ProviderResident {
                key_handle,
                provider_ref,
            },
            created_at,
            is_primary,
        }
    }

    /// Explicit version binding. Only resident versions may inherit a binding.
    #[must_use]
    pub fn provider_ref(&self) -> Option<&ProviderRef> {
        match &self.material {
            KeyMaterial::ProviderResident { provider_ref, .. } => provider_ref.as_ref(),
            KeyMaterial::ParentWrapped(material) => Some(material.provider_ref()),
        }
    }

    /// Obtain a durable resident handle, refusing wrapped material.
    /// A wrapped reference is never a provider handle or an operation lease.
    pub fn resident_handle(&self) -> crate::error::Result<&KeyHandle> {
        match &self.material {
            KeyMaterial::ProviderResident { key_handle, .. } => Ok(key_handle),
            KeyMaterial::ParentWrapped(_) => Err(crate::error::KeyRackError::Provider(
                "parent-wrapped material is not supported by this operation".into(),
            )),
        }
    }

    /// Mutable resident handle access for provider-controlled handle replacement.
    /// Refuses wrapped material without creating an independently usable copy.
    pub fn resident_handle_mut(&mut self) -> crate::error::Result<&mut KeyHandle> {
        match &mut self.material {
            KeyMaterial::ProviderResident { key_handle, .. } => Ok(key_handle),
            KeyMaterial::ParentWrapped(_) => Err(crate::error::KeyRackError::Provider(
                "parent-wrapped material is not supported by this operation".into(),
            )),
        }
    }
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

    /// Optimistic concurrency control counter. Bumped on every mutation
    /// (state change, tag update, rotation, metadata edit). Storage
    /// backends check `WHERE occ_version = $expected` and reject on
    /// mismatch (§9.2).
    pub occ_version: u64,

    /// Current primary key version number (for encrypt/sign). References
    /// the `version_number` of one of the entries in `key_versions`.
    pub current_key_version: u64,

    pub state: KeyState,
    /// Durable, logical-key-wide compromise history. Once set, never clear it:
    /// deletion cancellation and new material versions cannot rehabilitate a
    /// compromised key. Legacy records without the field deserialize as false;
    /// [`Self::has_compromise_history`] also recognizes their live state.
    #[serde(default)]
    pub was_compromised: bool,
    pub key_usage: KeyUsage,
    pub key_spec: KeySpec,
    pub origin: KeyOrigin,
    pub provider_class: ProviderClass,
    /// Default provider binding for NEW versions of this key, chosen by
    /// routing rules at creation time. Side property — never part of the
    /// LID. `None` => registry default. Individual versions may override
    /// via [`KeyVersionRecord::provider_ref`] (e.g. mid-migration).
    #[serde(default)]
    pub provider_ref: Option<ProviderRef>,
    /// Whether this key's material may be exported. Side property — never
    /// part of the LID. Legacy records deserialize as `NonExportable`.
    #[serde(default)]
    pub exportability: Exportability,
    /// Monotonic latch: set on the first successful `GetKeyMaterial` and
    /// never reset. Gates `RevokeKeyExportability` (tighten only pre-export).
    #[serde(default)]
    pub first_exported_at: Option<DateTime<Utc>>,
    /// Principal that created this key. Server-set at creation/import; used to
    /// scope `ListKeys` to the owning principal (tenant isolation). Side property
    /// — NEVER part of the LID / canonical form. Legacy records deserialize as
    /// `None` (treated as platform-owned, visible to all callers).
    #[serde(default)]
    pub owner_principal_id: Option<String>,
    pub identity_tags: IdentityTags,
    pub user_tags: UserTags,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub scheduled_deletion_at: Option<DateTime<Utc>>,
    pub description: String,

    /// All key versions (rotation history). Version 1 is the original.
    pub key_versions: Vec<KeyVersionRecord>,
}

impl KeyRecord {
    /// Whether this logical key is, or was previously, marked compromised.
    /// The live-state check handles pre-marker records until their next state
    /// transition persists the latch. History already erased by an older
    /// deployment cannot be reconstructed from an otherwise enabled record.
    #[must_use]
    pub fn has_compromise_history(&self) -> bool {
        self.was_compromised || self.state == KeyState::Compromised
    }

    /// Whether encryption, signing, MAC generation and rotation are permitted.
    #[must_use]
    pub fn permits_encrypt(&self) -> bool {
        !self.has_compromise_history() && self.state.permits_encrypt()
    }

    /// Whether ordinary decrypt is permitted, including durable history.
    #[must_use]
    pub fn permits_decrypt(&self) -> bool {
        !self.has_compromise_history() && self.state.permits_decrypt()
    }

    /// Whether raw material export is permitted, including durable history.
    #[must_use]
    pub fn permits_export(&self) -> bool {
        !self.has_compromise_history() && self.state.permits_export()
    }

    /// Attempt a state transition. Returns `Err` if the transition is invalid.
    pub fn transition_to(
        &mut self,
        target: KeyState,
    ) -> std::result::Result<KeyState, (KeyState, KeyState)> {
        let from = self.state;
        if from.can_transition_to(target)
            && !(target == KeyState::Enabled && self.has_compromise_history())
        {
            self.was_compromised = self.has_compromise_history() || target == KeyState::Compromised;
            self.state = target;
            self.occ_version += 1;
            self.updated_at = Utc::now();
            Ok(target)
        } else {
            Err((from, target))
        }
    }

    /// Get the primary key version record (for encrypt/sign).
    #[must_use]
    pub fn primary_version(&self) -> Option<&KeyVersionRecord> {
        self.key_versions
            .iter()
            .find(|v| v.version_number == self.current_key_version)
    }

    /// Get a specific key version by number (for decrypt/verify of
    /// ciphertext encrypted with an older version).
    #[must_use]
    pub fn get_version(&self, version_number: u64) -> Option<&KeyVersionRecord> {
        self.key_versions
            .iter()
            .find(|v| v.version_number == version_number)
    }

    /// Resolve the effective provider binding for a given key version.
    ///
    /// Resolution order: the version's own `provider_ref`, then the
    /// key's default `provider_ref`. `None` means the caller should fall
    /// back to the registry's default provider.
    #[must_use]
    pub fn effective_provider_ref(&self, version_number: u64) -> Option<&ProviderRef> {
        self.get_version(version_number)
            .and_then(KeyVersionRecord::provider_ref)
            .or(self.provider_ref.as_ref())
    }

    /// Attempt an exportability transition. Returns `Err` if the transition
    /// is invalid (e.g. tightening after material was exported).
    pub fn transition_exportability(
        &mut self,
        target: Exportability,
    ) -> std::result::Result<Exportability, &'static str> {
        match (self.exportability, target) {
            (from, to) if from == to => Ok(to),
            (Exportability::NonExportable, Exportability::Exportable) => {
                self.exportability = target;
                self.occ_version += 1;
                self.updated_at = Utc::now();
                Ok(target)
            }
            (Exportability::Exportable, Exportability::NonExportable) => {
                if self.first_exported_at.is_some() {
                    return Err(
                        "cannot revoke exportability: key material has already been exported",
                    );
                }
                self.exportability = target;
                self.occ_version += 1;
                self.updated_at = Utc::now();
                Ok(target)
            }
            _ => Err("invalid exportability transition"),
        }
    }

    /// Set the `first_exported_at` latch on the first successful export.
    /// No-op if already set. OCC-bumps.
    pub fn mark_exported(&mut self) {
        if self.first_exported_at.is_none() {
            self.first_exported_at = Some(Utc::now());
            self.occ_version += 1;
            self.updated_at = Utc::now();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
        assert!(!KeyState::Compromised.permits_decrypt());
        assert!(!KeyState::PendingDeletion.permits_decrypt());
        assert!(!KeyState::Destroyed.permits_decrypt());
    }

    #[test]
    fn verify_permissions_preserve_existing_behavior() {
        for state in [
            KeyState::Creating,
            KeyState::Enabled,
            KeyState::Disabled,
            KeyState::Compromised,
            KeyState::PendingDeletion,
            KeyState::Destroyed,
        ] {
            assert_eq!(
                state.permits_verify(),
                matches!(
                    state,
                    KeyState::Enabled | KeyState::Disabled | KeyState::Compromised
                ),
            );
        }
    }

    #[test]
    fn export_permissions() {
        assert!(!KeyState::Creating.permits_export());
        assert!(KeyState::Enabled.permits_export());
        assert!(!KeyState::Disabled.permits_export());
        assert!(!KeyState::Compromised.permits_export());
        assert!(!KeyState::PendingDeletion.permits_export());
        assert!(!KeyState::Destroyed.permits_export());
    }

    // Export must never be more permissive than decrypt: a state that
    // forbids decrypting with the key cannot be allowed to hand the key
    // out, since exported material decrypts outside KeyRack forever.
    #[test]
    fn export_is_never_broader_than_decrypt() {
        for state in [
            KeyState::Creating,
            KeyState::Enabled,
            KeyState::Disabled,
            KeyState::Compromised,
            KeyState::PendingDeletion,
            KeyState::Destroyed,
        ] {
            assert!(
                !state.permits_export() || state.permits_decrypt(),
                "{state} permits export but not decrypt"
            );
        }
    }

    #[test]
    fn key_record_transition() {
        let mut record = make_test_record(KeyState::Enabled);
        let v = record.occ_version;
        assert!(record.transition_to(KeyState::Disabled).is_ok());
        assert_eq!(record.state, KeyState::Disabled);
        assert_eq!(record.occ_version, v + 1);
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
        assert!(record.transition_to(KeyState::Enabled).is_ok());
        assert!(!record.has_compromise_history());
        assert!(record.permits_decrypt());
        assert!(record.permits_export());
    }

    #[test]
    fn compromise_history_blocks_deletion_cancellation_laundering() {
        let mut record = make_test_record(KeyState::Enabled);
        record.transition_to(KeyState::Compromised).unwrap();
        assert!(record.was_compromised);
        record.transition_to(KeyState::PendingDeletion).unwrap();
        record.transition_to(KeyState::Disabled).unwrap();

        let before = record.occ_version;
        assert!(record.transition_to(KeyState::Enabled).is_err());
        assert_eq!(record.occ_version, before);
        assert_eq!(record.state, KeyState::Disabled);
        assert!(record.was_compromised);
        assert!(!record.permits_decrypt());
        assert!(!record.permits_encrypt());
        assert!(!record.permits_export());
    }

    #[test]
    fn compromise_history_survives_pending_deletion_json_round_trip() {
        let mut record = make_test_record(KeyState::Enabled);
        record.transition_to(KeyState::Compromised).unwrap();
        record.transition_to(KeyState::PendingDeletion).unwrap();
        let persisted = serde_json::to_vec(&record).unwrap();
        let mut reloaded: KeyRecord = serde_json::from_slice(&persisted).unwrap();

        assert_eq!(reloaded.state, KeyState::PendingDeletion);
        assert!(reloaded.was_compromised);
        reloaded.transition_to(KeyState::Disabled).unwrap();
        assert!(reloaded.transition_to(KeyState::Enabled).is_err());
        assert!(!reloaded.permits_decrypt());
        assert!(!reloaded.permits_export());
    }

    #[test]
    fn legacy_compromised_record_latches_before_leaving_live_state() {
        let mut value = serde_json::to_value(make_test_record(KeyState::Compromised)).unwrap();
        value.as_object_mut().unwrap().remove("was_compromised");
        let mut record: KeyRecord = serde_json::from_value(value).unwrap();
        assert!(!record.was_compromised);
        assert!(record.has_compromise_history());
        assert!(!record.permits_decrypt());

        record.transition_to(KeyState::PendingDeletion).unwrap();
        assert!(record.was_compromised);
        record.transition_to(KeyState::Disabled).unwrap();
        assert!(record.transition_to(KeyState::Enabled).is_err());
        assert!(!record.permits_decrypt());
    }

    #[test]
    fn legacy_never_compromised_record_preserves_deletion_cancellation() {
        let mut value = serde_json::to_value(make_test_record(KeyState::PendingDeletion)).unwrap();
        value.as_object_mut().unwrap().remove("was_compromised");
        let mut record: KeyRecord = serde_json::from_value(value).unwrap();
        assert!(!record.has_compromise_history());
        record.transition_to(KeyState::Disabled).unwrap();
        record.transition_to(KeyState::Enabled).unwrap();
        assert!(record.permits_decrypt());
        assert!(record.permits_export());
    }

    #[test]
    fn new_version_cannot_clear_logical_key_compromise_history() {
        let mut record = make_test_record(KeyState::Enabled);
        record.transition_to(KeyState::Compromised).unwrap();
        record.key_versions[0].is_primary = false;
        let mut new_version = record.key_versions[0].clone();
        new_version.version_number = 2;
        let KeyMaterial::ProviderResident { key_handle, .. } = &mut new_version.material else {
            panic!("test fixture must be provider-resident");
        };
        key_handle.key_id = "fresh-material".into();
        new_version.is_primary = true;
        record.key_versions.push(new_version);
        record.current_key_version = 2;

        // Even accidentally installing fresh material cannot make the logical
        // record usable; service rotation itself must reject this state.
        assert!(record.get_version(1).is_some());
        assert!(record.get_version(2).is_some());
        assert!(record.has_compromise_history());
        assert!(!record.permits_decrypt());
        assert!(!record.permits_encrypt());
        assert!(!record.permits_export());
    }

    #[test]
    fn historical_compromise_denies_use_even_with_inconsistent_enabled_state() {
        let mut record = make_test_record(KeyState::Enabled);
        record.was_compromised = true;
        assert!(!record.permits_decrypt());
        assert!(!record.permits_encrypt());
        assert!(!record.permits_export());
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

    #[test]
    fn primary_version_lookup() {
        let record = make_test_record(KeyState::Enabled);
        let pv = record.primary_version().unwrap();
        assert_eq!(pv.version_number, 1);
        assert!(pv.is_primary);
    }

    #[test]
    fn get_version_lookup() {
        let record = make_test_record(KeyState::Enabled);
        assert!(record.get_version(1).is_some());
        assert!(record.get_version(999).is_none());
    }

    #[test]
    fn provider_ref_defaults_to_none_for_legacy_records() {
        // A record serialized before provider routing existed has no
        // `provider_ref` on the record or its versions. It must still
        // deserialize, defaulting both to `None` (=> registry default).
        let mut record = make_test_record(KeyState::Enabled);
        record.provider_ref = None;
        let json = serde_json::to_string(&record).unwrap();

        // Strip the fields entirely to simulate an older on-disk blob.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("provider_ref");
        if let Some(versions) = obj.get_mut("key_versions").and_then(|v| v.as_array_mut()) {
            for v in versions {
                v.as_object_mut().unwrap().remove("provider_ref");
            }
        }
        let legacy = serde_json::to_string(&value).unwrap();

        let parsed: KeyRecord = serde_json::from_str(&legacy).unwrap();
        assert_eq!(parsed.provider_ref, None);
        assert!(parsed
            .key_versions
            .iter()
            .all(|v| v.provider_ref().is_none()));
        assert_eq!(parsed.effective_provider_ref(1), None);
    }

    #[test]
    fn effective_provider_ref_resolution_order() {
        let mut record = make_test_record(KeyState::Enabled);

        // No binding anywhere => None (registry default).
        assert_eq!(record.effective_provider_ref(1), None);

        // Key-level default applies when the version has none.
        record.provider_ref = Some(ProviderRef::new("default-hsm"));
        assert_eq!(
            record.effective_provider_ref(1),
            Some(&ProviderRef::new("default-hsm"))
        );

        // Version-level binding overrides the key default (migration case).
        if let KeyMaterial::ProviderResident { provider_ref, .. } =
            &mut record.key_versions[0].material
        {
            *provider_ref = Some(ProviderRef::new("tenant-hsm"));
        }
        assert_eq!(
            record.effective_provider_ref(1),
            Some(&ProviderRef::new("tenant-hsm"))
        );

        // Unknown version falls back to the key default.
        assert_eq!(
            record.effective_provider_ref(999),
            Some(&ProviderRef::new("default-hsm"))
        );
    }

    pub(crate) fn make_test_record(state: KeyState) -> KeyRecord {
        use crate::attr::{AttributeSet, AttributeValue};
        use crate::canon::{canonicalize, CanonicalizationVersion};

        let mut attrs = AttributeSet::new();
        attrs.insert("tenant", AttributeValue::String("test".into()));
        let form = canonicalize(CanonicalizationVersion::V2, &attrs).unwrap();
        let lid = Lid::derive(CanonicalizationVersion::V2, &form);

        KeyRecord {
            lid,
            canonicalization_version: CanonicalizationVersion::V2,
            parent_lid: None,
            occ_version: 1,
            current_key_version: 1,
            state,
            was_compromised: false,
            key_usage: KeyUsage::EncryptDecrypt,
            key_spec: KeySpec::Aes256,
            origin: KeyOrigin::KeyRack,
            provider_class: ProviderClass::Software,
            provider_ref: None,
            exportability: Exportability::default(),
            first_exported_at: None,
            owner_principal_id: None,
            identity_tags: IdentityTags::from_attribute_set(&attrs).unwrap(),
            user_tags: UserTags::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scheduled_deletion_at: None,
            description: String::new(),
            key_versions: vec![KeyVersionRecord::provider_resident(
                1,
                KeyHandle {
                    key_id: "test-handle".into(),
                    key_spec: KeySpec::Aes256,
                },
                None,
                Utc::now(),
                true,
            )],
        }
    }

    /// Load-bearing invariant (provider-routing.md line 42, key.rs ~258-261):
    /// `provider_ref` is a create-time, per-version backend binding that MUST
    /// NOT feed LID derivation. Logical key identity stays independent of
    /// the physical backend — this is what lets a key migrate HSMs without
    /// its identity (and header-pinned ciphertext references) changing.
    #[test]
    fn lid_derivation_ignores_provider_ref() {
        use crate::attr::{AttributeSet, AttributeValue};
        use crate::canon::{canonicalize, CanonicalizationVersion};

        let mut attrs = AttributeSet::new();
        attrs.insert("tenant", AttributeValue::String("acme".into()));
        attrs.insert("namespace", AttributeValue::String("prod".into()));
        attrs.insert(
            "_keyrack_key_id",
            AttributeValue::String("deterministic-id-for-test".into()),
        );

        let canonical = canonicalize(CanonicalizationVersion::V2, &attrs).unwrap();
        let lid = Lid::derive(CanonicalizationVersion::V2, &canonical);

        // Deterministic: same attributes → same LID.
        let lid2 = Lid::derive(
            CanonicalizationVersion::V2,
            &canonicalize(CanonicalizationVersion::V2, &attrs).unwrap(),
        );
        assert_eq!(lid, lid2, "LID derivation must be deterministic");

        // Two KeyRecords with the SAME identity attributes but DIFFERENT
        // provider_ref values get identical LIDs (provider_ref is a side
        // property, not part of identity_tags or the canonical form).
        let identity_tags = IdentityTags::from_attribute_set(&attrs).unwrap();

        let record_software = KeyRecord {
            lid,
            canonicalization_version: CanonicalizationVersion::V2,
            parent_lid: None,
            occ_version: 1,
            current_key_version: 1,
            state: KeyState::Enabled,
            was_compromised: false,
            key_usage: KeyUsage::EncryptDecrypt,
            key_spec: KeySpec::Aes256,
            origin: KeyOrigin::KeyRack,
            provider_class: ProviderClass::Software,
            provider_ref: Some(ProviderRef::new("software-default")),
            exportability: Exportability::default(),
            first_exported_at: None,
            owner_principal_id: None,
            identity_tags: identity_tags.clone(),
            user_tags: UserTags::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scheduled_deletion_at: None,
            description: String::new(),
            key_versions: vec![KeyVersionRecord::provider_resident(
                1,
                KeyHandle {
                    key_id: "handle-a".into(),
                    key_spec: KeySpec::Aes256,
                },
                Some(ProviderRef::new("software-default")),
                Utc::now(),
                true,
            )],
        };

        let record_hsm = KeyRecord {
            lid,
            provider_class: ProviderClass::Pkcs11,
            provider_ref: Some(ProviderRef::new("hsm-tenant-a")),
            key_versions: vec![KeyVersionRecord::provider_resident(
                1,
                KeyHandle {
                    key_id: "handle-b".into(),
                    key_spec: KeySpec::Aes256,
                },
                Some(ProviderRef::new("hsm-tenant-a")),
                Utc::now(),
                true,
            )],
            ..record_software.clone()
        };

        assert_eq!(
            record_software.lid, record_hsm.lid,
            "LID must be identical for keys with same identity but different provider_ref — \
             the physical backend binding must never affect logical key identity"
        );

        // Positive control: if provider_ref WERE (incorrectly) included in the
        // attribute set, the LID WOULD change, proving the exclusion matters.
        let mut attrs_contaminated = attrs.clone();
        attrs_contaminated.insert(
            "provider_ref",
            AttributeValue::String("hsm-tenant-a".into()),
        );
        let contaminated_canonical =
            canonicalize(CanonicalizationVersion::V2, &attrs_contaminated).unwrap();
        let lid_contaminated = Lid::derive(CanonicalizationVersion::V2, &contaminated_canonical);
        assert_ne!(
            lid, lid_contaminated,
            "Including provider_ref in the attribute set WOULD change the LID — \
             this proves its exclusion from the canonical form is load-bearing"
        );
    }

    #[test]
    fn exportability_defaults_to_non_exportable_for_legacy_records() {
        let mut record = make_test_record(KeyState::Enabled);
        record.exportability = Exportability::NonExportable;
        let json = serde_json::to_string(&record).unwrap();

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("exportability");
        obj.remove("first_exported_at");
        let legacy = serde_json::to_string(&value).unwrap();

        let parsed: KeyRecord = serde_json::from_str(&legacy).unwrap();
        assert_eq!(parsed.exportability, Exportability::NonExportable);
        assert_eq!(parsed.first_exported_at, None);
    }

    #[test]
    fn lid_derivation_ignores_exportability() {
        use crate::attr::{AttributeSet, AttributeValue};
        use crate::canon::{canonicalize, CanonicalizationVersion};

        let mut attrs = AttributeSet::new();
        attrs.insert("tenant", AttributeValue::String("acme".into()));
        attrs.insert(
            "_keyrack_key_id",
            AttributeValue::String("export-lid-test".into()),
        );

        let canonical = canonicalize(CanonicalizationVersion::V2, &attrs).unwrap();
        let lid = Lid::derive(CanonicalizationVersion::V2, &canonical);
        let identity_tags = IdentityTags::from_attribute_set(&attrs).unwrap();

        let record_non_exportable = KeyRecord {
            lid,
            canonicalization_version: CanonicalizationVersion::V2,
            parent_lid: None,
            occ_version: 1,
            current_key_version: 1,
            state: KeyState::Enabled,
            was_compromised: false,
            key_usage: KeyUsage::EncryptDecrypt,
            key_spec: KeySpec::Aes256,
            origin: KeyOrigin::KeyRack,
            provider_class: ProviderClass::Software,
            provider_ref: None,
            exportability: Exportability::NonExportable,
            first_exported_at: None,
            owner_principal_id: None,
            identity_tags: identity_tags.clone(),
            user_tags: UserTags::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scheduled_deletion_at: None,
            description: String::new(),
            key_versions: vec![KeyVersionRecord::provider_resident(
                1,
                KeyHandle {
                    key_id: "handle-1".into(),
                    key_spec: KeySpec::Aes256,
                },
                None,
                Utc::now(),
                true,
            )],
        };

        let record_exportable = KeyRecord {
            exportability: Exportability::Exportable,
            first_exported_at: Some(Utc::now()),
            ..record_non_exportable.clone()
        };

        assert_eq!(
            record_non_exportable.lid, record_exportable.lid,
            "LID must be identical regardless of exportability — \
             exportability is a side property, not part of identity"
        );
    }

    #[test]
    fn transition_exportability_loosen() {
        let mut record = make_test_record(KeyState::Enabled);
        let v = record.occ_version;
        assert_eq!(record.exportability, Exportability::NonExportable);

        let result = record.transition_exportability(Exportability::Exportable);
        assert!(result.is_ok());
        assert_eq!(record.exportability, Exportability::Exportable);
        assert_eq!(record.occ_version, v + 1);
    }

    #[test]
    fn transition_exportability_tighten_pre_export() {
        let mut record = make_test_record(KeyState::Enabled);
        record.exportability = Exportability::Exportable;
        record.first_exported_at = None;

        let result = record.transition_exportability(Exportability::NonExportable);
        assert!(result.is_ok());
        assert_eq!(record.exportability, Exportability::NonExportable);
    }

    #[test]
    fn transition_exportability_tighten_post_export_refused() {
        let mut record = make_test_record(KeyState::Enabled);
        record.exportability = Exportability::Exportable;
        record.first_exported_at = Some(Utc::now());

        let result = record.transition_exportability(Exportability::NonExportable);
        assert!(result.is_err());
        assert_eq!(record.exportability, Exportability::Exportable);
    }

    #[test]
    fn mark_exported_sets_latch_once() {
        let mut record = make_test_record(KeyState::Enabled);
        record.exportability = Exportability::Exportable;
        assert!(record.first_exported_at.is_none());

        let v = record.occ_version;
        record.mark_exported();
        assert!(record.first_exported_at.is_some());
        assert_eq!(record.occ_version, v + 1);

        let ts = record.first_exported_at;
        let v2 = record.occ_version;
        record.mark_exported();
        assert_eq!(record.first_exported_at, ts);
        assert_eq!(record.occ_version, v2);
    }
}
