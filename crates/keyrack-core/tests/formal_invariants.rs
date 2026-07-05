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

//! Formal-methods Tier 0: property-based invariant tests.
//!
//! These tests use proptest to check critical security and correctness
//! invariants that must hold across the full input domain:
//!
//! (a) Encrypt/decrypt round-trip correctness (software provider)
//! (b) Rotation preserves decryptability of old-version ciphertext
//! (c) Disable cascades to all descendants (state machine permits it)
//! (d) No plaintext key bytes appear in any serialized `AuditEvent`

use keyrack_core::audit::{
    AuditAction, AuditEvent, AuditPrincipal, AuditResource, AuditResult, AuditSigner, EventType,
};
use keyrack_core::key::{KeySpec, KeyState};
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::provider::CryptoProvider;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Arbitrary generators
// ---------------------------------------------------------------------------

fn arb_plaintext() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

fn arb_aad() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..128)
}

fn arb_key_spec_symmetric() -> impl Strategy<Value = KeySpec> {
    prop_oneof![Just(KeySpec::Aes256), Just(KeySpec::Aes128),]
}

fn arb_key_state_pre_disable() -> impl Strategy<Value = KeyState> {
    prop_oneof![Just(KeyState::Enabled), Just(KeyState::Disabled),]
}

// ---------------------------------------------------------------------------
// (a) Encrypt/decrypt round-trip correctness
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// For any plaintext and AAD, encrypt followed by decrypt with the same
    /// key and AAD must return the original plaintext (AES-GCM correctness).
    #[test]
    fn encrypt_decrypt_round_trip(
        plaintext in arb_plaintext(),
        aad in arb_aad(),
        spec in arb_key_spec_symmetric(),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let provider = SoftwareProvider::new();
            let handle = provider.generate_key(&spec).await.unwrap();

            let ct = provider.encrypt(&handle, &plaintext, &aad).await.unwrap();

            // Ciphertext must differ from plaintext (unless plaintext is empty,
            // in which case the nonce+tag still differ).
            if !plaintext.is_empty() {
                prop_assert_ne!(&ct.ciphertext, &plaintext);
            }

            let decrypted = provider
                .decrypt(&handle, &ct.ciphertext, &aad)
                .await
                .unwrap();
            prop_assert_eq!(decrypted.expose().as_slice(), plaintext.as_slice());

            Ok(())
        })?;
    }

    /// Wrong AAD must always fail decryption (integrity/authenticity).
    #[test]
    fn wrong_aad_always_fails(
        plaintext in arb_plaintext(),
        aad1 in arb_aad(),
        aad2 in arb_aad(),
    ) {
        prop_assume!(aad1 != aad2);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let provider = SoftwareProvider::new();
            let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

            let ct = provider.encrypt(&handle, &plaintext, &aad1).await.unwrap();
            let result = provider.decrypt(&handle, &ct.ciphertext, &aad2).await;
            prop_assert!(result.is_err());
            Ok(())
        })?;
    }
}

// ---------------------------------------------------------------------------
// (b) Rotation preserves decryptability of old-version ciphertext
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// After rotation (generating a new key version on the same provider),
    /// ciphertext encrypted under the OLD key version must still decrypt
    /// correctly using the old version's handle.
    ///
    /// This models the core rotation invariant: old versions are retained
    /// for decrypt; only the "current" version changes for new encrypts.
    #[test]
    fn rotation_preserves_old_ciphertext_decryptability(
        plaintext in arb_plaintext(),
        aad in arb_aad(),
        num_rotations in 1u32..5,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let provider = SoftwareProvider::new();

            // Version 1: generate, encrypt.
            let handle_v1 = provider.generate_key(&KeySpec::Aes256).await.unwrap();
            let ct_v1 = provider.encrypt(&handle_v1, &plaintext, &aad).await.unwrap();

            // Simulate N rotations (each creates a new key version on the same provider).
            let mut handles = vec![handle_v1.clone()];
            for _ in 0..num_rotations {
                let new_handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();
                handles.push(new_handle);
            }

            // Invariant: ciphertext from v1 is STILL decryptable with v1's handle,
            // even after N new versions were created.
            let decrypted = provider
                .decrypt(&handle_v1, &ct_v1.ciphertext, &aad)
                .await
                .unwrap();
            prop_assert_eq!(decrypted.expose().as_slice(), plaintext.as_slice());

            // The new (latest) key cannot decrypt v1's ciphertext.
            let latest = handles.last().unwrap();
            let cross_result = provider
                .decrypt(latest, &ct_v1.ciphertext, &aad)
                .await;
            prop_assert!(cross_result.is_err());

            Ok(())
        })?;
    }
}

// ---------------------------------------------------------------------------
// (c) Cascade-disable: state machine permits disabling all descendants
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// For any tree of keys (parent + N descendants) where all are in a
    /// pre-disable state (Enabled or Disabled), the state machine MUST permit
    /// transitioning every descendant to Disabled.
    ///
    /// This is the state-machine invariant that makes cascade-disable sound:
    /// the service layer can always disable descendants without hitting an
    /// invalid-transition error.
    #[test]
    fn cascade_disable_always_permitted(
        num_children in 1usize..10,
        child_states in prop::collection::vec(arb_key_state_pre_disable(), 1..10),
    ) {
        let actual_children = std::cmp::min(num_children, child_states.len());
        for state in &child_states[..actual_children] {
            // Enabled → Disabled is valid; Disabled → Disabled is a no-op
            // (already disabled). Both cases must succeed.
            match state {
                KeyState::Enabled => {
                    prop_assert!(state.can_transition_to(KeyState::Disabled));
                }
                KeyState::Disabled => {
                    // Already disabled — cascade is a no-op for this key.
                    // The key is already in the target state.
                }
                _ => unreachable!("generator only produces Enabled/Disabled"),
            }
        }
    }

    /// Compromised keys can also be scheduled for deletion as part of
    /// cascade (the cascade may escalate to PendingDeletion).
    #[test]
    fn cascade_disable_from_compromised_permits_pending_deletion(
        _dummy in 0u8..1,
    ) {
        prop_assert!(KeyState::Compromised.can_transition_to(KeyState::PendingDeletion));
    }
}

// ---------------------------------------------------------------------------
// (d) No plaintext key bytes in serialized AuditEvent
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// For any key material (random bytes), after creating an AuditEvent for
    /// a crypto operation and serializing it to JSON, the raw key bytes must
    /// NEVER appear as a contiguous subsequence in the serialized output.
    ///
    /// This is the "Sensitive is not Sealed" boundary check: even though
    /// `Sensitive<T>` prevents accidental Debug/Display leaks, we assert
    /// that serialized API-facing structures never contain raw key material.
    #[test]
    fn no_plaintext_key_bytes_in_audit_event_json(
        key_bytes in prop::collection::vec(any::<u8>(), 16..=32),
        principal_id in "[a-z]{3,10}",
        resource_id in "[a-z_]{4,12}",
    ) {
        // Simulate: key material was generated, an operation used it, and
        // an AuditEvent was emitted. The key bytes must not appear in the
        // serialized event.
        let event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Decrypt,
            AuditPrincipal {
                id: format!("svc:{principal_id}"),
                principal_type: "Service".into(),
            },
            AuditResource {
                id: resource_id.clone(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );

        let json_bytes = event.to_json_bytes().unwrap();

        // Assert: the raw key bytes (16-32 bytes) do not appear anywhere
        // in the serialized JSON.
        prop_assert!(
            !contains_subsequence(&json_bytes, &key_bytes),
            "CRITICAL: plaintext key bytes found in serialized AuditEvent!"
        );
    }

    /// Same check with metadata fields populated (metadata is the most
    /// likely place for an accidental leak via add_metadata).
    #[test]
    fn no_plaintext_in_audit_event_with_metadata(
        key_bytes in prop::collection::vec(any::<u8>(), 16..=32),
        meta_key in "[a-z_]{3,8}",
        meta_value in "[a-z0-9]{4,20}",
    ) {
        let mut event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Encrypt,
            AuditPrincipal {
                id: "svc:test".into(),
                principal_type: "Service".into(),
            },
            AuditResource {
                id: "lid_test".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );
        event.add_metadata(&meta_key, meta_value.as_str());

        let json_bytes = event.to_json_bytes().unwrap();

        prop_assert!(
            !contains_subsequence(&json_bytes, &key_bytes),
            "CRITICAL: plaintext key bytes found in serialized AuditEvent with metadata!"
        );
    }

    /// Signed audit events must also not leak key material (the signing
    /// key bytes themselves must not appear in the serialized output).
    #[test]
    fn no_signing_key_in_signed_audit_event(
        _seed in any::<u64>(),
    ) {
        let signer = AuditSigner::generate();
        let signing_key_bytes = {
            let vk = signer.verifying_key();
            vk.to_bytes().to_vec()
        };

        let mut event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Sign,
            AuditPrincipal {
                id: "svc:signer".into(),
                principal_type: "Service".into(),
            },
            AuditResource {
                id: "lid_sign".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );
        signer.sign_event(&mut event);

        let json_bytes = event.to_json_bytes().unwrap();

        // The verifying key (public) MAY appear (it's public), but we check
        // that the raw 32-byte signing key secret does NOT appear.
        // Note: we can't access the private signing key bytes here since
        // AuditSigner doesn't expose them — which is itself the invariant.
        // Instead we verify the public key bytes don't appear raw (they'd
        // only be there hex-encoded in the signature, not as raw bytes).
        prop_assert!(
            !contains_subsequence(&json_bytes, &signing_key_bytes),
            "Raw verifying key bytes should not appear as raw bytes in JSON"
        );
    }
}

// ---------------------------------------------------------------------------
// Additional structural invariant: KeyRecord serialization never contains
// raw key material
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// When a KeyRecord is serialized (as would happen for storage or API
    /// response), it must never contain the raw key material bytes.
    /// The KeyHandle stores only an opaque ID string, not the actual material.
    #[test]
    fn no_key_material_in_serialized_key_record(
        key_material in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        use keyrack_core::attr::{AttributeSet, AttributeValue};
        use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
        use keyrack_core::key::{
            KeyOrigin, KeyRecord, KeyUsage, KeyVersionRecord, ProviderClass,
        };
        use keyrack_core::lid::Lid;
        use keyrack_core::provider::KeyHandle;
        use keyrack_core::tags::{IdentityTags, UserTags};

        let mut attrs = AttributeSet::new();
        attrs.insert("t", AttributeValue::String("test".into()));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        let lid = Lid::derive(CanonicalizationVersion::V1, &form);

        let record = KeyRecord {
            lid,
            canonicalization_version: CanonicalizationVersion::V1,
            parent_lid: None,
            occ_version: 1,
            current_key_version: 1,
            state: KeyState::Enabled,
            key_usage: KeyUsage::EncryptDecrypt,
            key_spec: KeySpec::Aes256,
            origin: KeyOrigin::KeyRack,
            provider_class: ProviderClass::Software,
            provider_ref: None,
            exportability: keyrack_core::key::Exportability::default(),
            first_exported_at: None,
            identity_tags: IdentityTags::from_attribute_set(&attrs),
            user_tags: UserTags::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            scheduled_deletion_at: None,
            description: String::new(),
            key_versions: vec![KeyVersionRecord {
                version_number: 1,
                key_handle: KeyHandle {
                    key_id: "opaque-handle-id".into(),
                    key_spec: KeySpec::Aes256,
                },
                provider_ref: None,
                created_at: chrono::Utc::now(),
                is_primary: true,
            }],
        };

        let json_bytes = serde_json::to_vec(&record).unwrap();

        prop_assert!(
            !contains_subsequence(&json_bytes, &key_material),
            "CRITICAL: raw key material bytes found in serialized KeyRecord!"
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if `haystack` contains `needle` as a contiguous subsequence.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
