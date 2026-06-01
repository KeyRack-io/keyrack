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

//! Conformance test harness macros.
//!
//! Any `CryptoProvider` implementation must pass the provider
//! conformance suite. Any `StorageBackend` implementation must pass
//! the storage conformance suite.
//!
//! Usage in a backend crate's `tests/`:
//!
//! ```ignore
//! use keyrack_test_support::conformance::*;
//!
//! // Instantiate the provider conformance suite.
//! provider_conformance_tests!(MyProvider::new());
//!
//! // Instantiate the storage conformance suite.
//! storage_conformance_tests!(MyStorage::new().await);
//! ```

/// Generate the provider conformance test suite for a `CryptoProvider`
/// implementation.
///
/// The argument is an expression that produces a `Box<dyn CryptoProvider>`.
#[macro_export]
macro_rules! provider_conformance_tests {
    ($provider_expr:expr) => {
        #[tokio::test]
        async fn conformance_aes256_round_trip() {
            use keyrack_core::key::KeySpec;
            use keyrack_core::provider::CryptoProvider;

            let provider = $provider_expr;
            let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

            let plaintext = b"conformance test plaintext data!";
            let aad = b"conformance-aad";

            let ct = provider.encrypt(&handle, plaintext, aad).await.unwrap();
            assert_ne!(ct.ciphertext.as_slice(), plaintext);

            let pt = provider.decrypt(&handle, &ct.ciphertext, aad).await.unwrap();
            assert_eq!(pt.expose().as_slice(), plaintext);
        }

        #[tokio::test]
        async fn conformance_aad_mismatch_fails() {
            use keyrack_core::key::KeySpec;
            use keyrack_core::provider::CryptoProvider;

            let provider = $provider_expr;
            let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

            let ct = provider
                .encrypt(&handle, b"test", b"aad-correct")
                .await
                .unwrap();

            let result = provider.decrypt(&handle, &ct.ciphertext, b"aad-wrong").await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn conformance_ed25519_sign_verify() {
            use keyrack_core::key::KeySpec;
            use keyrack_core::provider::{CryptoProvider, SigningAlgorithm};

            let provider = $provider_expr;
            let handle = provider.generate_key(&KeySpec::Ed25519).await.unwrap();

            let message = b"conformance sign/verify test";
            let sig = provider
                .sign(&handle, SigningAlgorithm::Ed25519, message)
                .await
                .unwrap();

            let valid = provider
                .verify(&handle, SigningAlgorithm::Ed25519, message, &sig)
                .await
                .unwrap();
            assert!(valid);

            let tampered = provider
                .verify(&handle, SigningAlgorithm::Ed25519, b"tampered", &sig)
                .await
                .unwrap();
            assert!(!tampered);
        }

        #[tokio::test]
        async fn conformance_generate_random() {
            use keyrack_core::provider::CryptoProvider;

            let provider = $provider_expr;
            let r1 = provider.generate_random(32).await.unwrap();
            let r2 = provider.generate_random(32).await.unwrap();

            assert_eq!(r1.expose().len(), 32);
            assert_ne!(r1.expose(), r2.expose());
        }

        #[tokio::test]
        async fn conformance_destroy_key() {
            use keyrack_core::key::KeySpec;
            use keyrack_core::provider::CryptoProvider;

            let provider = $provider_expr;
            let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

            provider.destroy_key(&handle).await.unwrap();

            let result = provider.encrypt(&handle, b"test", b"").await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn conformance_generate_data_key() {
            use keyrack_core::key::KeySpec;
            use keyrack_core::provider::CryptoProvider;

            let provider = $provider_expr;
            let cmk = provider.generate_key(&KeySpec::Aes256).await.unwrap();

            let dek_output = provider
                .generate_data_key(&cmk, 32, b"dek-aad")
                .await
                .unwrap();

            assert_eq!(dek_output.plaintext_key.expose().len(), 32);
            assert!(!dek_output.encrypted_key.is_empty());

            let decrypted = provider
                .decrypt(&cmk, &dek_output.encrypted_key, b"dek-aad")
                .await
                .unwrap();
            assert_eq!(decrypted.expose(), dek_output.plaintext_key.expose());
        }

        #[tokio::test]
        async fn conformance_re_encrypt() {
            use keyrack_core::key::KeySpec;
            use keyrack_core::provider::CryptoProvider;

            let provider = $provider_expr;
            let key_a = provider.generate_key(&KeySpec::Aes256).await.unwrap();
            let key_b = provider.generate_key(&KeySpec::Aes256).await.unwrap();

            let plaintext = b"re-encrypt conformance test";
            let ct_a = provider
                .encrypt(&key_a, plaintext, b"aad-a")
                .await
                .unwrap();

            let ct_b = provider
                .re_encrypt(&key_a, &ct_a.ciphertext, b"aad-a", &key_b, b"aad-b")
                .await
                .unwrap();

            let pt = provider
                .decrypt(&key_b, &ct_b.ciphertext, b"aad-b")
                .await
                .unwrap();
            assert_eq!(pt.expose().as_slice(), plaintext);
        }
    };
}

/// Generate the storage conformance test suite for a `StorageBackend`
/// implementation.
///
/// The argument is an expression that produces a `Box<dyn StorageBackend>`.
#[macro_export]
macro_rules! storage_conformance_tests {
    ($storage_expr:expr) => {
        #[tokio::test]
        async fn conformance_key_crud() {
            use keyrack_core::key::KeyState;
            use keyrack_core::storage::{KeyFilter, StorageBackend};
            use keyrack_test_support::fixtures::test_key_record;

            let store = $storage_expr;
            let record = test_key_record(KeyState::Creating);

            store.create_key(&record).await.unwrap();
            let fetched = store.get_key(&record.lid).await.unwrap();
            assert_eq!(fetched.state, KeyState::Creating);

            let mut updated = fetched;
            updated.state = KeyState::Enabled;
            updated.occ_version += 1;
            store.update_key(&updated).await.unwrap();

            let list = store.list_keys(&KeyFilter::default()).await.unwrap();
            assert!(!list.items.is_empty());
        }

        #[tokio::test]
        async fn conformance_occ_conflict() {
            use keyrack_core::error::KeyRackError;
            use keyrack_core::key::KeyState;
            use keyrack_core::storage::StorageBackend;
            use keyrack_test_support::fixtures::test_key_record;

            let store = $storage_expr;
            let record = test_key_record(KeyState::Enabled);
            store.create_key(&record).await.unwrap();

            let v1 = store.get_key(&record.lid).await.unwrap();
            let mut update_a = v1.clone();
            update_a.occ_version += 1;
            store.update_key(&update_a).await.unwrap();

            let mut update_b = v1;
            update_b.occ_version += 1;
            let err = store.update_key(&update_b).await;
            assert!(matches!(
                err,
                Err(KeyRackError::OptimisticConcurrencyConflict { .. })
            ));
        }

        #[tokio::test]
        async fn conformance_alias_round_trip() {
            use keyrack_core::key::KeyState;
            use keyrack_core::storage::{AliasRecord, StorageBackend};
            use keyrack_test_support::fixtures::test_key_record;

            let store = $storage_expr;
            let record = test_key_record(KeyState::Enabled);
            store.create_key(&record).await.unwrap();

            let alias = AliasRecord {
                alias_name: "alias/conformance/test".into(),
                target_lid: record.lid,
                created_at: chrono::Utc::now(),
            };
            store.create_alias(&alias).await.unwrap();

            let lid = store.resolve_alias("alias/conformance/test").await.unwrap();
            assert_eq!(lid, alias.target_lid);

            store.delete_alias("alias/conformance/test").await.unwrap();
            assert!(store.resolve_alias("alias/conformance/test").await.is_err());
        }

        #[tokio::test]
        async fn conformance_ping() {
            use keyrack_core::storage::StorageBackend;

            let store = $storage_expr;
            store.ping().await.unwrap();
        }
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn macros_compile() {
        // Macros are tested by downstream crates that provide
        // concrete implementations. This test just ensures the
        // conformance module itself compiles.
    }
}
