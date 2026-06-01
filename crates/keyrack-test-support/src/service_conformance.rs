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

//! Service-level conformance test suite.
//!
//! Black-box tests against the gRPC `KeyService` trait. Any
//! implementation (the core service, AWS KMS shim, Barbican shim)
//! must pass these tests.
//!
//! Usage:
//! ```ignore
//! keyrack_test_support::service_conformance_tests!(build_test_service());
//! ```

/// Generate the service conformance test suite.
///
/// The argument is an expression that produces an `Arc<impl KeyService>`.
/// All tests exercise the service through the `KeyService` trait.
#[macro_export]
macro_rules! service_conformance_tests {
    ($svc_expr:expr) => {
        use keyrack_service::proto::key_service_server::KeyService;
        use keyrack_service::proto::*;
        use tonic::Request;

        #[tokio::test]
        async fn conformance_create_and_get_key() {
            let svc = $svc_expr;
            let resp = svc
                .create_key(Request::new(CreateKeyRequest {
                    key_spec: KeySpec::Aes256.into(),
                    key_usage: KeyUsage::EncryptDecrypt.into(),
                    description: "conformance test".into(),
                    ..Default::default()
                }))
                .await
                .expect("CreateKey should succeed");

            let meta = resp.into_inner().metadata.expect("metadata present");
            assert!(!meta.key_id.is_empty());
            assert_eq!(meta.state, KeyState::Enabled as i32);

            let get_resp = svc
                .get_key(Request::new(GetKeyRequest {
                    key_id: meta.key_id.clone(),
                }))
                .await
                .expect("GetKey should succeed");

            let get_meta = get_resp.into_inner().metadata.expect("metadata present");
            assert_eq!(get_meta.key_id, meta.key_id);
        }

        #[tokio::test]
        async fn conformance_create_keys_unique_ids() {
            let svc = $svc_expr;
            let mut ids = std::collections::HashSet::new();
            for _ in 0..5 {
                let resp = svc
                    .create_key(Request::new(CreateKeyRequest {
                        key_spec: KeySpec::Aes256.into(),
                        key_usage: KeyUsage::EncryptDecrypt.into(),
                        description: "unique test".into(),
                        ..Default::default()
                    }))
                    .await
                    .expect("CreateKey should succeed");
                let key_id = resp.into_inner().metadata.expect("meta").key_id;
                assert!(ids.insert(key_id), "duplicate key ID");
            }
            assert_eq!(ids.len(), 5);
        }

        #[tokio::test]
        async fn conformance_describe_key() {
            let svc = $svc_expr;
            let resp = svc
                .create_key(Request::new(CreateKeyRequest {
                    key_spec: KeySpec::Aes256.into(),
                    key_usage: KeyUsage::EncryptDecrypt.into(),
                    description: "describe test".into(),
                    ..Default::default()
                }))
                .await
                .unwrap();
            let key_id = resp.into_inner().metadata.unwrap().key_id;

            let desc = svc
                .describe_key(Request::new(DescribeKeyRequest {
                    key_id: key_id.clone(),
                }))
                .await
                .expect("DescribeKey should succeed");
            let meta = desc.into_inner().metadata.unwrap();
            assert_eq!(meta.key_id, key_id);
            assert_eq!(meta.description, "describe test");
        }

        #[tokio::test]
        async fn conformance_enable_disable_key() {
            let svc = $svc_expr;
            let resp = svc
                .create_key(Request::new(CreateKeyRequest {
                    key_spec: KeySpec::Aes256.into(),
                    key_usage: KeyUsage::EncryptDecrypt.into(),
                    ..Default::default()
                }))
                .await
                .unwrap();
            let key_id = resp.into_inner().metadata.unwrap().key_id;

            let disable = svc
                .disable_key(Request::new(DisableKeyRequest {
                    key_id: key_id.clone(),
                }))
                .await
                .expect("DisableKey should succeed");
            assert_eq!(
                disable.into_inner().metadata.unwrap().state,
                KeyState::Disabled as i32,
            );

            let enable = svc
                .enable_key(Request::new(EnableKeyRequest {
                    key_id: key_id.clone(),
                }))
                .await
                .expect("EnableKey should succeed");
            assert_eq!(
                enable.into_inner().metadata.unwrap().state,
                KeyState::Enabled as i32,
            );
        }

        #[tokio::test]
        async fn conformance_encrypt_decrypt_round_trip() {
            let svc = $svc_expr;
            let resp = svc
                .create_key(Request::new(CreateKeyRequest {
                    key_spec: KeySpec::Aes256.into(),
                    key_usage: KeyUsage::EncryptDecrypt.into(),
                    ..Default::default()
                }))
                .await
                .unwrap();
            let key_id = resp.into_inner().metadata.unwrap().key_id;

            let plaintext = b"conformance test plaintext".to_vec();
            let enc_resp = svc
                .encrypt(Request::new(EncryptRequest {
                    key_id: key_id.clone(),
                    plaintext: plaintext.clone(),
                    encryption_context: Default::default(),
                }))
                .await
                .expect("Encrypt should succeed");
            let ct = enc_resp.into_inner().ciphertext_blob;
            assert_ne!(ct, plaintext);

            let dec_resp = svc
                .decrypt(Request::new(DecryptRequest {
                    key_id: key_id.clone(),
                    ciphertext_blob: ct,
                    encryption_context: Default::default(),
                }))
                .await
                .expect("Decrypt should succeed");
            assert_eq!(dec_resp.into_inner().plaintext, plaintext);
        }

        #[tokio::test]
        async fn conformance_sign_verify() {
            let svc = $svc_expr;
            let resp = svc
                .create_key(Request::new(CreateKeyRequest {
                    key_spec: KeySpec::Ed25519.into(),
                    key_usage: KeyUsage::SignVerify.into(),
                    ..Default::default()
                }))
                .await
                .unwrap();
            let key_id = resp.into_inner().metadata.unwrap().key_id;

            let message = b"conformance signature test".to_vec();
            let sign_resp = svc
                .sign(Request::new(SignRequest {
                    key_id: key_id.clone(),
                    message: message.clone(),
                    signing_algorithm: SigningAlgorithm::Ed25519Pure.into(),
                }))
                .await
                .expect("Sign should succeed");
            let signature = sign_resp.into_inner().signature;
            assert!(!signature.is_empty());

            let verify_resp = svc
                .verify(Request::new(VerifyRequest {
                    key_id: key_id.clone(),
                    message: message.clone(),
                    signature: signature.clone(),
                    signing_algorithm: SigningAlgorithm::Ed25519Pure.into(),
                }))
                .await
                .expect("Verify should succeed");
            assert!(verify_resp.into_inner().signature_valid);

            let bad_verify = svc
                .verify(Request::new(VerifyRequest {
                    key_id,
                    message: b"wrong message".to_vec(),
                    signature,
                    signing_algorithm: SigningAlgorithm::Ed25519Pure.into(),
                }))
                .await
                .expect("Verify with wrong message should succeed (returns false)");
            assert!(!bad_verify.into_inner().signature_valid);
        }

        #[tokio::test]
        async fn conformance_rotate_key() {
            let svc = $svc_expr;
            let resp = svc
                .create_key(Request::new(CreateKeyRequest {
                    key_spec: KeySpec::Aes256.into(),
                    key_usage: KeyUsage::EncryptDecrypt.into(),
                    ..Default::default()
                }))
                .await
                .unwrap();
            let key_id = resp.into_inner().metadata.unwrap().key_id;

            let rotate_resp = svc
                .rotate_key(Request::new(RotateKeyRequest {
                    key_id: key_id.clone(),
                }))
                .await
                .expect("RotateKey should succeed");
            assert!(rotate_resp.into_inner().new_version >= 2);
        }

        #[tokio::test]
        async fn conformance_generate_random() {
            let svc = $svc_expr;
            let resp = svc
                .generate_random(Request::new(GenerateRandomRequest {
                    number_of_bytes: 32,
                }))
                .await
                .expect("GenerateRandom should succeed");
            let bytes = resp.into_inner().random_bytes;
            assert_eq!(bytes.len(), 32);
        }

        #[tokio::test]
        async fn conformance_alias_lifecycle() {
            let svc = $svc_expr;
            let resp = svc
                .create_key(Request::new(CreateKeyRequest {
                    key_spec: KeySpec::Aes256.into(),
                    key_usage: KeyUsage::EncryptDecrypt.into(),
                    ..Default::default()
                }))
                .await
                .unwrap();
            let key_id = resp.into_inner().metadata.unwrap().key_id;

            let alias_name = format!("alias/conformance-{}", uuid::Uuid::new_v4());
            svc.create_alias(Request::new(CreateAliasRequest {
                alias_name: alias_name.clone(),
                target_key_id: key_id.clone(),
            }))
            .await
            .expect("CreateAlias should succeed");

            svc.delete_alias(Request::new(DeleteAliasRequest {
                alias_name: alias_name.clone(),
            }))
            .await
            .expect("DeleteAlias should succeed");
        }

        #[tokio::test]
        async fn conformance_get_nonexistent_key_fails() {
            let svc = $svc_expr;
            let result = svc
                .get_key(Request::new(GetKeyRequest {
                    key_id: "lid:0000000000000000000000000000000000000000000000000000000000000000".into(),
                }))
                .await;
            assert!(result.is_err(), "GetKey for nonexistent key should fail");
        }
    };
}
