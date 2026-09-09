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

//! KMIP message construction and response parsing.

use crate::ttlv::{
    block_cipher_mode, byte_string, crypto_algorithm, enumeration, integer, object_type, operation,
    revocation_reason, structure, tag, text_string, TtlvItem, TtlvType, TtlvValue,
};

/// Protocol version announced in every request header.
///
/// 1.4, because that is the version this module actually encodes: `Create`
/// carries a `TemplateAttribute` holding named `Attribute` structures, which
/// KMIP 2.0 removed in favour of typed `Attributes`. Announcing 2.1 while
/// sending 1.x payloads — as this client previously did — is rejected by
/// servers at either version: a 1.x server refuses the major version outright,
/// and a 2.x server cannot parse the body.
const KMIP_VERSION_MAJOR: i32 = 1;
const KMIP_VERSION_MINOR: i32 = 4;

fn request_header() -> TtlvItem {
    structure(
        tag::REQUEST_HEADER,
        vec![
            structure(
                tag::PROTOCOL_VERSION,
                vec![
                    integer(tag::PROTOCOL_VERSION_MAJOR, KMIP_VERSION_MAJOR),
                    integer(tag::PROTOCOL_VERSION_MINOR, KMIP_VERSION_MINOR),
                ],
            ),
            integer(tag::BATCH_COUNT, 1),
        ],
    )
}

fn wrap_request(operation_enum: u32, payload: TtlvItem) -> TtlvItem {
    structure(
        tag::REQUEST_MESSAGE,
        vec![
            request_header(),
            structure(
                tag::BATCH_ITEM,
                vec![enumeration(tag::OPERATION, operation_enum), payload],
            ),
        ],
    )
}

/// Build a KMIP Create request for a symmetric key.
pub fn create_symmetric_key(algorithm: u32, key_length: i32) -> TtlvItem {
    let usage_mask = 0x0C; // Encrypt | Decrypt
    let payload = structure(
        tag::REQUEST_PAYLOAD,
        vec![
            enumeration(tag::OBJECT_TYPE, object_type::SYMMETRIC_KEY),
            structure(
                tag::TEMPLATE_ATTRIBUTE,
                vec![
                    attribute("Cryptographic Algorithm", TtlvValue::Enumeration(algorithm)),
                    attribute("Cryptographic Length", TtlvValue::Integer(key_length)),
                    attribute("Cryptographic Usage Mask", TtlvValue::Integer(usage_mask)),
                ],
            ),
        ],
    );
    wrap_request(operation::CREATE, payload)
}

/// Build a KMIP Create request for an asymmetric key pair.
pub fn create_asymmetric_key(algorithm: u32, key_length: i32) -> TtlvItem {
    let usage_mask = 0x03; // Sign | Verify
    let payload = structure(
        tag::REQUEST_PAYLOAD,
        vec![
            enumeration(tag::OBJECT_TYPE, object_type::PRIVATE_KEY),
            structure(
                tag::TEMPLATE_ATTRIBUTE,
                vec![
                    attribute("Cryptographic Algorithm", TtlvValue::Enumeration(algorithm)),
                    attribute("Cryptographic Length", TtlvValue::Integer(key_length)),
                    attribute("Cryptographic Usage Mask", TtlvValue::Integer(usage_mask)),
                ],
            ),
        ],
    );
    wrap_request(operation::CREATE, payload)
}

/// AES-GCM authentication tag length, in bytes.
///
/// Sent explicitly because a server may refuse an authenticated mode that
/// does not state one, and because the tag has to be separated from the
/// ciphertext by length on the way back.
pub const GCM_TAG_LEN: usize = 16;

/// `CryptographicParameters` for an AES-GCM operation.
///
/// The algorithm is included alongside the mode: a server is entitled to
/// require it, and a mode alone does not say which cipher it modifies.
fn aes_gcm_parameters() -> TtlvItem {
    structure(
        tag::CRYPTOGRAPHIC_PARAMETERS,
        vec![
            enumeration(tag::BLOCK_CIPHER_MODE, block_cipher_mode::GCM),
            enumeration(tag::CRYPTOGRAPHIC_ALGORITHM, crypto_algorithm::AES),
            integer(tag::TAG_LENGTH, GCM_TAG_LEN as i32),
        ],
    )
}

/// Build a KMIP Encrypt request for AES-GCM.
///
/// `aad` is sent as `AuthenticatedEncryptionAdditionalData`: covered by the
/// authentication tag but not encrypted, which is what binds a ciphertext to
/// the context it was created in.
pub fn encrypt_request(
    unique_id: &str,
    plaintext: &[u8],
    iv_nonce: Option<&[u8]>,
    aad: &[u8],
) -> TtlvItem {
    let mut children = vec![
        text_string(tag::UNIQUE_ID, unique_id),
        aes_gcm_parameters(),
        byte_string(tag::DATA, plaintext.to_vec()),
    ];
    if let Some(iv) = iv_nonce {
        children.push(byte_string(tag::IV_COUNTER_NONCE, iv.to_vec()));
    }
    if !aad.is_empty() {
        children.push(byte_string(
            tag::AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,
            aad.to_vec(),
        ));
    }
    let payload = structure(tag::REQUEST_PAYLOAD, children);
    wrap_request(operation::ENCRYPT, payload)
}

/// Build a KMIP Decrypt request for AES-GCM.
///
/// The tag is a separate field, not a suffix of the ciphertext. Sending it is
/// what makes the mode authenticated: without it the server has nothing to
/// verify the ciphertext against.
pub fn decrypt_request(
    unique_id: &str,
    ciphertext: &[u8],
    iv_nonce: Option<&[u8]>,
    auth_tag: Option<&[u8]>,
    aad: &[u8],
) -> TtlvItem {
    let mut children = vec![
        text_string(tag::UNIQUE_ID, unique_id),
        aes_gcm_parameters(),
        byte_string(tag::DATA, ciphertext.to_vec()),
    ];
    if let Some(iv) = iv_nonce {
        children.push(byte_string(tag::IV_COUNTER_NONCE, iv.to_vec()));
    }
    // Additional data precedes the tag, and the order is not cosmetic: KMIP
    // payload fields are positional, so a server reading them in specification
    // order rejects the whole message as unparseable if they are swapped.
    if !aad.is_empty() {
        children.push(byte_string(
            tag::AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,
            aad.to_vec(),
        ));
    }
    if let Some(t) = auth_tag {
        children.push(byte_string(tag::AUTHENTICATED_ENCRYPTION_TAG, t.to_vec()));
    }
    let payload = structure(tag::REQUEST_PAYLOAD, children);
    wrap_request(operation::DECRYPT, payload)
}

/// Build a KMIP Activate request.
///
/// A created object is Pre-Active, and KMIP forbids using a Pre-Active object
/// for cryptography, so this is not optional bookkeeping — without it the key
/// exists and every Encrypt against it is refused.
pub fn activate_request(unique_id: &str) -> TtlvItem {
    let payload = structure(
        tag::REQUEST_PAYLOAD,
        vec![text_string(tag::UNIQUE_ID, unique_id)],
    );
    wrap_request(operation::ACTIVATE, payload)
}

/// Build a KMIP Revoke request with reason Cessation of Operation.
///
/// KMIP forbids destroying an Active object, so an activated key must be
/// revoked first. The reason is fixed: this is called from key destruction,
/// which is an operational retirement, not a compromise report — claiming
/// compromise would put a false assertion in the server's audit trail.
pub fn revoke_request(unique_id: &str) -> TtlvItem {
    let payload = structure(
        tag::REQUEST_PAYLOAD,
        vec![
            text_string(tag::UNIQUE_ID, unique_id),
            structure(
                tag::REVOCATION_REASON,
                vec![enumeration(
                    tag::REVOCATION_REASON_CODE,
                    revocation_reason::CESSATION_OF_OPERATION,
                )],
            ),
        ],
    );
    wrap_request(operation::REVOKE, payload)
}

/// Build a KMIP Sign request.
pub fn sign_request(
    unique_id: &str,
    message: &[u8],
    digital_sig_algorithm: Option<u32>,
) -> TtlvItem {
    let mut children = vec![
        text_string(tag::UNIQUE_ID, unique_id),
        byte_string(tag::DATA, message.to_vec()),
    ];
    if let Some(alg) = digital_sig_algorithm {
        children.push(structure(
            tag::CRYPTOGRAPHIC_PARAMETERS,
            vec![enumeration(tag::DIGITAL_SIGNATURE_ALGORITHM, alg)],
        ));
    }
    let payload = structure(tag::REQUEST_PAYLOAD, children);
    wrap_request(operation::SIGN, payload)
}

/// Build a KMIP Signature Verify request.
pub fn verify_request(
    unique_id: &str,
    message: &[u8],
    signature: &[u8],
    digital_sig_algorithm: Option<u32>,
) -> TtlvItem {
    let mut children = vec![
        text_string(tag::UNIQUE_ID, unique_id),
        byte_string(tag::DATA, message.to_vec()),
        byte_string(tag::SIGNATURE_DATA, signature.to_vec()),
    ];
    if let Some(alg) = digital_sig_algorithm {
        children.push(structure(
            tag::CRYPTOGRAPHIC_PARAMETERS,
            vec![enumeration(tag::DIGITAL_SIGNATURE_ALGORITHM, alg)],
        ));
    }
    let payload = structure(tag::REQUEST_PAYLOAD, children);
    wrap_request(operation::SIGNATURE_VERIFY, payload)
}

/// Build a KMIP Destroy request.
pub fn destroy_request(unique_id: &str) -> TtlvItem {
    let payload = structure(
        tag::REQUEST_PAYLOAD,
        vec![text_string(tag::UNIQUE_ID, unique_id)],
    );
    wrap_request(operation::DESTROY, payload)
}

/// Build a KMIP RNG Retrieve request.
///
/// The byte count goes in `DataLength`. Sending it as `Data` — which is what
/// this did — produces a request the server cannot parse, because `Data` is
/// where payload bytes live.
pub fn rng_retrieve_request(length: i32) -> TtlvItem {
    let payload = structure(
        tag::REQUEST_PAYLOAD,
        vec![integer(tag::DATA_LENGTH, length)],
    );
    wrap_request(operation::RNG_RETRIEVE, payload)
}

fn attribute(name: &str, value: TtlvValue) -> TtlvItem {
    let (typ, attr_tag) = match &value {
        TtlvValue::Enumeration(_) => (TtlvType::Enumeration, tag::ATTRIBUTE_VALUE),
        TtlvValue::Integer(_) => (TtlvType::Integer, tag::ATTRIBUTE_VALUE),
        TtlvValue::TextString(_) => (TtlvType::TextString, tag::ATTRIBUTE_VALUE),
        _ => (TtlvType::ByteString, tag::ATTRIBUTE_VALUE),
    };

    structure(
        tag::ATTRIBUTE,
        vec![
            text_string(tag::ATTRIBUTE_NAME, name),
            TtlvItem {
                tag: attr_tag,
                typ,
                value,
            },
        ],
    )
}

/// Parsed KMIP response.
#[derive(Debug)]
pub struct KmipResponse {
    pub result_status: u32,
    pub result_message: Option<String>,
    pub payload: Option<TtlvItem>,
}

/// Parse a decoded TTLV response message into a `KmipResponse`.
pub fn parse_response(msg: &TtlvItem) -> Result<KmipResponse, String> {
    let batch_item = msg
        .find(tag::BATCH_ITEM)
        .ok_or("no BatchItem in response")?;

    let status = batch_item
        .find(tag::RESULT_STATUS)
        .and_then(super::ttlv::TtlvItem::as_enum)
        .ok_or("no ResultStatus in response")?;

    let message = batch_item
        .find(tag::RESULT_MESSAGE)
        .and_then(|i| i.as_text())
        .map(String::from);

    let payload = batch_item.find(tag::RESPONSE_PAYLOAD).cloned();

    Ok(KmipResponse {
        result_status: status,
        result_message: message,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ttlv::{block_cipher_mode, crypto_algorithm, decode, encode};

    #[test]
    fn create_symmetric_encodes_and_decodes() {
        let msg = create_symmetric_key(crypto_algorithm::AES, 256);
        let encoded = encode(&msg);
        let mut slice: &[u8] = &encoded;
        let decoded = decode(&mut slice).unwrap();
        assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);

        let header = decoded.find(tag::REQUEST_HEADER).unwrap();
        let version = header.find(tag::PROTOCOL_VERSION).unwrap();
        let major = version.find(tag::PROTOCOL_VERSION_MAJOR).unwrap();
        let minor = version.find(tag::PROTOCOL_VERSION_MINOR).unwrap();
        // Must match the encoding below it: `Create` sends a TemplateAttribute,
        // which is KMIP 1.x. This assertion previously demanded major 2, which
        // is how a header no server would accept stayed in place.
        assert_eq!(major.as_integer(), Some(1));
        assert_eq!(minor.as_integer(), Some(4));
        assert!(
            decoded.find(tag::BATCH_ITEM).is_some_and(|b| b
                .find(tag::REQUEST_PAYLOAD)
                .is_some_and(|p| p.find(tag::TEMPLATE_ATTRIBUTE).is_some())),
            "the announced version has to match the payload shape; a TemplateAttribute \
             body under a 2.x header is unparseable at either version"
        );
    }

    /// Values that a round-trip test cannot catch.
    ///
    /// Encoding and decoding with the same table agrees with itself whatever
    /// the number is, so these are pinned against the specification's
    /// enumerations directly. Four of them were wrong simultaneously, each
    /// naming a different defined value, so every request was well-formed and
    /// described something other than what was intended.
    #[test]
    fn wire_constants_are_the_specification_values() {
        use crate::ttlv::{crypto_algorithm, object_type, result_status};

        // 0x01 here is Certificate, and was what every symmetric Create sent.
        assert_eq!(object_type::SYMMETRIC_KEY, 0x02);
        // 0x0E is X9.102 AESKW, a key-wrapping mode, not GCM.
        assert_eq!(block_cipher_mode::GCM, 0x09);
        // 0x2C is Log.
        assert_eq!(operation::RNG_RETRIEVE, 0x25);
        // 0x1B is One Time Pad.
        assert_eq!(crypto_algorithm::ED25519, 0x37);

        assert_eq!(operation::ACTIVATE, 0x12);
        assert_eq!(operation::REVOKE, 0x13);
        assert_eq!(crypto_algorithm::AES, 0x03);
        assert_eq!(object_type::PRIVATE_KEY, 0x04);
        assert_eq!(result_status::SUCCESS, 0x00);
    }

    #[test]
    fn encrypt_request_states_the_mode_the_algorithm_and_the_tag_length() {
        let msg = encrypt_request("key-1", b"plaintext", None, b"");
        let params = msg
            .find(tag::BATCH_ITEM)
            .and_then(|b| b.find(tag::REQUEST_PAYLOAD))
            .and_then(|p| p.find(tag::CRYPTOGRAPHIC_PARAMETERS))
            .expect("Encrypt must carry CryptographicParameters");

        assert_eq!(
            params
                .find(tag::BLOCK_CIPHER_MODE)
                .and_then(TtlvItem::as_enum),
            Some(block_cipher_mode::GCM)
        );
        assert_eq!(
            params
                .find(tag::CRYPTOGRAPHIC_ALGORITHM)
                .and_then(TtlvItem::as_enum),
            Some(crypto_algorithm::AES),
            "a mode alone does not say which cipher it modifies"
        );
        assert_eq!(
            params.find(tag::TAG_LENGTH).and_then(TtlvItem::as_integer),
            Some(GCM_TAG_LEN as i32),
            "a server may refuse an authenticated mode with no stated tag length"
        );
    }

    #[test]
    fn decrypt_request_sends_the_authentication_tag() {
        let msg = decrypt_request("key-1", b"ct", Some(&[7u8; 12]), Some(&[9u8; 16]), b"ctx");
        let payload = msg
            .find(tag::BATCH_ITEM)
            .and_then(|b| b.find(tag::REQUEST_PAYLOAD))
            .unwrap();

        assert_eq!(
            payload
                .find(tag::AUTHENTICATED_ENCRYPTION_TAG)
                .and_then(|i| i.as_bytes()),
            Some(&[9u8; 16][..]),
            "the tag is a separate field; without it the server has nothing to verify \
             the ciphertext against and the mode is authenticated in name only"
        );
    }

    #[test]
    fn activate_and_revoke_name_their_operations() {
        let activate = activate_request("k");
        assert_eq!(
            activate
                .find(tag::BATCH_ITEM)
                .and_then(|b| b.find(tag::OPERATION))
                .and_then(TtlvItem::as_enum),
            Some(operation::ACTIVATE)
        );

        let revoke = revoke_request("k");
        let payload = revoke
            .find(tag::BATCH_ITEM)
            .and_then(|b| b.find(tag::REQUEST_PAYLOAD))
            .unwrap();
        assert_eq!(
            payload
                .find(tag::REVOCATION_REASON)
                .and_then(|r| r.find(tag::REVOCATION_REASON_CODE))
                .and_then(TtlvItem::as_enum),
            Some(crate::ttlv::revocation_reason::CESSATION_OF_OPERATION),
            "destruction is an operational retirement; reporting compromise would write \
             a false assertion into the server's audit trail"
        );
    }

    /// A server's failure text is only reachable if `RESULT_MESSAGE` names the
    /// tag the server actually writes. This response is built from the spec
    /// values rather than from the constants, so it fails if they drift again.
    #[test]
    fn result_message_is_read_from_the_tag_servers_write() {
        const SPEC_RESULT_MESSAGE: u32 = 0x0042_007D;
        const SPEC_RESULT_STATUS: u32 = 0x0042_007F;

        let response = crate::ttlv::structure(
            tag::RESPONSE_MESSAGE,
            vec![crate::ttlv::structure(
                tag::BATCH_ITEM,
                vec![
                    crate::ttlv::enumeration(SPEC_RESULT_STATUS, 1),
                    crate::ttlv::text_string(SPEC_RESULT_MESSAGE, "key state not permitted"),
                ],
            )],
        );

        let parsed = parse_response(&response).unwrap();
        assert_eq!(
            parsed.result_message.as_deref(),
            Some("key state not permitted"),
            "the server's failure text must survive parsing; \
             a wrong RESULT_MESSAGE tag silently degrades every error to \"unknown error\""
        );
    }

    #[test]
    fn encrypt_request_round_trip() {
        let msg = encrypt_request("key-1", b"plaintext", None, b"");
        let encoded = encode(&msg);
        let mut slice: &[u8] = &encoded;
        let decoded = decode(&mut slice).unwrap();
        assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);
    }

    #[test]
    fn destroy_request_round_trip() {
        let msg = destroy_request("key-to-destroy");
        let encoded = encode(&msg);
        let mut slice: &[u8] = &encoded;
        let decoded = decode(&mut slice).unwrap();
        let batch = decoded.find(tag::BATCH_ITEM).unwrap();
        let op = batch.find(tag::OPERATION).unwrap();
        assert_eq!(op.as_enum(), Some(operation::DESTROY));
    }
}
