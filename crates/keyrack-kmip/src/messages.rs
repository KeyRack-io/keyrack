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
    byte_string, enumeration, integer, object_type, operation, structure, tag, text_string,
    TtlvItem, TtlvType, TtlvValue,
};

const KMIP_VERSION_MAJOR: i32 = 2;
const KMIP_VERSION_MINOR: i32 = 1;

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

/// Build a KMIP Encrypt request.
pub fn encrypt_request(
    unique_id: &str,
    plaintext: &[u8],
    iv_nonce: Option<&[u8]>,
    block_cipher_mode: Option<u32>,
) -> TtlvItem {
    let mut children = vec![
        text_string(tag::UNIQUE_ID, unique_id),
        byte_string(tag::DATA, plaintext.to_vec()),
    ];
    if let Some(iv) = iv_nonce {
        children.push(byte_string(tag::IV_COUNTER_NONCE, iv.to_vec()));
    }
    if let Some(mode) = block_cipher_mode {
        children.push(structure(
            tag::CRYPTOGRAPHIC_PARAMETERS,
            vec![enumeration(tag::BLOCK_CIPHER_MODE, mode)],
        ));
    }
    let payload = structure(tag::REQUEST_PAYLOAD, children);
    wrap_request(operation::ENCRYPT, payload)
}

/// Build a KMIP Decrypt request.
pub fn decrypt_request(
    unique_id: &str,
    ciphertext: &[u8],
    iv_nonce: Option<&[u8]>,
    block_cipher_mode: Option<u32>,
) -> TtlvItem {
    let mut children = vec![
        text_string(tag::UNIQUE_ID, unique_id),
        byte_string(tag::DATA, ciphertext.to_vec()),
    ];
    if let Some(iv) = iv_nonce {
        children.push(byte_string(tag::IV_COUNTER_NONCE, iv.to_vec()));
    }
    if let Some(mode) = block_cipher_mode {
        children.push(structure(
            tag::CRYPTOGRAPHIC_PARAMETERS,
            vec![enumeration(tag::BLOCK_CIPHER_MODE, mode)],
        ));
    }
    let payload = structure(tag::REQUEST_PAYLOAD, children);
    wrap_request(operation::DECRYPT, payload)
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
pub fn rng_retrieve_request(length: i32) -> TtlvItem {
    let payload = structure(tag::REQUEST_PAYLOAD, vec![integer(tag::DATA, length)]);
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
        assert_eq!(major.as_integer(), Some(2));
    }

    #[test]
    fn encrypt_request_round_trip() {
        let msg = encrypt_request("key-1", b"plaintext", None, Some(block_cipher_mode::GCM));
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
