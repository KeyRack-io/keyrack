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

//! TTLV (Tag-Type-Length-Value) codec for KMIP 2.1.
//!
//! KMIP wire format encodes every field as a TTLV item:
//!
//! ```text
//! +--------+------+--------+-------+
//! | Tag    | Type | Length | Value |
//! | 3 byte | 1 b  | 4 byte | var   |
//! +--------+------+--------+-------+
//! ```
//!
//! All values are padded to an 8-byte boundary.

use bytes::{Buf, BufMut, BytesMut};

/// KMIP type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TtlvType {
    Structure = 0x01,
    Integer = 0x02,
    LongInteger = 0x03,
    BigInteger = 0x04,
    Enumeration = 0x05,
    Boolean = 0x06,
    TextString = 0x07,
    ByteString = 0x08,
    DateTime = 0x09,
    Interval = 0x0A,
}

impl TtlvType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Structure),
            0x02 => Some(Self::Integer),
            0x03 => Some(Self::LongInteger),
            0x04 => Some(Self::BigInteger),
            0x05 => Some(Self::Enumeration),
            0x06 => Some(Self::Boolean),
            0x07 => Some(Self::TextString),
            0x08 => Some(Self::ByteString),
            0x09 => Some(Self::DateTime),
            0x0A => Some(Self::Interval),
            _ => None,
        }
    }
}

/// Well-known KMIP tags (3-byte values stored as u32 for convenience).
pub mod tag {
    pub const REQUEST_MESSAGE: u32 = 0x420078;
    pub const RESPONSE_MESSAGE: u32 = 0x42007B;
    pub const REQUEST_HEADER: u32 = 0x420077;
    pub const RESPONSE_HEADER: u32 = 0x42007A;
    pub const PROTOCOL_VERSION: u32 = 0x420069;
    pub const PROTOCOL_VERSION_MAJOR: u32 = 0x42006A;
    pub const PROTOCOL_VERSION_MINOR: u32 = 0x42006B;
    pub const BATCH_COUNT: u32 = 0x42000D;
    pub const BATCH_ITEM: u32 = 0x42000F;
    pub const OPERATION: u32 = 0x42005C;
    pub const RESULT_STATUS: u32 = 0x42007F;
    pub const RESULT_REASON: u32 = 0x420080;
    pub const RESULT_MESSAGE: u32 = 0x420081;
    pub const REQUEST_PAYLOAD: u32 = 0x420079;
    pub const RESPONSE_PAYLOAD: u32 = 0x42007C;
    pub const UNIQUE_ID: u32 = 0x420094;
    pub const OBJECT_TYPE: u32 = 0x420057;
    pub const TEMPLATE_ATTRIBUTE: u32 = 0x420091;
    pub const ATTRIBUTE: u32 = 0x420008;
    pub const ATTRIBUTE_NAME: u32 = 0x42000A;
    pub const ATTRIBUTE_VALUE: u32 = 0x42000B;
    pub const CRYPTOGRAPHIC_ALGORITHM: u32 = 0x420028;
    pub const CRYPTOGRAPHIC_LENGTH: u32 = 0x42002A;
    pub const CRYPTOGRAPHIC_USAGE_MASK: u32 = 0x42002C;
    pub const DATA: u32 = 0x4200C2;
    pub const IV_COUNTER_NONCE: u32 = 0x42003D;
    pub const CRYPTOGRAPHIC_PARAMETERS: u32 = 0x42002B;
    pub const BLOCK_CIPHER_MODE: u32 = 0x420011;
    pub const PADDING_METHOD: u32 = 0x42005F;
    pub const HASHING_ALGORITHM: u32 = 0x420038;
    pub const DIGITAL_SIGNATURE_ALGORITHM: u32 = 0x4200AE;
    pub const SIGNATURE_DATA: u32 = 0x4200C3;
    pub const MAC_DATA: u32 = 0x4200C4;
}

/// KMIP operation enum values.
pub mod operation {
    pub const CREATE: u32 = 0x01;
    pub const GET: u32 = 0x0A;
    pub const DESTROY: u32 = 0x14;
    pub const ENCRYPT: u32 = 0x1F;
    pub const DECRYPT: u32 = 0x20;
    pub const SIGN: u32 = 0x21;
    pub const SIGNATURE_VERIFY: u32 = 0x22;
    pub const RNG_RETRIEVE: u32 = 0x2C;
}

/// KMIP result status values.
pub mod result_status {
    pub const SUCCESS: u32 = 0x00;
    pub const OPERATION_FAILED: u32 = 0x01;
}

/// KMIP object type values.
pub mod object_type {
    pub const SYMMETRIC_KEY: u32 = 0x01;
    pub const PUBLIC_KEY: u32 = 0x03;
    pub const PRIVATE_KEY: u32 = 0x04;
}

/// KMIP cryptographic algorithm values.
pub mod crypto_algorithm {
    pub const AES: u32 = 0x03;
    pub const RSA: u32 = 0x04;
    pub const ECDSA: u32 = 0x06;
    pub const ED25519: u32 = 0x1B;
}

/// KMIP block cipher mode values.
pub mod block_cipher_mode {
    pub const GCM: u32 = 0x0E;
}

/// A decoded TTLV item.
#[derive(Debug, Clone)]
pub struct TtlvItem {
    pub tag: u32,
    pub typ: TtlvType,
    pub value: TtlvValue,
}

/// Possible TTLV values.
#[derive(Debug, Clone)]
pub enum TtlvValue {
    Structure(Vec<TtlvItem>),
    Integer(i32),
    LongInteger(i64),
    Enumeration(u32),
    Boolean(bool),
    TextString(String),
    ByteString(Vec<u8>),
}

impl TtlvItem {
    /// Find a child item by tag (first match).
    pub fn find(&self, tag: u32) -> Option<&TtlvItem> {
        match &self.value {
            TtlvValue::Structure(children) => children.iter().find(|c| c.tag == tag),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match &self.value {
            TtlvValue::TextString(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.value {
            TtlvValue::ByteString(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn as_enum(&self) -> Option<u32> {
        match &self.value {
            TtlvValue::Enumeration(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<i32> {
        match &self.value {
            TtlvValue::Integer(v) => Some(*v),
            _ => None,
        }
    }
}

// ── Encoding ────────────────────────────────────────────────────────

fn pad_len(len: usize) -> usize {
    (8 - (len % 8)) % 8
}

fn write_tag(buf: &mut BytesMut, tag: u32) {
    buf.put_u8((tag >> 16) as u8);
    buf.put_u8((tag >> 8) as u8);
    buf.put_u8(tag as u8);
}

pub fn encode_item(buf: &mut BytesMut, item: &TtlvItem) {
    write_tag(buf, item.tag);

    match &item.value {
        TtlvValue::Structure(children) => {
            buf.put_u8(TtlvType::Structure as u8);
            let len_pos = buf.len();
            buf.put_u32(0); // placeholder
            let start = buf.len();
            for child in children {
                encode_item(buf, child);
            }
            let content_len = buf.len() - start;
            let len_bytes = (content_len as u32).to_be_bytes();
            buf[len_pos..len_pos + 4].copy_from_slice(&len_bytes);
        }
        TtlvValue::Integer(v) => {
            buf.put_u8(TtlvType::Integer as u8);
            buf.put_u32(4);
            buf.put_i32(*v);
            buf.put_u32(0); // pad to 8
        }
        TtlvValue::LongInteger(v) => {
            buf.put_u8(TtlvType::LongInteger as u8);
            buf.put_u32(8);
            buf.put_i64(*v);
        }
        TtlvValue::Enumeration(v) => {
            buf.put_u8(TtlvType::Enumeration as u8);
            buf.put_u32(4);
            buf.put_u32(*v);
            buf.put_u32(0); // pad to 8
        }
        TtlvValue::Boolean(v) => {
            buf.put_u8(TtlvType::Boolean as u8);
            buf.put_u32(8);
            buf.put_u64(u64::from(*v));
        }
        TtlvValue::TextString(s) => {
            let bytes = s.as_bytes();
            buf.put_u8(TtlvType::TextString as u8);
            buf.put_u32(bytes.len() as u32);
            buf.put_slice(bytes);
            let pad = pad_len(bytes.len());
            for _ in 0..pad {
                buf.put_u8(0);
            }
        }
        TtlvValue::ByteString(b) => {
            buf.put_u8(TtlvType::ByteString as u8);
            buf.put_u32(b.len() as u32);
            buf.put_slice(b);
            let pad = pad_len(b.len());
            for _ in 0..pad {
                buf.put_u8(0);
            }
        }
    }
}

pub fn encode(item: &TtlvItem) -> BytesMut {
    let mut buf = BytesMut::with_capacity(256);
    encode_item(&mut buf, item);
    buf
}

// ── Decoding ────────────────────────────────────────────────────────

pub fn decode(buf: &mut &[u8]) -> Result<TtlvItem, String> {
    if buf.remaining() < 8 {
        return Err("buffer too short for TTLV header".into());
    }

    let tag = {
        let b0 = buf.get_u8() as u32;
        let b1 = buf.get_u8() as u32;
        let b2 = buf.get_u8() as u32;
        (b0 << 16) | (b1 << 8) | b2
    };

    let type_byte = buf.get_u8();
    let typ = TtlvType::from_u8(type_byte)
        .ok_or_else(|| format!("unknown TTLV type: 0x{type_byte:02X}"))?;

    let length = buf.get_u32() as usize;

    let padded = if typ == TtlvType::Structure {
        length
    } else {
        length + pad_len(length)
    };
    if buf.remaining() < padded {
        return Err(format!(
            "buffer underflow: need {padded} bytes (value {length} + padding), have {}",
            buf.remaining()
        ));
    }

    let value = match typ {
        TtlvType::Structure => {
            let end = buf.remaining() - length;
            let mut children = Vec::new();
            while buf.remaining() > end {
                children.push(decode(buf)?);
            }
            TtlvValue::Structure(children)
        }
        TtlvType::Integer => {
            let v = buf.get_i32();
            let pad = pad_len(4);
            buf.advance(pad);
            TtlvValue::Integer(v)
        }
        TtlvType::LongInteger => {
            let v = buf.get_i64();
            TtlvValue::LongInteger(v)
        }
        TtlvType::BigInteger => {
            let mut data = vec![0u8; length];
            buf.copy_to_slice(&mut data);
            let pad = pad_len(length);
            buf.advance(pad);
            TtlvValue::ByteString(data)
        }
        TtlvType::Enumeration => {
            let v = buf.get_u32();
            let pad = pad_len(4);
            buf.advance(pad);
            TtlvValue::Enumeration(v)
        }
        TtlvType::Boolean => {
            let v = buf.get_u64();
            TtlvValue::Boolean(v != 0)
        }
        TtlvType::TextString => {
            let mut data = vec![0u8; length];
            buf.copy_to_slice(&mut data);
            let pad = pad_len(length);
            buf.advance(pad);
            let s = String::from_utf8(data).map_err(|e| format!("invalid UTF-8: {e}"))?;
            TtlvValue::TextString(s)
        }
        TtlvType::ByteString => {
            let mut data = vec![0u8; length];
            buf.copy_to_slice(&mut data);
            let pad = pad_len(length);
            buf.advance(pad);
            TtlvValue::ByteString(data)
        }
        TtlvType::DateTime => {
            let v = buf.get_i64();
            TtlvValue::LongInteger(v)
        }
        TtlvType::Interval => {
            let v = buf.get_u32();
            let pad = pad_len(4);
            buf.advance(pad);
            TtlvValue::Integer(v as i32)
        }
    };

    Ok(TtlvItem { tag, typ, value })
}

// ── Builder helpers ─────────────────────────────────────────────────

pub fn structure(tag: u32, children: Vec<TtlvItem>) -> TtlvItem {
    TtlvItem {
        tag,
        typ: TtlvType::Structure,
        value: TtlvValue::Structure(children),
    }
}

pub fn integer(tag: u32, val: i32) -> TtlvItem {
    TtlvItem {
        tag,
        typ: TtlvType::Integer,
        value: TtlvValue::Integer(val),
    }
}

pub fn enumeration(tag: u32, val: u32) -> TtlvItem {
    TtlvItem {
        tag,
        typ: TtlvType::Enumeration,
        value: TtlvValue::Enumeration(val),
    }
}

pub fn text_string(tag: u32, val: impl Into<String>) -> TtlvItem {
    TtlvItem {
        tag,
        typ: TtlvType::TextString,
        value: TtlvValue::TextString(val.into()),
    }
}

pub fn byte_string(tag: u32, val: Vec<u8>) -> TtlvItem {
    TtlvItem {
        tag,
        typ: TtlvType::ByteString,
        value: TtlvValue::ByteString(val),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_integer() {
        let item = integer(0x420001, 42);
        let encoded = encode(&item);
        let mut slice: &[u8] = &encoded;
        let decoded = decode(&mut slice).unwrap();
        assert_eq!(decoded.tag, 0x420001);
        assert_eq!(decoded.as_integer(), Some(42));
    }

    #[test]
    fn round_trip_text_string() {
        let item = text_string(0x420002, "hello");
        let encoded = encode(&item);
        let mut slice: &[u8] = &encoded;
        let decoded = decode(&mut slice).unwrap();
        assert_eq!(decoded.as_text(), Some("hello"));
    }

    #[test]
    fn round_trip_byte_string() {
        let item = byte_string(0x420003, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let encoded = encode(&item);
        let mut slice: &[u8] = &encoded;
        let decoded = decode(&mut slice).unwrap();
        assert_eq!(decoded.as_bytes(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[test]
    fn round_trip_enumeration() {
        let item = enumeration(0x420004, 0x03);
        let encoded = encode(&item);
        let mut slice: &[u8] = &encoded;
        let decoded = decode(&mut slice).unwrap();
        assert_eq!(decoded.as_enum(), Some(0x03));
    }

    #[test]
    fn round_trip_structure() {
        let item = structure(
            tag::REQUEST_MESSAGE,
            vec![integer(0x420001, 1), text_string(0x420002, "test")],
        );
        let encoded = encode(&item);
        let mut slice: &[u8] = &encoded;
        let decoded = decode(&mut slice).unwrap();
        assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);
        let child1 = decoded.find(0x420001).unwrap();
        assert_eq!(child1.as_integer(), Some(1));
        let child2 = decoded.find(0x420002).unwrap();
        assert_eq!(child2.as_text(), Some("test"));
    }

    #[test]
    fn padding_aligns_to_8() {
        assert_eq!(pad_len(0), 0);
        assert_eq!(pad_len(1), 7);
        assert_eq!(pad_len(7), 1);
        assert_eq!(pad_len(8), 0);
        assert_eq!(pad_len(9), 7);
    }
}
