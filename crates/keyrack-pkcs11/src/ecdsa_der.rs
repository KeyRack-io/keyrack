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

//! ECDSA signature format conversion between PKCS#11 raw (r||s) and DER.
//!
//! PKCS#11 `CKM_ECDSA` returns signatures as `r || s` (fixed-size,
//! big-endian). The software provider uses DER encoding. These helpers
//! convert between the two so signatures are interoperable across
//! provider implementations.

use keyrack_core::error::{KeyRackError, Result};

/// Encode a fixed-size ECDSA raw signature (r || s) as DER.
///
/// `component_len` is the byte length of each component (32 for P-256).
#[allow(clippy::cast_possible_truncation)]
pub fn raw_to_der(raw: &[u8], component_len: usize) -> Result<Vec<u8>> {
    if raw.len() != component_len * 2 {
        return Err(KeyRackError::Provider(format!(
            "expected {} bytes for raw ECDSA sig, got {}",
            component_len * 2,
            raw.len()
        )));
    }

    let r = &raw[..component_len];
    let s = &raw[component_len..];

    let r_enc = encode_integer(r);
    let s_enc = encode_integer(s);

    let inner_len = r_enc.len() + s_enc.len();
    let mut out = Vec::with_capacity(2 + inner_len);
    out.push(0x30); // SEQUENCE
    out.push(inner_len as u8);
    out.extend_from_slice(&r_enc);
    out.extend_from_slice(&s_enc);
    Ok(out)
}

/// Decode a DER-encoded ECDSA signature to fixed-size raw (r || s).
///
/// Each component is zero-padded to `component_len` bytes.
pub fn der_to_raw(der: &[u8], component_len: usize) -> Result<Vec<u8>> {
    if der.len() < 6 || der[0] != 0x30 {
        return Err(KeyRackError::Provider(
            "invalid DER ECDSA signature".into(),
        ));
    }

    let mut pos = 2; // skip SEQUENCE tag + length

    let r = read_integer(der, &mut pos, component_len)?;
    let s = read_integer(der, &mut pos, component_len)?;

    let mut raw = Vec::with_capacity(component_len * 2);
    raw.extend_from_slice(&r);
    raw.extend_from_slice(&s);
    Ok(raw)
}

fn encode_integer(val: &[u8]) -> Vec<u8> {
    let start = val
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(val.len().saturating_sub(1));
    let trimmed = &val[start..];

    let needs_pad = !trimmed.is_empty() && trimmed[0] & 0x80 != 0;
    let len = trimmed.len() + usize::from(needs_pad);

    let mut out = Vec::with_capacity(2 + len);
    out.push(0x02); // INTEGER tag
    #[allow(clippy::cast_possible_truncation)]
    out.push(len as u8);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    out
}

fn read_integer(der: &[u8], pos: &mut usize, pad_to: usize) -> Result<Vec<u8>> {
    if *pos >= der.len() || der[*pos] != 0x02 {
        return Err(KeyRackError::Provider(
            "expected INTEGER tag in DER".into(),
        ));
    }
    *pos += 1;

    if *pos >= der.len() {
        return Err(KeyRackError::Provider("truncated DER".into()));
    }
    let len = der[*pos] as usize;
    *pos += 1;

    if *pos + len > der.len() {
        return Err(KeyRackError::Provider("truncated DER integer".into()));
    }
    let mut bytes = &der[*pos..*pos + len];
    *pos += len;

    // Strip leading zero used for positive encoding
    if bytes.len() > 1 && bytes[0] == 0x00 {
        bytes = &bytes[1..];
    }

    if bytes.len() > pad_to {
        return Err(KeyRackError::Provider(
            "DER integer too large for curve".into(),
        ));
    }

    let mut result = vec![0u8; pad_to - bytes.len()];
    result.extend_from_slice(bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_simple() {
        let raw = vec![0u8; 64]; // all zeros
        let der = raw_to_der(&raw, 32).unwrap();
        let back = der_to_raw(&der, 32).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn round_trip_high_bit() {
        let mut raw = vec![0u8; 64];
        raw[0] = 0xFF; // high bit set on r
        raw[32] = 0x80; // high bit set on s
        let der = raw_to_der(&raw, 32).unwrap();
        let back = der_to_raw(&der, 32).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(raw_to_der(&[0u8; 63], 32).is_err());
        assert!(raw_to_der(&[0u8; 65], 32).is_err());
    }
}
