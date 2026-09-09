// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! The actual private IPC decoder; shared by the executable and fuzz target.
use serde::{Deserialize, Serialize};
use std::io::BufRead;

pub(crate) const MAX_FRAME: usize = 65_536;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FrameError {
    Io,
    Truncated,
    Limit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Operation {
    Encrypt,
    Decrypt,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Signed {
    // Signature covers exact bytes, prefixed with a harness-only domain.
    pub(crate) body: String,
    pub(crate) signature: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Generate {
        grant: String,
    },
    Execute {
        signed: Signed,
        principal: String,
        operation: Operation,
        input: String,
    },
    Fence {
        // Base64 canonical Evidence<RevocationCommand>, not the legacy JSON body.
        evidence: String,
    },
}

pub(crate) fn decode(frame: &[u8]) -> Result<Request, serde_json::Error> {
    // read_frame is the executable's allocation boundary. Keep callers that
    // bypass framing (including the fuzz target) within the same limit.
    if frame.len() > MAX_FRAME {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "frame too large",
        ));
    }
    serde_json::from_slice(frame)
}

pub(crate) fn read_frame(
    reader: &mut impl BufRead,
    output: &mut Vec<u8>,
) -> Result<(), FrameError> {
    loop {
        let bytes = reader.fill_buf().map_err(|_| FrameError::Io)?;
        if bytes.is_empty() {
            return if output.is_empty() {
                Ok(())
            } else {
                Err(FrameError::Truncated)
            };
        }
        let end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1);
        let count = end.unwrap_or(bytes.len());
        if output.len() + count > MAX_FRAME {
            return Err(FrameError::Limit);
        }
        output.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_oversized_truncated_unknown_and_duplicate_frames() {
        assert!(read_frame(&mut &vec![b'x'; MAX_FRAME + 1][..], &mut Vec::new()).is_err());
        assert!(read_frame(&mut &b"{}"[..], &mut Vec::new()).is_err());
        assert!(read_frame(&mut &b"{}\n"[..], &mut Vec::new()).is_ok());
        for invalid in [
            r#"{"command":"generate","grant":"","extra":1}"#,
            r#"{"command":"generate","grant":"","grant":""}"#,
            r#"{"command":"export"}"#,
        ] {
            assert!(decode(invalid.as_bytes()).is_err());
        }
    }
}
