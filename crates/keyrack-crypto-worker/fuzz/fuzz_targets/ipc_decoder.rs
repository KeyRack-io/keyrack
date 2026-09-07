#![no_main]
// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
#[allow(dead_code)]
#[path = "../../src/ipc.rs"]
mod ipc;
use libfuzzer_sys::fuzz_target;
use std::io::{BufReader, Cursor};

fuzz_target!(|data: &[u8]| {
    // Compare fragmented input with contiguous input through the production
    // framing function. Newlines, invalid UTF-8, truncation and JSON recursion
    // all reach the production decoder; no substitute schema is used.
    let capacity = data.first().copied().unwrap_or(0) as usize + 1;
    let mut fragmented = BufReader::with_capacity(capacity, Cursor::new(data));
    let mut contiguous = Cursor::new(data);
    for _ in 0..32 {
        let mut left = Vec::new();
        let mut right = Vec::new();
        let a = ipc::read_frame(&mut fragmented, &mut left);
        let b = ipc::read_frame(&mut contiguous, &mut right);
        assert!(left.len() <= ipc::MAX_FRAME && right.len() <= ipc::MAX_FRAME);
        assert_eq!(a, b);
        if a.is_err() { break; }
        assert_eq!(left, right);
        if left.is_empty() { break; }
        assert!(left.ends_with(b"\n"));
        let _ = ipc::decode(&left);
    }
    let _ = ipc::decode(data);
});
