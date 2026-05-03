#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyrack_core::header::CiphertextHeader::parse(data);
});
