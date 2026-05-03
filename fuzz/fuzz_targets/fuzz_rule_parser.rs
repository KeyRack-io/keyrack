#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(yaml) = std::str::from_utf8(data) {
        let _ = keyrack_core::rule::RuleRegistry::from_yaml(yaml);
    }
});
