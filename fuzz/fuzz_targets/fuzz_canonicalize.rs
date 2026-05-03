#![no_main]
use libfuzzer_sys::fuzz_target;
use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};

fuzz_target!(|data: &[u8]| {
    if let Ok(json) = std::str::from_utf8(data) {
        if let Ok(map) = serde_json::from_str::<std::collections::BTreeMap<String, String>>(json) {
            let mut attrs = AttributeSet::new();
            for (k, v) in &map {
                attrs.insert(k.as_str(), AttributeValue::String(v.clone()));
            }
            let form = canonicalize(CanonicalizationVersion::V1, &attrs);
            let _ = keyrack_core::lid::Lid::derive(CanonicalizationVersion::V1, &form);
        }
    }
});
