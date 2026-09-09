// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{collections::BTreeSet, fs, path::Path};

#[test]
fn documented_kani_harnesses_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("verification/kani-harnesses.json")).unwrap(),
    )
    .unwrap();
    let source = fs::read_to_string(root.join(registry["source"].as_str().unwrap())).unwrap();
    let proofs = fs::read_to_string(root.join(registry["proofs"].as_str().unwrap())).unwrap();
    let doc = fs::read_to_string(root.join("VERIFICATION.md")).unwrap();
    assert!(source.contains("#[cfg(kani)]") && source.contains("mod proofs;"));
    let registered: BTreeSet<_> = registry["harnesses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(!registered.is_empty());
    let actual: BTreeSet<_> = proofs
        .split("#[kani::proof]")
        .skip(1)
        .map(|part| {
            part.split("fn ")
                .nth(1)
                .unwrap()
                .split('(')
                .next()
                .unwrap()
                .trim()
        })
        .collect();
    assert_eq!(
        registered, actual,
        "every real proof must be registered, and every registration must resolve"
    );
    for name in &registered {
        assert!(
            doc.contains(&format!("--harness {name}")),
            "registered proof missing its runnable documentation"
        );
    }
    for command in doc.split("--harness ").skip(1) {
        let name = command
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .next()
            .unwrap();
        assert!(
            registered.contains(name),
            "documented proof is absent from the execution registry"
        );
    }
}
