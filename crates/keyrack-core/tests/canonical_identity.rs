// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent Unicode reference conformance and identity/policy congruence.
//! Expected NFC outputs come from Unicode's vendored reference, not another
//! invocation of the product's normalizer. See data/unicode/README.md.

use keyrack_core::attr::{normalize_flat, AttributeSet, AttributeValue as V};
use keyrack_core::canon::{canonicalize, normalize_text, CanonicalizationVersion as CV};
use keyrack_core::lid::Lid;
use keyrack_core::rule::{ParentRef, RoutingRule};
use keyrack_core::tags::IdentityTags;
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

type Flat = BTreeMap<String, String>;
const REFERENCE: &str = include_str!("data/unicode/NormalizationTest-17.0.0.txt");
const LICENSE: &str = include_str!("data/unicode/LICENSE.txt");

fn attrs(entries: &[(&str, V)]) -> AttributeSet {
    AttributeSet(
        entries
            .iter()
            .map(|(k, v)| ((*k).into(), v.clone()))
            .collect(),
    )
}

fn flat_attrs(map: &Flat) -> AttributeSet {
    AttributeSet(
        map.iter()
            .map(|(k, v)| (k.clone(), V::String(v.clone())))
            .collect(),
    )
}

fn s(value: &str) -> V {
    V::String(value.into())
}

fn bytes(a: &AttributeSet) -> Vec<u8> {
    canonicalize(CV::V2, a)
        .expect("valid V2 input")
        .bytes()
        .to_vec()
}

fn lid(a: &AttributeSet) -> Lid {
    Lid::derive(CV::V2, &canonicalize(CV::V2, a).expect("valid V2 input"))
}

fn reference_string(column: &str) -> String {
    column
        .split_whitespace()
        .map(|hex| {
            char::from_u32(u32::from_str_radix(hex, 16).expect("reference hex"))
                .expect("reference scalar")
        })
        .collect()
}

// Reference byte framing: deliberately no product encoding or normalization.
fn expected_single_entry(key: &str, value: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for field in [key, value] {
        result.push(1);
        result.extend_from_slice(&u32::try_from(field.len()).unwrap().to_le_bytes());
        result.extend_from_slice(field.as_bytes());
    }
    result
}

fn reference_tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    result.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    result.extend_from_slice(payload);
    result
}

#[test]
fn official_unicode_17_reference_matches_actual_v2_bytes_and_normalization() {
    assert_eq!(
        format!("{:x}", Sha256::digest(REFERENCE.as_bytes())),
        "5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(LICENSE.as_bytes())),
        "e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96"
    );
    assert_eq!(unicode_normalization::UNICODE_VERSION, (17, 0, 0));
    let mut count = 0;
    let mut part_one = false;
    let mut part_one_sources = BTreeSet::new();
    for (line_number, line) in REFERENCE.lines().enumerate() {
        let data = line.split('#').next().unwrap().trim();
        if data.starts_with('@') {
            part_one = data == "@Part1";
            continue;
        }
        if data.is_empty() {
            continue;
        }
        let columns: Vec<_> = data.split(';').take(5).map(reference_string).collect();
        assert_eq!(columns.len(), 5, "reference line {}", line_number + 1);
        if part_one {
            let mut source = columns[0].chars();
            let scalar = source.next().expect("Part 1 source");
            assert!(source.next().is_none(), "Part 1 source is one scalar");
            part_one_sources.insert(scalar);
        }
        for (i, input) in columns.iter().enumerate() {
            // NFC(c1/c2/c3)=c2, NFC(c4/c5)=c4, as specified by Unicode.
            let expected = &columns[if i < 3 { 1 } else { 3 }];
            assert_eq!(
                &normalize_text(input),
                expected,
                "reference line {}, column {}",
                line_number + 1,
                i + 1
            );
            let raw = Flat::from([(input.clone(), input.clone())]);
            assert_eq!(
                normalize_flat(&raw).unwrap(),
                Flat::from([(expected.clone(), expected.clone())]),
                "flat reference line {}, column {}",
                line_number + 1,
                i + 1
            );
            assert_eq!(
                bytes(&flat_attrs(&raw)),
                expected_single_entry(expected, expected),
                "canonical reference line {}, column {}",
                line_number + 1,
                i + 1
            );
        }
        // Cover the independent recursive/list normalization paths too, using
        // c1 -> c2 reference data and manually framed V2 payloads.
        let expected = &columns[1];
        let mut list_payload = 1_u32.to_le_bytes().to_vec();
        list_payload.extend_from_slice(&u32::try_from(expected.len()).unwrap().to_le_bytes());
        list_payload.extend_from_slice(expected.as_bytes());
        let list = attrs(&[("list", V::ListOfString(vec![columns[0].clone()]))]);
        assert_eq!(
            bytes(&list),
            [reference_tlv(1, b"list"), reference_tlv(4, &list_payload)].concat()
        );
        let nested = attrs(&[(
            "record",
            V::Record(flat_attrs(&Flat::from([(columns[0].clone(), columns[0].clone())])).0),
        )]);
        assert_eq!(
            bytes(&nested),
            [
                reference_tlv(1, b"record"),
                reference_tlv(5, &expected_single_entry(expected, expected))
            ]
            .concat()
        );
        count += 1;
    }
    assert_eq!(
        count, 20_034,
        "do not silently truncate the independent oracle"
    );
    assert!(!part_one_sources.is_empty());
    for scalar in (0..=0x10_FFFF).filter_map(char::from_u32) {
        if !part_one_sources.contains(&scalar) {
            let input = scalar.to_string();
            assert_eq!(
                normalize_text(&input),
                input,
                "unlisted scalar U+{:04X}",
                u32::from(scalar)
            );
        }
    }
}

fn rule(pattern: Flat) -> RoutingRule {
    RoutingRule {
        match_pattern: pattern,
        parent: ParentRef::Pattern(Flat::from([("captured".into(), "$observed".into())])),
        priority: 0,
        key_spec: None,
    }
}

// Capture outcomes separate presence and value, including values beginning '$'.
// A rule's boolean alone cannot distinguish all maps.
fn observe(rule: &RoutingRule, raw: &Flat) -> Option<(Flat, Option<Flat>)> {
    rule.matches(raw).then(|| {
        let bindings = rule.extract_bindings(raw);
        let parent = rule.resolve_parent(&bindings);
        (bindings, parent)
    })
}

fn complete_observations_equal(a: &Flat, b: &Flat) -> bool {
    let na = normalize_flat(a).unwrap();
    let nb = normalize_flat(b).unwrap();
    let keys: BTreeSet<_> = na.keys().chain(nb.keys()).cloned().collect();
    keys.into_iter().all(|key| {
        let capture = rule(Flat::from([(key, "$observed".into())]));
        observe(&capture, a) == observe(&capture, b)
    })
}

fn rich_string() -> BoxedStrategy<String> {
    prop_oneof![
        prop::collection::vec(any::<char>(), 0..12).prop_map(|chars| chars.into_iter().collect()),
        prop::collection::vec(
            prop::sample::select(vec![
                "",
                "z",
                "$",
                "$actual",
                "\0",
                "é",
                "e\u{301}",
                "Å",
                "A\u{30a}",
                "\u{212b}",
                "각",
                "\u{1100}\u{1161}\u{11a8}",
                "\u{1e0c}\u{307}",
                "D\u{307}\u{323}",
                "😀",
                "\u{0344}",
                "\u{0308}\u{0301}",
                "\u{1d15e}",
                "\u{1d157}\u{1d165}",
            ]),
            0..5
        )
        .prop_map(|parts| parts.concat()),
    ]
    .boxed()
}

fn flat_map() -> BoxedStrategy<Flat> {
    prop::collection::btree_map(rich_string(), rich_string(), 0..7)
        .prop_filter(
            "accepted maps only; collisions have a dedicated property",
            |m| normalize_flat(m).is_ok(),
        )
        .boxed()
}

fn reference_equivalent_pairs() -> &'static [(String, String)] {
    static PAIRS: OnceLock<Vec<(String, String)>> = OnceLock::new();
    PAIRS.get_or_init(|| {
        let mut pairs = BTreeSet::new();
        for line in REFERENCE.lines() {
            let data = line.split('#').next().unwrap().trim();
            if data.is_empty() || data.starts_with('@') {
                continue;
            }
            let columns: Vec<_> = data.split(';').take(5).map(reference_string).collect();
            for (i, raw) in columns.iter().enumerate() {
                let expected = &columns[if i < 3 { 1 } else { 3 }];
                if raw != expected {
                    pairs.insert((raw.clone(), expected.clone()));
                }
            }
        }
        // All distinct nonidentity NFC relations from the full pinned corpus,
        // not a handpicked list of scripts or old regression examples.
        assert_eq!(pairs.len(), 16_776);
        pairs.into_iter().collect()
    })
}

fn equivalent_spellings() -> impl Strategy<Value = (String, String)> {
    let pairs = reference_equivalent_pairs();
    (0..pairs.len(), rich_string(), rich_string(), any::<bool>()).prop_map(
        move |(index, prefix, suffix, reverse)| {
            let (a, b) = &pairs[index];
            // Canonical equivalence is closed under common concatenation.
            // Arbitrary surrounding text exercises composition/reordering at
            // both boundaries while distinct raw spellings stay distinct.
            let a = format!("{prefix}{a}{suffix}");
            let b = format!("{prefix}{b}{suffix}");
            if reverse {
                (b, a)
            } else {
                (a, b)
            }
        },
    )
}

fn equivalent_maps() -> impl Strategy<Value = (Flat, Flat)> {
    prop::collection::vec(
        (
            equivalent_spellings(),
            equivalent_spellings(),
            any::<bool>(),
        ),
        0..7,
    )
    .prop_map(|rows| {
        let mut a = Flat::new();
        let mut b = Flat::new();
        for (index, ((ka, kb), (va, vb), dollar)) in rows.into_iter().enumerate() {
            let prefix = if dollar { "$" } else { "" };
            a.insert(format!("{index}/{ka}"), format!("{prefix}{va}"));
            b.insert(format!("{index}/{kb}"), format!("{prefix}{vb}"));
        }
        (a, b)
    })
}

fn map_pairs() -> impl Strategy<Value = (Flat, Flat)> {
    prop_oneof![
        3 => equivalent_maps(),
        3 => (flat_map(), flat_map()),
        2 => flat_map().prop_map(|a| {
            let mut b = a.clone();
            let mut key = "different".to_string();
            while normalize_flat(&a).unwrap().contains_key(&key) { key.push('!'); }
            b.insert(key, "new-value".into());
            (a, b)
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn canonical_bytes_equal_iff_rule_observations_equal((a, b) in map_pairs()) {
        let same_bytes = bytes(&flat_attrs(&a)) == bytes(&flat_attrs(&b));
        prop_assert_eq!(same_bytes, complete_observations_equal(&a, &b));
    }

    #[test]
    fn equal_identity_has_congruent_arbitrary_rule_results(
        (a, b) in equivalent_maps(),
        pattern in prop::collection::btree_map(rich_string(), rich_string(), 0..6),
        parent in prop::collection::btree_map(rich_string(), rich_string(), 0..6),
    ) {
        prop_assert_eq!(bytes(&flat_attrs(&a)), bytes(&flat_attrs(&b)));
        let arbitrary = RoutingRule { match_pattern: pattern, parent: ParentRef::Pattern(parent), priority: 0, key_spec: None };
        prop_assert_eq!(observe(&arbitrary, &a), observe(&arbitrary, &b));
        // Always exercise a matching capture, not only random nonmatches.
        for raw_key in a.keys() {
            let capture = rule(Flat::from([(raw_key.clone(), "$observed".into())]));
            prop_assert!(capture.matches(&a));
            prop_assert!(capture.matches(&b));
            prop_assert_eq!(observe(&capture, &a), observe(&capture, &b));
            // Also anchor arbitrary Unicode concrete patterns in the actual
            // map so generated matching behavior is not all wildcard traffic.
            let value = &a[raw_key];
            if !value.starts_with('$') {
                let concrete = rule(Flat::from([(raw_key.clone(), value.clone())]));
                prop_assert!(concrete.matches(&a));
                prop_assert!(concrete.matches(&b));
                prop_assert_eq!(observe(&concrete, &a), observe(&concrete, &b));
            }
        }
    }

    #[test]
    fn generated_duplicate_normalized_keys_rejected(
        (first, second) in equivalent_spellings(),
        prefix in "[a-z0-9]{0,12}", a in rich_string(), b in rich_string(),
    ) {
        let duplicate = Flat::from([(format!("{prefix}{first}"), a), (format!("{prefix}{second}"), b)]);
        prop_assert_eq!(duplicate.len(), 2);
        prop_assert!(normalize_flat(&duplicate).is_err());
        prop_assert!(canonicalize(CV::V2, &flat_attrs(&duplicate)).is_err());
        prop_assert!(!rule(Flat::new()).matches(&duplicate));
        let nested = attrs(&[("nested", V::Record(flat_attrs(&duplicate).0))]);
        prop_assert!(canonicalize(CV::V2, &nested).is_err());
    }
}

#[test]
fn absent_empty_and_types_do_not_collide() {
    let cases = [
        AttributeSet::new(),
        attrs(&[("tenant", s(""))]),
        attrs(&[("tenant", V::ListOfString(vec![]))]),
        attrs(&[("tenant", V::Record(BTreeMap::new()))]),
        attrs(&[("tenant", V::Bool(false))]),
        attrs(&[("tenant", V::I64(0))]),
        attrs(&[("tenant", s("0"))]),
        attrs(&[("tenant", s("false"))]),
        attrs(&[("tenant", V::ListOfString(vec![String::new()]))]),
        attrs(&[("", s(""))]),
    ];
    assert_eq!(
        cases.iter().map(bytes).collect::<BTreeSet<_>>().len(),
        cases.len()
    );
}

#[test]
fn length_framing_and_list_order_do_not_collide() {
    let list = |v: &[&str]| {
        attrs(&[(
            "x",
            V::ListOfString(v.iter().map(|s| (*s).into()).collect()),
        )])
    };
    for (a, b) in [
        (attrs(&[("ab", s("c"))]), attrs(&[("a", s("bc"))])),
        (list(&["a", "bc"]), list(&["ab", "c"])),
        (list(&["a", "b"]), list(&["b", "a"])),
        (
            attrs(&[("x", V::Record(BTreeMap::new()))]),
            AttributeSet::new(),
        ),
    ] {
        assert_ne!(bytes(&a), bytes(&b));
    }
}

#[test]
fn nfc_equal_values_have_equal_raw_rule_decisions_and_stored_tags() {
    let a = Flat::from([("tenant".into(), "é".into())]);
    let b = Flat::from([("tenant".into(), "e\u{301}".into())]);
    let concrete = rule(Flat::from([("tenant".into(), "é".into())]));
    assert_eq!(lid(&flat_attrs(&a)), lid(&flat_attrs(&b)));
    assert!(concrete.matches(&a));
    assert!(concrete.matches(&b));
    assert_eq!(
        IdentityTags::from_attribute_set(&flat_attrs(&a)).unwrap(),
        IdentityTags::from_attribute_set(&flat_attrs(&b)).unwrap()
    );
}

#[test]
fn nfc_key_equivalence_and_ambiguous_normalized_names() {
    let a = Flat::from([("é".into(), "value".into())]);
    let b = Flat::from([("e\u{301}".into(), "value".into())]);
    assert_eq!(bytes(&flat_attrs(&a)), bytes(&flat_attrs(&b)));
    let capture = rule(Flat::from([("é".into(), "$observed".into())]));
    assert!(capture.matches(&a));
    assert_eq!(observe(&capture, &a), observe(&capture, &b));
    for duplicate in [
        attrs(&[("A\u{30a}", s("first")), ("Å", s("second"))]),
        attrs(&[("Å", s("first")), ("\u{212b}", s("second"))]),
    ] {
        assert!(canonicalize(CV::V2, &duplicate).is_err());
    }
}

#[test]
fn sorting_after_nfc_preserves_equivalent_map_identity() {
    let a = attrs(&[("é", s("value")), ("z", s("other"))]);
    let b = attrs(&[("e\u{301}", s("value")), ("z", s("other"))]);
    assert_eq!(bytes(&a), bytes(&b));
    let expected = [
        expected_single_entry("z", "other"),
        expected_single_entry("é", "value"),
    ]
    .concat();
    assert_eq!(bytes(&a), expected);
}

#[test]
fn typed_preimages_cannot_be_flattened_into_string_identity_tags() {
    let typed = attrs(&[("x", V::I64(1))]);
    let string = attrs(&[("x", s("1"))]);
    assert_ne!(bytes(&typed), bytes(&string));
    assert!(IdentityTags::from_attribute_set(&typed).is_err());
    assert!(IdentityTags::from_attribute_set(&string).is_ok());
}

#[test]
fn version_two_prefix_is_explicit_and_version_one_is_rejected() {
    let a = attrs(&[("tenant", s("example"))]);
    let form = bytes(&a);
    let digest = |version: u32| {
        let mut h = blake3::Hasher::new();
        h.update(&version.to_le_bytes());
        h.update(&form);
        h.finalize()
    };
    assert_eq!(lid(&a).as_bytes(), digest(2).as_bytes());
    assert_ne!(lid(&a).as_bytes(), digest(1).as_bytes());
    assert!(serde_json::from_str::<CV>("\"V1\"").is_err());
    assert_eq!(serde_json::from_str::<CV>("\"V2\"").unwrap(), CV::V2);
}

#[test]
fn side_metadata_does_not_silently_enter_logical_identity() {
    let identity = attrs(&[("_keyrack_key_id", s("00000000-0000-4000-8000-000000000001"))]);
    let before = lid(&identity);
    // This deliberately narrow model retains the contract that unrelated
    // record fields do not become implicit canonicalization input. It makes
    // no claim about database integrity or native wrapped-key enforcement.
    let records = [
        ("parent-A", 1_u64, "tenant-A"),
        ("parent-B", 2_u64, "tenant-B"),
    ];
    assert_ne!(records[0], records[1]);
    for _side_metadata in records {
        assert_eq!(lid(&identity), before);
    }
}

#[test]
fn equivalent_identity_aad_opens_but_different_identity_aad_fails() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    let cipher = Aes256Gcm::new_from_slice(&[0x42; 32]).unwrap();
    let nonce = Nonce::from([0x24; 12]);
    let a = attrs(&[("tenant", s("é"))]);
    let b = attrs(&[("tenant", s("e\u{301}"))]);
    let different = attrs(&[("tenant", s("different"))]);
    let plaintext = b"public identity test fixture";
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: lid(&a).as_bytes(),
            },
        )
        .unwrap();
    assert_eq!(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: lid(&b).as_bytes()
                }
            )
            .unwrap(),
        plaintext
    );
    assert!(cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: lid(&different).as_bytes()
            }
        )
        .is_err());
}
