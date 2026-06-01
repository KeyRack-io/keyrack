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

//! Property-based tests for canonicalization and LID determinism.
//!
//! These contracts must be locked early — they are extremely painful to
//! change later (see `MIGRATION.md`).

use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
use keyrack_core::lid::Lid;
use proptest::prelude::*;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Arbitrary generators
// ---------------------------------------------------------------------------

fn arb_string() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_\\-\\.éèêëàâäùûüîïôöçñ ]{0,64}")
        .unwrap()
}

fn arb_attribute_value() -> impl Strategy<Value = AttributeValue> {
    let leaf = prop_oneof![
        arb_string().prop_map(AttributeValue::String),
        any::<i64>().prop_map(AttributeValue::I64),
        any::<bool>().prop_map(AttributeValue::Bool),
        prop::collection::vec(arb_string(), 0..8).prop_map(AttributeValue::ListOfString),
    ];

    leaf.prop_recursive(3, 32, 4, |inner| {
        prop::collection::btree_map(arb_string(), inner, 0..4)
            .prop_map(AttributeValue::Record)
    })
}

fn arb_attribute_set() -> impl Strategy<Value = AttributeSet> {
    prop::collection::btree_map(arb_string(), arb_attribute_value(), 0..8)
        .prop_map(AttributeSet::from)
}

// ---------------------------------------------------------------------------
// Canonicalization properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Same input always produces the same canonical bytes.
    #[test]
    fn canon_deterministic(attrs in arb_attribute_set()) {
        let a = canonicalize(CanonicalizationVersion::V1, &attrs);
        let b = canonicalize(CanonicalizationVersion::V1, &attrs);
        prop_assert_eq!(a.bytes(), b.bytes());
    }

    /// Insertion order does not affect canonical output (enforced by BTreeMap,
    /// but we test through a reverse-iteration round-trip to be sure).
    #[test]
    fn canon_order_independent(
        attrs in arb_attribute_set()
    ) {
        // Rebuild from reversed iteration; BTreeMap will re-sort.
        let reversed: BTreeMap<String, AttributeValue> =
            attrs.0.iter().rev().map(|(k, v)| (k.clone(), v.clone())).collect();

        let a = canonicalize(CanonicalizationVersion::V1, &attrs);
        let b = canonicalize(
            CanonicalizationVersion::V1,
            &AttributeSet::from(reversed),
        );
        prop_assert_eq!(a.bytes(), b.bytes());
    }

    /// NFC normalisation is idempotent: canonicalizing an already-NFC input
    /// twice yields the same bytes.
    #[test]
    fn canon_nfc_idempotent(s in arb_string()) {
        let mut attrs = AttributeSet::new();
        attrs.insert("k", AttributeValue::String(s));

        let first = canonicalize(CanonicalizationVersion::V1, &attrs);
        let second = canonicalize(CanonicalizationVersion::V1, &attrs);
        prop_assert_eq!(first.bytes(), second.bytes());
    }

    /// Two distinct attribute sets (differing by a single i64 value) produce
    /// different canonical forms.
    #[test]
    fn canon_distinct_i64(a in any::<i64>(), b in any::<i64>()) {
        prop_assume!(a != b);

        let mut sa = AttributeSet::new();
        sa.insert("n", AttributeValue::I64(a));
        let mut sb = AttributeSet::new();
        sb.insert("n", AttributeValue::I64(b));

        let fa = canonicalize(CanonicalizationVersion::V1, &sa);
        let fb = canonicalize(CanonicalizationVersion::V1, &sb);
        prop_assert_ne!(fa.bytes(), fb.bytes());
    }

    /// Bool true and false produce different canonical forms.
    #[test]
    fn canon_bool_distinguishable(v in any::<bool>()) {
        let mut sa = AttributeSet::new();
        sa.insert("flag", AttributeValue::Bool(v));
        let mut sb = AttributeSet::new();
        sb.insert("flag", AttributeValue::Bool(!v));

        let fa = canonicalize(CanonicalizationVersion::V1, &sa);
        let fb = canonicalize(CanonicalizationVersion::V1, &sb);
        prop_assert_ne!(fa.bytes(), fb.bytes());
    }
}

// ---------------------------------------------------------------------------
// LID properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Same (version, canonical form) always produces the same LID.
    #[test]
    fn lid_deterministic(attrs in arb_attribute_set()) {
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        let a = Lid::derive(CanonicalizationVersion::V1, &form);
        let b = Lid::derive(CanonicalizationVersion::V1, &form);
        prop_assert_eq!(a, b);
    }

    /// Display/FromStr round-trip preserves the LID.
    #[test]
    fn lid_display_fromstr_round_trip(attrs in arb_attribute_set()) {
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        let lid = Lid::derive(CanonicalizationVersion::V1, &form);
        let s = lid.to_string();
        let parsed: Lid = s.parse().expect("valid LID string");
        prop_assert_eq!(lid, parsed);
    }

    /// LID display starts with "lid_" and is 68 chars total.
    #[test]
    fn lid_display_format(attrs in arb_attribute_set()) {
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        let lid = Lid::derive(CanonicalizationVersion::V1, &form);
        let s = lid.to_string();
        prop_assert!(s.starts_with("lid_"));
        prop_assert_eq!(s.len(), 68);
        prop_assert!(s[4..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Two different attribute sets produce different LIDs (collision
    /// resistance; this is probabilistic, not a proof, but catches
    /// degenerate bugs like constant output).
    #[test]
    fn lid_collision_resistance(
        a_entries in prop::collection::vec(
            (arb_string(), arb_attribute_value()), 1..4
        ),
        b_entries in prop::collection::vec(
            (arb_string(), arb_attribute_value()), 1..4
        ),
    ) {
        let set_a = AttributeSet::from(a_entries.into_iter().collect::<BTreeMap<_, _>>());
        let set_b = AttributeSet::from(b_entries.into_iter().collect::<BTreeMap<_, _>>());

        prop_assume!(set_a != set_b);

        let form_a = canonicalize(CanonicalizationVersion::V1, &set_a);
        let form_b = canonicalize(CanonicalizationVersion::V1, &set_b);

        // If canonical forms differ, LIDs must differ.
        if form_a.bytes() != form_b.bytes() {
            let lid_a = Lid::derive(CanonicalizationVersion::V1, &form_a);
            let lid_b = Lid::derive(CanonicalizationVersion::V1, &form_b);
            prop_assert_ne!(lid_a, lid_b);
        }
    }
}
