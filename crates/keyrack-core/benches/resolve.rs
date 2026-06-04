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

//! Benchmarks for the resolver and canonicalization pipeline.
//!
//! Targets from PLAN.md W7:
//! - 10,000+ resolve/s with cache hot
//! - Encrypt under 5ms p99

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
use keyrack_core::lid::Lid;
use keyrack_core::resolver::{resolve_chain, ResolverConfig};
use keyrack_core::rule::{Namespace, ParentRef, RoutingRule, RuleRegistry, DEFAULT_MAX_DEPTH};
use std::collections::BTreeMap;

fn build_registry() -> RuleRegistry {
    let mut reg = RuleRegistry::new();

    reg.register(Namespace {
        name: "_infrastructure_".into(),
        attachment: None,
        max_depth: DEFAULT_MAX_DEPTH,
        routing_rules: vec![
            RoutingRule {
                match_pattern: BTreeMap::from([("kind".into(), "root".into())]),
                parent: ParentRef::Root,
                priority: 0,
                key_spec: None,
            },
            RoutingRule {
                match_pattern: BTreeMap::from([
                    ("kind".into(), "tenant-root".into()),
                    ("tenant".into(), "$T".into()),
                ]),
                parent: ParentRef::Pattern(BTreeMap::from([("kind".into(), "root".into())])),
                priority: 0,
                key_spec: None,
            },
        ],
    });

    reg.register(Namespace {
        name: "app".into(),
        attachment: Some(BTreeMap::from([
            ("kind".into(), "tenant-root".into()),
            ("tenant".into(), "acme".into()),
        ])),
        max_depth: DEFAULT_MAX_DEPTH,
        routing_rules: vec![
            RoutingRule {
                match_pattern: BTreeMap::from([
                    ("kind".into(), "dek".into()),
                    ("user".into(), "$U".into()),
                ]),
                parent: ParentRef::Pattern(BTreeMap::from([("kind".into(), "kek".into())])),
                priority: 0,
                key_spec: None,
            },
            RoutingRule {
                match_pattern: BTreeMap::from([("kind".into(), "kek".into())]),
                parent: ParentRef::Attachment,
                priority: 0,
                key_spec: None,
            },
        ],
    });

    reg
}

fn bench_resolve(c: &mut Criterion) {
    let reg = build_registry();
    let config = ResolverConfig::default();
    let attrs = BTreeMap::from([
        ("kind".into(), "dek".into()),
        ("user".into(), "alice".into()),
    ]);

    c.bench_function("resolve_chain (4-deep)", |b| {
        b.iter(|| {
            let chain =
                resolve_chain(black_box(&reg), black_box(&attrs), black_box(&config)).unwrap();
            black_box(chain);
        });
    });
}

fn bench_canonicalize(c: &mut Criterion) {
    let mut attrs = AttributeSet::new();
    attrs.insert("kind", AttributeValue::String("dek".into()));
    attrs.insert("user", AttributeValue::String("alice".into()));
    attrs.insert("tenant", AttributeValue::String("acme".into()));
    attrs.insert("doc", AttributeValue::String("document-001".into()));

    c.bench_function("canonicalize V1 (4 attrs)", |b| {
        b.iter(|| {
            let form = canonicalize(black_box(CanonicalizationVersion::V1), black_box(&attrs));
            black_box(form);
        });
    });
}

fn bench_lid_derive(c: &mut Criterion) {
    let mut attrs = AttributeSet::new();
    attrs.insert("kind", AttributeValue::String("dek".into()));
    attrs.insert("user", AttributeValue::String("alice".into()));
    let form = canonicalize(CanonicalizationVersion::V1, &attrs);

    c.bench_function("lid_derive (BLAKE3)", |b| {
        b.iter(|| {
            let lid = Lid::derive(black_box(CanonicalizationVersion::V1), black_box(&form));
            black_box(lid);
        });
    });
}

criterion_group!(benches, bench_resolve, bench_canonicalize, bench_lid_derive);
criterion_main!(benches);
