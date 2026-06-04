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

//! Resolver state machine.
//!
//! The resolver takes an attribute set, walks the rule engine to
//! determine the key hierarchy, and lazily provisions keys as needed.
//!
//! Safety mechanisms:
//!
//! - **Cycle detection**: a visited set of LIDs prevents infinite
//!   loops when rules produce circular parent references.
//! - **Depth guard**: configurable maximum depth (default 16) prevents
//!   runaway resolution in deep or misconfigured hierarchies.

use crate::attr::{AttributeSet, AttributeValue};
use crate::canon::{canonicalize, CanonicalizationVersion};
use crate::error::{KeyRackError, Result};
use crate::lid::Lid;
use crate::rule::{RuleRegistry, DEFAULT_MAX_DEPTH};
use std::collections::{BTreeMap, HashSet};

/// Outcome of a resolve step.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    /// The LID of the resolved (possibly newly provisioned) key.
    pub lid: Lid,
    /// The full chain of LIDs from leaf to root.
    pub chain: Vec<Lid>,
}

/// Configuration for the resolver.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub max_depth: u32,
    pub canonicalization_version: CanonicalizationVersion,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            canonicalization_version: CanonicalizationVersion::V1,
        }
    }
}

/// Resolve an attribute set to a chain of LIDs by walking the rule
/// engine. This is the "dry" resolution path — it computes the chain
/// without provisioning keys or touching storage. The service layer
/// uses this to determine which keys to provision or look up.
///
/// # Errors
///
/// - [`KeyRackError::DepthLimitExceeded`] if the chain exceeds `max_depth`.
/// - [`KeyRackError::CycleDetected`] if a LID appears twice in the chain.
/// - [`KeyRackError::Other`] if no rule matches the attributes.
pub fn resolve_chain(
    rules: &RuleRegistry,
    attrs: &BTreeMap<String, String>,
    config: &ResolverConfig,
) -> Result<Vec<Lid>> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut current_attrs = attrs.clone();
    let mut depth = 0u32;

    loop {
        if depth >= config.max_depth {
            return Err(KeyRackError::DepthLimitExceeded {
                max_depth: config.max_depth,
            });
        }

        let lid = lid_from_flat_attrs(&current_attrs, config.canonicalization_version);

        if !visited.insert(lid) {
            return Err(KeyRackError::CycleDetected { lid });
        }
        chain.push(lid);
        depth += 1;

        let rule_match = rules.match_rule(&current_attrs).ok_or_else(|| {
            KeyRackError::Other(format!("no rule matches attributes: {current_attrs:?}"))
        })?;

        if rule_match.rule.is_root() {
            break;
        }

        if rule_match.rule.is_attachment_boundary() {
            let attachment = rule_match.namespace.attachment.as_ref().ok_or_else(|| {
                KeyRackError::Other(format!(
                    "namespace '{}' has attachment rule but no attachment context",
                    rule_match.namespace.name
                ))
            })?;

            current_attrs = attachment.clone();
            continue;
        }

        let parent_attrs = rule_match
            .rule
            .resolve_parent(&rule_match.bindings)
            .ok_or_else(|| KeyRackError::Other("rule matched but produced no parent".into()))?;

        current_attrs = parent_attrs;
    }

    Ok(chain)
}

/// Helper: compute a LID from flat string attributes.
fn lid_from_flat_attrs(attrs: &BTreeMap<String, String>, version: CanonicalizationVersion) -> Lid {
    let mut attr_set = AttributeSet::new();
    for (k, v) in attrs {
        attr_set.insert(k, AttributeValue::String(v.clone()));
    }
    let form = canonicalize(version, &attr_set);
    Lid::derive(version, &form)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::*;

    fn setup_registry() -> RuleRegistry {
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
            name: "acme-app".into(),
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
                    parent: ParentRef::Pattern(BTreeMap::from([("kind".into(), "app-kek".into())])),
                    priority: 0,
                    key_spec: None,
                },
                RoutingRule {
                    match_pattern: BTreeMap::from([("kind".into(), "app-kek".into())]),
                    parent: ParentRef::Attachment,
                    priority: 0,
                    key_spec: None,
                },
            ],
        });

        reg
    }

    #[test]
    fn resolve_full_chain() {
        let reg = setup_registry();
        let config = ResolverConfig::default();

        let attrs = BTreeMap::from([
            ("kind".into(), "dek".into()),
            ("user".into(), "alice".into()),
        ]);

        let chain = resolve_chain(&reg, &attrs, &config).unwrap();

        // dek → app-kek → tenant-root:acme → root
        assert_eq!(chain.len(), 4);
        // All LIDs are distinct
        let unique: HashSet<_> = chain.iter().collect();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn resolve_infra_only() {
        let reg = setup_registry();
        let config = ResolverConfig::default();

        let attrs = BTreeMap::from([
            ("kind".into(), "tenant-root".into()),
            ("tenant".into(), "globex".into()),
        ]);

        let chain = resolve_chain(&reg, &attrs, &config).unwrap();
        // tenant-root:globex → root
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn resolve_root_only() {
        let reg = setup_registry();
        let config = ResolverConfig::default();

        let attrs = BTreeMap::from([("kind".into(), "root".into())]);
        let chain = resolve_chain(&reg, &attrs, &config).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn depth_limit_exceeded() {
        // Build a chain that is deeper than the limit by using distinct
        // concrete values at each level: level-0 → level-1 → level-2 → ...
        let mut rules = Vec::new();
        for i in 0..10 {
            rules.push(RoutingRule {
                match_pattern: BTreeMap::from([("kind".into(), format!("level-{i}"))]),
                parent: ParentRef::Pattern(BTreeMap::from([(
                    "kind".into(),
                    format!("level-{}", i + 1),
                )])),
                priority: 0,
                key_spec: None,
            });
        }

        let mut reg = RuleRegistry::new();
        reg.register(Namespace {
            name: "deep".into(),
            attachment: None,
            max_depth: 3,
            routing_rules: rules,
        });

        let config = ResolverConfig {
            max_depth: 3,
            ..Default::default()
        };

        let attrs = BTreeMap::from([("kind".into(), "level-0".into())]);
        let err = resolve_chain(&reg, &attrs, &config).unwrap_err();
        assert!(matches!(
            err,
            KeyRackError::DepthLimitExceeded { max_depth: 3 }
        ));
    }

    #[test]
    fn cycle_detection() {
        let mut reg = RuleRegistry::new();
        reg.register(Namespace {
            name: "cycle".into(),
            attachment: None,
            max_depth: DEFAULT_MAX_DEPTH,
            routing_rules: vec![
                RoutingRule {
                    match_pattern: BTreeMap::from([("kind".into(), "a".into())]),
                    parent: ParentRef::Pattern(BTreeMap::from([("kind".into(), "b".into())])),
                    priority: 0,
                    key_spec: None,
                },
                RoutingRule {
                    match_pattern: BTreeMap::from([("kind".into(), "b".into())]),
                    parent: ParentRef::Pattern(BTreeMap::from([("kind".into(), "a".into())])),
                    priority: 0,
                    key_spec: None,
                },
            ],
        });

        let config = ResolverConfig::default();
        let attrs = BTreeMap::from([("kind".into(), "a".into())]);
        let err = resolve_chain(&reg, &attrs, &config).unwrap_err();
        assert!(matches!(err, KeyRackError::CycleDetected { .. }));
    }

    #[test]
    fn no_matching_rule() {
        let reg = RuleRegistry::new();
        let config = ResolverConfig::default();
        let attrs = BTreeMap::from([("kind".into(), "unknown".into())]);
        let err = resolve_chain(&reg, &attrs, &config).unwrap_err();
        assert!(matches!(err, KeyRackError::Other(_)));
    }

    #[test]
    fn deterministic_lid_across_calls() {
        let reg = setup_registry();
        let config = ResolverConfig::default();
        let attrs = BTreeMap::from([
            ("kind".into(), "dek".into()),
            ("user".into(), "alice".into()),
        ]);

        let chain1 = resolve_chain(&reg, &attrs, &config).unwrap();
        let chain2 = resolve_chain(&reg, &attrs, &config).unwrap();
        assert_eq!(chain1, chain2);
    }
}
