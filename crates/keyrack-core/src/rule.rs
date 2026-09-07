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

//! Namespace rule engine.
//!
//! Defines routing rules that determine key hierarchy relationships.
//! Rules are declared in YAML (`namespaces.yaml`) and parsed at startup.
//!
//! ## Matching
//!
//! Each rule has a `match_pattern`: a map of attribute keys to either
//! concrete values or variable bindings (`$NAME`). A rule matches an
//! attribute set when every key in the pattern exists in the attribute
//! set and either the pattern value is a variable (matches any value)
//! or the pattern value equals the attribute value exactly.
//!
//! ## Specificity
//!
//! Rules are ranked by a specificity tuple (`concrete_count`,
//! `variable_count`) — more concrete matches are preferred. Ties on
//! specificity are broken by an explicit `priority` field (higher
//! wins). This replaces the `PoC`'s `priority`-then-length ordering
//! (Problem 2 fix).
//!
//! ## Variable propagation
//!
//! Variables in the match pattern capture values from the child's
//! attributes. They can be interpolated into the `parent_pattern` to
//! produce the parent's attributes. Only **parameterised attachments**
//! propagate variables — no implicit propagation (Problem 1 fix).
//!
//! ## `_attachment_` dual role
//!
//! When `parent_pattern` is `Attachment`, the rule marks a boundary
//! between an application namespace and the infrastructure namespace.
//! The attachment context provides the attributes used to match
//! against infrastructure rules (scope filter + boundary marker,
//! Problem 4).
//!
//! ## Cycle detection
//!
//! At resolution time, a visited set tracks LIDs already seen. If a
//! LID recurs, resolution fails with [`KeyRackError::CycleDetected`].
//!
//! ## Depth guard
//!
//! Configurable maximum resolution depth per namespace (default 16,
//! Problem 13). Exceeding the limit fails with
//! [`KeyRackError::DepthLimitExceeded`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Default maximum resolution depth.
pub const DEFAULT_MAX_DEPTH: u32 = 16;

/// A single routing rule within a namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Pattern to match against a key's attribute set.
    /// Values starting with `$` are variable bindings.
    #[serde(deserialize_with = "crate::attr::deserialize_flat")]
    pub match_pattern: BTreeMap<String, String>,

    /// What parent to resolve to.
    pub parent: ParentRef,

    /// Explicit priority for tie-breaking when specificity is equal.
    /// Higher wins. Default 0.
    #[serde(default)]
    pub priority: i32,

    /// Optional key spec override for keys created via this rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_spec: Option<crate::key::KeySpec>,
}

/// Where the parent key comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParentRef {
    /// Root key (no parent). `null` in YAML.
    #[serde(deserialize_with = "deserialize_null")]
    Root,

    /// Cross-namespace boundary: the key's parent is determined by
    /// the namespace's attachment context.
    #[serde(deserialize_with = "deserialize_attachment")]
    Attachment,

    /// An inline attribute pattern for the parent. Variables from the
    /// match pattern are interpolated.
    Pattern(#[serde(deserialize_with = "crate::attr::deserialize_flat")] BTreeMap<String, String>),
}

fn deserialize_null<'de, D: serde::Deserializer<'de>>(d: D) -> Result<(), D::Error> {
    let v: Option<serde_json::Value> = Option::deserialize(d)?;
    if v.is_none() {
        Ok(())
    } else {
        Err(serde::de::Error::custom("expected null for Root variant"))
    }
}

fn deserialize_attachment<'de, D: serde::Deserializer<'de>>(d: D) -> Result<(), D::Error> {
    let v = String::deserialize(d)?;
    if v == "_attachment_" {
        Ok(())
    } else {
        Err(serde::de::Error::custom("expected \"_attachment_\""))
    }
}

/// A complete namespace definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Namespace {
    pub name: String,

    /// Attachment context: attributes that link this namespace to its
    /// parent namespace. `None` for the infrastructure namespace.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_attachment_map"
    )]
    pub attachment: Option<BTreeMap<String, String>>,

    pub routing_rules: Vec<RoutingRule>,

    /// Maximum resolution depth. Defaults to [`DEFAULT_MAX_DEPTH`].
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
}

fn deserialize_attachment_map<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, String>>, D::Error> {
    #[derive(Deserialize)]
    struct Flat(
        #[serde(deserialize_with = "crate::attr::deserialize_flat")] BTreeMap<String, String>,
    );
    Option::<Flat>::deserialize(deserializer).map(|value| value.map(|flat| flat.0))
}

fn default_max_depth() -> u32 {
    DEFAULT_MAX_DEPTH
}

/// Specificity tuple for rule ranking. Higher is more specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Specificity {
    pub concrete_count: u32,
    pub variable_count: u32,
}

fn normalize_pattern(
    map: &BTreeMap<String, String>,
) -> crate::error::Result<BTreeMap<String, String>> {
    Ok(crate::attr::normalize_flat(map)?)
}

impl RoutingRule {
    /// Compute the specificity of this rule.
    #[must_use]
    pub fn specificity(&self) -> Specificity {
        let mut concrete = 0u32;
        let mut variable = 0u32;
        for value in self.match_pattern.values() {
            if value.starts_with('$') {
                variable += 1;
            } else {
                concrete += 1;
            }
        }
        Specificity {
            concrete_count: concrete,
            variable_count: variable,
        }
    }

    /// Normalize a rule before validating or using its patterns.
    fn normalized(&self) -> crate::error::Result<Self> {
        let mut rule = self.clone();
        rule.match_pattern = normalize_pattern(&self.match_pattern)?;
        let mut variables = std::collections::HashSet::new();
        for value in rule.match_pattern.values().filter(|v| v.starts_with('$')) {
            if value.len() == 1 || !variables.insert(value) {
                return Err(crate::error::KeyRackError::Other(format!(
                    "empty or duplicate normalized variable binding: {value}"
                )));
            }
        }
        if let ParentRef::Pattern(parent) = &self.parent {
            rule.parent = ParentRef::Pattern(normalize_pattern(parent)?);
        }
        Ok(rule)
    }

    /// Check a normalized pattern against normalized attributes.
    fn matches_normalized(&self, attrs: &BTreeMap<String, String>) -> bool {
        self.match_pattern.iter().all(|(key, pattern)| {
            attrs
                .get(key)
                .is_some_and(|value| pattern.starts_with('$') || pattern == value)
        })
    }

    /// Check if this rule matches the given attributes after NFC normalization.
    /// Ambiguous normalized keys or variable bindings never match.
    #[must_use]
    pub fn matches(&self, attrs: &BTreeMap<String, String>) -> bool {
        let (Ok(rule), Ok(attrs)) = (self.normalized(), normalize_pattern(attrs)) else {
            return false;
        };
        rule.matches_normalized(&attrs)
    }

    /// Extract normalized variable bindings from a valid match.
    #[must_use]
    pub fn extract_bindings(&self, attrs: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let (Ok(rule), Ok(attrs)) = (self.normalized(), normalize_pattern(attrs)) else {
            return BTreeMap::new();
        };
        if !rule.matches_normalized(&attrs) {
            return BTreeMap::new();
        }
        rule.match_pattern
            .iter()
            .filter(|(_, pattern)| pattern.starts_with('$'))
            .map(|(key, pattern)| (pattern.clone(), attrs[key].clone()))
            .collect()
    }

    /// Interpolate the normalized parent pattern with normalized bindings.
    /// Returns `None` for root rules, attachment boundaries, invalid patterns,
    /// or missing variable bindings. A missing variable is never a literal value.
    #[must_use]
    pub fn resolve_parent(
        &self,
        bindings: &BTreeMap<String, String>,
    ) -> Option<BTreeMap<String, String>> {
        let rule = self.normalized().ok()?;
        let bindings = normalize_pattern(bindings).ok()?;
        match &rule.parent {
            ParentRef::Root | ParentRef::Attachment => None,
            ParentRef::Pattern(parent) => parent
                .iter()
                .map(|(key, value)| {
                    let resolved = if value.starts_with('$') {
                        bindings.get(value)?.clone()
                    } else {
                        value.clone()
                    };
                    Some((key.clone(), resolved))
                })
                .collect(),
        }
    }

    /// Whether this rule's parent is `_attachment_`.
    #[must_use]
    pub fn is_attachment_boundary(&self) -> bool {
        matches!(self.parent, ParentRef::Attachment)
    }

    /// Whether this is a root rule (no parent).
    #[must_use]
    pub fn is_root(&self) -> bool {
        matches!(self.parent, ParentRef::Root)
    }
}

/// Rule registry: holds all namespaces and matches rules against
/// attribute sets using the specificity-tuple ranking.
#[derive(Debug, Clone, Default)]
pub struct RuleRegistry {
    namespaces: Vec<Namespace>,
}

/// Result of matching a rule.
#[derive(Debug, Clone)]
pub struct RuleMatch<'a> {
    pub rule: &'a RoutingRule,
    pub namespace: &'a Namespace,
    pub bindings: BTreeMap<String, String>,
}

/// YAML document structure: `namespaces` is a list of [`Namespace`].
#[derive(Debug, Deserialize)]
struct NamespaceConfig {
    namespaces: Vec<Namespace>,
}

impl RuleRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            namespaces: Vec::new(),
        }
    }

    /// Load namespaces from a YAML string and validate them.
    ///
    /// Validation checks:
    /// - No duplicate namespace names.
    /// - No duplicate rules within a namespace (same match pattern).
    /// - No cycles detectable from static parent patterns.
    /// - `max_depth` within `[1, 256]`.
    pub fn from_yaml(yaml: &str) -> crate::error::Result<Self> {
        let config: NamespaceConfig = serde_yaml::from_str(yaml)
            .map_err(|e| crate::error::KeyRackError::Other(format!("YAML parse: {e}")))?;

        let mut registry = Self::new();
        for ns in config.namespaces {
            registry.register(ns)?;
        }
        registry.detect_static_cycles()?;
        Ok(registry)
    }

    /// Normalize and validate a namespace before storing it.
    pub fn register(&mut self, mut namespace: Namespace) -> crate::error::Result<()> {
        namespace.name = crate::canon::normalize_text(&namespace.name);
        if namespace.name.is_empty() {
            return Err(crate::error::KeyRackError::Other(
                "empty namespace name".into(),
            ));
        }
        if self.namespaces.iter().any(|ns| ns.name == namespace.name) {
            return Err(crate::error::KeyRackError::Other(format!(
                "duplicate namespace: {}",
                namespace.name
            )));
        }
        if !(1..=256).contains(&namespace.max_depth) {
            return Err(crate::error::KeyRackError::Other(format!(
                "namespace {}: max_depth must be 1–256, got {}",
                namespace.name, namespace.max_depth
            )));
        }
        namespace.attachment = namespace
            .attachment
            .as_ref()
            .map(normalize_pattern)
            .transpose()?;
        namespace.routing_rules = namespace
            .routing_rules
            .iter()
            .map(RoutingRule::normalized)
            .collect::<crate::error::Result<_>>()?;
        let mut seen_patterns = std::collections::HashSet::new();
        for rule in &namespace.routing_rules {
            if !seen_patterns.insert(rule.match_pattern.clone()) {
                return Err(crate::error::KeyRackError::Other(format!(
                    "namespace {}: duplicate rule with pattern {:?}",
                    namespace.name, rule.match_pattern
                )));
            }
        }
        self.namespaces.push(namespace);
        Ok(())
    }

    /// Detect cycles reachable from static parent patterns alone.
    fn detect_static_cycles(&self) -> crate::error::Result<()> {
        for ns in &self.namespaces {
            for rule in &ns.routing_rules {
                if let ParentRef::Pattern(ref parent_pattern) = rule.parent {
                    let mut visited = std::collections::HashSet::new();
                    let start_key = format!("{:?}", rule.match_pattern);
                    visited.insert(start_key);

                    let mut current = parent_pattern.clone();
                    for _ in 0..256 {
                        let key = format!("{current:?}");
                        if !visited.insert(key) {
                            return Err(crate::error::KeyRackError::Other(format!(
                                "static cycle detected in namespace {}: pattern {:?} loops",
                                ns.name, rule.match_pattern
                            )));
                        }
                        if let Some(m) = self.match_rule(&current) {
                            match &m.rule.parent {
                                ParentRef::Pattern(_) => {
                                    let Some(parent) = m.rule.resolve_parent(&m.bindings) else {
                                        break;
                                    };
                                    current = parent;
                                }
                                _ => break,
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Find the best-matching rule for the given attributes.
    ///
    /// Searches all namespaces. Rules are ranked by specificity
    /// `(concrete_count, variable_count)` descending, then by
    /// `priority` descending. The highest-ranked match wins.
    #[must_use]
    pub fn match_rule(&self, attrs: &BTreeMap<String, String>) -> Option<RuleMatch<'_>> {
        let mut best: Option<(Specificity, i32, &RoutingRule, &Namespace)> = None;

        for ns in &self.namespaces {
            for rule in &ns.routing_rules {
                if rule.matches(attrs) {
                    let spec = rule.specificity();
                    let is_better = match &best {
                        None => true,
                        Some((bs, bp, _, _)) => (spec, rule.priority) > (*bs, *bp),
                    };
                    if is_better {
                        best = Some((spec, rule.priority, rule, ns));
                    }
                }
            }
        }

        best.map(|(_, _, rule, ns)| RuleMatch {
            rule,
            namespace: ns,
            bindings: rule.extract_bindings(attrs),
        })
    }

    /// Get a namespace by name.
    #[must_use]
    pub fn get_namespace(&self, name: &str) -> Option<&Namespace> {
        let name = crate::canon::normalize_text(name);
        self.namespaces.iter().find(|ns| ns.name == name)
    }

    /// List all registered namespaces.
    #[must_use]
    pub fn namespaces(&self) -> &[Namespace] {
        &self.namespaces
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn infra_namespace() -> Namespace {
        Namespace {
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
        }
    }

    fn app_namespace() -> Namespace {
        Namespace {
            name: "acme-docs-app".into(),
            attachment: Some(BTreeMap::from([("tenant".into(), "acme".into())])),
            max_depth: DEFAULT_MAX_DEPTH,
            routing_rules: vec![
                RoutingRule {
                    match_pattern: BTreeMap::from([
                        ("kind".into(), "dek".into()),
                        ("user".into(), "$U".into()),
                        ("doc".into(), "$D".into()),
                    ]),
                    parent: ParentRef::Pattern(BTreeMap::from([
                        ("kind".into(), "user-kek".into()),
                        ("user".into(), "$U".into()),
                    ])),
                    priority: 0,
                    key_spec: None,
                },
                RoutingRule {
                    match_pattern: BTreeMap::from([
                        ("kind".into(), "user-kek".into()),
                        ("user".into(), "$U".into()),
                    ]),
                    parent: ParentRef::Pattern(BTreeMap::from([(
                        "kind".into(),
                        "app-root".into(),
                    )])),
                    priority: 0,
                    key_spec: None,
                },
                RoutingRule {
                    match_pattern: BTreeMap::from([("kind".into(), "app-root".into())]),
                    parent: ParentRef::Attachment,
                    priority: 0,
                    key_spec: None,
                },
            ],
        }
    }

    #[test]
    fn specificity_concrete_preferred() {
        let concrete_rule = RoutingRule {
            match_pattern: BTreeMap::from([
                ("kind".into(), "dek".into()),
                ("tenant".into(), "acme".into()),
            ]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };
        let variable_rule = RoutingRule {
            match_pattern: BTreeMap::from([
                ("kind".into(), "dek".into()),
                ("tenant".into(), "$T".into()),
            ]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };

        let cs = concrete_rule.specificity();
        let vs = variable_rule.specificity();
        assert!(cs > vs, "concrete (2,0) should beat variable (1,1)");
    }

    #[test]
    fn specificity_more_vars_beats_fewer_total() {
        let two_var = RoutingRule {
            match_pattern: BTreeMap::from([
                ("kind".into(), "dek".into()),
                ("user".into(), "$U".into()),
                ("doc".into(), "$D".into()),
            ]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };
        let one_concrete = RoutingRule {
            match_pattern: BTreeMap::from([("kind".into(), "dek".into())]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };

        let s2 = two_var.specificity();
        let s1 = one_concrete.specificity();
        assert!(s2 > s1, "(1,2) should beat (1,0)");
    }

    #[test]
    fn priority_breaks_tie() {
        let mut reg = RuleRegistry::new();
        reg.register(Namespace {
            name: "test".into(),
            attachment: None,
            max_depth: DEFAULT_MAX_DEPTH,
            routing_rules: vec![
                RoutingRule {
                    match_pattern: BTreeMap::from([("kind".into(), "$K".into())]),
                    parent: ParentRef::Root,
                    priority: 10,
                    key_spec: None,
                },
                RoutingRule {
                    match_pattern: BTreeMap::from([("kind".into(), "$OTHER".into())]),
                    parent: ParentRef::Pattern(BTreeMap::from([("kind".into(), "kek".into())])),
                    priority: 20,
                    key_spec: None,
                },
            ],
        })
        .unwrap();

        let attrs = BTreeMap::from([("kind".into(), "dek".into())]);
        let m = reg.match_rule(&attrs).unwrap();
        assert_eq!(m.rule.priority, 20);
    }

    #[test]
    fn matching_and_bindings() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([
                ("kind".into(), "tenant-root".into()),
                ("tenant".into(), "$T".into()),
            ]),
            parent: ParentRef::Pattern(BTreeMap::from([("kind".into(), "root".into())])),
            priority: 0,
            key_spec: None,
        };

        let attrs = BTreeMap::from([
            ("kind".into(), "tenant-root".into()),
            ("tenant".into(), "acme".into()),
        ]);
        assert!(rule.matches(&attrs));
        let bindings = rule.extract_bindings(&attrs);
        assert_eq!(bindings.get("$T"), Some(&"acme".into()));
    }

    #[test]
    fn no_match_on_missing_attr() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([
                ("kind".into(), "dek".into()),
                ("tenant".into(), "$T".into()),
            ]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };

        let attrs = BTreeMap::from([("kind".into(), "dek".into())]);
        assert!(!rule.matches(&attrs));
    }

    #[test]
    fn no_match_on_value_mismatch() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([("kind".into(), "dek".into())]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };

        let attrs = BTreeMap::from([("kind".into(), "kek".into())]);
        assert!(!rule.matches(&attrs));
    }

    #[test]
    fn parent_interpolation() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([
                ("kind".into(), "dek".into()),
                ("user".into(), "$U".into()),
            ]),
            parent: ParentRef::Pattern(BTreeMap::from([
                ("kind".into(), "user-kek".into()),
                ("user".into(), "$U".into()),
            ])),
            priority: 0,
            key_spec: None,
        };

        let bindings = BTreeMap::from([("$U".into(), "alice".into())]);
        let parent = rule.resolve_parent(&bindings).unwrap();
        assert_eq!(parent.get("kind"), Some(&"user-kek".into()));
        assert_eq!(parent.get("user"), Some(&"alice".into()));
    }

    #[test]
    fn root_rule_has_no_parent() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([("kind".into(), "root".into())]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };
        assert!(rule.is_root());
        assert!(rule.resolve_parent(&BTreeMap::new()).is_none());
    }

    #[test]
    fn attachment_boundary() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([("kind".into(), "app-root".into())]),
            parent: ParentRef::Attachment,
            priority: 0,
            key_spec: None,
        };
        assert!(rule.is_attachment_boundary());
        assert!(rule.resolve_parent(&BTreeMap::new()).is_none());
    }

    #[test]
    fn cross_namespace_resolution() {
        let mut reg = RuleRegistry::new();
        reg.register(infra_namespace()).unwrap();
        reg.register(app_namespace()).unwrap();

        // App-level DEK match
        let dek_attrs = BTreeMap::from([
            ("kind".into(), "dek".into()),
            ("user".into(), "alice".into()),
            ("doc".into(), "doc-001".into()),
        ]);
        let m = reg.match_rule(&dek_attrs).unwrap();
        assert_eq!(m.namespace.name, "acme-docs-app");
        assert_eq!(m.bindings.get("$U"), Some(&"alice".into()));
        assert_eq!(m.bindings.get("$D"), Some(&"doc-001".into()));

        let parent_attrs = m.rule.resolve_parent(&m.bindings).unwrap();
        assert_eq!(parent_attrs.get("kind"), Some(&"user-kek".into()));
        assert_eq!(parent_attrs.get("user"), Some(&"alice".into()));

        // Walk up: user-kek → app-root
        let kek_m = reg.match_rule(&parent_attrs).unwrap();
        let kek_parent = kek_m.rule.resolve_parent(&kek_m.bindings).unwrap();
        assert_eq!(kek_parent.get("kind"), Some(&"app-root".into()));

        // Walk up: app-root hits attachment boundary
        let root_m = reg.match_rule(&kek_parent).unwrap();
        assert!(root_m.rule.is_attachment_boundary());

        // After crossing attachment: use namespace attachment context
        let attachment = root_m.namespace.attachment.as_ref().unwrap();
        let infra_attrs: BTreeMap<String, String> = [("kind".into(), "tenant-root".into())]
            .into_iter()
            .chain(attachment.iter().map(|(k, v)| (k.clone(), v.clone())))
            .collect();
        let infra_m = reg.match_rule(&infra_attrs).unwrap();
        assert_eq!(infra_m.namespace.name, "_infrastructure_");
        let infra_parent = infra_m.rule.resolve_parent(&infra_m.bindings).unwrap();
        assert_eq!(infra_parent.get("kind"), Some(&"root".into()));

        // Walk up: root has no parent
        let root_r = reg.match_rule(&infra_parent).unwrap();
        assert!(root_r.rule.is_root());
    }

    #[test]
    fn specificity_ordering_across_namespaces() {
        let mut reg = RuleRegistry::new();
        reg.register(infra_namespace()).unwrap();
        reg.register(app_namespace()).unwrap();

        // Infra tenant-root has (1 concrete, 1 var) = (1,1)
        // App dek has (1 concrete, 2 var) = (1,2)
        // App dek should win over infra tenant-root for dek-shaped attrs
        let attrs = BTreeMap::from([
            ("kind".into(), "dek".into()),
            ("user".into(), "bob".into()),
            ("doc".into(), "d1".into()),
        ]);
        let m = reg.match_rule(&attrs).unwrap();
        assert_eq!(m.namespace.name, "acme-docs-app");
    }

    #[test]
    fn namespace_listing() {
        let mut reg = RuleRegistry::new();
        reg.register(infra_namespace()).unwrap();
        assert_eq!(reg.namespaces().len(), 1);
        assert!(reg.get_namespace("_infrastructure_").is_some());
        assert!(reg.get_namespace("nonexistent").is_none());
    }

    #[test]
    fn from_yaml_basic() {
        let yaml = r#"
namespaces:
  - name: infra
    routing_rules:
      - match_pattern:
          kind: root
        parent: null
        priority: 0
      - match_pattern:
          kind: tenant-root
          tenant: "$T"
        parent:
          kind: root
        priority: 0
"#;
        let reg = RuleRegistry::from_yaml(yaml).unwrap();
        assert_eq!(reg.namespaces().len(), 1);
        assert_eq!(reg.namespaces()[0].routing_rules.len(), 2);
    }

    #[test]
    fn from_yaml_duplicate_namespace_rejected() {
        let yaml = r"
namespaces:
  - name: dup
    routing_rules: []
  - name: dup
    routing_rules: []
";
        let err = RuleRegistry::from_yaml(yaml);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("duplicate namespace"));
    }

    #[test]
    fn from_yaml_bad_max_depth() {
        let yaml = r"
namespaces:
  - name: test
    max_depth: 0
    routing_rules: []
";
        let err = RuleRegistry::from_yaml(yaml);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("max_depth"));
    }

    #[test]
    fn from_yaml_duplicate_rule_rejected() {
        let yaml = r"
namespaces:
  - name: test
    routing_rules:
      - match_pattern:
          kind: root
        parent: null
      - match_pattern:
          kind: root
        parent: null
";
        let err = RuleRegistry::from_yaml(yaml);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("duplicate rule"));
    }

    #[test]
    fn from_yaml_with_attachment() {
        let yaml = r#"
namespaces:
  - name: infra
    routing_rules:
      - match_pattern:
          kind: root
        parent: null
  - name: app
    attachment:
      tenant: acme
    routing_rules:
      - match_pattern:
          kind: app-root
        parent: "_attachment_"
"#;
        let reg = RuleRegistry::from_yaml(yaml).unwrap();
        assert_eq!(reg.namespaces().len(), 2);
        let app = reg.get_namespace("app").unwrap();
        assert!(app.attachment.is_some());
    }

    #[test]
    fn normalized_namespace_is_stored_and_found_by_either_spelling() {
        let mut ns = infra_namespace();
        ns.name = "cafe\u{301}".into();
        ns.attachment = Some(BTreeMap::from([(
            "re\u{301}gion".into(),
            "e\u{301}".into(),
        )]));
        let mut registry = RuleRegistry::new();
        registry.register(ns.clone()).unwrap();
        assert_eq!(registry.namespaces()[0].name, "café");
        assert_eq!(
            registry
                .get_namespace("cafe\u{301}")
                .unwrap()
                .attachment
                .as_ref()
                .unwrap(),
            &BTreeMap::from([("région".into(), "é".into())])
        );
        ns.name = "café".into();
        assert!(registry.register(ns).is_err());
        assert_eq!(registry.namespaces().len(), 1);
    }

    #[test]
    fn normalized_patterns_match_and_bind_before_parent_resolution() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([
                ("te\u{301}nant".into(), "e\u{301}".into()),
                ("user".into(), "$E\u{301}".into()),
            ]),
            parent: ParentRef::Pattern(BTreeMap::from([("pare\u{301}nt".into(), "$É".into())])),
            priority: 0,
            key_spec: None,
        };
        let attrs = BTreeMap::from([
            ("ténant".into(), "é".into()),
            ("user".into(), "$e\u{301}".into()),
        ]);
        assert!(rule.matches(&attrs));
        let bindings = rule.extract_bindings(&attrs);
        assert_eq!(bindings, BTreeMap::from([("$É".into(), "$é".into())]));
        assert_eq!(
            rule.resolve_parent(&bindings),
            Some(BTreeMap::from([("parént".into(), "$é".into())]))
        );
        assert!(rule.resolve_parent(&BTreeMap::new()).is_none());
    }

    #[test]
    fn normalized_duplicate_attribute_keys_fail_closed_even_with_identical_values() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([("é".into(), "$E".into())]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };
        let invalid = BTreeMap::from([
            ("é".into(), "same".into()),
            ("e\u{301}".into(), "same".into()),
        ]);
        assert!(!rule.matches(&invalid));
        assert!(rule.extract_bindings(&invalid).is_empty());
        let invalid_rule = RoutingRule {
            match_pattern: invalid,
            ..rule
        };
        assert!(!invalid_rule.matches(&BTreeMap::from([("é".into(), "same".into())])));
        let mut ns = infra_namespace();
        ns.routing_rules = vec![invalid_rule];
        assert!(RuleRegistry::new().register(ns).is_err());
    }

    #[test]
    fn normalized_duplicate_rules_parents_and_attachments_are_rejected() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([("tenant".into(), "é".into())]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };
        let mut ns = infra_namespace();
        ns.routing_rules = vec![
            rule.clone(),
            RoutingRule {
                match_pattern: BTreeMap::from([("tenant".into(), "e\u{301}".into())]),
                ..rule.clone()
            },
        ];
        assert!(RuleRegistry::new().register(ns.clone()).is_err());
        let duplicate = BTreeMap::from([("é".into(), "a".into()), ("e\u{301}".into(), "b".into())]);
        ns.routing_rules = vec![RoutingRule {
            parent: ParentRef::Pattern(duplicate.clone()),
            ..rule.clone()
        }];
        assert!(RuleRegistry::new().register(ns.clone()).is_err());
        ns.routing_rules = vec![rule];
        ns.attachment = Some(duplicate);
        assert!(RuleRegistry::new().register(ns).is_err());
    }

    #[test]
    fn normalized_duplicate_variable_names_are_rejected() {
        let rule = RoutingRule {
            match_pattern: BTreeMap::from([
                ("a".into(), "$É".into()),
                ("b".into(), "$E\u{301}".into()),
            ]),
            parent: ParentRef::Root,
            priority: 0,
            key_spec: None,
        };
        assert!(!rule.matches(&BTreeMap::from([
            ("a".into(), "one".into()),
            ("b".into(), "two".into())
        ])));
        let mut ns = infra_namespace();
        ns.routing_rules = vec![rule];
        assert!(RuleRegistry::new().register(ns).is_err());
    }

    #[test]
    fn yaml_duplicate_raw_and_normalized_keys_are_rejected_before_collection() {
        for duplicate_key in ["é", "e\u{301}"] {
            for location in ["match_pattern", "parent", "attachment"] {
                let duplicate = format!("é: same\n          {duplicate_key}: same");
                let yaml = match location {
                    "match_pattern" => format!("namespaces:\n  - name: test\n    routing_rules:\n      - match_pattern:\n          {duplicate}\n        parent: null\n"),
                    "parent" => format!("namespaces:\n  - name: test\n    routing_rules:\n      - match_pattern: {{kind: child}}\n        parent:\n          {duplicate}\n"),
                    _ => format!("namespaces:\n  - name: test\n    attachment:\n      é: same\n      {duplicate_key}: same\n    routing_rules: []\n"),
                };
                assert!(
                    RuleRegistry::from_yaml(&yaml).is_err(),
                    "{location}: {duplicate_key}"
                );
            }
        }
    }
}
