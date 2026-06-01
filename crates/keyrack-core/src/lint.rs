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

//! Namespace rule linting engine.
//!
//! Operates on a parsed [`RuleRegistry`] and returns a list of
//! diagnostics.  This module runs purely offline — it does not touch
//! storage or providers.
//!
//! Checks performed (beyond what [`RuleRegistry::from_yaml`] already validates):
//!
//! 1. **Unbound variables** — parent pattern references `$VAR` not captured
//!    by the match pattern (Problem 1).
//! 2. **Unreachable rules** — a rule is completely shadowed by a
//!    higher-specificity rule that matches a superset of inputs (Problem 2).
//! 3. **Ambiguous rules** — two rules with equal specificity and priority
//!    both match some input, but resolve to different parents (Problem 2).
//! 4. **Missing attachment context** — a namespace has an attachment-boundary
//!    rule but no `attachment` field.
//! 5. **Empty namespaces** — a namespace with zero routing rules.
//! 6. **Depth budget warnings** — `max_depth` set unusually low (<3) or
//!    high (>64).

use crate::rule::{Namespace, ParentRef, RuleRegistry, RoutingRule};
use serde::Serialize;

/// Severity level for a lint diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// A single lint diagnostic.
#[derive(Debug, Clone, Serialize)]
pub struct LintDiagnostic {
    pub severity: Severity,
    pub namespace: String,
    pub rule_index: Option<usize>,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for LintDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let loc = match self.rule_index {
            Some(i) => format!("{}[rule {}]", self.namespace, i),
            None => self.namespace.clone(),
        };
        write!(f, "{}: [{}] {} ({})", loc, self.severity_tag(), self.message, self.code)
    }
}

impl LintDiagnostic {
    fn severity_tag(&self) -> &'static str {
        match self.severity {
            Severity::Error => "ERROR",
            Severity::Warning => "WARN",
            Severity::Info => "INFO",
        }
    }
}

/// Run all lint checks against a parsed registry and return diagnostics.
pub fn lint(registry: &RuleRegistry) -> Vec<LintDiagnostic> {
    let mut diags = Vec::new();
    for ns in registry.namespaces() {
        check_empty_namespace(ns, &mut diags);
        check_depth_budget(ns, &mut diags);
        check_missing_attachment(ns, &mut diags);
        for (i, rule) in ns.routing_rules.iter().enumerate() {
            check_unbound_variables(ns, i, rule, &mut diags);
        }
        check_ambiguous_rules(ns, &mut diags);
        check_unreachable_rules(ns, &mut diags);
    }
    diags
}

fn check_empty_namespace(ns: &Namespace, diags: &mut Vec<LintDiagnostic>) {
    if ns.routing_rules.is_empty() {
        diags.push(LintDiagnostic {
            severity: Severity::Warning,
            namespace: ns.name.clone(),
            rule_index: None,
            code: "W001".into(),
            message: "namespace has no routing rules".into(),
        });
    }
}

fn check_depth_budget(ns: &Namespace, diags: &mut Vec<LintDiagnostic>) {
    if ns.max_depth < 3 {
        diags.push(LintDiagnostic {
            severity: Severity::Warning,
            namespace: ns.name.clone(),
            rule_index: None,
            code: "W002".into(),
            message: format!("max_depth={} is unusually low — most hierarchies need at least 3 levels", ns.max_depth),
        });
    } else if ns.max_depth > 64 {
        diags.push(LintDiagnostic {
            severity: Severity::Warning,
            namespace: ns.name.clone(),
            rule_index: None,
            code: "W003".into(),
            message: format!("max_depth={} is unusually high — deep hierarchies impact cascade-disable latency", ns.max_depth),
        });
    }
}

fn check_missing_attachment(ns: &Namespace, diags: &mut Vec<LintDiagnostic>) {
    let has_boundary = ns.routing_rules.iter().any(RoutingRule::is_attachment_boundary);
    if has_boundary && ns.attachment.is_none() {
        diags.push(LintDiagnostic {
            severity: Severity::Error,
            namespace: ns.name.clone(),
            rule_index: None,
            code: "E001".into(),
            message: "namespace has an _attachment_ boundary rule but no attachment context defined".into(),
        });
    }
}

/// Check that every `$VAR` in the parent pattern is captured by the
/// match pattern (Problem 1: no implicit variable propagation).
fn check_unbound_variables(
    ns: &Namespace,
    idx: usize,
    rule: &RoutingRule,
    diags: &mut Vec<LintDiagnostic>,
) {
    let ParentRef::Pattern(ref parent) = rule.parent else {
        return;
    };

    let bound_vars: std::collections::HashSet<&str> = rule
        .match_pattern
        .values()
        .filter(|v| v.starts_with('$'))
        .map(String::as_str)
        .collect();

    for (key, value) in parent {
        if value.starts_with('$') && !bound_vars.contains(value.as_str()) {
            diags.push(LintDiagnostic {
                severity: Severity::Error,
                namespace: ns.name.clone(),
                rule_index: Some(idx),
                code: "E002".into(),
                message: format!(
                    "parent pattern key \"{key}\" references unbound variable \"{value}\" — \
                     it must be captured by the match pattern"
                ),
            });
        }
    }
}

/// Detect pairs of rules with equal specificity+priority that could
/// both match some input but resolve to different parents.
fn check_ambiguous_rules(ns: &Namespace, diags: &mut Vec<LintDiagnostic>) {
    let rules = &ns.routing_rules;
    for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            let a = &rules[i];
            let b = &rules[j];
            let spec_a = (a.specificity(), a.priority);
            let spec_b = (b.specificity(), b.priority);
            if spec_a != spec_b {
                continue;
            }
            if a.parent == b.parent {
                continue;
            }
            if could_overlap(a, b) {
                diags.push(LintDiagnostic {
                    severity: Severity::Warning,
                    namespace: ns.name.clone(),
                    rule_index: Some(i),
                    code: "W004".into(),
                    message: format!(
                        "rule {i} and rule {j} have equal specificity and priority but \
                         different parents — matching is ambiguous for overlapping inputs"
                    ),
                });
            }
        }
    }
}

/// Detect rules that are completely shadowed by a higher-specificity rule.
fn check_unreachable_rules(ns: &Namespace, diags: &mut Vec<LintDiagnostic>) {
    let rules = &ns.routing_rules;
    for (i, candidate) in rules.iter().enumerate() {
        let candidate_rank = (candidate.specificity(), candidate.priority);
        for (j, dominator) in rules.iter().enumerate() {
            if i == j {
                continue;
            }
            let dominator_rank = (dominator.specificity(), dominator.priority);
            if dominator_rank <= candidate_rank {
                continue;
            }
            if subsumes(dominator, candidate) {
                diags.push(LintDiagnostic {
                    severity: Severity::Warning,
                    namespace: ns.name.clone(),
                    rule_index: Some(i),
                    code: "W005".into(),
                    message: format!(
                        "rule {i} is unreachable — completely shadowed by higher-specificity rule {j}"
                    ),
                });
                break;
            }
        }
    }
}

/// Conservative overlap check: two rules *could* overlap if every key
/// present in both patterns either has the same concrete value, or at
/// least one side is a variable.
fn could_overlap(a: &RoutingRule, b: &RoutingRule) -> bool {
    for (key, va) in &a.match_pattern {
        if let Some(vb) = b.match_pattern.get(key) {
            let a_var = va.starts_with('$');
            let b_var = vb.starts_with('$');
            if !a_var && !b_var && va != vb {
                return false;
            }
        }
    }
    true
}

/// `dominator` subsumes `candidate` if every input matching `candidate`
/// also matches `dominator`.  This holds when dominator's pattern keys
/// are a subset of candidate's, and for each shared key the dominator
/// either has a variable (matches anything) or the same concrete value.
fn subsumes(dominator: &RoutingRule, candidate: &RoutingRule) -> bool {
    for (key, dval) in &dominator.match_pattern {
        match candidate.match_pattern.get(key) {
            None => return false,
            Some(cval) => {
                if dval.starts_with('$') {
                    continue;
                }
                if cval.starts_with('$') {
                    return false;
                }
                if dval != cval {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::DEFAULT_MAX_DEPTH;
    use std::collections::BTreeMap;

    fn make_ns(name: &str, rules: Vec<RoutingRule>) -> Namespace {
        Namespace {
            name: name.into(),
            attachment: None,
            routing_rules: rules,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }

    fn make_rule(
        pattern: &[(&str, &str)],
        parent: ParentRef,
        priority: i32,
    ) -> RoutingRule {
        RoutingRule {
            match_pattern: pattern.iter().map(|(k, v)| ((*k).into(), (*v).into())).collect(),
            parent,
            priority,
            key_spec: None,
        }
    }

    #[test]
    fn unbound_variable_detected() {
        let rule = make_rule(
            &[("kind", "dek"), ("user", "$U")],
            ParentRef::Pattern(BTreeMap::from([
                ("kind".into(), "kek".into()),
                ("region".into(), "$R".into()),
            ])),
            0,
        );
        let ns = make_ns("test", vec![rule]);
        let mut reg = RuleRegistry::new();
        reg.register(ns);

        let diags = lint(&reg);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "E002");
        assert!(diags[0].message.contains("$R"));
    }

    #[test]
    fn bound_variable_clean() {
        let rule = make_rule(
            &[("kind", "dek"), ("user", "$U")],
            ParentRef::Pattern(BTreeMap::from([
                ("kind".into(), "kek".into()),
                ("user".into(), "$U".into()),
            ])),
            0,
        );
        let ns = make_ns("test", vec![rule]);
        let mut reg = RuleRegistry::new();
        reg.register(ns);

        let diags = lint(&reg);
        assert!(diags.is_empty(), "no diagnostics expected: {diags:?}");
    }

    #[test]
    fn empty_namespace_warning() {
        let ns = make_ns("empty", vec![]);
        let mut reg = RuleRegistry::new();
        reg.register(ns);
        let diags = lint(&reg);
        assert!(diags.iter().any(|d| d.code == "W001"));
    }

    #[test]
    fn missing_attachment_error() {
        let rule = make_rule(&[("kind", "app-root")], ParentRef::Attachment, 0);
        let ns = make_ns("app", vec![rule]);
        let mut reg = RuleRegistry::new();
        reg.register(ns);
        let diags = lint(&reg);
        assert!(diags.iter().any(|d| d.code == "E001"));
    }

    #[test]
    fn low_depth_warning() {
        let ns = Namespace {
            name: "shallow".into(),
            attachment: None,
            routing_rules: vec![make_rule(&[("kind", "root")], ParentRef::Root, 0)],
            max_depth: 2,
        };
        let mut reg = RuleRegistry::new();
        reg.register(ns);
        let diags = lint(&reg);
        assert!(diags.iter().any(|d| d.code == "W002"));
    }

    #[test]
    fn ambiguous_rules_detected() {
        let r1 = make_rule(
            &[("kind", "$K")],
            ParentRef::Root,
            0,
        );
        let r2 = make_rule(
            &[("kind", "$K")],
            ParentRef::Pattern(BTreeMap::from([("kind".into(), "other".into())])),
            0,
        );
        let ns = make_ns("ambig", vec![r1, r2]);
        let mut reg = RuleRegistry::new();
        reg.register(ns);
        let diags = lint(&reg);
        assert!(diags.iter().any(|d| d.code == "W004"), "expected ambiguity warning: {diags:?}");
    }

    #[test]
    fn unreachable_rule_detected() {
        let general = make_rule(&[("kind", "$K")], ParentRef::Root, 0);
        let specific = make_rule(
            &[("kind", "dek"), ("tenant", "$T")],
            ParentRef::Root,
            0,
        );
        // general has specificity (0,1), specific has (1,1) — specific dominates
        // But general matches a superset, so it's NOT unreachable
        // Let's make a case where it IS unreachable:
        let dominated = make_rule(&[("kind", "dek")], ParentRef::Root, 0);
        let dominator = make_rule(&[("kind", "dek")], ParentRef::Root, 10);

        let ns = make_ns("shadow", vec![dominated, dominator, general, specific]);
        let mut reg = RuleRegistry::new();
        reg.register(ns);
        let diags = lint(&reg);
        assert!(diags.iter().any(|d| d.code == "W005"), "expected unreachable warning: {diags:?}");
    }

    #[test]
    fn clean_config_no_diagnostics() {
        let yaml = r#"
namespaces:
  - name: infra
    routing_rules:
      - match_pattern:
          kind: root
        parent: null
      - match_pattern:
          kind: tenant-root
          tenant: "$T"
        parent:
          kind: root
"#;
        let reg = RuleRegistry::from_yaml(yaml).unwrap();
        let diags = lint(&reg);
        assert!(diags.is_empty(), "clean config should have no diags: {diags:?}");
    }
}
