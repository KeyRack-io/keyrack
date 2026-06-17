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

//! Provider router: selects which named provider backs a NEW key based on
//! its identity tags and the operator-configured routing rules.
//!
//! Routing only applies to key CREATION (and lazy provisioning). Once a key
//! version exists, its `provider_ref` is authoritative — routing rules are
//! not re-evaluated at read/crypto time.
//!
//! ## Rule actions (ADR-0001 Amendment 1)
//!
//! - **`Route`** — authoritative pin to a provider; caller cannot override.
//! - **`Delegate`** — caller may select within a bounded set (or any
//!   registered provider with `DelegateAny`). Caller selection is
//!   DEFAULT-DENY unless a delegate opens it.
//!
//! ## Precedence
//!
//! 1. Route pin (first match wins)
//! 2. Delegate (first match wins; caller selects within set)
//! 3. Default provider (configured fallback)

use crate::key::ProviderRef;
use crate::tags::IdentityTags;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The action a routing rule takes when matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    /// Pin to a specific provider — authoritative, caller cannot override.
    Route(ProviderRef),
    /// Caller may select from a bounded set of providers.
    Delegate(BTreeSet<ProviderRef>),
    /// Caller may select any registered provider (wildcard delegate).
    DelegateAny,
}

/// A single routing rule: match tags → action.
#[derive(Debug, Clone)]
pub struct RoutingRule {
    pub match_tags: BTreeMap<String, String>,
    pub action: RuleAction,
}

/// The outcome of routing evaluation — what the router decided and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    /// A `route` rule matched — provider is pinned; caller cannot override.
    Pinned(ProviderRef),
    /// A `delegate` rule matched — caller may select from the given set.
    Delegated(BTreeSet<ProviderRef>),
    /// A `delegate *` rule matched — caller may select any registered provider.
    DelegatedAny,
    /// No rule matched — use the default provider.
    Default(ProviderRef),
}

/// Selects the provider for a new key given its identity tags.
///
/// Rules are evaluated in order; the first rule whose `match_tags` are all
/// present with the required values wins. Falls back to `default` if no rule
/// matches.
#[derive(Clone)]
pub struct ProviderRouter {
    rules: Vec<RoutingRule>,
    default: ProviderRef,
}

impl ProviderRouter {
    /// Build a router from a list of `(match_tags, provider_ref)` rules and
    /// a default provider name.
    ///
    /// This is the backward-compatible constructor for the simple route-only
    /// model (pre-0.3.0). Each rule is a `Route` action.
    pub fn new(rules: Vec<(BTreeMap<String, String>, ProviderRef)>, default: ProviderRef) -> Self {
        let rules = rules
            .into_iter()
            .map(|(match_tags, provider)| RoutingRule {
                match_tags,
                action: RuleAction::Route(provider),
            })
            .collect();
        Self { rules, default }
    }

    /// Build a router with the full rule model (route + delegate).
    pub fn with_rules(rules: Vec<RoutingRule>, default: ProviderRef) -> Self {
        Self { rules, default }
    }

    /// Evaluate routing rules and return the outcome (without resolving caller
    /// selection). Use this for the two-phase resolution in
    /// `resolve_create_provider`.
    pub fn evaluate(&self, tags: &IdentityTags) -> RouteOutcome {
        for rule in &self.rules {
            if rule
                .match_tags
                .iter()
                .all(|(k, v)| tags.get(k) == Some(v.as_str()))
            {
                return match &rule.action {
                    RuleAction::Route(provider) => RouteOutcome::Pinned(provider.clone()),
                    RuleAction::Delegate(set) => RouteOutcome::Delegated(set.clone()),
                    RuleAction::DelegateAny => RouteOutcome::DelegatedAny,
                };
            }
        }
        RouteOutcome::Default(self.default.clone())
    }

    /// Select the provider for a new key based on its identity tags.
    ///
    /// Returns a clone of the matching (or default) [`ProviderRef`].
    /// This is the simple path (no caller selection); equivalent to
    /// `evaluate()` → take the pinned/default provider.
    pub fn select(&self, tags: &IdentityTags) -> ProviderRef {
        match self.evaluate(tags) {
            RouteOutcome::Pinned(p) | RouteOutcome::Default(p) => p,
            // Delegate without a caller selection → use the default.
            RouteOutcome::Delegated(_) | RouteOutcome::DelegatedAny => self.default.clone(),
        }
    }

    /// The name of the default provider.
    pub fn default_ref(&self) -> &ProviderRef {
        &self.default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> IdentityTags {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        IdentityTags::from_map(map)
    }

    #[test]
    fn route_rule_pins_provider() {
        let router = ProviderRouter::new(
            vec![(
                BTreeMap::from([("tenant".to_string(), "acme".to_string())]),
                ProviderRef::new("acme-hsm"),
            )],
            ProviderRef::new("default"),
        );
        assert_eq!(
            router.evaluate(&tags(&[("tenant", "acme")])),
            RouteOutcome::Pinned(ProviderRef::new("acme-hsm"))
        );
    }

    #[test]
    fn no_match_gives_default() {
        let router = ProviderRouter::new(
            vec![(
                BTreeMap::from([("tenant".to_string(), "acme".to_string())]),
                ProviderRef::new("acme-hsm"),
            )],
            ProviderRef::new("default"),
        );
        assert_eq!(
            router.evaluate(&tags(&[("tenant", "other")])),
            RouteOutcome::Default(ProviderRef::new("default"))
        );
    }

    #[test]
    fn delegate_rule_returns_set() {
        let set: BTreeSet<ProviderRef> = [ProviderRef::new("a"), ProviderRef::new("b")]
            .into_iter()
            .collect();
        let router = ProviderRouter::with_rules(
            vec![RoutingRule {
                match_tags: BTreeMap::from([("tier".to_string(), "premium".to_string())]),
                action: RuleAction::Delegate(set.clone()),
            }],
            ProviderRef::new("default"),
        );
        assert_eq!(
            router.evaluate(&tags(&[("tier", "premium")])),
            RouteOutcome::Delegated(set)
        );
    }

    #[test]
    fn delegate_any_rule() {
        let router = ProviderRouter::with_rules(
            vec![RoutingRule {
                match_tags: BTreeMap::from([("mode".to_string(), "imperative".to_string())]),
                action: RuleAction::DelegateAny,
            }],
            ProviderRef::new("default"),
        );
        assert_eq!(
            router.evaluate(&tags(&[("mode", "imperative")])),
            RouteOutcome::DelegatedAny
        );
    }

    #[test]
    fn first_match_wins() {
        let router = ProviderRouter::with_rules(
            vec![
                RoutingRule {
                    match_tags: BTreeMap::from([("tenant".to_string(), "acme".to_string())]),
                    action: RuleAction::Route(ProviderRef::new("first")),
                },
                RoutingRule {
                    match_tags: BTreeMap::from([("tenant".to_string(), "acme".to_string())]),
                    action: RuleAction::Route(ProviderRef::new("second")),
                },
            ],
            ProviderRef::new("default"),
        );
        assert_eq!(
            router.evaluate(&tags(&[("tenant", "acme")])),
            RouteOutcome::Pinned(ProviderRef::new("first"))
        );
    }

    #[test]
    fn select_falls_through_delegate_to_default() {
        let router = ProviderRouter::with_rules(
            vec![RoutingRule {
                match_tags: BTreeMap::from([("tier".to_string(), "premium".to_string())]),
                action: RuleAction::DelegateAny,
            }],
            ProviderRef::new("default"),
        );
        // select() without explicit caller choice falls back to default
        assert_eq!(
            router.select(&tags(&[("tier", "premium")])),
            ProviderRef::new("default")
        );
    }

    #[test]
    fn backward_compat_no_rules_returns_default() {
        let router = ProviderRouter::new(vec![], ProviderRef::new("software"));
        assert_eq!(
            router.evaluate(&tags(&[("anything", "here")])),
            RouteOutcome::Default(ProviderRef::new("software"))
        );
        assert_eq!(
            router.select(&tags(&[("anything", "here")])),
            ProviderRef::new("software")
        );
    }
}
