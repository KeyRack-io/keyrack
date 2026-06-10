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

use crate::key::ProviderRef;
use crate::tags::IdentityTags;
use std::collections::BTreeMap;

/// Selects the provider for a new key given its identity tags.
///
/// Rules are evaluated in order; the first rule whose `match_tags` are all
/// present with the required values wins. Falls back to `default` if no rule
/// matches.
#[derive(Clone)]
pub struct ProviderRouter {
    rules: Vec<(BTreeMap<String, String>, ProviderRef)>,
    default: ProviderRef,
}

impl ProviderRouter {
    /// Build a router from a list of `(match_tags, provider_ref)` rules and
    /// a default provider name.
    pub fn new(rules: Vec<(BTreeMap<String, String>, ProviderRef)>, default: ProviderRef) -> Self {
        Self { rules, default }
    }

    /// Select the provider for a new key based on its identity tags.
    ///
    /// Returns a clone of the matching (or default) [`ProviderRef`].
    pub fn select(&self, tags: &IdentityTags) -> ProviderRef {
        for (match_tags, provider) in &self.rules {
            if match_tags
                .iter()
                .all(|(k, v)| tags.get(k) == Some(v.as_str()))
            {
                return provider.clone();
            }
        }
        self.default.clone()
    }

    /// The name of the default provider.
    pub fn default_ref(&self) -> &ProviderRef {
        &self.default
    }
}
