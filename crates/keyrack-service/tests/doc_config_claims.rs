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

//! Checks documented configuration defaults against the actual defaults.
//!
//! A claim about a default is mechanically checkable, so it should not need a
//! human to notice when it goes stale. It twice did not: making the audit
//! chain unconditional left three docs claiming the chain only existed with
//! signing, and making `audit_signing_key_ephemeral` an explicit opt-in left
//! three docs claiming an ephemeral key is the default. Both times the code
//! change was correct and the docs were reviewed by reading them.
//!
//! The expected value in each rule below is compared against what is parsed
//! out of `ServiceConfig::default()`, so flipping a default in `config.rs`
//! changes what this test demands of the prose rather than silently passing.
//!
//! Detection-claim wording is guarded separately, by
//! `keyless_audit_claims_state_their_bounds` in
//! `crates/keyrack-core/tests/doc_claims.rs`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // crates/keyrack-service -> crates -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root above crates/keyrack-service")
        .to_path_buf()
}

/// Phrases that turn a mention of a setting into an assertion about its
/// default. "`audit_signing_key_ephemeral: true` (development only)" describes
/// a setting; "ephemeral key by default" asserts a default.
const DEFAULT_ASSERTION_MARKERS: &[&str] =
    &["by default", "defaults to", "default is", "the default"];

/// `CHANGELOG.md` is an append-only record: entries describe what was true at
/// the time and are not rewritten, so its historical "ephemeral by default" is
/// correct in context.
const EXEMPT: &[&str] = &["CHANGELOG.md"];

struct DefaultClaimRule {
    /// Field in `ServiceConfig::default()`.
    field: &'static str,
    /// Words that name the field's *enabled* state in prose.
    subject_words: &'static [&'static str],
    /// The literal that would have to appear in `ServiceConfig::default()` for
    /// "<subject> by default" to be a true statement.
    true_when_default_is: &'static str,
    /// How to state it correctly while the default is something else.
    hint: &'static str,
}

/// Only defaults whose *enabled* state has an unambiguous name in prose are
/// listed. `sign_audit_events` is deliberately absent: "signing is off by
/// default" is both correct and useful, so pairing "signing" with a default
/// marker cannot be forbidden outright, and a rule needing negation detection
/// would be a worse control than none.
const RULES: &[DefaultClaimRule] = &[
    DefaultClaimRule {
        field: "legacy_compromised_key_decrypt",
        subject_words: &["legacy_compromised_key_decrypt: true"],
        true_when_default_is: "true",
        hint:
            "compromised decrypt is denied unless the dangerous legacy flag is explicitly enabled.",
    },
    DefaultClaimRule {
        field: "audit_signing_key_ephemeral",
        subject_words: &["ephemeral"],
        true_when_default_is: "true",
        hint: "enabling signing requires a persistent `audit_signing_key_path`; \
               `audit_signing_key_ephemeral: true` is an explicit development opt-in. \
               Describe the setting without asserting it is the default.",
    },
    DefaultClaimRule {
        field: "pdp",
        subject_words: &[
            "always_allow",
            "always allow",
            "allow everything",
            "allow-everything",
        ],
        true_when_default_is: "Some(PdpConfig::AlwaysAllow)",
        hint: "`pdp:` is required and has no default; omitting it is a startup error, \
               and `always_allow` must be selected explicitly.",
    },
];

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Field-to-literal map parsed from the `ServiceConfig::default()` body.
fn service_config_defaults(source: &str) -> BTreeMap<String, String> {
    let start = source
        .find("impl Default for ServiceConfig")
        .expect("config.rs should contain `impl Default for ServiceConfig`");
    let body = &source[start..];
    let end = body
        .find("\n}\n")
        .expect("impl block should be terminated at column 0");

    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("//") {
                return None;
            }
            let (field, value) = line.split_once(':')?;
            let field = field.trim();
            if field.is_empty() || !field.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                return None;
            }
            Some((
                field.to_string(),
                value.trim().trim_end_matches(',').to_string(),
            ))
        })
        .collect()
}

fn markdown_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(name.as_ref(), "target" | "node_modules" | ".git") {
                markdown_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// Sentence-ish units. Splitting on line breaks as well as terminators keeps a
/// claim in one table cell from being qualified by a different row.
fn sentences(text: &str) -> impl Iterator<Item = &str> {
    text.split(['.', '!', '?', '\n', '|'])
}

#[test]
fn service_config_defaults_are_parsable() {
    let root = repo_root();
    let defaults =
        service_config_defaults(&read(&root.join("crates/keyrack-service/src/config.rs")));

    assert!(
        defaults.len() >= 10,
        "parsed only {} fields from ServiceConfig::default() — the parser has drifted from \
         config.rs and every rule below would pass vacuously",
        defaults.len()
    );

    for rule in RULES {
        assert!(
            defaults.contains_key(rule.field),
            "rule references `{}`, which is not a field in ServiceConfig::default(). If it \
             was renamed, update the rule; do not delete it.",
            rule.field
        );
    }
}

#[test]
fn documented_config_defaults_match_config_rs() {
    let root = repo_root();
    let defaults =
        service_config_defaults(&read(&root.join("crates/keyrack-service/src/config.rs")));

    let mut docs = Vec::new();
    markdown_files(&root, &mut docs);
    let mut violations = Vec::new();

    for rule in RULES {
        let actual = defaults
            .get(rule.field)
            .unwrap_or_else(|| panic!("missing field `{}`; see the parsability test", rule.field));

        // The claim the docs make would be true — nothing to enforce.
        if actual == rule.true_when_default_is {
            continue;
        }

        for path in &docs {
            let rel = path.strip_prefix(&root).unwrap_or(path);
            if EXEMPT.iter().any(|e| rel.to_string_lossy().as_ref() == *e) {
                continue;
            }

            let text = read(path).to_lowercase();
            for (idx, line) in text.lines().enumerate() {
                let asserts = sentences(line).any(|sentence| {
                    rule.subject_words.iter().any(|w| sentence.contains(w))
                        && DEFAULT_ASSERTION_MARKERS
                            .iter()
                            .any(|m| sentence.contains(m))
                });
                if asserts {
                    violations.push(format!(
                        "  {}:{} — asserts that `{}` defaults to {}, but \
                         ServiceConfig::default() sets it to `{actual}`.\n      Fix: {}",
                        rel.display(),
                        idx + 1,
                        rule.field,
                        rule.true_when_default_is,
                        rule.hint
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "{} documented configuration default(s) contradict crates/keyrack-service/src/config.rs:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[test]
fn compromised_legacy_operator_example_matches_literal_and_yaml_defaults() {
    let root = repo_root();
    let source = read(&root.join("crates/keyrack-service/src/config.rs"));
    let defaults = service_config_defaults(&source);
    let literal = &defaults["legacy_compromised_key_decrypt"];
    let yaml = keyrack_service::config::ServiceConfig::from_yaml("pdp: {type: always_deny}\n")
        .expect("missing legacy flag is valid");
    assert_eq!(yaml.legacy_compromised_key_decrypt.to_string(), *literal);
    let snippet = format!("```yaml\nlegacy_compromised_key_decrypt: {literal}\n```");
    assert!(read(&root.join("docs/OPERATOR.md")).contains(&snippet));
}
