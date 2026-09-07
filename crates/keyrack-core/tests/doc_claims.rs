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

//! Executable checks on verification claims made in the documentation.
//!
//! `docs/FORMAL_VERIFICATION.md` tells readers to run named Kani harnesses.
//! A name that does not exist is an unfalsifiable claim: the reader gets an
//! error, not a proof. Reviewing the prose is not a control against that
//! drifting again, so the names are checked mechanically.
//!
//! The same applies to the keyless audit-verification claim: it is true only
//! within two bounds, and the bounds were stated in some docs and omitted in
//! others by the same change. See `keyless_audit_claims_state_their_bounds`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // crates/keyrack-core -> crates -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root above crates/keyrack-core")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Harness names the doc instructs the reader to pass to `--harness`.
fn documented_harness_names(doc: &str) -> Vec<String> {
    doc.split("--harness ")
        .skip(1)
        .filter_map(|rest| {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

#[test]
fn documented_kani_harnesses_exist() {
    let root = repo_root();
    let doc = read(&root.join("docs/FORMAL_VERIFICATION.md"));
    let proofs = read(&root.join("crates/keyrack-core/src/kani_proofs.rs"));

    let documented = documented_harness_names(&doc);
    assert!(
        !documented.is_empty(),
        "expected FORMAL_VERIFICATION.md to document at least one --harness invocation"
    );

    for name in documented {
        assert!(
            proofs.contains(&format!("fn {name}(")),
            "docs/FORMAL_VERIFICATION.md tells the reader to run \
             `cargo kani -p keyrack-core --harness {name}`, but no such harness exists in \
             crates/keyrack-core/src/kani_proofs.rs. Either write the harness or correct \
             the document."
        );
    }
}

/// Every harness in the file must also carry `#[kani::proof]`, so a name that
/// exists as a plain helper cannot satisfy the check above.
#[test]
fn documented_kani_harnesses_are_actually_proofs() {
    let root = repo_root();
    let doc = read(&root.join("docs/FORMAL_VERIFICATION.md"));
    let proofs = read(&root.join("crates/keyrack-core/src/kani_proofs.rs"));

    for name in documented_harness_names(&doc) {
        let Some(offset) = proofs.find(&format!("fn {name}(")) else {
            continue; // reported by `documented_kani_harnesses_exist`
        };
        let preceding = &proofs[..offset];
        assert!(
            preceding
                .rsplit("#[kani::proof]")
                .next()
                .is_some_and(|between| !between.contains("fn ")),
            "harness `{name}` is documented as a Kani harness but is not annotated \
             `#[kani::proof]`"
        );
    }
}

/// Phrases that assert audit tampering is detectable without a verifying key.
const KEYLESS_CLAIM_PHRASES: &[&str] = &[
    "with no key",
    "no key at all",
    "no key is needed",
    "no key or configuration",
    "from the log alone",
    "without a key",
];

/// A doc claiming keyless detection must also say what it does not cover: the
/// chain can be recomputed from the edit point forward by anyone who can
/// rewrite the whole log, and tail-truncation breaks no link at all.
const REWRITE_BOUND_MARKER: &str = "recomput";
const TRUNCATION_BOUND_MARKER: &str = "truncat";

/// `CHANGELOG.md` is an append-only historical record — past entries are not
/// rewritten when wording elsewhere improves — and its statement is about the
/// chain being re-derivable, not about what tampering is detectable.
const CLAIM_SCAN_EXEMPT: &[&str] = &["CHANGELOG.md"];

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

/// True if `text` claims keyless detection. "without a key **path**" and
/// "without a key **file**" are configuration statements, not claims.
fn makes_keyless_claim(text: &str) -> Option<&'static str> {
    KEYLESS_CLAIM_PHRASES.iter().copied().find(|phrase| {
        text.match_indices(phrase).any(|(at, _)| {
            let rest = text[at + phrase.len()..].trim_start();
            !rest.starts_with("path") && !rest.starts_with("file")
        })
    })
}

/// Guards against the failure mode this test was written for: the bounds on
/// keyless verification were added to the operator and demo docs while the
/// quickstart, integration guide and compliance posture kept claiming
/// detection without qualification. Prose review did not catch the split.
#[test]
fn keyless_audit_claims_state_their_bounds() {
    let root = repo_root();
    let mut docs = Vec::new();
    markdown_files(&root, &mut docs);
    assert!(
        !docs.is_empty(),
        "expected to find markdown files under the repo root"
    );

    let mut scanned = 0usize;
    let mut violations = Vec::new();
    for path in docs {
        let rel = path.strip_prefix(&root).unwrap_or(&path);
        if CLAIM_SCAN_EXEMPT
            .iter()
            .any(|exempt| rel.to_string_lossy().as_ref() == *exempt)
        {
            continue;
        }

        let lower = read(&path).to_lowercase();
        let Some(phrase) = makes_keyless_claim(&lower) else {
            continue;
        };
        scanned += 1;

        let mut missing = Vec::new();
        if !lower.contains(REWRITE_BOUND_MARKER) {
            missing.push("full-log rewrite");
        }
        if !lower.contains(TRUNCATION_BOUND_MARKER) {
            missing.push("tail-truncation");
        }

        if !missing.is_empty() {
            violations.push(format!(
                "  {} — claims detection without a key (\"{phrase}\"), missing the {} bound(s)",
                rel.display(),
                missing.join(" and ")
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "the keyless audit-verification claim is stated without its bounds in {} \
         doc(s). That claim is only true within them; state them or drop the claim.\n{}\n\n\
         Missing bounds are:\n\
         \x20 - full-log rewrite: repairing the chain only means recomputing every link \
         from the edit point forward, so a chain does not establish authorship. Signing \
         closes this.\n\
         \x20 - tail-truncation: dropping the newest events breaks no link, and signing \
         does not fix it either. This needs an external anchor.",
        violations.len(),
        violations.join("\n")
    );

    assert!(
        scanned >= 4,
        "expected the keyless audit claim in at least 4 docs, found {scanned} — if the \
         claim was reworded, update KEYLESS_CLAIM_PHRASES so this stays a control"
    );
}
