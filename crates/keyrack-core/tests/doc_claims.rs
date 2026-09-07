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
