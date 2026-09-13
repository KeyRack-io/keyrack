#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove initializer regressions kill guard removals using real SoftHSM.

KEYRACK_SOFTHSM_TEST_LIB must name the installed SoftHSM shared library.
Only source copies in a temporary Cargo package are mutated. The original
worktree is never edited. Each test creates its own disposable token store.
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/keyrack-service/src/bin/keyrack-softhsm-init.rs"
TEST_SOURCE = ROOT / "crates/keyrack-service/tests/softhsm_initializer.rs"

# Tie each mutant to the actual semantic assertion that must fail. Pinning the
# panic location to an existing assertion also excludes fixture/setup failures.
EXPECTED = {
    "label_validation": ("refused", "    assert!(stderr.contains(reason)", 0,
        ["unexpected refusal: SoftHSM initialization refused: dedicated store contains a different token label"]),
    "pin_length_validation": ("invalid_label_and_pin_are_rejected_before_token_mutation",
        "    assert!(fixture.initialized().is_empty());", 1,
        ["assertion failed: fixture.initialized().is_empty()"]),
    "reset_existing_token": ("fresh_and_repeated_initialization_preserve_private_objects",
        "    assert_eq!(fixture.marker(false), 1);", 0,
        ["assertion `left == right` failed", "  left: 0", " right: 1"]),
    "reject_partial_resume": ("succeeded", "    assert!(", 0,
        ["SoftHSM initialization refused: user PIN verification failed"]),
}
for _name in ["wrong_label", "duplicate_labels", "reset_existing_user_pin",
              "omit_user_authentication", "omit_so_authentication", "accept_cli_arguments"]:
    EXPECTED[_name] = ("refused", "    assert!(", 0, ["initializer accepted forbidden input"])


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assertion_line(source, function, statement, occurrence):
    lines = source.splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith(f"fn {function}("))
    end = next(index for index in range(start + 1, len(lines)) if lines[index] == "}")
    matches = [index + 1 for index in range(start, end) if lines[index].startswith(statement)]
    if len(matches) <= occurrence:
        raise SystemExit(f"expected assertion changed in {function}; review mutation expectations")
    return matches[occurrence]


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=900, **kwargs)


def require_success(result, stage):
    if result.returncode:
        raise SystemExit(f"{stage} failed:\n{result.stdout}\n{result.stderr}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "target/proofs/softhsm-initializer")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not os.environ.get("KEYRACK_SOFTHSM_TEST_LIB"):
        raise SystemExit("KEYRACK_SOFTHSM_TEST_LIB is required; no silent skip")
    source_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in [SOURCE, TEST_SOURCE, ROOT / "Cargo.lock"]}
    library = Path(os.environ["KEYRACK_SOFTHSM_TEST_LIB"]).resolve(strict=True)
    receipt = {"status": "running", "baseline_passed": False, "source_sha256": source_hashes,
               "library": str(library), "library_sha256": sha256(library), "cases": []}

    def save_receipt():
        (args.output_dir / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")

    save_receipt()
    baseline = run([
        "cargo", "test", "--locked", "-p", "keyrack-service", "--features",
        "softhsm-init-tests", "--test", "softhsm_initializer", "--no-run",
        "--message-format=json",
    ])
    (args.output_dir / "baseline-build.log").write_text(baseline.stdout + baseline.stderr)
    require_success(baseline, "baseline compilation")
    artifacts = [json.loads(line) for line in baseline.stdout.splitlines() if line.startswith("{")]
    test_binary = next(
        item["executable"] for item in artifacts
        if item.get("reason") == "compiler-artifact"
        and item.get("target", {}).get("name") == "softhsm_initializer"
        and item.get("executable")
    )
    initializer_binary = next(
        item["executable"] for item in artifacts
        if item.get("reason") == "compiler-artifact"
        and item.get("target", {}).get("name") == "keyrack-softhsm-init"
        and item.get("executable")
    )
    clean_env = os.environ.copy()
    clean_env.pop("KEYRACK_SOFTHSM_INIT_TEST_BIN", None)
    baseline_tests = run([test_binary, "--test-threads=1"], env=clean_env)
    (args.output_dir / "baseline.log").write_text(baseline_tests.stdout + baseline_tests.stderr)
    require_success(baseline_tests, "baseline tests")
    if "8 passed; 0 failed" not in baseline_tests.stdout:
        raise SystemExit("baseline must execute all eight real-token initializer tests")
    receipt["baseline_passed"] = True
    receipt["test_binary_sha256"] = sha256(test_binary)
    receipt["initializer_binary_sha256"] = sha256(initializer_binary)
    save_receipt()
    original = SOURCE.read_text()
    test_source = TEST_SOURCE.read_text()
    mutations = [
        ("label_validation", "    validate_label(input.label.expose())?;", "",
         "invalid_label_and_pin_are_rejected_before_token_mutation"),
        ("pin_length_validation", "    validate_pins(input, info)?;", "",
         "invalid_label_and_pin_are_rejected_before_token_mutation"),
        ("wrong_label", "[token] if token.1.label() == label => Ok(token),", "[token] => Ok(token),",
         "wrong_label_cannot_adopt_or_reset_existing_store"),
        ("duplicate_labels", '_ => Err("dedicated store contains multiple initialized tokens"),',
         "_ => Ok(initialized[0]),", "duplicate_labels_cannot_select_arbitrary_token"),
        ("reset_existing_token", "    if !info.token_initialized() {", "    if true {",
         "fresh_and_repeated_initialization_preserve_private_objects"),
        ("reset_existing_user_pin", "    if !info.user_pin_initialized() {", "    if true {",
         "wrong_existing_user_pin_is_rejected_without_reset"),
        ("omit_user_authentication", '    session\n        .login(UserType::User, Some(&auth(&input.user_pin)))\n        .map_err(|_| "user PIN verification failed")?;\n    session.logout().map_err(|_| "user logout failed")?;', "",
         "wrong_existing_user_pin_is_rejected_without_reset"),
        ("omit_so_authentication", '    session\n        .login(UserType::So, Some(&auth(&input.so_pin)))\n        .map_err(|_| "SO PIN verification failed")?;',
         '    if !info.user_pin_initialized() { session.login(UserType::So, Some(&auth(&input.so_pin))).map_err(|_| "SO PIN verification failed")?; }',
         "wrong_existing_so_pin_is_rejected_without_reset"),
        ("reject_partial_resume", "    if !info.user_pin_initialized() {", "    if false {",
         "partial_initialization_resumes_without_reinitializing_token"),
        ("accept_cli_arguments", "    if std::env::args_os().len() != 1 {", "    if false {",
         "secret_references_and_cli_reject_before_token_mutation"),
    ]
    with tempfile.TemporaryDirectory(prefix="keyrack-softhsm-mutants-") as temporary:
        project = Path(temporary)
        # Reuse the existing dependency cache, but use a distinct binary name.
        manifest = '\n'.join([
            '[package]', 'name = "keyrack-softhsm-init-mutant"', 'version = "0.0.0"',
            'edition = "2021"', '[workspace]', '[dependencies]', 'cryptoki = "0.12"',
            f'keyrack-core = {{ path = {json.dumps(str(ROOT / "crates/keyrack-core"))} }}',
            f'keyrack-service = {{ path = {json.dumps(str(ROOT / "crates/keyrack-service"))} }}',
        ])
        (project / "Cargo.toml").write_text(manifest + "\n")
        # Preserve reviewed dependency selections, including cached yanked
        # versions that Cargo correctly refuses to select in a fresh resolve.
        (project / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
        (project / "src").mkdir()
        for name, old, new, test_name in mutations:
            if old not in original:
                raise SystemExit(f"mutation {name} no longer matches source; review it")
            mutant = original.replace(old, new, 1)
            if name == "omit_so_authentication":
                mutant = mutant.replace('    session.logout().map_err(|_| "SO logout failed")?;',
                    '    if !info.user_pin_initialized() { session.logout().map_err(|_| "SO logout failed")?; }', 1)
            (project / "src/main.rs").write_text(mutant)
            build = run(["cargo", "build", "--offline", "--manifest-path", str(project / "Cargo.toml"),
                         "--target-dir", str(ROOT / "target")])
            (args.output_dir / f"{name}-build.log").write_text(build.stdout + build.stderr)
            require_success(build, f"mutant {name} compilation")
            env = clean_env | {"KEYRACK_SOFTHSM_INIT_TEST_BIN": str(ROOT / "target/debug/keyrack-softhsm-init-mutant")}
            result = run([test_binary, "--exact", test_name, "--nocapture"], env=env)
            (args.output_dir / f"{name}.log").write_text(result.stdout + result.stderr)
            function, statement, occurrence, messages = EXPECTED[name]
            line = assertion_line(test_source, function, statement, occurrence)
            output = result.stdout + result.stderr
            location = rf"panicked at [^\n]*softhsm_initializer\.rs:{line}:\d+:"
            detected = (result.returncode == 101
                and f"test {test_name} ... FAILED" in result.stdout
                and re.search(location, output) is not None
                and all(message in output for message in messages))
            receipt["cases"].append({"name": name, "test": test_name,
                "expected_assertion": {"function": function, "statement": statement.strip(),
                    "line": line, "messages": messages},
                "mutation_source_sha256": hashlib.sha256(mutant.encode()).hexdigest(),
                "mutant_binary_sha256": sha256(ROOT / "target/debug/keyrack-softhsm-init-mutant"),
                "exit_code": result.returncode, "detected": detected,
                "build_log": f"{name}-build.log", "test_log": f"{name}.log"})
            save_receipt()
            if not detected:
                raise SystemExit(f"mutant {name} did not fail its expected semantic assertion at line {line}:\n{output}")
            print(f"KILLED {name}: {test_name}, line {line}: {'; '.join(messages)}", flush=True)
    after_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in [SOURCE, TEST_SOURCE, ROOT / "Cargo.lock"]}
    if after_hashes != source_hashes:
        raise SystemExit("reviewed source or lockfile changed during proof; results cannot be credited")
    receipt["status"] = "passed"
    receipt["working_sources_unchanged"] = True
    save_receipt()
    print(f"Verified baseline and exact semantic assertion failures for {len(mutations)} initializer guard mutations.")


if __name__ == "__main__":
    main()
