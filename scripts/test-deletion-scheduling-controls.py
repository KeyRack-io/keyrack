#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove deletion scheduling refusals depend on the shared admission check.

Both runs use a disposable source copy. The checkout is never edited. Logs and
source hashes remain in --output after the copy is removed, including on failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
DOMAIN = Path("crates/keyrack-service/src/domain.rs")
GUARD = "if !dependencies.is_empty() {"
MUTATION = "if false && !dependencies.is_empty() {"
SURFACE_REFUSALS = {
    f"deletion_dependencies::{surface}_refuses_{kind}"
    for surface in ("grpc", "rest")
    for kind in (
        "own_wrapped_version",
        "dependent_wrapped_version",
        "parent_creation_journal",
        "child_creation_journal",
    )
}
DOMAIN_REFUSAL = "deletion_dependencies::domain_refuses_each_dependency_kind_without_mutation"
POSITIVE = "deletion_dependencies::logical_only_children_allow_scheduling_on_every_surface"
REFUSALS = SURFACE_REFUSALS | {DOMAIN_REFUSAL}
EXPECTED = REFUSALS | {POSITIVE}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def copy_source(destination: Path, output: Path, target: Path) -> dict[str, str]:
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
    ).split(b"\0")
    manifest = {}
    for raw in sorted(set(paths)):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        require(not relative.is_absolute() and ".." not in relative.parts, "unsafe source path")
        if any(part in (".git", "target") for part in relative.parts):
            continue
        source = ROOT / relative
        resolved = source.resolve()
        if resolved.is_relative_to(output) or resolved.is_relative_to(target):
            continue
        require(resolved.is_relative_to(ROOT), f"source link leaves checkout: {relative}")
        if not source.is_file():
            continue
        data = source.read_bytes()
        copied = destination / relative
        copied.parent.mkdir(parents=True, exist_ok=True)
        copied.write_bytes(data)
        shutil.copymode(source, copied)
        manifest[str(relative)] = digest(data)
    require(str(DOMAIN) in manifest, "domain source was not copied")
    return manifest


def check_results(log: str, exit_code: int, mutated: bool) -> None:
    rows = re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\s*$", log, re.MULTILINE)
    require(len(rows) == len(EXPECTED), "expected exactly ten reported test outcomes")
    require({name for name, _ in rows} == EXPECTED, "missing, duplicated or unexpected test names")
    outcomes = dict(rows)
    if not mutated:
        require(exit_code == 0, f"baseline exited {exit_code}")
        require(all(outcome == "ok" for outcome in outcomes.values()), "baseline did not pass every test")
        return

    require(exit_code == 101, f"reverted run exited {exit_code}, expected a Rust test failure")
    require(outcomes[POSITIVE] == "ok", "logical-only positive control stopped passing")
    require(all(outcomes[name] == "FAILED" for name in REFUSALS), "a refusal survived removing the check")

    # With default test capture, each failure has its own named diagnostic block.
    # Check causes individually: a compile error, panic elsewhere or unrelated
    # status code cannot count as evidence that scheduling was accepted.
    sections = re.split(r"^---- (\S+) stdout ----\s*$", log, flags=re.MULTILINE)
    failures = dict(zip(sections[1::2], sections[2::2]))
    require(set(failures) == REFUSALS, "missing or unexpected named failure diagnostics")
    for name in REFUSALS:
        detail = failures[name]
        if "::rest_" in name:
            require(
                "assertion `left == right` failed" in detail
                and re.search(r"^\s*left: 200\s*$", detail, re.MULTILINE) is not None
                and re.search(r"^\s*right: 409\s*$", detail, re.MULTILINE) is not None,
                f"{name} did not fail because REST accepted scheduling",
            )
        else:
            require(
                "called `Result::unwrap_err()` on an `Ok` value" in detail,
                f"{name} did not fail because scheduling returned success",
            )


def run_tests(work: Path, output: Path, env: dict[str, str], timeout: int, mutated: bool, count_control=None, restored=False) -> None:
    phase = count_control[0] if count_control else "restored" if restored else "reverted" if mutated else "baseline"
    command = [
        "cargo", "test", "--locked", "-p", "keyrack-service", "--test", "integration",
        "deletion_dependencies", "--", "--test-threads=1",
    ]
    write_json(output / f"{phase}-command.json", {"argv": command, "cwd": str(work)})
    with (output / f"{phase}.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            exit_code = process.wait(timeout=timeout)
        except BaseException:
            # Cargo can leave compiler children behind if only its own PID is
            # killed. Stop this invocation's process group before removing source.
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            except ProcessLookupError:
                pass
            raise
    write_json(output / f"{phase}-exit.json", {"exit_code": exit_code})
    text = (output / f"{phase}.log").read_text()
    if count_control:
        rows = re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\s*$", text, re.MULTILINE)
        require(exit_code == 101 and len(rows) == len(EXPECTED) and {name for name,_ in rows} == EXPECTED, "count control must execute every named test")
        require(dict(rows)[POSITIVE] == "FAILED" and all(status == "ok" for name,status in rows if name != POSITIVE), "only the logical-count response assertion must fail")
        for diagnostic in count_control[1]:
            require(diagnostic in text, f"{phase}: missing specific count failure {diagnostic!r}")
    else:
        check_results(text, exit_code, mutated)
    print(f"{phase}: expected outcomes and causes verified", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new or empty directory for retained evidence")
    parser.add_argument("--timeout", type=int, default=1800, help="maximum seconds per cargo invocation (default: 1800)")
    args = parser.parse_args()
    require(args.timeout > 0, "timeout must be positive")
    output = args.output.expanduser().resolve()
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())), "output must be a new or empty directory")
    output.mkdir(parents=True, exist_ok=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target"))).expanduser().resolve()
    require(not output.is_relative_to(target), "output must not be inside the build target directory")
    env = os.environ | {"CARGO_TARGET_DIR": str(target), "CARGO_TERM_COLOR": "never", "RUST_TEST_NOCAPTURE": "0"}
    result = {"status": "started", "baseline_verified": False, "reverted_verified": False}
    write_json(output / "result.json", result)
    try:
        with tempfile.TemporaryDirectory(prefix="keyrack-deletion-controls-") as temporary:
            work = Path(temporary)
            manifest = copy_source(work, output, target)
            write_json(output / "source-sha256.json", manifest)
            write_json(output / "input.json", {
                "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "source_manifest_sha256": digest((output / "source-sha256.json").read_bytes()),
                "target": str(target),
                "expected_tests": sorted(EXPECTED),
                "timeout_seconds_per_run": args.timeout,
            })
            source = (work / DOMAIN).read_text()
            require(source.count(GUARD) == 1, "shared admission guard is missing or ambiguous")
            run_tests(work, output, env, args.timeout, mutated=False)
            result["baseline_verified"] = True
            write_json(output / "result.json", result)
            changed = source.replace(GUARD, MUTATION)
            (work / DOMAIN).write_text(changed)
            write_json(output / "mutation.json", {
                "path": str(DOMAIN), "before": GUARD, "after": MUTATION,
                "original_sha256": digest(source.encode()), "mutated_sha256": digest(changed.encode()),
            })
            run_tests(work, output, env, args.timeout, mutated=True)
            result["reverted_verified"] = True
            (work / DOMAIN).write_text(source)
            controls = [
                ("stored_count", "crates/keyrack-core/src/destruction.rs", ".logical_only_children\n                .checked_add(1)", ".logical_only_children\n                .checked_add(0)", ["logical-only child count must match admission", "left: 0", "right: 2"]),
                ("grpc_count", "crates/keyrack-service/src/grpc.rs", "logical_only_children: dependencies.logical_only_children,", "logical_only_children: 0,", ["gRPC logical-only child count must match admission", "left: 0", "right: 2"]),
                ("rest_count", "crates/keyrack-service/src/rest.rs", 'response["logical_only_children"] = serde_json::json!(dependencies.logical_only_children);', 'response["logical_only_children"] = serde_json::json!(0_u64);', ["REST logical-only child count must match admission", "left: Some(0)", "right: Some(2)"]),
            ]
            result["count_controls"] = []
            for name,path,before,after,diagnostics in controls:
                file = work / path
                original = file.read_text()
                require(original.count(before) == 1, f"{name}: count anchor missing or ambiguous")
                changed = original.replace(before, after)
                # Preserve use of the admission observation under -D warnings.
                if name in ("grpc_count", "rest_count"):
                    changed = changed.replace("let dependencies = crate::domain::ensure_deletion_can_be_scheduled", "let _dependencies = crate::domain::ensure_deletion_can_be_scheduled")
                file.write_text(changed)
                write_json(output / f"{name}-mutation.json", {"path":path,"before":before,"after":after,"original_sha256":digest(original.encode()),"mutated_sha256":digest(changed.encode())})
                try:
                    run_tests(work,output,env,args.timeout,mutated=False,count_control=(name,diagnostics))
                    result["count_controls"].append(name)
                finally:
                    file.write_text(original)
            run_tests(work,output,env,args.timeout,mutated=False,restored=True)
            result["restored_verified"] = True
        result["status"] = "passed"
    except (OSError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        result["status"] = "refused"
        result["error"] = str(error)
        print(f"REFUSED: {error}; evidence retained in {output}", file=sys.stderr)
    finally:
        write_json(output / "result.json", result)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
