#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Revert deletion recovery and bounded-open controls in an isolated source copy.

Each mutation must execute the named Rust test and fail for the expected wire
outcome. Compiler errors, absent tests, and timeouts are never proof.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "scheduling", ROOT / "scripts/test-deletion-scheduling-controls.py"
)
scheduling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scheduling)
require = scheduling.require
write_json = scheduling.write_json

VAULT = "crates/keyrack-vault/src/lib.rs"
KMIP = "crates/keyrack-kmip/src/provider.rs"
TESTS = [
    ("keyrack-vault", None, "tests::destroy_recovers_only_confirmed_absence"),
    ("keyrack-kmip", None, "provider::tests::repeated_destroy_accepts_only_wire_item_not_found"),
    ("keyrack-service", "wrapped_key_migration", "successive_parent_retirements_refresh_the_open_binding_only_once"),
]
CONTROLS = [
    (
        "bounded_parent_refresh", 2, "crates/keyrack-service/src/domain.rs",
        "if refreshed_parent {", "if false && refreshed_parent {",
        ["a second retired binding must stop refresh"],
    ),
    (
        "vault_absence_fallback", 0, VAULT,
        "if !self.confirm_key_absent(handle).await.unwrap_or(false) { return Err(error); }",
        "if true || !self.confirm_key_absent(handle).await.unwrap_or(false) { return Err(error); }",
        ["called `Result::unwrap()` on an `Err` value", "vault keys/key/config returned 400"],
    ),
    (
        "vault_unconfirmed_success", 0, VAULT,
        "if !self.confirm_key_absent(handle).await.unwrap_or(false) { return Err(error); }",
        "if !self.confirm_key_absent(handle).await.unwrap_or(false) { let _ = error; }",
        ['200/{"data":{}}/None'],
    ),
    (
        "kmip_item_not_found", 1, KMIP,
        "resp.result_status == ttlv::result_status::OPERATION_FAILED && resp.result_reason == Some(0x0000_0001)",
        "resp.result_status == ttlv::result_status::OPERATION_FAILED && false",
        ["left: false", "right: true"],
    ),
    (
        "kmip_unrelated_reasons", 1, KMIP,
        "resp.result_status == ttlv::result_status::OPERATION_FAILED && resp.result_reason == Some(0x0000_0001)",
        "resp.result_status == ttlv::result_status::OPERATION_FAILED",
        ["left: true", "right: false"],
    ),
]


def run(work, output, env, timeout, name, selection, diagnostics=None):
    package, target, test = TESTS[selection]
    target_args = ["--lib"] if target is None else ["--test", target]
    command = [
        "cargo", "test", "--locked", "-p", package, *target_args, test,
        "--", "--exact", "--test-threads=1",
    ]
    write_json(output / f"{name}-command.json", {"argv": command, "cwd": str(work)})
    with (output / f"{name}.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            exit_code = process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            except ProcessLookupError:
                pass
            raise
    write_json(output / f"{name}-exit.json", {"exit_code": exit_code})
    log = (output / f"{name}.log").read_text()
    rows = re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\s*$", log, re.MULTILINE)
    expected_status = "ok" if diagnostics is None else "FAILED"
    require(
        rows == [(test, expected_status)],
        f"{name}: expected executed {test} {expected_status}, not a compile failure or unrelated test",
    )
    require(exit_code == (0 if diagnostics is None else 101), f"{name}: unexpected exit {exit_code}")
    for diagnostic in diagnostics or []:
        require(diagnostic in log, f"{name}: missing specific failure diagnostic {diagnostic!r}")
    print(f"{name}: expected outcome and cause verified", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    require(args.timeout > 0, "timeout must be positive")
    require(not output.exists() or not any(output.iterdir()), "output must be new or empty")
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
    require(not output.is_relative_to(target), "output must not be inside target")
    output.mkdir(parents=True, exist_ok=True)
    env = os.environ | {
        "CARGO_TARGET_DIR": str(target), "CARGO_TERM_COLOR": "never", "RUST_TEST_NOCAPTURE": "0",
    }
    result = {"status": "started", "verified": []}
    try:
        with tempfile.TemporaryDirectory(prefix="keyrack-destruction-recovery-") as directory:
            work = Path(directory)
            write_json(output / "source-sha256.json", scheduling.copy_source(work, output, target))
            for selection, (package, _, _) in enumerate(TESTS):
                name = f"baseline-{package}"
                run(work, output, env, args.timeout, name, selection)
                result["verified"].append(name)
            for name, selection, path, before, after, diagnostics in CONTROLS:
                file = work / path
                original = file.read_text()
                pattern = re.compile(r"\s*".join(re.escape(char) for char in before if not char.isspace()))
                matches = list(pattern.finditer(original))
                require(len(matches) == 1, f"{name}: mutation anchor missing or ambiguous")
                match = matches[0]
                changed = original[:match.start()] + after + original[match.end():]
                file.write_text(changed)
                write_json(output / f"{name}-mutation.json", {
                    "path": path, "before": match.group(), "after": after,
                    "original_sha256": scheduling.digest(original.encode()),
                    "mutated_sha256": scheduling.digest(changed.encode()),
                })
                try:
                    run(work, output, env, args.timeout, name, selection, diagnostics)
                    result["verified"].append(name)
                finally:
                    file.write_text(original)
            for selection, (package, _, _) in enumerate(TESTS):
                name = f"restored-{package}"
                run(work, output, env, args.timeout, name, selection)
                result["verified"].append(name)
        result["status"] = "passed"
    except (OSError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        result["status"] = "refused"
        result["error"] = str(error)
        print(f"REFUSED: {error}; evidence in {output}", flush=True)
    finally:
        write_json(output / "result.json", result)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
