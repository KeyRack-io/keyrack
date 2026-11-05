#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: Apache-2.0
"""Revert wrapped-child rotation fences in a disposable copy; require real assertion failures."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CORE = "crates/keyrack-core/src/creation.rs"
SQLITE = "crates/keyrack-sqlite/src/"
POSTGRES = "crates/keyrack-postgres/src/creation.rs"
POSTGRES_MIGRATION = "crates/keyrack-postgres/src/migration.rs"
SERVICE = "crates/keyrack-service/src/"

SQLITE_ROTATION = ("keyrack-sqlite", (), "rotation_conformance", None)
SERVICE_ROTATION = ("keyrack-service", (), "wrapped_child_rotation", None)
SERVICE_REWRAP = ("keyrack-service", (), "rewrap_authorization", None)
# Repeated runs accumulate keys in one database; unrelated tests in this binary expect a first-page listing.
POSTGRES_ROTATION = ("keyrack-postgres", ("--features", "live-tests"), "conformance", "rotation_postgres::")

# Each mutation is bounded to one function and leaves the code warning-free.
# Compilation failures and zero-test runs never count as successful controls.
CONTROLS = [
    ("parent_current_version", CORE, "pub fn validate_records(",
     "if material.parent().version.get() != parent.current_key_version {",
     "if false && material.parent().version.get() != parent.current_key_version {",
     SQLITE_ROTATION, "journal_pins_parent_current_version_and_lineage"),
    ("parent_lineage", CORE, "pub fn validate(&self)",
     "|| record.parent_lid != Some(material.parent().lid)",
     "|| (false && record.parent_lid != Some(material.parent().lid))",
     SQLITE_ROTATION, "journal_pins_parent_current_version_and_lineage"),
    ("owed_entries_kept", CORE, "pub fn withdrawable(",
     "CreationPhase::Reserved if !self.dispatch_started => Ok(()),",
     "CreationPhase::Reserved if self.dispatch_started || !self.dispatch_started => Ok(()),",
     SQLITE_ROTATION, "crash_recovery_each_phase"),
    ("sqlite_withdraw_phase", SQLITE + "creation.rs", "fn withdraw_a2(",
     "value.withdrawable()?;", "let _ = value.withdrawable();",
     SQLITE_ROTATION, "withdraw_semantics"),
    ("migration_blocks_rotation_reservation", SQLITE + "creation.rs", "fn reserve_a2(",
     "crate::migration::guard_record(conn, &request.record)?;", "",
     SERVICE_ROTATION, "migration_reserved_after_rotation_check_refuses_before_provider"),
    ("sqlite_migration_blocks_rotation_reservation", SQLITE + "creation.rs", "fn reserve_a2(",
     "crate::migration::guard_record(conn, &request.record)?;", "",
     SQLITE_ROTATION, "rotation_and_migration_fences"),
    ("rotation_blocks_migration_reservation", SQLITE + "migration.rs", "fn migration_reserve(",
     "if pending { return Err(migration_busy()); }", "let _ = pending;",
     SERVICE_ROTATION, "rotation_reserved_first_refuses_rewrap_until_rotation_commits"),
    ("stale_snapshot_reread", SERVICE + "hierarchy.rs", "async fn rotate_until_settled(",
     "if !superseded(state, &child, &parent).await? {",
     "if !superseded(state, &child, &parent).await? || STALE_SNAPSHOT_ATTEMPTS > 0 {",
     SERVICE_ROTATION, "migration_commit_before_rotation_reservation_wraps_under_new_parent"),
    ("superseded_publication_retry", SERVICE + "hierarchy.rs", "async fn rotate_until_settled(",
     "if !(resolved && superseded(state, &child, &parent).await?) {",
     "if !(resolved && superseded(state, &child, &parent).await?) || STALE_SNAPSHOT_ATTEMPTS > 0 {",
     SERVICE_ROTATION, "parent_rotation_during_generate_retries_with_new_parent_version"),
    ("wraps_under_current_parent_version", SERVICE + "hierarchy.rs", "fn journaled_version(",
     "VersionedKeyId::new(parent.lid, parent.current_key_version)",
     "VersionedKeyId::new(parent.lid, parent.current_key_version.min(1))",
     SERVICE_ROTATION,
     "parent_rotation_queues_job_without_rewrapping_child_then_child_rotation_uses_new_parent_version"),
    ("grpc_rotation_detached", SERVICE + "grpc.rs", "async fn rotate_key(",
     "ops::execute_detached(", "ops::execute(",
     SERVICE_ROTATION, "dropped_rotation_request_leaves_key_consistent"),
    ("rest_rotation_detached", SERVICE + "rest.rs", "async fn rotate_key(",
     "ops::execute_rest_detached(", "ops::execute_rest(",
     SERVICE_ROTATION, "dropped_rotation_request_leaves_key_consistent"),
    ("one_rotation_per_key_in_process", SERVICE + "hierarchy.rs", "fn take(lid: Lid)",
     "if !held.insert(lid) {", "if !held.insert(lid) && held.is_empty() {",
     SERVICE_ROTATION, "dropped_rotation_request_leaves_key_consistent"),
    ("mixed_history_refused", SERVICE + "domain.rs", "fn wrapped_history(",
     "Err(DomainError::FailedPrecondition(WRAPPED_UNSUPPORTED.into()))",
     "Ok(record.parent_lid.is_some())",
     SERVICE_ROTATION, "wrapped_child_rotation_refuses_ineligible_keys_and_mixed_history"),
    ("resident_rotation_slot", SERVICE + "domain.rs", "pub async fn rotate_key(",
     "let _slot = crate::hierarchy::RotationInFlight::take(lid)?;", "",
     SERVICE_ROTATION, "resident_rotation_holds_one_slot_per_key_across_dropped_requests"),
    ("unpublished_version_cleanup", SERVICE + "domain.rs", "async fn rotate_resident(",
     "if matches!(error, KeyRackError::OptimisticConcurrencyConflict { .. }) {",
     "if false && matches!(error, KeyRackError::OptimisticConcurrencyConflict { .. }) {",
     SERVICE_ROTATION, "resident_rotation_losing_occ_destroys_and_audits_its_unpublished_key"),
    ("panic_audited", SERVICE + "ops.rs", "fn poll(",
     "Err(panic) => std::task::Poll::Ready(Err(panic)),",
     "Err(panic) => std::panic::resume_unwind(panic),",
     SERVICE_ROTATION, "executors_audit_a_panicking_operation_as_an_error"),
    ("rewrap_panic_audited", SERVICE + "ops.rs", "fn poll(",
     "Err(panic) => std::task::Poll::Ready(Err(panic)),",
     "Err(panic) => std::panic::resume_unwind(panic),",
     SERVICE_REWRAP, "a_panicking_rewrap_is_audited_as_an_error"),
]

POSTGRES_CONTROLS = [
    ("postgres_withdraw_phase", POSTGRES, "async fn creation_withdraw(",
     "stored.journal.withdrawable()?;", "let _ = stored.journal.withdrawable();",
     POSTGRES_ROTATION, "rotation_postgres::rotation_withdraw_semantics"),
    ("postgres_migration_blocks_rotation_reservation", POSTGRES, "async fn creation_reserve(",
     "crate::migration::guard_record(&mut transaction, &request.record).await?;", "",
     POSTGRES_ROTATION, "rotation_postgres::rotation_and_migration_fences"),
    ("postgres_rotation_blocks_migration_reservation", POSTGRES_MIGRATION, "async fn migration_reserve(",
     "if pending {", "if pending && false {",
     POSTGRES_ROTATION, "rotation_postgres::rotation_and_migration_fences"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "target/proofs/rotation")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target")
    args = parser.parse_args()
    controls = CONTROLS + (POSTGRES_CONTROLS if os.environ.get("DATABASE_URL") else [])
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    paths = sorted({item[1] for item in controls})
    hashes = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}
    receipt = {"status": "running", "source_sha256": hashes, "postgres": len(controls) > len(CONTROLS), "controls": []}

    def save():
        (output / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")

    save()
    env = os.environ | {"CARGO_TERM_COLOR": "never"}
    with tempfile.TemporaryDirectory(prefix="keyrack-rotation-controls-") as temporary:
        copy = Path(temporary) / "source"
        # Fresh mtimes: a shared target dir must never reuse a mutated build from an earlier run.
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "target", "__pycache__"), copy_function=shutil.copy)

        def run(name, suite, test=None):
            package, features, target, scope = suite
            command = ["cargo", "test", "--locked", "--offline", "-p", package, *features, "--test", target,
                       "--target-dir", str(args.target_dir.resolve()), "--"]
            command += [test, "--exact", "--nocapture"] if test else [*([scope] if scope else []), "--nocapture"]
            with (output / f"{name}.log").open("w") as log:
                result = subprocess.run(command, cwd=copy, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=900)
            text = (output / f"{name}.log").read_text()
            if "error: could not compile" in text or "error[E" in text:
                raise AssertionError(f"{name}: compilation failure is not a control")
            return result.returncode, text

        suites = sorted({control[5] for control in controls})

        def all_pass(label):
            for index, suite in enumerate(suites):
                code, text = run(f"{label}-{index}-{suite[2]}", suite)
                assert code == 0 and re.search(r"test result: ok\. [1-9][0-9]* passed;", text), f"{label} {suite[0]}/{suite[2]} must execute and pass"

        try:
            all_pass("baseline")
            for name, file, scope, old, new, suite, test in controls:
                path = copy / file
                original = path.read_text()
                start = original.index(scope)
                position = original.index(old, start)
                path.write_text(original[:position] + new + original[position + len(old):])
                try:
                    code, text = run(name, suite, test)
                    assert code != 0 and "running 1 test" in text and f"{test} ... FAILED" in text and "panicked at" in text, f"{name}: missing named assertion failure"
                    receipt["controls"].append({"name": name, "file": file, "test": test, "exit_code": code, "grade": "synthetic"})
                    save()
                    print(f"PASS {name}: {test} fails with its fence reverted", flush=True)
                finally:
                    path.write_text(original)
            all_pass("restored")
            assert hashes == {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}, "source changed during controls"
            receipt["status"] = "passed"
        except BaseException as error:
            receipt.update(status="failed", error=str(error))
            raise
        finally:
            save()


if __name__ == "__main__":
    main()
