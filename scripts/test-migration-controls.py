#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: Apache-2.0
"""Revert migration fences in a disposable copy; require real assertion failures."""
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
SQLITE = "crates/keyrack-sqlite/src/"
# Each mutation is bounded to a function where identical guard calls exist.
# Compilation failures and zero-test runs never count as successful controls.
CONTROLS = [
    ("writer", SQLITE + "lib.rs", "async fn update_key(", "migration::guard_update(conn, &previous, record)?;", "let _ = migration::guard_update;", "tests::migration_all_writer_fences"),
    ("creation", SQLITE + "creation.rs", "fn reserve_a2(", "crate::migration::guard_record(conn, &request.record)?;", "", "tests::migration_all_writer_fences"),
    ("destruction", SQLITE + "destruction.rs", "fn destruction_claim(", "counts.validate_intent(&intent(conn, &record)?.unwrap_or_default())?;", "let _ = counts;", "migration::tests::migration_blocks_due_unreferenced_target_destruction"),
    ("migration_child_dependency", SQLITE + "destruction.rs", "fn dependencies(", "child_lid=?1 OR old_parent_lid=?1 OR new_parent_lid=?1", "old_parent_lid=?1 OR new_parent_lid=?1", "tests::migration_destruction_dependency_query_tracks_migration"),
    ("migration_old_parent_dependency", SQLITE + "destruction.rs", "fn dependencies(", "child_lid=?1 OR old_parent_lid=?1 OR new_parent_lid=?1", "child_lid=?1 OR new_parent_lid=?1", "tests::migration_destruction_dependency_query_tracks_migration"),
    ("migration_new_parent_dependency", SQLITE + "destruction.rs", "fn dependencies(", "child_lid=?1 OR old_parent_lid=?1 OR new_parent_lid=?1", "child_lid=?1 OR old_parent_lid=?1", "tests::migration_destruction_dependency_query_tracks_migration"),
    ("pending_creation", SQLITE + "migration.rs", "fn migration_reserve(", "if pending { return Err(migration_busy()); }", "let _ = pending;", "tests::migration_creation_and_occ_preempt"),
    ("overlapping_migration", SQLITE + "migration.rs", "fn migration_reserve(", "guard(conn, &record.lid)?;", "", "tests::migration_all_writer_fences"),
    ("reservation_occ", SQLITE + "migration.rs", "fn snapshots(", "request.validate_snapshots(&child, &old, &new)", "{ let _ = (&child, &old, &new); Ok(()) }", "tests::migration_creation_and_occ_preempt"),
    ("commit_occ", SQLITE + "migration.rs", "fn migration_commit(", "snapshots(conn,&value.request,true)?;", "", "migration::tests::migration_commit_rechecks_every_occ"),
    ("target_fence", SQLITE + "migration.rs", "fn snapshots(", "destruction::guard(conn, &record.lid)?;", "let _ = (destruction::guard, record);", "migration::tests::migration_reservation_checks_destruction_fence_independently"),
    ("parent_immutable", SQLITE + "migration.rs", "fn guard_update(", "if previous.parent_lid != next.parent_lid {", "if false && previous.parent_lid != next.parent_lid {", "tests::migration_deny_paths"),
    ("stage_owner", SQLITE + "migration.rs", "fn migration_stage(", "value.require_owner(ownership)?;", "", "tests::migration_ownership_epoch_and_unknown_outcome"),
    ("commit_owner", SQLITE + "migration.rs", "fn migration_commit(", "value.require_owner(ownership)?;", "", "tests::migration_ownership_epoch_and_unknown_outcome"),
    ("stage_dispatch_epoch", SQLITE + "migration.rs", "fn migration_stage(", "if value.dispatch.as_ref().map(|d| d.epoch) != Some(ownership.epoch) {", "if false && value.dispatch.as_ref().map(|d| d.epoch) != Some(ownership.epoch) {", "tests::migration_ownership_epoch_and_unknown_outcome"),
    ("dispatch_owner", "crates/keyrack-core/src/migration/wrapped.rs", "pub fn begin_dispatch(", "self.require_owner(ownership)?;", "", "tests::migration_ownership_epoch_and_unknown_outcome"),
    ("unknown_outcome", "crates/keyrack-core/src/migration/wrapped.rs", "pub fn begin_dispatch(", "if self.dispatch.is_some_and(|dispatch| !dispatch.retry_safe) {", "if false && self.dispatch.is_some_and(|dispatch| !dispatch.retry_safe) {", "tests::migration_ownership_epoch_and_unknown_outcome"),
    ("creation_envelope_erasure", SQLITE + "migration.rs", "fn migration_commit(", "DELETE FROM creation_journal WHERE child_lid=?1 AND phase='committed'", "DELETE FROM creation_journal WHERE child_lid=?1 AND phase='committed' AND 0", "tests::migration_atomic_publication_and_retirement"),
    ("migration_envelope_erasure", SQLITE + "migration.rs", "fn migration_commit(", "DELETE FROM migration_envelopes WHERE operation_id IN", "DELETE FROM migration_envelopes WHERE 0 AND operation_id IN", "tests::migration_atomic_publication_and_retirement"),
    ('disabled_source_support', 'crates/keyrack-core/src/migration/wrapped.rs', 'pub fn validate(&self)', 'if !matches!(old.state, KeyState::Enabled | KeyState::Disabled) {', 'if old.state != KeyState::Enabled {', 'tests::migration_disabled_source_maintenance_binds_state'),
    ('source_state_eligibility', 'crates/keyrack-core/src/migration/wrapped.rs', 'pub fn validate(&self)', 'if !matches!(old.state, KeyState::Enabled | KeyState::Disabled) {', 'if false {', 'tests::migration_disabled_source_maintenance_binds_state'),
    ('destination_enabled', 'crates/keyrack-core/src/migration/wrapped.rs', 'pub fn validate(&self)', 'if new.state != KeyState::Enabled {', 'if false {', 'tests::migration_disabled_source_maintenance_binds_state'),
    ('source_state_at_claim', 'crates/keyrack-sqlite/src/migration.rs', 'fn migration_claim(', 'snapshots(conn, &value.request, true)?;', '', 'migration::tests::migration_source_state_drift_blocks_recovery'),
    ('source_state_at_dispatch', 'crates/keyrack-sqlite/src/migration.rs', 'fn migration_dispatch(', 'snapshots(conn, &value.request, true)?;', '', 'migration::tests::migration_source_state_drift_blocks_recovery'),
    ('source_state_at_stage', 'crates/keyrack-sqlite/src/migration.rs', 'fn migration_stage(', 'snapshots(conn,&value.request,true)?;', '', 'migration::tests::migration_source_state_drift_blocks_recovery'),
    ('source_state_at_commit', 'crates/keyrack-sqlite/src/migration.rs', 'fn migration_commit(', 'snapshots(conn,&value.request,true)?;', '', 'migration::tests::migration_source_state_drift_blocks_recovery'),
    ('old_receipt_digest', 'crates/keyrack-core/src/migration/wrapped.rs', 'terminal result binding mismatch', '|| entry.old_envelope_digest\n                        != blake3::Hash::from_bytes(self.old_envelope_digests[index])\n                            .to_hex()\n                            .as_str()', '', 'tests::migration_terminal_result_and_reader_snapshots'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "target/proofs/migration")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    paths = sorted({item[1] for item in CONTROLS})
    hashes = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}
    receipt = {"status": "running", "source_sha256": hashes, "controls": []}

    def save():
        (output / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")

    save()
    env = os.environ | {"CARGO_TERM_COLOR": "never"}
    with tempfile.TemporaryDirectory(prefix="keyrack-migration-controls-") as temporary:
        copy = Path(temporary) / "source"
        # Fresh mtimes force Cargo to rebuild this source, even when a previous
        # interrupted run left a mutant artifact in the shared target directory.
        shutil.copytree(ROOT, copy, copy_function=shutil.copy, ignore=shutil.ignore_patterns(".git", "target", "__pycache__"))

        def run(name, test=None):
            command = ["cargo", "test", "--locked", "--offline", "-p", "keyrack-sqlite", "--lib", "--target-dir", str(args.target_dir.resolve())]
            command += [test or "migration", "--", "--nocapture"]
            if test:
                command += ["--exact"]
            with (output / f"{name}.log").open("w") as log:
                result = subprocess.run(command, cwd=copy, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
            text = (output / f"{name}.log").read_text()
            if "error: could not compile" in text or "error[E" in text:
                raise AssertionError(f"{name}: compilation failure is not a control")
            return result.returncode, text

        try:
            code, text = run("baseline")
            assert code == 0 and re.search(r"test result: ok\. [1-9][0-9]* passed;", text), "baseline must execute and pass"
            for name, file, scope, old, new, test in CONTROLS:
                path = copy / file
                original = path.read_text()
                start = original.index(scope)
                position = original.index(old, start)
                path.write_text(original[:position] + new + original[position + len(old):])
                try:
                    code, text = run(name, test)
                    assert code != 0 and "running 1 test" in text and f"{test} ... FAILED" in text and "panicked at" in text, f"{name}: missing named assertion failure"
                    receipt["controls"].append({"name": name, "test": test, "exit_code": code, "grade": "synthetic"})
                    save()
                    print(f"PASS {name}: {test} fails with its fence reverted", flush=True)
                finally:
                    path.write_text(original)
            code, text = run("restored")
            assert code == 0 and "test result: ok." in text, "restored tests must pass"
            assert hashes == {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}, "source changed during controls"
            receipt["status"] = "passed"
        except BaseException as error:
            receipt.update(status="failed", error=str(error))
            raise
        finally:
            save()


if __name__ == "__main__":
    main()
