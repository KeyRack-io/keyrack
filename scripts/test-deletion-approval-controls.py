#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Revert deletion controls individually; require each specific unsafe outcome.

Uses a disposable source copy. No checkout changes; hashes, logs, commands and
individual failure diagnostics are retained in --output.
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
spec = importlib.util.spec_from_file_location("scheduling", ROOT / "scripts/test-deletion-scheduling-controls.py")
scheduling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scheduling)
require = scheduling.require
write_json = scheduling.write_json
CORE = "crates/keyrack-core/src/destruction.rs"
SQLITE = "crates/keyrack-sqlite/src/destruction.rs"
SERVICE = "crates/keyrack-service/src/"
# A compile failure never satisfies an oracle. Each mutation must run the named
# test and produce its exact assertion diagnostic, with the unsafe value.
CONTROLS = [
    ("snapshot", CORE, "self.dependents.iter().any(|edge| !intent.approved_dependents.contains(edge))", "self.dependents.iter().any(|_edge| false)",
     "dependency_override_event_surface_matrix", ["grpc/none/true/appears", "left: Destroyed", "right: PendingDeletion"]),
    ("journal", CORE, "self.in_flight_creation_journal_rows > 0 || self.migration_journal_rows > 0", "false",
     "migration_journals_refuse_all_roles_and_overrides_on_both_surfaces", ["migration journal must refuse", "left: 200", "right: 409"]),
    ("authorization", SERVICE + "ops.rs", "if ctx.allow_dependent_data_loss {", "if false && ctx.allow_dependent_data_loss {",
     "override_requires_its_own_permission_on_both_surfaces", ["override permission must refuse", "left: 200", "right: 403"]),
    ("claim_recheck", SQLITE, "counts.validate_intent(&intent(conn,&record)?.unwrap_or_default())?;", "let _ = (&counts, intent(conn,&record)?);",
     "dependency_override_event_surface_matrix", ["grpc/none/false/appears", "left: Destroyed", "right: PendingDeletion"]),
    ("envelope_erasure", SQLITE, 'conn.execute("DELETE FROM creation_journal WHERE child_lid=?1 AND phase=\'committed\'",[lid.to_string()]).map_err(|e|map_sql(&e))?;',
     'conn.execute("DELETE FROM creation_journal WHERE child_lid=?1 AND phase=\'committed\' AND 0",[lid.to_string()]).map_err(|e|map_sql(&e))?;',
     "destroyed_parent_is_explicit_and_child_envelopes_can_be_erased_on_both_surfaces", ["wrapped child envelope must be erased"]),
    ("loss_marker", SQLITE, "for edge in observed.dependents {", "for edge in observed.dependents.into_iter().take(0) {",
     "destroyed_parent_is_explicit_and_child_envelopes_can_be_erased_on_both_surfaces", ["destroyed parent version must be reported", "left: []", "right: [1]"]),
    ("claim_loss_markers", SQLITE, "record_loss_markers(conn, lid)?; save_key(conn, &record, expected)?;", "save_key(conn, &record, expected)?;",
     "destruction_completion_failure_recovers_after_restart_on_both_surfaces", ["loss metadata must match the current wrapping parent", "left: []", "right: [1]"]),
    ("claim_recovery", SQLITE, "return Ok(Some((operation, snapshot, true)));", "return Ok(None);",
     "destruction_completion_failure_recovers_after_restart_on_both_surfaces", ["retained destruction claim must eventually complete", "left: PendingDeletion", "right: Destroyed"]),
    ("marker_parent_binding", SERVICE + "domain.rs", "if material.parent().lid == lost.parent_lid && material.parent().version.get() == lost.parent_version", "if { let _ = material; true }",
     "retained_loss_markers_match_current_parent_identity_and_version", ["loss metadata must match the current wrapping parent", "left: [1]", "right: []"]),
    ("changed_edge_snapshot", CORE, "self.dependents.iter().any(|edge| !intent.approved_dependents.contains(edge))", "self.dependents.iter().any(|_edge| false)",
     "rotation_and_rewrap_reject_persisted_stale_approval_on_both_surfaces", ["changed wrapping edge must refuse stale approval", "DestructionClaim"]),
    ("legacy_intent", SQLITE, "counts.validate_intent(&intent(conn,&record)?.unwrap_or_default())?;", "counts.validate_intent(&intent(conn,&record)?.unwrap_or(counts.approval(true)?))?;",
     "existing_database_pending_deletion_has_no_implicit_loss_approval", ["legacy pending row must not gain data-loss approval", "left: Destroyed", "right: PendingDeletion"]),
    ("retry_audit", SERVICE + "workers.rs", 'emit_destruction_progress(state, &claim, AuditAction::KeyDestructionRetried, "durable_claim_resumed",).await;', "let _ = &claim;",
     "destruction_completion_failure_recovers_after_restart_on_both_surfaces", ["durable retry must be audited"]),
    ("snapshot_audit", SERVICE + "ops.rs", 'event.add_metadata("approved_dependents", serde_json::json!(edges));', 'event.add_metadata("approved_dependents", serde_json::json!(&edges[..0]));',
     "dependency_override_event_surface_matrix", ["audit must contain the exact persisted approved edge list", "left: Some(Array [])"]),
    ("boolean_intent", SERVICE + "rest.rs", 'Some(_) => { return Err(ops::rest_error( StatusCode::BAD_REQUEST, "InvalidArgument", "allow_dependent_data_loss must be a boolean", )) }', 'Some(_) => false,',
     "rest_rejects_non_boolean_data_loss_intent", ["non-boolean approval must refuse", "left: 200", "right: 400"]),
    ("refusal_metric", SERVICE + "workers.rs", 'metrics::counter!("keyrack_deletion_claim_refusals_total", "reason" => reason).increment(1);',
     'metrics::counter!("keyrack_deletion_claim_refusals_total", "reason" => reason).increment(0);',
     "refusal_is_audited_and_counted_without_destroying_material", ["assertion failed: handle.render().contains"]),
]


def run(work, output, env, timeout, name, test, expected):
    command = ["cargo", "test", "--locked", "-p", "keyrack-service", "--test", "integration", test, "--", "--test-threads=1"]
    write_json(output / f"{name}-command.json", {"argv": command, "cwd": str(work), "surface": env.get("KEYRACK_DELETION_TEST_SURFACE", "both")})
    with (output / f"{name}.log").open("w") as log:
        process = subprocess.Popen(command, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
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
    if expected is None:
        expected_names = {f"deletion_override::{control[4]}" for control in CONTROLS}
        require(exit_code == 0 and len(rows) == len(expected_names) and {name for name,_ in rows} == expected_names and all(status == "ok" for _,status in rows), "baseline did not run and pass the exact approval suite")
    else:
        require(exit_code == 101, f"{name}: expected executed Rust test failure")
        require(rows == [(f"deletion_override::{test}", "FAILED")], f"{name}: expected one named test failure, not compilation or unrelated failure")
        for diagnostic in expected:
            require(diagnostic in log, f"{name}: missing specific failure diagnostic {diagnostic!r}")
    print(f"{name}: expected outcomes and causes verified", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    require(args.timeout > 0, "timeout must be positive")
    require(not output.exists() or not any(output.iterdir()), "output must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
    require(not output.is_relative_to(target), "output must not be inside target")
    env = os.environ | {"CARGO_TARGET_DIR": str(target), "CARGO_TERM_COLOR": "never", "RUST_TEST_NOCAPTURE": "0"}
    env.pop("KEYRACK_DELETION_TEST_SURFACE", None)
    result = {"status": "started", "verified": []}
    try:
        with tempfile.TemporaryDirectory(prefix="keyrack-deletion-approvals-") as directory:
            work = Path(directory)
            write_json(output / "source-sha256.json", scheduling.copy_source(work, output, target))
            run(work,output,env,args.timeout,"baseline","deletion_override",None)
            result["verified"].append("baseline")
            for name,path,before,after,test,diagnostics in CONTROLS:
                file = work / path
                original = file.read_text()
                # Formatting changes may alter whitespace, but never identifiers,
                # conditions, or SQL. Record the exact replaced source.
                pattern = re.compile(r"\s*".join(re.escape(char) for char in before if not char.isspace()))
                matches = list(pattern.finditer(original))
                require(len(matches)==1, f"{name}: mutation anchor missing or ambiguous")
                match=matches[0]
                changed=original[:match.start()]+after+original[match.end():]
                file.write_text(changed)
                write_json(output/f"{name}-mutation.json", {"path":path,"before":match.group(),"after":after,"original_sha256":scheduling.digest(original.encode()),"mutated_sha256":scheduling.digest(changed.encode())})
                try:
                    for surface in (["grpc"] if name == "refusal_metric" else ["rest"] if name == "boolean_intent" else ["grpc", "rest"]):
                        label = f"{name}-{surface}"
                        expected = [text.replace("grpc/", f"{surface}/") for text in diagnostics]
                        run(work,output,env | {"KEYRACK_DELETION_TEST_SURFACE": surface},args.timeout,label,test,expected)
                        result["verified"].append(label)
                finally:
                    file.write_text(original)
            # Restoration is executable evidence, not just a source-copy claim.
            run(work,output,env,args.timeout,"restored","deletion_override",None)
            result["verified"].append("restored")
        result["status"]="passed"
    except (OSError,RuntimeError,subprocess.SubprocessError,KeyboardInterrupt) as error:
        result["status"]="refused";result["error"]=str(error)
        print(f"REFUSED: {error}; evidence in {output}",flush=True)
    finally:
        write_json(output/"result.json",result)
    return 0 if result["status"]=="passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())
