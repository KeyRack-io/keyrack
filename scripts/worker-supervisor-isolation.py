#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Root-only fixture provisioning; all acceptance actors run as non-root users.

Uses the already-running A2 Vault fixture. Creates no container or Vault stack.
Requires a real Linux host with systemd, useradd/runuser and sudo; no mock fallback.
"""
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import urllib.request
import uuid


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=90, **kwargs)


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("fixture provisioning requires root on Linux/systemd")
    config = json.loads(Path(sys.argv[1]).read_text())
    suffix = uuid.uuid4().hex[:12]
    worker, coordinator = "krw" + suffix, "krc" + suffix
    root = Path("/tmp/keyrack-supervisor-" + suffix)
    unit = "keyrack-worker-isolation-" + suffix + ".service"
    unit_file = Path("/run/systemd/system") / unit
    created = []
    unit_installed = False
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    try:
        for name in [worker, coordinator]:
            run("useradd", "--system", "--no-create-home", "--user-group", "--shell", "/usr/sbin/nologin", name)
            created.append(name)
        worker_uid = pwd.getpwnam(worker).pw_uid
        coordinator_uid = pwd.getpwnam(coordinator).pw_uid
        worker_gid = pwd.getpwnam(worker).pw_gid
        if worker_uid == 0 or coordinator_uid == 0 or worker_uid == coordinator_uid:
            raise RuntimeError("distinct non-root fixture users required")
        # Root-owned executables/config; coordinator cannot replace launch inputs.
        for source, name in [(config["worker_binary"], "worker"), (config["test_binary"], "worker-tests"),
                             (Path(__file__).with_name("worker-isolation-read-probe.py"), "read-probe.py")]:
            shutil.copyfile(source, root / name)
            (root / name).chmod(0o555)
        private = root / "private"
        private.mkdir(mode=0o700)
        os.chown(private, worker_uid, worker_gid)
        token = private / "worker.token"
        report = private / "worker-report.json"
        control = root / "public.control"
        control.write_text("public-read-control\n")
        control.chmod(0o444)

        def provision(source):
            temporary = private / "next.token"
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(Path(source).read_bytes())
                os.fchown(stream.fileno(), worker_uid, worker_gid)
            os.replace(temporary, token)

        def probe():
            # runuser drops privileges BEFORE Python starts. Python refuses root,
            # wrong real/effective/saved UID, capabilities, or anything but EACCES.
            run("runuser", "--user", coordinator, "--", "/usr/bin/python3", str(root / "read-probe.py"),
                str(coordinator_uid), str(worker_uid), str(token), str(control),
                env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C.UTF-8"})

        # No shell interpretation in unit values. All variable paths are generated
        # under our fixed /tmp prefix; address/parent are validated by the caller.
        values = {
            "VAULT_ADDR": config["address"], "KEYRACK_WORKER_VAULT_PARENT":config["parent"],
            "KEYRACK_WORKER_VAULT_TOKEN_FILE":str(token),
            "KEYRACK_WORKER_FIXTURE_BINARY":str(root / "worker"),
            "KEYRACK_WORKER_ISOLATION_REPORT":str(report),
            "KEYRACK_WORKER_EXPECTED_UID":str(worker_uid),
        }
        if any(any(c in value for c in '\n\r"\\%') for value in values.values()):
            raise RuntimeError("unsafe unit configuration")
        unit_file.write_text("\n".join([
            "[Unit]", "Description=Disposable worker distinct-UID acceptance fixture", "[Service]",
            "Type=oneshot", "RemainAfterExit=yes", "User=" + worker, "Group=" + worker,
            "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "UMask=0077",
            "TimeoutStartSec=60", "TimeoutStopSec=10", "KillMode=control-group",
            "WorkingDirectory=" + str(root),
            *['Environment="' + name + '=' + value + '"' for name, value in values.items()],
            "ExecStart=" + str(root / "worker-tests") + " real_vault_worker_subprocess_round_trip --exact --ignored --nocapture",
        ]) + "\n")
        unit_installed = True
        run("systemctl", "daemon-reload")
        previous = None
        for phase in ["initial", "restart", "credential-rotation"]:
            if phase == "initial":
                provision(config["initial_token"])
            elif phase == "credential-rotation":
                provision(config["rotated_token"])
                # Provisioning action, not a permission-denial test. Neither test
                # identity gets the administrator credential used to revoke old.
                request = urllib.request.Request(config["address"] + "/v1/auth/token/revoke",
                    data=json.dumps({"token":Path(config["initial_token"]).read_text()}).encode(),
                    headers={"X-Vault-Token":Path(config["admin_token"]).read_text(), "Content-Type":"application/json"})
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(request, timeout=5) as response:
                    if response.status != 204:
                        raise RuntimeError("credential revocation failed")
            print("Supervisor phase: " + phase, flush=True)
            probe()
            if report.exists():
                report.unlink()
            try:
                run("systemctl", "start" if phase == "initial" else "restart", unit)
            except subprocess.CalledProcessError:
                # The unit contains only redacted Rust fixture output; credentials
                # are never command arguments or Environment values.
                subprocess.run(["journalctl", "--unit", unit, "--no-pager", "--lines=60"],
                               check=False, timeout=10)
                raise
            result = run("systemctl", "show", unit, "--property=Result", "--value", capture_output=True, text=True)
            if result.stdout.strip() != "success":
                raise RuntimeError("worker service did not succeed")
            evidence = json.loads(report.read_text())
            if evidence["uid"] != worker_uid or evidence["child_uid"] != worker_uid:
                raise RuntimeError("worker proof ran as wrong identity")
            if previous and (evidence["worker"] == previous["worker"] or evidence["pid"] == previous["pid"]):
                raise RuntimeError("service restart did not start a fresh worker")
            previous = evidence
            print(json.dumps({"phase":phase, "worker_uid":worker_uid, "worker_pid":evidence["pid"],
                              "worker_incarnation":evidence["worker"], "native_vault_round_trip":"passed"}), flush=True)
            probe()
    finally:
        # Finish all cleanup attempts before reporting failure, including on CI
        # SIGTERM. A timeout/failure on one resource cannot skip the rest.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        failures = []

        def cleanup_command(*args):
            try:
                completed = subprocess.run(args, check=False, capture_output=True, timeout=20)
                if completed.returncode != 0:
                    failures.append(args[0] + ":" + args[1])
            except (OSError, subprocess.TimeoutExpired):
                failures.append(args[0] + ":" + args[1])

        if unit_installed:
            cleanup_command("systemctl", "stop", unit)
            cleanup_command("systemctl", "reset-failed", unit)
            try:
                state = run("systemctl", "show", unit, "--property=ActiveState", "--value", capture_output=True, text=True)
                if state.stdout.strip() != "inactive":
                    failures.append("service-still-active")
            except (OSError, subprocess.SubprocessError):
                failures.append("service-state-check")
        try:
            unit_file.unlink(missing_ok=True)
        except OSError:
            failures.append("unit-file-removal")
        if unit_installed:
            cleanup_command("systemctl", "daemon-reload")
        for name in reversed(created):
            cleanup_command("userdel", name)
            try:
                grp.getgrnam(name)
            except KeyError:
                pass
            else:
                cleanup_command("groupdel", name)
        try:
            shutil.rmtree(root)
        except OSError:
            failures.append("private-file-cleanup")
        if failures:
            print("Supervisor cleanup failures: " + ", ".join(failures), file=sys.stderr)
            raise RuntimeError("fixture cleanup incomplete")
    print("Distinct-UID supervisor acceptance PASSED: three native worker launches, six coordinator EACCES probes; unit/users/files cleaned", flush=True)


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print("Supervisor fixture interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception:
        print("Distinct-UID supervisor acceptance FAILED (no credential details logged)", file=sys.stderr)
        sys.exit(1)
