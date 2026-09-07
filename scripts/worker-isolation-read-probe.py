#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Executed only as the real, unprivileged coordinator fixture identity."""
import errno
import json
import os
from pathlib import Path
import sys


class ProbeCheckFailed(RuntimeError):
    """Only static check descriptions are safe to expose in fixture logs."""


def main():
    expected_uid, worker_uid = map(int, sys.argv[1:3])
    token, control = map(Path, sys.argv[3:5])
    uids = os.getresuid()
    if expected_uid == 0 or worker_uid == 0 or expected_uid == worker_uid:
        raise ProbeCheckFailed("invalid fixture identities")
    if uids != (expected_uid,) * 3:
        raise ProbeCheckFailed("probe did not run as coordinator")
    if any(name in os.environ for name in ["VAULT_TOKEN", "KEYRACK_WORKER_VAULT_TOKEN_FILE",
            "KEYRACK_WORKER_VAULT_ADMIN_TOKEN_FILE"]):
        raise ProbeCheckFailed("coordinator inherited credential configuration")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if int(status["CapEff"].strip(), 16) != 0:
        raise ProbeCheckFailed("capable probe is not isolation evidence")
    # Positive control prevents an unrelated read/setup failure from passing.
    if control.read_text() != "public-read-control\n":
        raise ProbeCheckFailed("public read control failed")
    try:
        fd = os.open(token, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as error:
        if error.errno != errno.EACCES:
            raise ProbeCheckFailed("token read failed for wrong reason") from None
    else:
        os.close(fd)
        raise ProbeCheckFailed("coordinator could open worker credential")
    print(json.dumps({"probe":"coordinator-token-read", "ruid":uids[0],
                      "euid":uids[1], "suid":uids[2], "worker_uid":worker_uid,
                      "effective_capabilities":0, "result":"EACCES"}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except ProbeCheckFailed as error:
        print(f"Coordinator isolation probe FAILED: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Unexpected exception text may contain paths or credential data.
        print("Coordinator isolation probe FAILED: unexpected setup/runtime error", file=sys.stderr)
        sys.exit(1)
