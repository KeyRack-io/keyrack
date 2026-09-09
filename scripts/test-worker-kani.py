#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run every registered worker proof; a missing or empty registry is an error."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent
worker = root / "crates/keyrack-crypto-worker"
registry = json.loads((worker / "verification/kani-harnesses.json").read_text())
names = registry["harnesses"]
if not names or len(set(names)) != len(names):
    raise RuntimeError("worker proof registry must be nonempty and unique")
for name in names:
    subprocess.run(["kani", str(worker / registry["source"]), "--harness", name,
                    "--output-format", "terse"], check=True, timeout=120)
print(f"Worker Kani verification PASSED: {len(names)} registered harnesses", flush=True)
