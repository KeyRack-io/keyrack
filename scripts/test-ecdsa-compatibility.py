#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-version EC wire compatibility with isolated legacy dependencies."""
import itertools
import json
import os
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance/ecdsa-compatibility"
OUTPUT = ROOT / "target/proofs/ecdsa-compatibility"


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    workspace = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    oracle = tomllib.loads((FIXTURE / "Cargo.lock").read_text())["package"]
    for name in ("p256", "p384", "ecdsa", "elliptic-curve", "crypto-bigint"):
        current = [p["version"] for p in workspace if p["name"] == name]
        assert len(current) == 1, f"expected one runtime {name}"
        assert any(p["name"] == name and p["version"] == current[0] for p in oracle), f"oracle must test runtime {name} {current}"
    env = dict(os.environ)
    env.pop("ECDSA_CORRUPT", None)
    command = ["cargo", "run", "--locked", "--manifest-path", str(FIXTURE / "Cargo.toml")]

    def run(name, mutation=None):
        result = subprocess.run(command, cwd=ROOT, env={**env, **({"ECDSA_CORRUPT": mutation} if mutation else {})}, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        (OUTPUT / (name + ".log")).write_text(result.stdout)
        return result

    baseline = run("baseline")
    assert baseline.returncode == 0 and baseline.stdout.count("PASS ") == 4, baseline.stdout
    controls = []
    for source, target in (("p256_old", "p256_new"), ("p256_new", "p256_old"), ("p384_old", "p384_new"), ("p384_new", "p384_old")):
        for encoding, mode in itertools.product(("der", "fixed"), ("message", "prehash")):
            label = f"{source}-{target}:{encoding}:{mode}"
            result = run(label.replace(":", "-"), label)
            assert result.returncode != 0 and f"{label}: valid signature refused" in result.stdout, result.stdout
            controls.append(label)
            print(f"PASS corrupted signature refused: {label}", flush=True)
    restored = run("restored")
    assert restored.returncode == 0 and restored.stdout.count("PASS ") == 4, restored.stdout
    (OUTPUT / "results.json").write_text(json.dumps({"status": "passed", "controls": controls, "legacy_versions": {"p256": "0.13.2", "p384": "0.13.1"}}, indent=2) + "\n")


if __name__ == "__main__":
    main()
