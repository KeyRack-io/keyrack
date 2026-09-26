#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run D baselines and kill eight guard removals in an isolated source copy.

Requires KEYRACK_SOFTHSM_TEST_LIB and local loopback sockets. A fresh token is
initialized through keyrack-softhsm-init and file secret references. No existing
token, production credential, or working-tree source is changed. JSON receipts
and SHA256-addressed stage logs are suitable for CI artifact upload. Compilation
errors, setup failures, zero selected tests, and unexpected assertions never
count as killed mutants. Build output is separate from the receipt directory.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SERVICE = "crates/keyrack-service/src/"
PROVIDER = "crates/keyrack-pkcs11/src/provider.rs"
NATIVE = "provider::concurrent_login_tests::readiness_authenticates_token_and_rejects_overlapping_probes"
OUTAGE = "nondefault_token_outage_fails_readiness_and_recovery_restores_it"
DYNAMIC = "dynamically_registered_token_participates_in_readiness"
MISSING = "persisted_token_missing_after_rehydration_fails_readiness"
HUNG = "hung_token_is_bounded_and_does_not_starve_the_async_executor"
STARTUP = "process_refuses_unsafe_topology_before_creating_metadata"
WARNING = "process_emits_conspicuous_warning_when_development_acknowledgement_is_used"
WARNING_BLOCK = '''    if !ephemeral.is_empty() {
        tracing::warn!(
            dev_only_allow_ephemeral_provider_with_persistent_metadata = true,
            providers = ?ephemeral,
            "DEVELOPMENT ONLY: persistent metadata does not persist these providers' key material; restarting loses keys and makes existing ciphertext undecryptable"
        );
    }'''

# name, source, exact original, replacement, suite, selected test, assertion
MUTATIONS = [
    ("ignore_provider_result", SERVICE + "rest.rs",
     "let ready = storage_ok && providers_ok;", "let ready = storage_ok;",
     "readiness", OUTAGE, "healthy storage and default must not hide a named token outage"),
    ("probe_default_only", SERVICE + "readiness.rs",
     "for (name, entry) in entries.iter().cloned() {",
     "for (name, entry) in entries.iter().cloned() { if name != *providers.default_ref() { continue; }",
     "readiness", DYNAMIC, "left: 200\n right: 503"),
    ("ignore_failed_rehydration", SERVICE + "readiness.rs",
     "if connection.pkcs11_params().is_some()",
     "if false && connection.pkcs11_params().is_some()",
     "readiness", MISSING, "left: 200\n right: 503"),
    ("remove_probe_deadline", SERVICE + "readiness.rs",
     "Duration::from_secs(2)", "Duration::from_secs(60)",
     "readiness", HUNG, "readiness must finish within its 2-second budget: Elapsed"),
    ("omit_native_session", PROVIDER, "provider.run(|_session| Ok(())).await",
     "let _ = provider; Ok(())", "native", NATIVE,
     "readiness must authenticate, not inspect cached capabilities"),
    ("omit_shared_probe_permit", PROVIDER,
     "let permit = Arc::clone(&self.readiness_gate)",
     "let permit = Arc::new(tokio::sync::Semaphore::new(1))", "native", NATIVE,
     "an overlapping native readiness probe must be rejected"),
    ("omit_startup_durability_guard", SERVICE + "config.rs",
     "        self.validate_provider_durability()?;", "",
     "provider_durability_startup", STARTUP,
     "startup validation must run before opening metadata"),
    ("omit_development_warning", SERVICE + "main.rs", WARNING_BLOCK,
     "    let _ = ephemeral;", "provider_durability_startup", WARNING,
     "acknowledgement must produce a conspicuous warning"),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Proof:
    def __init__(self, project, output, target, timeout, library):
        self.project, self.output, self.target = project, output, target
        self.timeout, self.library = timeout, library
        # No caller-injected provider/PIN configuration participates in proofs.
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("KEYRACK_", "KMS_", "SOFTHSM"))}
        self.env.update({"CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                         "CARGO_INCREMENTAL": "0", "CARGO_TERM_COLOR": "never"})
        self.receipt = {"started_utc": datetime.now(timezone.utc).isoformat(),
                        "status": "running", "stages": [], "controls": []}

    def save(self):
        (self.output / "receipt.json").write_text(json.dumps(self.receipt, indent=2) + "\n")

    def run(self, name, command, env=None):
        path = self.output / (name + ".log")
        started = time.monotonic()
        print(f"RUN {name}", flush=True)
        with path.open("w") as log:
            process = subprocess.Popen(command, cwd=self.project, env=env or self.env,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            timed_out = False
            try:
                code = process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
                timed_out = True
            except BaseException:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise
        data = path.read_bytes()
        self.receipt["stages"].append({"name": name, "command": command, "exit_code": code,
                                       "seconds": round(time.monotonic() - started, 3),
                                       "log": path.name, "sha256": digest(data)})
        self.save()
        if timed_out:
            raise RuntimeError(f"{name}: command timeout; never counts as a killed mutant")
        return code, data.decode(errors="replace")

    def cargo(self, *args):
        return ["cargo", *args, "--locked", "--target-dir", str(self.target)]

    def tests(self, suite, selected=None):
        if suite == "native":
            args = ["test", "-p", "keyrack-pkcs11", "--features", "softhsm-tests", "--lib"]
        else:
            args = ["test", "-p", "keyrack-service", "--test", suite]
        if selected:
            args.append(selected)
        command = self.cargo(*args) + ["--", "--test-threads=1"]
        if selected:
            command.append("--exact")
        return command

    def fixture(self, root, label):
        root.mkdir(mode=0o700)
        (root / "tokens").mkdir(mode=0o700)
        (root / "secrets").mkdir(mode=0o700)
        for name, value in (("token-label", label), ("user-pin", secrets.token_hex(12)),
                            ("so-pin", secrets.token_hex(12))):
            path = root / "secrets" / name
            path.write_text(value)
            path.chmod(0o600)
        config = root / "softhsm2.conf"
        config.write_text(f"directories.tokendir = {root / 'tokens'}\nobjectstore.backend = file\n"
                          "log.level = ERROR\nslots.removable = false\n")
        env = self.env | {"SOFTHSM2_CONF": str(config), "KEYRACK_SOFTHSM_LIB": self.library,
                          "KEYRACK_SECRET_ROOT": str(root / "secrets"),
                          "KEYRACK_SOFTHSM_TOKEN_LABEL_REF": "file:token-label",
                          "KEYRACK_SOFTHSM_USER_PIN_REF": "file:user-pin",
                          "KEYRACK_SOFTHSM_SO_PIN_REF": "file:so-pin",
                          "KMS_PKCS11_LIB": self.library, "KMS_PKCS11_TOKEN_LABEL": label,
                          "KMS_PKCS11_PIN_FILE": str(root / "secrets/user-pin")}
        code, _ = self.run(label + "-init", [str(self.target / "debug/keyrack-softhsm-init")], env)
        if code:
            raise RuntimeError(f"{label}: initializer failed; this is a setup failure")
        return env


def passed(output, name):
    return re.search(r"^test " + re.escape(name) + r" \.\.\. ok$", output, re.MULTILINE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "target/proofs/softhsm-deliverable-d")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/softhsm-deliverable-d-build")
    parser.add_argument("--timeout-seconds", type=int, default=900,
                        help="per command build/test bound; tests have their own shorter deadlines")
    args = parser.parse_args()
    library = os.environ.get("KEYRACK_SOFTHSM_TEST_LIB")
    if not library or not Path(library).is_file():
        parser.error("KEYRACK_SOFTHSM_TEST_LIB must name an existing library; no silent skip")
    if args.timeout_seconds < 15:
        parser.error("timeout must allow the 10-second missing-warning assertion")
    output, target = args.output_dir.resolve(), args.target_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output directory must be empty (preserve earlier receipts)")
    # Snapshot while the source is pristine; exact anchors prevent stale mutants.
    originals = {file: (ROOT / file).read_text() for _, file, *_ in MUTATIONS}
    for name, file, old, *_ in MUTATIONS:
        if originals[file].count(old) != 1:
            parser.error(f"{name}: mutation anchor changed; review rather than silently skip")
    with tempfile.TemporaryDirectory(prefix="keyrack-deliverable-d-") as temporary:
        project = Path(temporary) / "source"
        # Fresh mtimes are essential: preserving old source mtimes can make
        # Cargo reuse a prior mutant from this dedicated target cache. Baseline
        # execution must rebuild the pristine copy, not trust those artifacts.
        shutil.copytree(ROOT, project, symlinks=True, copy_function=shutil.copy,
                        ignore=shutil.ignore_patterns(".git", "target", ".aikdb", "node_modules",
                                                      "__pycache__", ".venv"))
        proof = Proof(project, output, target, args.timeout_seconds, str(Path(library).resolve()))
        proof.receipt["source_sha256"] = {file: digest(text.encode()) for file, text in originals.items()}
        proof.save()
        try:
            code, _ = proof.run("build-initializer", proof.cargo("build", "-p", "keyrack-service",
                                                               "--bin", "keyrack-softhsm-init"))
            if code:
                raise RuntimeError("baseline initializer compilation failed")
            native_env = proof.fixture(Path(temporary) / "baseline-token", "d-baseline")
            for suite, names, env in (
                ("readiness", [OUTAGE, DYNAMIC, MISSING, HUNG], proof.env),
                ("provider_durability_startup", [STARTUP, WARNING], proof.env),
                ("native", [NATIVE], native_env),
            ):
                selected = NATIVE if suite == "native" else None
                code, text = proof.run("baseline-" + suite, proof.tests(suite, selected), env)
                if code or any(not passed(text, name) for name in names):
                    raise RuntimeError(f"{suite}: expected baseline tests did not execute and pass")
            for name, file, old, new, suite, test, assertion in MUTATIONS:
                source = project / file
                if source.is_symlink():
                    raise RuntimeError("refusing to mutate a source symlink")
                env = proof.fixture(Path(temporary) / name, "d-" + name[:25]) if suite == "native" else proof.env
                source.write_text(originals[file].replace(old, new, 1))
                try:
                    code, text = proof.run(name, proof.tests(suite, test), env)
                    failed = re.search(r"^test " + re.escape(test) + r" \.\.\. FAILED$", text, re.MULTILINE)
                    if code != 101 or not failed or assertion not in text:
                        raise RuntimeError(f"{name}: not killed by the expected executed test/assertion; inspect log")
                    proof.receipt["controls"].append({"mutation": name, "file": file, "test": test,
                                                       "expected_assertion": assertion, "result": "killed"})
                    proof.save()
                    print(f"KILLED {name}: {test}", flush=True)
                finally:
                    source.write_text(originals[file])
            for file, original in originals.items():
                if (ROOT / file).read_text() != original:
                    raise RuntimeError(f"working-tree source changed during run: {file}; receipt needs review")
            proof.receipt["status"] = "passed"
            print(f"PASS: all baselines and {len(MUTATIONS)} killed controls; {output / 'receipt.json'}", flush=True)
        except Exception as error:
            proof.receipt["status"] = "failed"
            proof.receipt["failure"] = str(error)
            raise
        finally:
            proof.receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
            proof.save()


if __name__ == "__main__":
    main()
