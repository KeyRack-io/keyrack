#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise the actual release workflow validators and guard-deletion controls.

Uses only the Python standard library. GitHub responses and sleep are mocked;
source artifacts and manifests are synthetic files in a temporary directory.
The workflow is never edited, and this script performs no network or publishing.
"""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import tempfile
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def workflow_validators():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    promotion = workflow.split("\n  publish-softhsm:\n", 1)[1]
    programs = []
    for raw in re.findall(r"          python3 - <<'PY'\n(.*?)\n          PY", promotion, re.S):
        programs.append("\n".join(
            line[10:] if line.startswith(" " * 10) else line
            for line in raw.splitlines()
        ))
    assert len(programs) == 3, "release validator structure changed; review the controls"
    for number, source in enumerate(programs):
        compile(source, f"release-validator-{number}", "exec")
    return programs


def main():
    programs = workflow_validators()
    sha = "a" * 40
    run = {
        "head_sha": sha, "head_branch": "main", "event": "push",
        "run_number": 15, "status": "completed", "conclusion": "success",
        "id": 123, "run_attempt": 2,
    }
    artifact = {
        "schema": 1, "commit": sha,
        "image": "ghcr.io/keyrack-io/keyrack-service-softhsm",
        "platforms": ["linux/amd64", "linux/arm64"],
        "run_id": "123", "run_attempt": "2", "digest": "sha256:" + "b" * 64,
    }
    manifest = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"platform": {"os": "linux", "architecture": arch}}
            for arch in ["amd64", "arm64"]
        ],
    }
    checks = 0
    with tempfile.TemporaryDirectory(prefix="keyrack-release-guards-") as temporary:
        root = Path(temporary)
        env = {
            "GITHUB_SHA": sha, "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_REPOSITORY": "KeyRack-io/keyrack", "GH_TOKEN": "synthetic-unused-token",
            "GITHUB_OUTPUT": str(root / "output"),
            "SOURCE_FILE": str(root / "release-source.json"),
            "SOFTHSM_IMAGE": artifact["image"], "TESTED_RUN_ID": "123",
            "TESTED_RUN_ATTEMPT": "2", "RUNNER_TEMP": str(root),
        }

        def evaluate(index, value, source=None):
            if index == 1:
                (root / "release-source.json").write_text(json.dumps(value))
            if index == 2:
                (root / "softhsm-source-manifest.json").write_text(json.dumps(value))

            def response(*_args, **_kwargs):
                return io.StringIO(json.dumps({"workflow_runs": value}))

            try:
                with (
                    patch.dict(os.environ, env),
                    patch("urllib.request.urlopen", response),
                    patch("time.sleep", lambda _: None),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    exec(compile(source or programs[index], "<workflow>", "exec"), {})
                return True
            except (SystemExit, TypeError, ValueError, KeyError):
                return False

        def check(name, index, value, wanted):
            nonlocal checks
            assert evaluate(index, value) == wanted, name
            checks += 1
            print("PASS", name)

        check("exact-successful-main-run", 0, [run], True)
        check("no-successful-run", 0, [], False)
        for field, value in [
            ("head_sha", "c" * 40), ("head_branch", "feature"),
            ("event", "pull_request"), ("conclusion", "failure"),
            ("status", "in_progress"),
        ]:
            check("run-" + field, 0, [run | {field: value}], False)
        newer_failure = run | {"run_number": 16, "conclusion": "failure"}
        check("newer-failed-run-blocks-old-success", 0, [run, newer_failure], False)
        check("latest-success-is-selected", 0, [run | {"conclusion": "failure"},
                                               run | {"run_number": 16}], True)
        check("artifact-exact-success", 1, artifact, True)
        for field, value in [
            ("schema", True), ("commit", "c" * 40), ("image", "example/other"),
            ("platforms", ["linux/amd64"]), ("run_id", "124"),
            ("run_attempt", "1"), ("digest", "sha256:bad"),
        ]:
            check("artifact-" + field, 1, artifact | {field: value}, False)
        check("artifact-extra-field", 1, artifact | {"unexpected": 1}, False)
        check("manifest-dual-native", 2, manifest, True)
        with_attestation = copy.deepcopy(manifest)
        with_attestation["manifests"].append({
            "platform": {"os": "unknown", "architecture": "unknown"},
            "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
        })
        check("manifest-attestation-allowed", 2, with_attestation, True)
        anonymous_unknown = manifest["manifests"] + [
            {"platform": {"os": "unknown", "architecture": "unknown"}}
        ]
        for name, descriptors in [
            ("missing", manifest["manifests"][:1]),
            ("duplicate", manifest["manifests"] + [manifest["manifests"][0]]),
            ("unexpected", manifest["manifests"] + [
                {"platform": {"os": "linux", "architecture": "s390x"}}
            ]),
            ("anonymous-unknown", anonymous_unknown),
        ]:
            check("manifest-" + name, 2, manifest | {"manifests": descriptors}, False)
        check("manifest-wrong-media", 2, manifest | {"mediaType": "wrong"}, False)
        mutants = [
            ("remove-run-binding", 0,
             'runs = [run for run in runs if run["head_sha"] == sha\n'
             '            and run["head_branch"] == "main" and run["event"] == "push"]',
             "runs = runs", [run | {"head_sha": "c" * 40}]),
            ("remove-run-success", 0, 'if latest["conclusion"] != "success":',
             "if False:", [run | {"conclusion": "failure"}]),
            ("remove-run-completion", 0, 'if latest["status"] == "completed":',
             "if True:", [run | {"status": "in_progress"}]),
            ("remove-latest-run-selection", 0,
             'latest = max(runs, key=lambda run: int(run["run_number"]))',
             "latest = runs[0]", [run, newer_failure]),
            ("remove-artifact-schema", 1,
             'if not isinstance(value, dict) or set(value) != set(expected) | {"digest"}:',
             "if False:", artifact | {"unexpected": 1}),
            ("remove-artifact-bindings", 1,
             'if any(type(value[key]) is not type(wanted) or value[key] != wanted for key, wanted in expected.items()):',
             "if False:", artifact | {"commit": "c" * 40}),
            ("remove-immutable-digest", 1,
             'if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):',
             "if False:", artifact | {"digest": "sha256:bad"}),
            ("remove-platform-count", 2,
             'if sorted(platforms) != [("linux", "amd64"), ("linux", "arm64")]:',
             "if False:", manifest | {"manifests": manifest["manifests"][:1]}),
            ("remove-index-media-check", 2, 'if manifest.get("mediaType") not in {',
             'if False and manifest.get("mediaType") not in {', manifest | {"mediaType": "wrong"}),
            ("remove-attestation-kind-check", 2,
             'if pair == ("unknown", "unknown") and descriptor.get("annotations", {}).get(\n'
             '        "vnd.docker.reference.type"\n    ) == "attestation-manifest":',
             'if pair == ("unknown", "unknown"):', manifest | {"manifests": anonymous_unknown}),
        ]
        for name, index, old, new, value in mutants:
            assert programs[index].count(old) == 1, name + " source mismatch; review control"
            assert not evaluate(index, value), name + " baseline must reject"
            assert evaluate(index, value, programs[index].replace(old, new, 1)), (
                name + " guard deletion must admit forbidden case"
            )
            print("KILLED", name)
    print(f"Verified {checks} cases and {len(mutants)} guard-deletion mutations; no network or publishing.")


if __name__ == "__main__":
    main()
