#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Provision worker assertions inside A2's existing disposable demo Vault.

No server/container/workflow is created here. The caller is the optional command
hook in test-vault-provider.sh. This trusted test launcher intentionally has admin
access; it is not evidence of distinct-UID coordinator isolation.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid


def main():
    address = os.environ.get("VAULT_ADDR", "")
    parsed = urllib.parse.urlsplit(address)
    admin = os.environ.get("VAULT_TOKEN", "")
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or not parsed.port or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or admin != "demo-root-token"):
        raise RuntimeError("requires A2's localhost demo fixture and development token")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, body=None, method=None, allow_missing=False):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(address.rstrip("/") + "/v1/" + path, data=data,
                                     method=method,
                                     headers={"X-Vault-Token": admin,
                                              "Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=5) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise RuntimeError("oversized fixture response")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as error:
            if allow_missing and error.code == 404:
                return {}
            raise RuntimeError("fixture request refused") from None
        except urllib.error.URLError:
            raise RuntimeError("fixture unavailable") from None

    suffix = uuid.uuid4().hex
    parent = "worker-fixture-" + suffix
    worker_policy = "worker-tests-" + suffix
    coordinator_policy = "coordinator-tests-" + suffix
    tokens, policies = [], []
    parent_created = False
    cleanup_failed = False
    result = 1
    with tempfile.TemporaryDirectory(prefix="keyrack-worker-vault-") as directory:
        root = Path(directory)
        root.chmod(0o700)

        def token_file(name, value):
            path = root / name
            # Atomic private creation, independent of the caller's umask.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(value)
            return str(path)

        try:
            request("transit/keys/" + parent, {"type": "aes256-gcm96", "derived": True,
                    "exportable": False, "allow_plaintext_backup": False})
            parent_created = True
            worker_rules = "\n".join(
                'path "transit/' + path + '/worker-fixture-*" { capabilities = ["' + capability + '"] }'
                for path, capability in [("keys", "read"), ("datakey/wrapped", "update"),
                                          ("decrypt", "update")])
            request("sys/policies/acl/" + worker_policy, {"policy": worker_rules})
            policies.append(worker_policy)
            coordinator_rules = ('path "auth/token/lookup-self" { capabilities = ["read"] }\n'
                                 'path "transit/decrypt/*" { capabilities = ["deny"] }')
            request("sys/policies/acl/" + coordinator_policy, {"policy": coordinator_rules})
            policies.append(coordinator_policy)
            for policy in [worker_policy, coordinator_policy]:
                token = request("auth/token/create", {"policies": [policy],
                                "no_default_policy": True, "ttl": "20m"})["auth"]["client_token"]
                tokens.append(token)
            env = os.environ.copy()
            env.pop("VAULT_TOKEN", None)
            env.pop("VAULT_NAMESPACE", None)
            env.update({
                "KEYRACK_WORKER_VAULT_PARENT": parent,
                "KEYRACK_WORKER_VAULT_TOKEN_FILE": token_file("worker.token", tokens[0]),
                "KEYRACK_WORKER_VAULT_COORDINATOR_TOKEN_FILE": token_file("coordinator.token", tokens[1]),
                "KEYRACK_WORKER_VAULT_ADMIN_TOKEN_FILE": token_file("admin.token", admin),
            })
            print("Running worker assertions inside the existing Vault provider fixture", flush=True)
            result = subprocess.run(["bash", str(Path(__file__).with_name(
                "test-worker-vault-contribution.sh"))], env=env, check=False).returncode
        finally:
            # Revoke only this run's tokens/policies/parent. A2 owns container
            # teardown, including any failed parent-loss test's temporary key.
            cleanup = [("auth/token/revoke", {"token": token}, None) for token in tokens]
            if parent_created:
                cleanup += [("transit/keys/" + parent + "/config", {"deletion_allowed": True}, None),
                            ("transit/keys/" + parent, None, "DELETE")]
            cleanup += [("sys/policies/acl/" + policy, None, "DELETE") for policy in policies]
            for path, body, method in cleanup:
                try:
                    request(path, body, method, allow_missing=True)
                except (RuntimeError, ValueError, OSError):
                    cleanup_failed = True
            if cleanup_failed:
                print("Worker fixture cleanup incomplete; A2 fixture teardown is still required", file=sys.stderr)
    return result if result != 0 else int(cleanup_failed)


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        # Never print provider response bodies, credentials, or chained errors.
        print("Worker fixture preparation failed; use the A2 disposable-fixture hook", file=sys.stderr)
        sys.exit(1)
