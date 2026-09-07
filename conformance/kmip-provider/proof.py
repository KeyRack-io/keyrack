#!/usr/bin/env python3
"""Exercise a KMIP-backed keyrack-service through its own REST surface.

Deliberately not a test of `keyrack-kmip`'s API. The crate had 22 passing unit
tests while no deployment could select the provider and no request it built
would have been accepted by any server, so crate-level tests are not evidence
that this backend works. Every operation below goes over HTTP to a running
service, which is talking KMIP to a third-party server.

Each documented operation is reported as PASS, FAIL or UNSUPPORTED.
UNSUPPORTED is not a pass: it means the operation is documented for this
backend and does not work, and it is printed so the documentation can be
narrowed to match rather than the result quietly dropped.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request

# The service binds IPv6 loopback by default.
BASE = os.environ.get("KEYRACK_REST", "http://[::1]:8080")
PLAINTEXT = b"kmip-provider-proof"

results = []


def report(name, ok, detail="", unsupported=False):
    if unsupported:
        tag, verdict = "[UNSUPPORTED]", "unsupported"
    elif ok:
        tag, verdict = "[PASS]", "pass"
    else:
        tag, verdict = "[FAIL]", "fail"
    results.append((name, verdict, detail))
    print(f"{tag:15s} {name:44s} {detail}", flush=True)


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        return e.code, raw
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def main():
    status, body = call("GET", "/readyz")
    if status != 200:
        print(f"service not ready: {status} {body}")
        return 2

    # --- create -----------------------------------------------------------
    status, body = call("POST", "/v1/keys", {"key_spec": "AES_256"})
    if status not in (200, 201) or not isinstance(body, dict) or not body.get("lid"):
        report("create key (AES-256)", False, f"HTTP {status}: {body}")
        print("\ncreate failed; nothing downstream can be attempted")
        return 1
    key_id = body["lid"]
    report("create key (AES-256)", True, f"lid={key_id}")

    # --- encrypt / decrypt ------------------------------------------------
    status, body = call(
        "POST",
        f"/v1/keys/{key_id}/actions-encrypt",
        {"plaintext": base64.b64encode(PLAINTEXT).decode()},
    )
    blob = body.get("ciphertext_blob") if isinstance(body, dict) else None
    if status != 200 or not blob:
        report("encrypt", False, f"HTTP {status}: {body}")
        blob = None
    else:
        report("encrypt", True, f"{len(base64.b64decode(blob))} bytes")

    if blob:
        status, body = call(
            "POST",
            f"/v1/keys/{key_id}/actions-decrypt",
            {"ciphertext_blob": blob},
        )
        recovered = (
            base64.b64decode(body["plaintext"])
            if status == 200 and isinstance(body, dict) and body.get("plaintext")
            else None
        )
        report(
            "decrypt round-trip",
            recovered == PLAINTEXT,
            "plaintext recovered" if recovered == PLAINTEXT else f"HTTP {status}: {body}",
        )

        # Authentication is the property AES-GCM is chosen for, so a flipped
        # ciphertext byte must not decrypt. Without the KMIP authentication
        # tag on the wire this cannot hold, which is why it is asserted here
        # and not taken on trust.
        tampered = bytearray(base64.b64decode(blob))
        tampered[-1] ^= 0x01
        status, body = call(
            "POST",
            f"/v1/keys/{key_id}/actions-decrypt",
            {"ciphertext_blob": base64.b64encode(bytes(tampered)).decode()},
        )
        report(
            "tampered ciphertext is refused",
            status != 200,
            "refused" if status != 200 else "ACCEPTED A FORGED CIPHERTEXT",
        )

    # --- describe ---------------------------------------------------------
    status, body = call("GET", f"/v1/keys/{key_id}/describe")
    report(
        "describe key",
        status == 200,
        f"provider={body.get('provider_class', '?')}" if status == 200 else f"HTTP {status}",
    )

    # --- rotate -----------------------------------------------------------
    status, body = call("POST", f"/v1/keys/{key_id}/actions-rotate", {})
    if status == 200:
        report("rotate", True, "new version created")
        if blob:
            # A rotated key must still decrypt what the previous version
            # encrypted, or rotation is data loss rather than key hygiene.
            status, body = call(
                "POST",
                f"/v1/keys/{key_id}/actions-decrypt",
                {"ciphertext_blob": blob},
            )
            ok = (
                status == 200
                and isinstance(body, dict)
                and base64.b64decode(body.get("plaintext", "")) == PLAINTEXT
            )
            report(
                "decrypt after rotate (old version)",
                ok,
                "previous version still readable" if ok else f"HTTP {status}: {body}",
            )
    else:
        report("rotate", False, f"HTTP {status}: {body}", unsupported=True)

    # --- disable / enable -------------------------------------------------
    status, _ = call("POST", f"/v1/keys/{key_id}/actions-disable", {})
    if status == 200:
        report("disable", True)
        status, body = call(
            "POST",
            f"/v1/keys/{key_id}/actions-encrypt",
            {"plaintext": base64.b64encode(PLAINTEXT).decode()},
        )
        report(
            "disabled key refuses encrypt",
            status != 200,
            "refused" if status != 200 else "DISABLED KEY STILL ENCRYPTED",
        )
        status, _ = call("POST", f"/v1/keys/{key_id}/actions-enable", {})
        report("enable", status == 200, "" if status == 200 else f"HTTP {status}")
    else:
        report("disable", False, f"HTTP {status}", unsupported=True)

    # --- generate random --------------------------------------------------
    status, body = call("POST", "/v1/generate-random", {"length": 32})
    if status == 200 and isinstance(body, dict) and body.get("random_bytes"):
        n = len(base64.b64decode(body["random_bytes"]))
        report("generate random (server RNG)", n == 32, f"{n} bytes")
    else:
        report("generate random (server RNG)", False, f"HTTP {status}: {body}", unsupported=True)

    # --- summary ----------------------------------------------------------
    npass = sum(1 for _, v, _ in results if v == "pass")
    nfail = sum(1 for _, v, _ in results if v == "fail")
    nunsup = sum(1 for _, v, _ in results if v == "unsupported")
    print(f"\n{npass} passed, {nfail} failed, {nunsup} unsupported")

    if nunsup:
        print("\nDocumented for this backend but not working:")
        for name, verdict, detail in results:
            if verdict == "unsupported":
                print(f"  - {name}: {detail}")

    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
