# Demo 09 — Audit Tamper-Evidence

Proves that KeyRack's **Ed25519-signed + BLAKE3 hash-chained** audit log
detects both field-level tampering (broken signature) and structural
tampering (line deletion / reordering that breaks the chain).

## How it works

Every audit event written by KeyRack (when `sign_audit_events: true`) is:

1. **Signed** with Ed25519 over the canonical JSON of the event (with
   the `signature` field nulled before signing).
2. **Chained** via BLAKE3: `event.previous_hash = hex(blake3(prev_event.signature_hex_bytes))`.
   The first event's `previous_hash` is 64 hex zeros.

```
Event 1: previous_hash="000...0"  signature=Ed25519(event1_content)
Event 2: previous_hash=blake3(event1.signature)  signature=Ed25519(event2_content)
Event 3: previous_hash=blake3(event2.signature)  signature=Ed25519(event3_content)
```

### What each tamper breaks

| Tamper | Detected by |
|--------|-------------|
| Modify any field value | Ed25519 signature check (signature no longer matches content) |
| Delete or reorder a line | BLAKE3 hash chain (subsequent `previous_hash` no longer matches) |
| Inject a new line | BLAKE3 hash chain (injected event's `previous_hash` is wrong) |

## Quick start

```bash
cd demos/09-audit-tamper-evidence
docker compose up --build
# The `demo` container exits 0 on success.
docker compose down -v
```

## What the demo verifies

| Check | Expected result |
|-------|----------------|
| `keyrack audit verify` on the clean log | Exit 0, all events OK |
| Falsify outcome (`"result":"success"` → `"denied"`) in event 1 | Exit 1, "invalid signature" |
| Delete event 2, recheck | Exit 1, "hash chain break" |

## CLI: keyrack audit verify

The verifier is a subcommand of the `keyrack` CLI built in this repo:

```bash
# Verify a log file against its signing key
keyrack audit verify /data/audit.log --key /data/audit-signing.key

# Output:
# event 1: OK
# event 2: OK
# event 3: OK
#
# 3/3 events OK
```

### Signing key format

The signing key file contains the raw 32-byte Ed25519 seed (same file the
service writes when `audit_signing_key_path` is set in `keyrack.yaml`).

## Services

| Service | Role |
|---------|------|
| `keyrack` | KeyRack service with file audit sink + signing enabled |
| `demo` | Same image, `/bin/sh` entrypoint; runs the verification script |

Both containers share the `audit-data` volume at `/data`, giving the demo
container read access to `audit.log` and `audit-signing.key`.

## Configuration

Key settings in `config/keyrack.yaml`:

```yaml
audit:
  type: file
  path: /data/audit.log

sign_audit_events: true
audit_signing_key_path: /data/audit-signing.key
```

The service generates and persists a new Ed25519 key at startup if the file
does not yet exist.
