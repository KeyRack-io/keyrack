# Demo 09 — Audit Tamper-Evidence

Proves that KeyRack's **Ed25519-signed + BLAKE3 hash-chained** audit log
detects both field-level tampering (broken signature) and structural
tampering (line deletion / reordering that breaks the chain).

## How it works

Chaining and signing are separate properties. **Chaining is unconditional** —
every KeyRack deployment gets it, with no key and no configuration — and gives
tamper evidence. **Signing is opt-in** via `sign_audit_events: true` and gives
authenticity. This demo enables both so it can show what each one catches.

Every audit event is:

1. **Chained** via BLAKE3: `event.previous_hash = hex(blake3(link(prev_event)))`,
   where `link` is the previous event's signature hex when it is signed and its
   canonical JSON when it is not. Either preimage appears verbatim in the log,
   so the chain is checkable from the log alone. The first event's
   `previous_hash` is 64 hex zeros.
2. **Signed**, when signing is enabled, with Ed25519 over the canonical JSON of
   the event (with the `signature` field nulled before signing). The signed
   bytes include `previous_hash`, so the signature also attests to the link.

```
Event 1: previous_hash="000...0"  signature=Ed25519(event1_content)
Event 2: previous_hash=blake3(event1.signature)  signature=Ed25519(event2_content)
Event 3: previous_hash=blake3(event2.signature)  signature=Ed25519(event3_content)
```

### What each tamper breaks

| Tamper | Detected by | Needs a key? |
|--------|-------------|--------------|
| Modify any field value | Ed25519 signature check (signature no longer matches content) | Yes |
| Delete or reorder a line | BLAKE3 hash chain (subsequent `previous_hash` no longer matches) | No |
| Inject a new line | BLAKE3 hash chain (injected event's `previous_hash` is wrong) | No |

Two limits, stated plainly:

- **Tail-truncation** (dropping the newest N events) breaks nothing internal to
  the log. Detecting it requires an external anchor, e.g. periodically
  recording the current head hash somewhere else.
- **A chain alone does not prove authorship.** An attacker with write access to
  the whole file can rewrite every event and recompute every link. Signing is
  what makes that infeasible, which is why an audit-grade deployment sets
  `sign_audit_events: true` with a persistent key.

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
| `keyrack audit verify --key` on the clean log | Exit 0, all events OK |
| Falsify outcome (`"result":"success"` → `"denied"`) in event 1 | Exit 1, "invalid signature" |
| Delete event 2, recheck | Exit 1, "hash chain break" |
| `keyrack audit verify` on the clean log, **no key** | Exit 0, "hash chain only" |
| `keyrack audit verify` on the deletion-tampered log, **no key** | Exit 1, "hash chain break" |

The last two are what an unsigned deployment gets. They run in CI, so the claim
"tamper evidence without a signing key" is asserted rather than asserted-about.

## CLI: keyrack audit verify

The verifier is a subcommand of the `keyrack` CLI built in this repo:

```bash
# Verify the hash chain and the signatures
keyrack audit verify /data/audit.log --key /data/audit-signing.key

# Output:
# event 1: OK
# event 2: OK
# event 3: OK
#
# 3/3 events OK — checked hash chain + Ed25519 signatures
```

Omit `--key` to check only the hash chain. That is the mode an unsigned
deployment uses, and it still detects deletion, reordering, and injection:

```bash
keyrack audit verify /data/audit.log
# 3/3 events OK — checked hash chain only (no --key given; tamper evidence, not authenticity)
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
