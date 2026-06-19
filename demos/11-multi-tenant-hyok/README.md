# Demo 11: Multi-Tenant HYOK — scope_owner isolation + backend_id routing

Showcases KeyRack 0.3.0 differentiators in a two-tenant HYOK deployment:

| Feature | What the demo proves |
|---------|---------------------|
| **`scope_owner` tenant isolation** | A tenant's principal can only use HSM connections scoped to its own tenant — cross-tenant access returns `PermissionDenied` on both REST and gRPC. |
| **`backend_id` selector** | Callers name their crypto backend explicitly on `CreateKey`. The response echoes the resolved `backend_id`. |
| **`route` pin** | Operator pins `regulated=true` keys to the default software backend — caller `backend_id` conflicting with the pin is rejected. |
| **`delegate_any`** | Untagged keys use `delegate_any` — callers select any registered backend via `backend_id`. |
| **Absent-scope denial** | A principal with no scope claim is denied access to any scoped connection. |
| **Audit (NATS)** | Subscribes to the NATS audit subject and asserts that `scope_owner_check` events with `result=success` (allowed op) and `result=denied` (cross-tenant block) are present. Fails the demo if either is missing. |

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────────────────────┐
│ JWT Issuer   │────▶│  KeyRack     │────▶│  SoftHSM2                        │
│ (scope claim)│     │  (REST+gRPC) │     │  ├─ token: tenant-a (scope:a)    │
└─────────────┘     │              │     │  └─ token: tenant-b (scope:b)    │
                    │  scope_owner │     └──────────────────────────────────┘
                    │  enforcement │
                    │              │────▶ NATS (audit events)
                    │              │────▶ Postgres (key + connection storage)
                    └──────────────┘
```

The JWT issuer mints tokens with a namespaced `keyrack:scope` claim (e.g.
`tenant:a`). KeyRack's JWT authenticator lifts this into the principal's `scope`
attribute. When a crypto operation resolves to an HSM connection with
`scope_owner = tenant:a`, KeyRack checks `principal.scope == scope_owner` —
mismatch or absent → `PermissionDenied` (fail-closed).

## Running

```bash
# From keyrack-oss/demos/11-multi-tenant-hyok:
docker compose up --build

# Or via the CI driver (from keyrack-oss/):
./scripts/run-demos-ci.sh 11-multi-tenant-hyok
```

## Assertions (CI-gated, fail-on-error)

The demo exits non-zero if any check fails. Key assertions:

- gRPC `CreateHsmConnection` succeeds for both tenants (exits if not)
- REST `CreateKey` with `backend_id=conn-tenant-b` by `scope=tenant:a` → HTTP 403
- REST `Encrypt`/`Decrypt` on cross-tenant keys → HTTP 403
- gRPC `Encrypt` on cross-tenant key → `PermissionDenied`
- `CreateKey` with no scope claim on scoped connection → HTTP 403
- `regulated=true` route pin → `backend_id=default`; conflicting `backend_id` rejected
- `delegate_any` → caller-selected `backend_id` echoed
- NATS audit: `scope_owner_check` event with `result=success` present
- NATS audit: `scope_owner_check` event with `result=denied` present
