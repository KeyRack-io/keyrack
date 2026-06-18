# Demo 11: Multi-Tenant HYOK — scope_owner isolation + backend_id routing

Showcases KeyRack 0.3.0 differentiators in a two-tenant HYOK deployment:

| Feature | What the demo proves |
|---------|---------------------|
| **`scope_owner` tenant isolation** | A tenant's principal can only use HSM connections scoped to its own tenant — cross-tenant access returns `PermissionDenied`. |
| **`backend_id` selector** | Callers name their crypto backend explicitly on `CreateKey`. The response echoes the resolved `backend_id`. |
| **Route / delegate routing** | Operator `route` pins a namespace to a backend (authoritative). `delegate_any` lets callers choose via `backend_id`. |
| **Absent-scope denial** | A principal with no scope claim is denied access to any scoped connection. |
| **Audit** | Every `scope_owner` evaluation emits a `scope_owner_check` audit event to NATS. |

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

The demo exits non-zero if any check fails. Key deny-path assertions:

- `CreateKey` with `backend_id=conn-tenant-b` by a `scope=tenant:a` principal → HTTP 403
- `Encrypt` on a key bound to `conn-tenant-b` by a `scope=tenant:a` principal → HTTP 403
- `Decrypt` on a cross-tenant key → HTTP 403
- `CreateKey` with no scope claim on a scoped connection → HTTP 403
