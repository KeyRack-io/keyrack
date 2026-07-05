# KeyRack Operator Guide

Running KeyRack in production.

---

## Prerequisites

- Rust toolchain (1.80+) or a pre-built container image
- A supported storage backend: SQLite (single-node) or PostgreSQL (recommended for production)
- A TLS certificate for gRPC/REST endpoints
- An external PDP (bundled `keyrack-cedar-pdp`, OPA, or any HTTP/gRPC-shaped PDP)
- Optional: PKCS#11 HSM or KMIP HYOK endpoint
- Optional: NATS server for event distribution

---

## Configuration

KeyRack is configured via a YAML file. Point to it with the `KEYRACK_CONFIG`
environment variable. If unset, the service starts with built-in defaults
(in-memory storage, software provider, insecure auth — suitable only for dev).

### Minimal configuration

```yaml
grpc_addr: "0.0.0.0:50051"
rest_addr: "0.0.0.0:8080"

storage:
  type: sqlite
  path: "/var/lib/keyrack/keyrack.db"

provider:
  type: software

pdp:
  type: http
  endpoint: "http://localhost:8181/v1/authorize"
  timeout_ms: 5000

audit:
  type: file
  path: "/var/log/keyrack/audit.jsonl"

authn:
  type: bootstrap_token
  max_age_secs: 900
```

With `bootstrap_token` auth, set the token via the `KMS_BOOTSTRAP_TOKEN`
environment variable. The token is hashed at startup — the plaintext is
not retained in memory.

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `KEYRACK_CONFIG` | Path to YAML config file | (built-in defaults) |
| `KMS_BOOTSTRAP_TOKEN` | Bootstrap auth token (hashed at startup) | — |
| `RUST_LOG` | Tracing filter (e.g. `info`, `keyrack_service=debug`) | — |

---

## Storage backends

### SQLite (single-node)

Suitable for development and small single-node deployments.

```yaml
storage:
  type: sqlite
  path: "/var/lib/keyrack/keyrack.db"
```

**Backup:** Copy the `.db` file while the service is stopped, or use SQLite's `.backup` command.

### PostgreSQL (production)

Recommended for production. Supports concurrent access and standard backup tooling.

```yaml
storage:
  type: postgres
  database_url: "postgres://keyrack:secret@db.internal:5432/keyrack"
```

### In-memory (dev/test only)

```yaml
storage:
  type: memory
```

---

## Crypto providers

### Software provider (dev/test)

Pure-Rust cryptography. Key material lives in process memory and is zeroized
on drop. Not for production HSM-grade security.

```yaml
provider:
  type: software
```

### PKCS#11 (production)

Delegates all cryptographic operations to an HSM via PKCS#11.

```yaml
provider:
  type: pkcs11
  lib_path: "/usr/lib/softhsm/libsofthsm2.so"
  token_label: "keyrack-production"
  pin: "${KMS_PKCS11_PIN}"
```

### Vault Transit (FOSS — external KMS integration)

Delegates key operations to HashiCorp Vault's Transit engine. Ideal for
teams already running Vault.

```yaml
provider:
  type: vault_transit
  vault_addr: "https://vault.internal:8200"
  vault_token: "${VAULT_TOKEN}"
  mount_path: "transit"        # optional, defaults to "transit"
```

### KMIP (HYOK / multi-cloud)

Delegates key operations to a remote KMIP-compliant HSM. Enables Hold
Your Own Key (HYOK) deployments where tenants control their own HSMs.

```yaml
provider:
  type: kmip
  host: "kmip.internal"
  port: 5696
  client_cert: "/etc/keyrack/tls/kmip-client.pem"
  client_key: "/etc/keyrack/tls/kmip-client-key.pem"
  ca_cert: "/etc/keyrack/tls/kmip-ca.pem"   # optional
```

### In-memory (test fixtures)

```yaml
provider:
  type: in_memory
```

### Multiple providers and routing

The single `provider:` block above is shorthand for one provider named
`default`. To back keys with more than one provider (e.g. multi-tenant HYOK,
or migrating keys between HSMs), use the `providers:` list instead. Each entry
has a `name` plus the same fields the single `provider:` block accepts:

```yaml
providers:
  - name: shared-soft
    type: software
  - name: tenant-acme
    type: kmip
    host: "kmip.acme.internal"
    port: 5696
    client_cert: "/etc/keyrack/tls/acme-client.pem"
    client_key: "/etc/keyrack/tls/acme-client-key.pem"

# Provider used for new keys when no routing rule matches.
# Required whenever more than one provider is configured.
default_provider: shared-soft

# Ordered rules; the first whose `match` tags are ALL present (AND logic)
# wins. Matched against the new key's identity tags.
provider_routing:
  - match:
      tenant: acme
    provider: tenant-acme
```

Notes:

- **Backward compatible.** A lone `provider:` block keeps working unchanged; it
  is equivalent to a single provider named `default`. Do not set both
  `provider:` and `providers:`.
- **Routing is by identity tag, not by request choice.** A new key is routed to
  a provider based on its identity tags. Callers populate those tags via the
  `attributes` (and `namespace`) fields on `CreateKey`; a routing rule then
  matches on them. With no caller attributes, keys go to `default_provider`.
- **Binding is per key version and permanent.** The selected provider is
  persisted on the key (and each version). Reads, decrypts, and signatures
  always use the provider that minted that version — routing rules are never
  re-evaluated for existing keys. This is what lets a key migrate backends
  (BYOK ↔ HYOK) via `rotate_key`: the new version can land on a different
  provider while old ciphertext keeps decrypting on the original.
- **Optional fail-closed assertion.** A caller may set the reserved attribute
  `keyrack.provider` to assert the expected target. If it does not match what
  the routing policy selects, `CreateKey` is rejected. The assertion never
  overrides policy — it only guards against silent misplacement (the reserved
  key is stripped before identity derivation, so it never affects the key's
  identity or LID).

---

## Authorization (PDP)

KeyRack delegates all authorization decisions to an external Policy Decision
Point. Every operation is checked before execution; the service fails closed
if the PDP is unreachable.

### HTTP PDP (OPA, Cedar, custom)

```yaml
pdp:
  type: http
  endpoint: "http://localhost:8181/v1/authorize"
  timeout_ms: 5000
```

### gRPC PDP

```yaml
pdp:
  type: grpc
  endpoint: "http://localhost:8182"
  timeout_ms: 5000
```

### Test fixtures

```yaml
pdp:
  type: always_allow   # or: always_deny
```

### Bundled Cedar PDP

KeyRack ships `keyrack-cedar-pdp`, a standalone Cedar PDP binary.
Configure it via environment variables:

| Variable | Description | Default |
|---|---|---|
| `CEDAR_POLICY_PATH` | Path to `.cedar` policy file | `policies.cedar` |
| `CEDAR_SCHEMA_PATH` | Optional Cedar schema file | — |
| `CEDAR_PDP_ADDR` | Listen address | `[::1]:8181` |

See [CEDAR_STARTER_SCHEMA.md](CEDAR_STARTER_SCHEMA.md) for an example
schema that operators can copy into their PDP deployment.

### Cedar sidecar PDP (convenience alias)

A shorthand for pointing at the bundled `keyrack-cedar-pdp` HTTP endpoint:

```yaml
pdp:
  type: cedar
  endpoint: "http://cedar-pdp:8181/v1/authorize"
  timeout_ms: 5000
```

Functionally identical to `type: http` — saves operators from remembering
which PDP backend they're running.

### PDP TLS / mTLS

Both `http` and `grpc` PDP types support optional TLS:

```yaml
pdp:
  type: http
  endpoint: "https://pdp.internal:8443/v1/authorize"
  timeout_ms: 5000
  ca_cert: "/etc/keyrack/tls/pdp-ca.pem"
  client_cert: "/etc/keyrack/tls/pdp-client.pem"
  client_key: "/etc/keyrack/tls/pdp-client-key.pem"
```

- `ca_cert`: Custom CA for the PDP's server certificate
- `client_cert` + `client_key`: Client cert/key for mTLS to the PDP

---

## Authentication

### Insecure (dev/test only)

All requests are accepted as anonymous. **Never use in production.**

```yaml
authn:
  type: insecure
```

### Bootstrap token

Time-bounded fallback for deployments without mTLS or JWT.

```yaml
authn:
  type: bootstrap_token
  max_age_secs: 900        # default: 15 minutes
```

Set the token via `KMS_BOOTSTRAP_TOKEN` env var. Audit-logged with
WARN on every use.

### mTLS

```yaml
authn:
  type: mtls
```

Extracts the principal from the peer certificate's SAN.

### JWT

```yaml
authn:
  type: jwt
  jwks_url: "https://auth.example.com/.well-known/jwks.json"
  issuer: "https://auth.example.com/"          # optional: validate `iss` claim
  audience: "keyrack"                          # optional: extracted for PDP, not enforced at authn layer
  claims_namespace: "https://keyrack.io/v1"    # optional: prefix for custom claims
```

The `issuer` field, if set, rejects tokens whose `iss` claim does not match.
The `audience` field is extracted into principal attributes so the PDP can
enforce audience restrictions — it is not validated at the authn layer.
The `claims_namespace` lets you scope custom claims (e.g.
`https://keyrack.io/v1/tenant_id`).

### Forwarded identity

Trust the `x-keyrack-principal-id` header set by an already-authenticated
upstream (e.g. the Barbican shim). **Only safe behind mTLS.**

```yaml
authn:
  type: forwarded_identity
```

### Chain (multiple authenticators)

Try authenticators in order; first successful match wins.

```yaml
authn:
  type: chain
  authenticators:
    - type: jwt
      jwks_url: "https://auth.example.com/.well-known/jwks.json"
      issuer: "https://auth.example.com/"
    - type: mtls
    - type: bootstrap_token
      max_age_secs: 300
```

---

## Audit sinks

### Stdout (dev/test)

```yaml
audit:
  type: stdout
```

### File (compliance fallback)

Append-only JSON-lines file.

```yaml
audit:
  type: file
  path: "/var/log/keyrack/audit.jsonl"
```

### NATS (production)

```yaml
audit:
  type: nats
  url: "nats://nats.internal:4222"
```

---

## TLS configuration

### gRPC server TLS

Enable TLS (and optionally mTLS) on the gRPC endpoint:

```yaml
tls:
  server_cert: "/etc/keyrack/tls/server.pem"
  server_key: "/etc/keyrack/tls/server-key.pem"
  ca_cert: "/etc/keyrack/tls/ca.pem"   # enables mTLS — omit for TLS-only
```

When `ca_cert` is set, clients must present a valid certificate signed by
this CA. Unauthenticated connections are rejected at the TLS handshake.

### gRPC keepalive

```yaml
grpc_keepalive:
  time_secs: 30       # send keepalive ping every 30s (default)
  timeout_secs: 10    # close connection if no response in 10s (default)
```

Keepalive prevents load-balancer idle timeouts and detects dead peers
faster.

### Certificate hot-reload

When TLS is enabled, KeyRack polls the cert/key files every 30 seconds.
If the files change on disk (e.g. after cert-manager renewal), the
service logs a notice. **V1 limitation:** tonic does not support live TLS
credential swapping on a running listener; perform a rolling restart
after certificate renewal. The infrastructure is in place for seamless
reload in a future version.

### Audit event signing

Enable Ed25519 tamper-evidence signatures on audit events:

```yaml
sign_audit_events: true
```

On startup the service generates an ephemeral Ed25519 keypair and logs
the hex-encoded verifying key. Each audit event is signed and includes a
hash-chain reference to the previous event, ensuring interior tampering
or deletion is detectable. Tail-truncation (dropping the latest N events)
is not detectable without an external anchor.

To persist the signing key across restarts (so verifiers can use a stable
public key), provide a path to a 32-byte Ed25519 seed file:

```yaml
audit_signing_key_path: "/etc/keyrack/keys/audit-signing.key"
```

If not set, an ephemeral key is generated each startup and the verifying
key is logged at INFO level.

---

## Monitoring

### Health endpoints

| Endpoint | Description |
|---|---|
| `GET /healthz` | Liveness: checks storage and crypto provider |
| `GET /readyz` | Readiness: checks storage ping |
| `GET /metrics` | Prometheus-format metrics |

### Key metrics

| Metric | Description |
|---|---|
| `keyrack_operations_total{action, result}` | RPC call counts by action and result |
| `keyrack_operation_duration_seconds{action, result}` | Latency histogram |
| `keyrack_pdp_request_duration_seconds` | PDP evaluation latency |
| `keyrack_pdp_errors_total` | PDP transport/evaluation failures |
| `keyrack_audit_emit_errors_total` | Audit sink write failures |

### Request correlation (`x-request-id`)

All REST and gRPC endpoints propagate the `x-request-id` header for
end-to-end tracing. If the client omits the header, the service
generates a UUIDv7. The REST gateway echoes the resolved request ID in
every response header. The same ID appears in audit events and PDP
authorization requests.

---

## NATS event distribution

Configure NATS for distributed audit events, key state-change
notifications, and cache invalidation:

```yaml
nats_notify:
  url: "nats://nats.internal:4222"
  audit_subject_prefix: "kms.audit"
  state_changed_subject_prefix: "kms.key.state-changed"
  invalidation_subject_prefix: "kms.cache.invalidate"
```

---

## Key record cache

Enable in-memory caching of key records to reduce storage round-trips:

```yaml
cache:
  ttl_secs: 300          # cache TTL in seconds (default: 300 = 5 minutes)
  max_capacity: 10000    # maximum cached entries (default: 10,000)
```

The cache is invalidated on key state changes and rotation. For HYOK
deployments, `ttl_secs` is the upper bound on time-to-lockout after a
tenant disconnects their HSM — lower it if faster revocation is required.

If omitted, caching is disabled and every operation hits the storage backend.

---

## Graceful shutdown

KeyRack handles `SIGINT` and `SIGTERM`:

1. Stops accepting new connections
2. Drains in-flight requests (30s timeout)
3. Flushes audit sinks
4. Exits cleanly

---

## Docker

### Running with Docker Compose

The repository includes a `docker-compose.yml` that starts KeyRack with the
Cedar PDP:

```bash
docker compose up -d keyrack-service
```

This starts:
- `cedar-pdp` — the Cedar PDP with a permissive test policy
- `keyrack-service` — the KeyRack service (gRPC on 50051, REST on 8080)

### Building the container

```bash
docker build -f docker/Dockerfile.service -t keyrack-service .
```

The image includes both `keyrack-service` and `keyrack-cedar-pdp` binaries.

---

## Backup and restore

1. **Stop the service** (or use a read replica for Postgres)
2. **Back up storage:** `pg_dump` for Postgres, file copy for SQLite
3. **Back up config:** `keyrack.yaml` and TLS certificates
4. **Audit logs are append-only** — archive with standard log rotation

**Restore:** Deploy config, restore storage dump, start service.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `PERMISSION_DENIED` on all RPCs | PDP unreachable or denying all | Check PDP endpoint and policy |
| `UNAVAILABLE` on startup | Storage backend not reachable | Check database connection or SQLite path |
| Audit events missing | Sink misconfigured or disk full | Check sink config and disk space |
| High latency on encrypt | HSM contention | Check HSM session pool or switch to software provider for non-sensitive keys |
