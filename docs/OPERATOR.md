# KeyRack Operator Guide

Running KeyRack in production.

---

## Prerequisites

- Rust toolchain (1.80+) or a pre-built binary
- A supported storage backend: SQLite (single-node) or PostgreSQL (recommended for production)
- A TLS certificate for gRPC/REST endpoints
- An external PDP (bundled `keyrack-cedar-pdp`, OPA, or any HTTP/gRPC-shaped PDP)
- Optional: PKCS#11 HSM or KMIP HYOK endpoint
- Optional: NATS server for event distribution

---

## Configuration

KeyRack is configured via a YAML file (`keyrack.yaml`) and environment variable overrides.

### Minimal configuration

```yaml
service:
  grpc_addr: "0.0.0.0:9090"
  rest_addr: "0.0.0.0:8080"

storage:
  backend: sqlite
  path: "/var/lib/keyrack/keyrack.db"

authn:
  bootstrap_token: "${KEYRACK_BOOTSTRAP_TOKEN}"

pdp:
  type: http
  endpoint: "http://localhost:8181/v1/authz"

audit:
  sinks:
    - type: file
      path: "/var/log/keyrack/audit.jsonl"
```

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `KEYRACK_CONFIG` | Path to config file | `keyrack.yaml` |
| `KEYRACK_BOOTSTRAP_TOKEN` | Initial auth token (hashed at startup) | — |
| `KEYRACK_LOG_LEVEL` | Tracing level (`error`, `warn`, `info`, `debug`, `trace`) | `info` |
| `KEYRACK_GRPC_ADDR` | gRPC listen address | `0.0.0.0:9090` |
| `KEYRACK_REST_ADDR` | REST listen address | `0.0.0.0:8080` |
| `DATABASE_URL` | PostgreSQL connection string (if using Postgres backend) | — |

---

## Storage backends

### SQLite (single-node)

Suitable for development and small single-node deployments.

```yaml
storage:
  backend: sqlite
  path: "/var/lib/keyrack/keyrack.db"
```

**Backup:** Copy the `.db` file while the service is stopped, or use SQLite's `.backup` command.

### PostgreSQL (production)

Recommended for production. Supports concurrent access and standard backup tooling.

```yaml
storage:
  backend: postgres
  url: "postgres://keyrack:secret@db.internal:5432/keyrack"
```

---

## HSM integration

### PKCS#11

```yaml
provider:
  type: pkcs11
  library_path: "/usr/lib/softhsm/libsofthsm2.so"
  slot: 0
  pin: "${KEYRACK_HSM_PIN}"
```

### KMIP (HYOK)

```yaml
provider:
  type: kmip
  endpoint: "https://kmip.internal:5696"
  tls_cert: "/etc/keyrack/kmip-client.pem"
  tls_key: "/etc/keyrack/kmip-client-key.pem"
```

---

## Monitoring

### Health endpoints

| Endpoint | Description |
|---|---|
| `GET /healthz` | Liveness probe (always 200 if process is running) |
| `GET /readyz` | Readiness probe (200 when storage and PDP are reachable) |
| `GET /metrics` | Prometheus-format metrics |

### Key metrics

- `keyrack_requests_total{rpc, status}` — RPC call counts
- `keyrack_request_duration_seconds{rpc}` — Latency histogram
- `keyrack_pdp_latency_seconds` — PDP evaluation latency
- `keyrack_keys_total{state}` — Key count by state
- `keyrack_audit_events_total{result}` — Audit event counts

---

## Graceful shutdown

KeyRack handles `SIGINT` and `SIGTERM`:

1. Stops accepting new connections
2. Drains in-flight requests (30s timeout)
3. Flushes audit sinks
4. Closes storage connections
5. Exits with code 0

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `PERMISSION_DENIED` on all RPCs | PDP unreachable or denying all | Check PDP endpoint and policy |
| `UNAVAILABLE` on startup | Storage backend not reachable | Check `DATABASE_URL` or SQLite path |
| Audit events missing | Sink misconfigured or disk full | Check sink config and disk space |
| High latency on encrypt | HSM contention | Increase HSM session pool or switch to software provider for non-sensitive keys |
| LID collision on `CreateKey` | Bug or misconfiguration | Upgrade to latest version (fixed in W2 patch) |

---

## Backup and restore

1. **Stop the service** (or use a read replica for Postgres)
2. **Back up storage:** `pg_dump` for Postgres, file copy for SQLite
3. **Back up config:** `keyrack.yaml` and TLS certificates
4. **Back up namespace YAML:** these define your key hierarchy
5. **Audit logs are append-only** — archive with standard log rotation (e.g. `logrotate`)

**Restore:** Deploy config, restore storage dump, start service.
