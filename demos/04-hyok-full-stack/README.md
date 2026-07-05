# Demo 04 — HYOK Full-Stack

Production-realistic **Hold Your Own Key** deployment demonstrating the full KeyRack security stack:

| Layer | Implementation |
|-------|---------------|
| **AuthN** | JWT tokens (RSA-256) via a minimal issuer |
| **AuthZ** | Cedar PDP with tenant-isolation policies |
| **Audit** | Signed events delivered to NATS JetStream |
| **HSM** | SoftHSM2 (PKCS#11) simulating a tenant-controlled HSM |
| **Storage** | PostgreSQL (durable metadata; survives service restarts) |
| **HYOK Disconnect** | Bounded lockout via cache TTL (10s) |

## Architecture

```
┌──────────┐     JWT      ┌──────────────────────────────────────────────┐
│  Demo    │─────────────▶│  KeyRack Service                             │
│  Client  │◀─────────────│  (JWT auth, Cedar PDP, NATS audit, cache)    │
└──────────┘              └────────┬────────────────┬───────────────┬────┘
                                   │                │               │
                          ┌────────▼──────┐  ┌─────▼─────┐  ┌─────▼─────┐
                          │  SoftHSM      │  │ Cedar PDP │  │   NATS    │
                          │  (tenant-a)   │  │ (policies)│  │(JetStream)│
                          │  PKCS#11      │  └───────────┘  └───────────┘
                          └───────────────┘
                                   │
                          ┌────────▼──────┐
                          │  JWT Issuer   │
                          │  (RSA JWKS)   │
                          └───────────────┘
```

## Quick Start

```bash
# Build and start all services
docker compose up --build

# The demo service runs automatically and shows:
#   1. JWT token acquisition
#   2. Key creation via REST API
#   3. Encrypt/Decrypt round-trip
#   4. Cross-tenant denial (Cedar AuthZ)
#   5. Instructions for HYOK disconnect test
```

## Services

| Service | Port | Role |
|---------|------|------|
| `postgres` | — | Durable key/metadata storage (`kr_*` tables) |
| `nats` | 4222, 8222 | Audit event bus (JetStream) |
| `jwt-issuer` | 9000 | Minimal RSA JWT issuer with JWKS endpoint |
| `cedar-pdp` | 8181 | Cedar policy evaluation (deny-by-default) |
| `keyrack` | 8080, 50051 | KeyRack service (REST + gRPC) |
| `demo` | — | Automated demo script |

## What To Observe

### 1. JWT Authentication
The demo client obtains a signed JWT from the issuer and uses it as a Bearer token.
KeyRack validates the token against the JWKS endpoint and extracts the `sub` claim as the principal ID.

### 2. Cedar Authorization
Cedar policies permit only known principals (`tenant-a-admin`, `tenant-b-admin`).
An unknown principal (`tenant-b-intruder`) receives an implicit DENY — no matching permit rule exists.

### 3. Signed Audit Events
Every KeyRack operation emits a signed audit event to NATS. To observe them:

```bash
# Subscribe to all audit events using a nats-box one-off container
# (the nats:alpine image does not include the nats CLI)
docker run --rm --network "$(basename $PWD)_default" \
  natsio/nats-box:latest \
  nats sub --server nats://nats:4222 "kms.audit.>"

# In another terminal, trigger operations:
curl -X POST http://localhost:8080/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256"}'
```

### 4. HYOK Disconnect (Bounded Lockout)

The most important property of HYOK: when a tenant revokes HSM access, KeyRack's ability to perform crypto operations becomes limited. With a network HSM (KMIP), disconnect fails the provider call immediately at the transport layer. This demo uses in-process SoftHSM, where the session artifact remains valid until the metadata cache TTL expires — demonstrating the upper-bound lockout window visible in HA/multi-node deployments.

**Automated test** (run from host after `docker compose up -d`):

```bash
./scripts/disconnect-demo.sh
```

**Manual test:**

```bash
# 1. Verify encrypt works
# The REST API returns the token's access_token field
TOKEN=$(curl -s -X POST http://localhost:9000/token \
  -H "Content-Type: application/json" \
  -d '{"sub":"tenant-a-admin","tenant_id":"tenant-a"}' \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

# The REST API returns the key's LID in the "lid" field (not "key_id")
KEY_LID=$(curl -s -X POST http://localhost:8080/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_spec":"AES_256"}' \
  | sed -n 's/.*"lid":"\([^"]*\)".*/\1/p')

curl -s -X POST "http://localhost:8080/v1/keys/$KEY_LID/actions-encrypt" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"aGVsbG8="}'
# → 200 OK

# 2. Simulate HSM disconnect (wipe token store)
docker compose exec keyrack rm -rf /var/lib/softhsm/tokens/*

# 3. Immediate retry — may still work (cache hit)
curl -s -X POST "http://localhost:8080/v1/keys/$KEY_LID/actions-encrypt" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"aGVsbG8="}'
# → 200 OK (cached)

# 4. Wait > 10 seconds, retry — FAILS
sleep 12
curl -s -X POST "http://localhost:8080/v1/keys/$KEY_LID/actions-encrypt" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"aGVsbG8="}'
# → 500 / UNAVAILABLE (lockout)
```

**Timeline:**
```
t=0     HSM connected       → encrypt ✓
t=0     HSM disconnected    → encrypt ✓ (from cache)
t<10s   Cache still valid   → encrypt ✓
t>10s   Cache expired       → encrypt ✗ (LOCKOUT)
```

### 5. Restart Survival (durable storage)

This demo stores metadata in **PostgreSQL** (not in-memory), and the SoftHSM
token lives in a named volume, so keys and ciphertext survive a service restart.

**Automated test** (run from host):

```bash
./scripts/restart-survival.sh
```

It creates a key, encrypts, restarts **only** the `keyrack` service, then proves
the key still resolves (GET 200) and the pre-restart ciphertext still decrypts.
With the old in-memory storage this failed; with Postgres it survives.

## Configuration

### Cache TTL

The `cache.ttl_secs: 10` in `config/keyrack.yaml` controls the bounded lockout window.
In production, this would typically be 60–300 seconds (balancing latency vs lockout speed).

### Cedar Policies

Edit `config/cedar-policy.cedar` to add/remove permitted principals.
The PDP hot-reloads on file change (if using the file-watch mode in production).

### JWT Claims

The issuer adds `keyrack:tenant_id` to tokens. KeyRack's `claims_namespace: "keyrack:"` configuration extracts any claim prefixed with `keyrack:` into principal attributes for PDP evaluation.

## Cleanup

```bash
docker compose down -v
```

## Production Considerations

| Demo Simplification | Production Reality |
|--------------------|--------------------|
| SoftHSM in same container | Separate network-HSM (Thales Luna, AWS CloudHSM, etc.) |
| Cache TTL = 10s | 60–300s based on SLA requirements |
| Single PKCS#11 token | Per-tenant HSM partitions or separate appliances |
| Permit-by-principal-UID policies | Attribute-based Cedar policies with entity stores |
| Minimal JWT issuer | Keycloak, Auth0, Azure AD, etc. |
| Single-node PostgreSQL | HA PostgreSQL (replication/failover) with encryption at rest |
