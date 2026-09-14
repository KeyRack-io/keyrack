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
environment variable. If unset, the service falls back to built-in defaults
(SQLite at `keyrack.db`, software provider, mTLS auth) — but it will not start,
because there is no default authorization policy and `pdp:` has to be stated
explicitly. A config file is therefore always required in practice.

### Minimal configuration

```yaml
grpc_addr: "0.0.0.0:50051"
rest_addr: "0.0.0.0:8080"

storage:
  type: sqlite
  path: "/var/lib/keyrack/keyrack.db"

provider:
  type: pkcs11
  lib_path: "/usr/lib/softhsm/libsofthsm2.so"
  token_label_ref: "file:token-label"
  pin_ref: "file:user-pin"

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

Mount the token label and user PIN as files beneath `KEYRACK_SECRET_ROOT`.
The example pairs persistent metadata with a persistent token; see the
[packaged SoftHSM deployment](SOFTHSM.md) for token initialization and storage.

With `bootstrap_token` auth, set the token via the `KMS_BOOTSTRAP_TOKEN`
environment variable. The token is hashed at startup — the plaintext is
not retained in memory.

### Child keys wrapped under a parent

Creating a key with a `parent_key_id` means its material is wrapped under that
parent. It is refused unless the provider that will hold it has been activated
for wrapping:

```yaml
wrapping:
  - provider: default
    mechanism: software:aes-256-gcm:v1
    security_domain: dev-single-process
```

Both values are recorded in every child's durable descriptor, which is why they
are stated here rather than derived from the provider name. Startup refuses to
run if that provider does not declare the mechanism for generate, open and
close, or cannot evidence its own closures. Omit the block — the default — and
child creation is refused everywhere.

`software:aes-256-gcm:v1` is a development and conformance mechanism, and
startup says so: the child is unwrapped into the service process's memory for
the length of a lease, which is exactly as contained as the parent wrapping it.
It gives you the hierarchy's shape, not its custody. No provider with a custody
boundary implements the operations yet.

Parent and child must be on the same provider: a wrapped child in another
security domain is refused, not deferred. A parent must be enabled,
non-exportable and independently resident, so a wrapped key cannot itself wrap
children yet.

**Keys created before 0.5.0 that name a parent are refused.** In earlier
versions a parent binding recorded lineage only, and the child had its own
independent material; 0.5 cannot distinguish that from a wrapped child except
by what the material is. Such keys are refused as wrapping parents with a
message naming the change, and startup warns when any are present. Migration is
required before using them under 0.5 semantics; there is no migration script
yet.

### Compromised-key default denial and dangerous legacy opt-in

Ordinary Decrypt and the source side of ReEncrypt deny a `Compromised` key.
This is the default even when the following setting is absent:

```yaml
legacy_compromised_key_decrypt: false
```

An explicit `legacy_compromised_key_decrypt: true` restores dangerous legacy
decrypt behavior for keys currently in `Compromised` state only. It does not
permit encrypt, sign, MAC generation, data-key generation, destination-side
ReEncrypt, rotation or raw key-material export. Normal authorization and scope
checks still apply. It is not a controlled recovery mechanism.

The setting emits a named WARN on every startup. Each exceptional decrypt or
source-side ReEncrypt emits another named WARN and a structured audit event
immediately before provider dispatch, with
`metadata.legacy_compromised_key_decrypt = "true"`,
`metadata.phase = "provider_dispatch"` and `metadata.key_state = "compromised"`.
The event names the source key, authenticated principal, operation and request
ID. Its `success` means the override was exercised, not that the subsequent
crypto operation succeeded; the ordinary operation event records that outcome.
Audit delivery is **best-effort**: an emit failure is logged, but does not withhold
the operation or result. This change does not implement audit-failure release
suppression or the separate controlled-recovery contract.

Compromise history is a persisted, monotonic `was_compromised` marker on the
logical key, independent of its current state and versions. Deletion cancellation
still returns to `Disabled`, but a historically compromised key cannot be enabled,
decrypted or exported from that state. Keys never marked compromised retain the
existing deletion-cancellation and `Disabled` behavior. Rotation cannot clear the
marker. Verify and VerifyMac retain their previous mathematical verification
behavior for Enabled, Disabled and Compromised; validity does not establish
trustworthy key provenance.

Crypto and lifecycle decisions read authoritative storage through
`get_key_for_use`, bypassing the metadata cache. Do not rely on cache TTL to
enforce compromise. Deploy the companion AWS shim change that forwards every
Decrypt to the service: older shim plaintext caches can bypass fresh service
decisions. Metadata caching remains available for queries.

**Upgrade all writers and serving replicas together.** Old binaries can ignore
or erase the new JSON marker on a subsequent write, so mixed-version operation
or rollback to those binaries is unsafe. Existing live Compromised records are
recognized and latched when written. History already erased by the old laundering
path cannot be reconstructed from a current Enabled, Disabled or PendingDeletion
record; review historical incident/audit records before treating those keys as
uncompromised. This does not protect against direct database tampering or cancel
already-dispatched provider operations.

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `KEYRACK_CONFIG` | Path to YAML config file | (built-in defaults, which lack the mandatory `pdp:` and so refuse to start) |
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

### Metadata and key-material durability

Startup rejects persistent SQLite or PostgreSQL metadata paired with any
configured `software` or `in_memory` provider, including nondefault providers.
Those providers lose key material at every process restart; stored records and
handles cannot reconstruct it. Use a durable provider for persistent keys.
`storage: {type: memory}` and SQLite's exact `:memory:` or empty temporary
filename do not require an acknowledgement. SQLite URI filenames are treated
conservatively as persistent; choose the explicit memory storage type for an
unambiguous ephemeral configuration.

A disposable development deployment may explicitly accept the loss:

```yaml
# DEVELOPMENT ONLY: restarting loses key material despite persisted metadata.
dev_only_allow_ephemeral_provider_with_persistent_metadata: true
```

The acknowledgement defaults to false. When it permits an otherwise rejected
configuration, startup emits a WARN naming the flag and affected providers.
It does not preserve keys, repair old records, or provide a migration path.

### PKCS#11 (production)

Delegates all cryptographic operations to an HSM via PKCS#11.

```yaml
provider:
  type: pkcs11
  lib_path: "/usr/lib/softhsm/libsofthsm2.so"
  token_label: "keyrack-production"
  pin_ref: "file:user-pin"
```

#### When a token goes away and comes back

Operations against a token that is not currently reachable fail with
`ProviderUnavailable` — HTTP 503, gRPC `UNAVAILABLE` — and no key material is
served from cache in its place.

When the token becomes reachable again, service returns **without restarting
KeyRack**. It is not automatic in the background: a PKCS#11 module keeps an
unusable view of a token it lost, which does not clear by itself, so KeyRack
reinitializes the library on the next request that fails against it and then
retries that request. In practice the first call after custody returns
succeeds. A client that treats 503 as retryable therefore recovers on its own;
a client that treats it as fatal will keep the outage alive on its own side.

Two consequences worth knowing before an incident:

- Reinitializing is **per library, not per token**, so it briefly affects
  every provider configured with the same `lib_path` — several tenant tokens
  on one vendor `.so`, for example. Calls already in flight are allowed to
  finish first and calls arriving during the reinitialization wait for it. A
  caller waits up to ten seconds for the window to end; beyond that it
  receives 503 `ProviderUnavailable`, because a library that has not reopened
  by then is stuck rather than busy. So the usual effect on a healthy token
  sharing the library is added latency, but a request can be refused, and a
  client that treats 503 as retryable is what keeps that from becoming an
  outage. If in-flight calls do not drain within five seconds, KeyRack
  **abandons** the recovery and leaves the token unavailable, because
  finalizing a library while another thread is inside it terminates the
  process.
- Recovery is attempted **at most once every two seconds per library**. While
  custody is still absent it cannot succeed, and repeating it per request
  would keep interrupting the tokens that are still healthy. The one exception
  is a library that an earlier attempt left finalized — if `C_Initialize`
  itself failed, there are no healthy tokens on it left to protect, so the
  next attempt is not deferred.
- A 503 from this path **says what recovery did**: reinitialized, deferred
  because one ran moments ago, abandoned because calls would not drain, or
  attempted and the library is now uninitialized. The underlying PKCS#11
  failure is kept in the same message. If you are reading one of these in an
  incident, that phrase is the fastest way to tell a rationed attempt from a
  failed one without the vendor module's own logs.

`token_label` is what gets re-resolved, not the slot number, so a token that
returns on a different slot is still found.

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

What your server has to provide for this to work:

- **KMIP 1.4.** That is the version KeyRack announces and encodes. A
  server that only speaks 2.x will reject the connection.
- **An AEAD TLS cipher suite.** KeyRack's TLS implementation offers only
  AEAD suites (AES-GCM and ChaCha20-Poly1305), so a server restricted to
  CBC suites shares no cipher with it and the handshake fails. If your
  server's AEAD suites are ECDHE-ECDSA, it needs an ECDSA certificate.
- **Mutual TLS.** The client certificate is the only authentication
  mechanism; there is no username or password field.
- **`Create`, `Activate`, `Encrypt`, `Decrypt`, `Revoke`, `Destroy`.** Keys
  are activated on creation, and revoked before destruction, because KMIP
  forbids using a Pre-Active object and forbids destroying an Active one.
- **`AuthenticatedEncryptionAdditionalData` that is actually bound.**
  KeyRack sends the encryption context in this field and relies on the
  server covering it with the authentication tag. A server that accepts
  the field and ignores it produces ciphertexts that decrypt under any
  context, which KeyRack cannot detect on its own.

Not supported over KMIP:

- **`generate-random`.** The request is built, but it has never been
  exercised against a real server, because the server this backend is
  proven against does not implement `RNGRetrieve`. Treat it as untested
  rather than working.
- **Signing keys.** Only AES-256 has been proven end to end. The other key
  specs the provider advertises are unexercised.

`conformance/kmip-provider/run-proof.sh` runs the whole lifecycle against a
third-party KMIP server. Pointing it at your own server is the way to find
out whether the requirements above hold there — in particular the AAD
binding, which is asserted rather than assumed.

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
# This routing example uses ephemeral metadata for the software provider.
storage:
  type: memory
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

**`pdp:` is mandatory and has no default.** A config without it is a hard
startup error — the service refuses to serve rather than fall back to
permitting everything. The error message lists the accepted variants. This also
applies to the built-in defaults used when `KEYRACK_CONFIG` is unset, so there
is no way to reach a running service without having stated the authorization
decision.

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

`always_allow` bypasses authorization for every request. It is accepted only
when written out like this, and the service logs a `WARN` naming it at every
startup. Use it for fixtures and local experiments, never for a deployment
holding real keys.

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

### mTLS-bound forwarded identity

For an already-authenticated upstream, bind the asserted principal and tenant
to a pinned mTLS workload identity:

```yaml
tls:
  server_cert: /etc/keyrack/tls/server.crt
  server_key: /etc/keyrack/tls/server.key
  ca_cert: /etc/keyrack/tls/delegator-ca.pem

authn:
  type: mtls_bound_forwarded_identity
  trusted_ca_cert_path: /etc/keyrack/tls/delegator-ca.pem
  required_san: spiffe://cluster.local/ns/essentials/sa/essentials
```

The upstream must set `x-keyrack-principal-id` and
`x-keyrack-tenant-id`; the latter derives `scope=tenant:<id>`.
`x-keyrack-project-id` and `x-keyrack-domain-id` are optional. Use the
unbound `forwarded_identity` authenticator only for legacy compatibility in a
separately enforced trusted perimeter.

This profile is gRPC-only because the current REST listener does not terminate
TLS or expose a client certificate to authentication. The service fails
startup unless the gRPC TLS client CA contains exactly the same PEM material as
`trusted_ca_cert_path` and an exact SAN or OU workload pin is configured. If a
REST API is required, add a REST-capable authenticator such as JWT to the
chain. Otherwise authenticated REST API calls fail explicitly with
`501 AuthenticationTransportUnsupported`; `/healthz`, `/readyz`, and
`/metrics` remain available.

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

### Audit tamper evidence and authenticity

These are two separate properties, configured separately.

**Hash chaining (tamper evidence) is always on.** Every audit event carries a
`previous_hash` linking it to its predecessor: BLAKE3 over the preceding
event's signature hex when signed, and over the preceding event's canonical
JSON when not. Either preimage is present verbatim in the written log, so the
chain is re-derivable from the log alone:

```bash
keyrack audit verify /var/log/keyrack/audit.jsonl
```

An in-place edit or an interior deletion breaks every link after it and is
detected with no key and no configuration. There are two bounds on that, and
they are closed by different things:

1. **Full-log rewrite.** Repairing the chain after an edit only means
   recomputing every link from that point forward, which anyone with write
   access to the whole log can do. So an unsigned chain does not establish
   *who* wrote the log. Signing closes this: the attacker would also need the
   signing key.
2. **Tail-truncation.** Dropping the latest N events breaks no link at all, so
   it is not detectable from the log alone — and **signing does not help
   either**. This one needs an external anchor, such as periodically recording
   the current head hash elsewhere.

**Ed25519 signing (authenticity) is opt-in.**

```yaml
sign_audit_events: true
audit_signing_key_path: "/etc/keyrack/keys/audit-signing.key"
```

The key file is 32 raw bytes (an Ed25519 seed), created on first start if it
does not exist. The hex-encoded verifying key is logged at startup. Verify with:

```bash
keyrack audit verify /var/log/keyrack/audit.jsonl --key /etc/keyrack/keys/audit-signing.key
```

`audit_signing_key_path` is **required** whenever `sign_audit_events` is true.
An ephemeral key would leave every signature written before the last restart
permanently unverifiable, which is not the property signing advertises, so the
service refuses to start in that configuration. Development deployments that
genuinely want a throwaway key must say so:

```yaml
sign_audit_events: true
audit_signing_key_ephemeral: true   # development only; logs a WARN each start
```

Back up the signing key alongside your storage. Losing it does not break the
chain — tamper evidence survives — but it does make every existing signature
unverifiable.

---

## Monitoring

### Health endpoints

| Endpoint | Description |
|---|---|
| `GET /healthz` | Storage ping and default-provider capability metadata; no live token check |
| `GET /readyz` | Bounded storage and registered-provider readiness checks; PKCS#11 opens and authenticates fresh token sessions |
| `GET /metrics` | Prometheus-format metrics |

Use `/readyz` for readiness probes. It returns 503 when a configured PKCS#11
token cannot open and authenticate a session, including a nondefault token or
a persisted connection that failed startup rehydration. The provider probe
has a two-second total budget; a timeout fails readiness. Other provider
implementations currently inherit a no-op readiness method, so a successful
response does not prove KMIP or Vault connectivity. `/healthz` capability
metadata is likewise not evidence that a token can be opened.

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

Enable in-memory caching of key metadata queries to reduce storage round-trips:

```yaml
cache:
  ttl_secs: 300          # cache TTL in seconds (default: 300 = 5 minutes)
  max_capacity: 10000    # maximum cached entries (default: 10,000)
```

Local writes replace cached entries; other replicas' metadata can remain stale
until expiry. No cross-replica invalidation subscriber is wired in this service.
Crypto, raw export, rotation and lifecycle transitions use authoritative
`get_key_for_use` reads instead. `ttl_secs` is not an authorization lease,
revocation bound or guarantee about already-dispatched operations.

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

Metadata backups do not contain software-provider key material. For a
file-backed SoftHSM token, stop all writers and preserve the token directory
alongside metadata; follow the [quiesced backup and restore procedure](SOFTHSM.md).

**Restore:** Restore config, metadata and the matching provider material before
starting the service. Verify readiness and decrypt an existing ciphertext.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `PERMISSION_DENIED` on all RPCs | PDP unreachable or denying all | Check PDP endpoint and policy |
| `UNAVAILABLE` on startup | Storage backend not reachable | Check database connection or SQLite path |
| Audit events missing | Sink misconfigured or disk full | Check sink config and disk space |
| High latency on encrypt | HSM contention | Check HSM session pool and durable-provider capacity |
