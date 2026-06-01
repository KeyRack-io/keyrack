# KeyRack Technical Architecture

KeyRack is a key lifecycle coordination layer. It separates two
concerns that existing tools conflate:

1. **Cryptographic operations** (encrypt, decrypt, sign, verify, wrap,
   unwrap) — HSMs, Vault, and cloud KMS already do this well
2. **Lifecycle coordination** (what wraps what, what depends on this
   key, what needs rotating) — no existing solution provides this

KeyRack sits above cryptographic providers, coordinating lifecycle
while delegating actual cryptography to pluggable backends.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        APPLICATION                                  │
│                                                                     │
│  Uses KeyRack via:                                                  │
│   • gRPC client (any language with protobuf)                        │
│   • REST API (any language with HTTP)                               │
│   • keyrack-core Rust library (embedded)                            │
│   • AWS SDK (via compatibility shim — commercial)                   │
│   • Barbican API (via compatibility shim — commercial)              │
└──────────────┬──────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     KEYRACK SERVICE (Rust)                           │
│                                                                     │
│   ┌───────────────┐  ┌──────────────┐  ┌───────────────────────┐   │
│   │  gRPC Server  │  │  REST Server │  │  Prometheus /metrics  │   │
│   │  (tonic)      │  │  (axum)      │  │  /healthz  /readyz    │   │
│   └───────┬───────┘  └──────┬───────┘  └───────────────────────┘   │
│           │                 │                                       │
│   ┌───────▼─────────────────▼───────────────────────────────────┐   │
│   │                    Operation Layer                           │   │
│   │  PDP authorization (every operation) → Audit emission       │   │
│   │  Key state machine → Rotation jobs → Background workers     │   │
│   └──────────┬──────────────────────────────────┬───────────────┘   │
│              │                                  │                   │
│   ┌──────────▼──────────┐        ┌──────────────▼───────────┐      │
│   │  CryptoProvider     │        │  StorageBackend          │      │
│   │  (pluggable trait)  │        │  (pluggable trait)       │      │
│   └──────────┬──────────┘        └──────────────┬───────────┘      │
└──────────────┼──────────────────────────────────┼───────────────────┘
               │                                  │
     ┌─────────┼─────────┐              ┌────────┼────────┐
     ▼         ▼         ▼              ▼                 ▼
┌─────────┐┌────────┐┌───────┐   ┌──────────┐     ┌────────────┐
│Software ││PKCS#11 ││ KMIP  │   │PostgreSQL│     │  SQLite    │
│Provider ││Provider││Provider│   │          │     │            │
│(RustCry)││(HSM)   ││(HSM)  │   └──────────┘     └────────────┘
└─────────┘└────────┘└───────┘
```

### External Dependencies

```
┌──────────────────────┐     ┌──────────────────────┐
│  Policy Decision     │     │  NATS JetStream       │
│  Point (PDP)         │     │  (optional)           │
│                      │     │                       │
│  • Cedar (bundled)   │     │  • Audit events       │
│  • OPA              │     │  • Cache invalidation  │
│  • Any HTTP/gRPC PDP │     │  • State-changed       │
└──────────────────────┘     └──────────────────────┘
```

---

### Internal Layering (keyrack-service)

```
gRPC handlers  ─┐
                 ├──▶  domain.rs (protocol-agnostic business logic)
REST handlers  ─┘           │
                            ▼
                     ops layer (PDP authorization + audit emission)
                            │
                            ▼
                   CryptoProvider / StorageBackend
```

All business logic lives in `domain.rs`. Both gRPC and REST handlers
delegate to the same domain functions, eliminating behavioral divergence
between API surfaces. The `ops` layer wraps every domain call with PDP
authorization and audit emission, making those guarantees structural
rather than per-handler.

---

## Key Concepts

### Logical Key Identity (LID)

Keys are addressed by Logical IDs derived deterministically from
attribute sets:

```
LID = Base64URL(BLAKE3(canonicalization_version || canonical(attributes)))
```

Properties:
- **Deterministic**: same attributes always produce the same LID
- **Forward-referenceable**: compute a LID before the key exists
- **Collision-resistant**: BLAKE3 provides 256-bit output
- **Version-stable**: LID doesn't change when key material rotates

Each `CreateKey` call injects a UUID into the attribute set, ensuring
uniqueness even without caller-supplied identity attributes.

### Key Hierarchy

Keys form a parent-child hierarchy:

```
Root KEK (operator-managed)
├── Tenant KEK (per-tenant)
│   ├── Service DEK (per-service)
│   └── Backup DEK (per-tenant)
└── Tenant KEK (another tenant)
    └── Service DEK
```

The hierarchy is defined by **namespace routing rules** — YAML
configuration that maps attribute patterns to parent relationships:

```yaml
namespace: "acme-app"
attachment:
  tenant: "acme"

routing_rules:
  - match: {kind: "dek", user: "$U", doc: "$D"}
    parent: {kind: "user-kek", user: "$U"}

  - match: {kind: "user-kek", user: "$U"}
    parent: {kind: "app-root"}

  - match: {kind: "app-root"}
    parent: _attachment_
```

Rules use variable binding (`$U`, `$D`) to propagate attributes from
child to parent. More specific rules (more attribute matches) take
precedence.

### Key State Machine

```
Creating → Enabled ⇄ Disabled → PendingDeletion → Destroyed
```

State transitions are guarded, audited, and emit NATS events when
configured.

### Key Versioning

- LID is stable (derived from attributes)
- Version is metadata tracked separately
- Rotation creates a new version with fresh material; same LID
- Old versions are retained for decryption until all dependents are
  re-wrapped
- Self-describing ciphertext header embeds key ID and version, so
  decrypt knows which version to use

### Self-Describing Ciphertext Header

Every ciphertext begins with an 80-byte header:

```
┌──────────┬───────────┬──────────┬─────────┬─────────────────────┬──────────┐
│ Magic(4) │ Version(1)│ Algo(1)  │ LID(32) │ KeyVersion(4)       │ ECHash(32)│
│ "KRAK"   │ 0x01      │ AES256GCM│ BLAKE3  │ u32                 │ BLAKE3    │
│          │           │ Ed25519  │         │                     │           │
│          │           │ etc.     │         │                     │           │
└──────────┴───────────┴──────────┴─────────┴─────────────────────┴──────────┘
```

The header enables:
- Decryption without knowing which key was used (read from header)
- Key rotation safety (old versions retained, version in header)
- Encryption context validation (hash comparison)

### Encryption Context (AAD)

Callers provide a map of key-value pairs as encryption context. This
context is:
- Cryptographically bound to the ciphertext via AES-GCM AAD
- Hashed (BLAKE3 internally, SHA-256 on the PDP wire) and stored in
  the ciphertext header
- Required at decrypt time — mismatch fails decryption
- Opaque to KeyRack: not parsed, not schema-validated, not stored
  after the operation

This prevents cross-tenant ciphertext swapping and provides audit
correlation.

---

## Cryptographic Provider Architecture

The `CryptoProvider` trait is the abstraction boundary:

```rust
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle>;
    async fn encrypt(&self, handle: &KeyHandle, plaintext: &[u8], aad: Option<&EncryptionContext>) -> Result<Vec<u8>>;
    async fn decrypt(&self, ciphertext: &[u8], aad: Option<&EncryptionContext>) -> Result<Vec<u8>>;
    async fn sign(&self, handle: &KeyHandle, message: &[u8]) -> Result<Vec<u8>>;
    async fn verify(&self, handle: &KeyHandle, message: &[u8], signature: &[u8]) -> Result<bool>;
    async fn destroy(&self, handle: &KeyHandle) -> Result<()>;
    fn capabilities(&self) -> ProviderCapabilities;
}
```

### Provider Implementations

| Provider | Key Material | Production Use | FIPS Path |
|----------|-------------|----------------|-----------|
| **Software** (RustCrypto) | In-process memory | Dev/test, non-regulated | No (not validated) |
| **PKCS#11** | HSM hardware | Production, regulated | Yes (if HSM is FIPS-validated) |
| **KMIP** | Remote HSM via TTLV/TLS | Production, HYOK | Yes (if HSM is FIPS-validated) |
| **Parsec** (stub) | PSA Crypto / TPM | IoT/embedded (future) | Depends on backend |
| **Vault Transit** | Vault server | Brownfield adoption | No (Vault is not FIPS module) |

The provider choice is a deployment-time configuration decision. Same
KeyRack API, same key hierarchy, different security properties based
on provider. Organizations can start with Software and graduate to
PKCS#11 when requirements demand it.

### Security Boundary by Provider

| Component | Software | PKCS#11 | KMIP |
|-----------|----------|---------|------|
| Key material location | Process memory | HSM hardware | Remote HSM |
| KeyRack sees material? | Yes | No (handle only) | No (UID only) |
| Zeroization | Partial (AES, Ed25519) | HSM-managed | HSM-managed |
| FIPS-compliant path? | No | Yes | Yes |

---

## Authorization Architecture

KeyRack separates the policy decision from the policy enforcement
point:

- **PolicyDecisionPoint trait**: defines the request/response contract
  (principal, action, resource, context → allow/deny + reasons +
  obligations)
- **PDP is architecturally external by default**: the trust boundary
  between key operations and policy evaluation is explicit
- **Every operation** passes through PDP before execution. There is no
  code path that bypasses authorization.
- **Fail-closed**: if PDP is unavailable, all operations are denied

### PDP Implementations

| PDP | Deployment | Use Case |
|-----|-----------|----------|
| **Cedar** (bundled sidecar) | Separate binary, HTTP | Simple deployments, dev/test |
| **HTTP PDP** | External HTTP service | OPA, custom PDP |
| **gRPC PDP** | External gRPC service | Lower latency, strict typing |
| **AlwaysAllow** | In-process | Test fixtures only |

Cedar is bundled as a convenience sidecar (`keyrack-cedar-pdp`), but
KeyRack has no hard dependency on Cedar. The starter Cedar schema is
documentation that operators copy into their PDP deployment.

---

## Rotation System

### Cooperative Rotation Protocol

When a key rotates:

1. KeyRack creates a new key version (fresh material, same LID)
2. Old versions remain valid for decryption
3. Rotation jobs are created for all dependent keys (recursive)
4. Applications poll for pending jobs via the rotation job API
5. Applications re-encrypt affected data with the new key version
6. Applications report completion via the job API
7. When all dependents are re-wrapped, old versions can be destroyed

KeyRack orchestrates but does not execute data re-encryption. Only
applications understand their data model — transaction boundaries,
table relationships, atomicity requirements.

### Background Workers

Two idempotent workers run as `tokio::spawn` tasks:

- **Deletion worker**: transitions `PendingDeletion` keys past
  `scheduled_deletion_at` to `Destroyed` (60s scan interval)
- **Rotation expiry worker**: expires rotation jobs in `Pending` or
  `Acknowledged` past `expires_at` (60s scan interval)

---

## Audit and Observability

### Audit Events

Every operation emits a structured `AuditEvent` containing:
- `event_type`, `action`, `result` (allowed/denied/error)
- `principal` (who), `resource` (what key), `timestamp`
- `encryption_context_hash` (when applicable)
- `request_id` (cross-system correlation)

Audit sinks: stdout (dev), NATS (production), file (compliance
fallback). Key material never appears in audit events.

### Metrics

Prometheus-format metrics on `/metrics`:
- Per-action latency histograms
- PDP request latency histogram
- Audit error counter
- Operation counters

### Health

- `/healthz`: probes storage + provider, returns 200 or 503
- `/readyz`: storage ping

---

## Storage Architecture

The `StorageBackend` trait abstracts key and metadata persistence:

- **PostgreSQL**: production, optimistic concurrency control (OCC)
- **SQLite**: single-node, lighter deployments, development

Both implement the full storage interface: keys, key versions,
rotation jobs, aliases, tags, namespaces. Schema migrations run at
startup via `sqlx`.

---

## Deployment Topologies

### Single-node (FOSS)

```
┌──────────────────────────────┐
│       keyrack-service        │
│  gRPC :50051  REST :8080     │
│  SQLite or PostgreSQL        │
│  Software or PKCS#11 provider│
│  Cedar PDP (sidecar) or OPA  │
└──────────────────────────────┘
```

### Sidecar (host-application deployment)

```
┌─────────────────────────────────────────────┐
│  Pod / VM                                   │
│  ┌─────────────┐   ┌─────────────────────┐  │
│  │  Host app   │──▶│  keyrack-service    │  │
│  │  monolith   │   │  localhost:50051    │  │
│  │             │   │  localhost:8080     │  │
│  └─────────────┘   └──────────┬──────────┘  │
│                               │              │
│                    ┌──────────▼──────────┐   │
│                    │  PostgreSQL (own DB)│   │
│                    └────────────────────┘   │
└─────────────────────────────────────────────┘
         │
         ▼
    External PDP (TCP + gRPC + mTLS)
```

### HA / Multi-node (Commercial, V2)

Active-active for reads, leader for writes. NATS for state
replication, cache invalidation, and peer discovery.

---

## Crate Map

| Crate | Role |
|-------|------|
| `keyrack-core` | Library: crypto traits, key state machine, LID, canonicalization, audit, PDP trait, encryption context, ciphertext header |
| `keyrack-service` | Binary: gRPC + REST server, PDP integration, health, metrics, workers |
| `keyrack-cedar-pdp` | Binary: standalone Cedar policy evaluation sidecar |
| `keyrack-cli` | Binary: lint, provision, admin, migrate subcommands |
| `keyrack-pkcs11` | Library: PKCS#11 HSM CryptoProvider via `cryptoki` |
| `keyrack-kmip` | Library: KMIP HSM CryptoProvider with TTLV codec |
| `keyrack-parsec` | Library: Parsec CryptoProvider (stub, for IoT/TPM) |
| `keyrack-sqlite` | Library: SQLite StorageBackend |
| `keyrack-postgres` | Library: PostgreSQL StorageBackend |
| `keyrack-nats` | Library: NATS audit sink, invalidation sink, state publisher |
| `keyrack-pii` | Library: PII tokenization helper (BLAKE3-keyed hashing) |
| `keyrack-wasm` | Library: WASM compilation target |
| `keyrack` | Library: high-level Rust client facade |
| `keyrack-aws-common` | Library: shared AWS KMS JSON-RPC parsing |
| `keyrack-aws-proxy` | Library: FOSS AWS KMS pass-through proxy |
| `keyrack-vault` | Library: HashiCorp Vault Transit CryptoProvider |
| `keyrack-e2e` | Integration tests: end-to-end API test suite |
