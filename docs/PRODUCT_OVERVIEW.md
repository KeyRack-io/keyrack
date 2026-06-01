# KeyRack Product Overview

## What is KeyRack?

KeyRack is the coordination layer for cryptographic key lifecycle
management. It tracks which key wraps which, what data depends on
which key, and orchestrates safe, zero-downtime key rotation — a
capability that no existing tool provides, at any price point.

KeyRack does not replace your HSM, Vault, or cloud KMS. It sits above
them. It answers "what depends on this key?" and handles the
operational complexity of rotating it safely.

## The Problem

The industry has mature primitives (libsodium, ring), reasonable
storage (Vault, Barbican), and compliance frameworks (NIST 800-57,
PCI-DSS) — but no coordination layer between them. This means:

1. **Most organizations never rotate keys.** The tooling doesn't
   exist.
2. **Those who rotate do it manually.** Error-prone, undocumented,
   cannot answer "what depends on this key."
3. **Cloud KMS creates vendor lock-in.** AWS KMS, Azure Key Vault lock
   you into specific ecosystems.

**Precedent: Microsoft Storm-0558 (2023).** A signing key was used for
7+ years instead of the intended 5. Microsoft had "stopped their
manual key rotation processes in 2021" and failed to build automated
rotation tooling. The capability gap is universal.

## Who Uses KeyRack?

| Persona | Uses | License |
|---------|------|---------|
| **Self-hosters** (Nextcloud, Matrix, CryptPad operators) | FOSS core, native API | AGPL-3.0 |
| **Sovereign cloud providers** (European national clouds, Gaia-X) | FOSS core + commercial shims | Commercial |
| **Platform integrators** (enterprise platforms) | FOSS core embedded as sidecar | AGPL-3.0 + commercial |
| **Security-conscious enterprises** (healthcare, finance, defence) | FOSS core, self-hosted | AGPL-3.0 |
| **IoT gateway operators** | FOSS core on ARM64, Parsec provider | AGPL-3.0 |

---

## Features

### FOSS Core

**Key Lifecycle Coordination**
- Hierarchical key management with parent-child dependency tracking
- Deterministic key addressing via Logical IDs (LIDs)
- Full key state machine: Creating → Enabled ⇄ Disabled →
  PendingDeletion → Destroyed
- Cascade disable: disable one key, all descendants instantly
  become inoperable
- LID aliasing for routing evolution stability

**Zero-Downtime Key Rotation**
- Cooperative rotation protocol: KeyRack orchestrates, applications
  execute
- Rotation jobs with scheduling, retry, progress tracking
- Recursive dependency discovery: "what needs rotating?"
- Version coexistence: old key versions remain valid until all
  dependents are re-wrapped
- Policy-driven scheduling (30d, 90d, 365d per key pattern)

**Pluggable Crypto Providers**
- Software (RustCrypto): development, non-regulated workloads
- PKCS#11: production HSMs (SoftHSM, Thales, Entrust, Utimaco)
- KMIP: remote HSM via standardized network protocol
- Parsec: IoT/embedded via PSA Crypto API (planned)
- Vault Transit: brownfield adoption path (planned)

**Self-Describing Ciphertext**
- Every ciphertext embeds key ID, version, algorithm, and encryption
  context hash in an 80-byte header
- Decryption without out-of-band metadata
- Encryption context (AAD) cryptographically bound to ciphertext

**Authorization**
- External Policy Decision Point (PDP): Cedar, OPA, or any HTTP/gRPC
  PDP
- Every operation authorized before execution; fail-closed
- Cedar sidecar bundled for simple deployments

**API Surface**
- gRPC (tonic): canonical interface, protobuf definitions published
- REST (axum): pragmatic surface for tooling and ad-hoc use
- Rust library: embedded in-process mode
- TypeScript/WASM: browser and Node.js via wasm-bindgen

**Audit and Observability**
- Structured audit events for every operation
- Prometheus metrics, health endpoints
- NATS JetStream for event streaming (optional)

**Storage**
- PostgreSQL (production)
- SQLite (development, single-node)

**AWS KMS Pass-Through Proxy (FOSS)**
- Proxy that forwards AWS SDK calls to real AWS KMS
- Adds KeyRack metadata tracking (LIDs, dependency graph)
- Zero-risk adoption: no crypto behavior changes
- Migration path to full KeyRack when ready

### Commercial Extensions

**Protocol Compatibility Shims**
- AWS KMS JSON-RPC + SigV4 authentication: use existing AWS SDK code
  unchanged
- OpenStack Barbican REST: run unmodified Cinder/Nova against KeyRack

**Operational**
- High-availability clustering (leader election, NATS replication)
- Connection pooling across HSM backends
- Management UI for operators

**Compliance**
- PCI-DSS, SOC 2, ISO 27001 evidence pack generators
- Auditor-ready export formats
- GRC platform integration

---

## Deployment Modes

### Standalone (FOSS)

Single binary, SQLite or PostgreSQL, any supported provider. Suitable
for:
- Self-hosted infrastructure
- Development and testing
- Single-tenant deployments
- IoT gateways (ARM64 Docker image)

### Sidecar (Platform Integration)

KeyRack runs alongside a host application (e.g. a host monolith)
on localhost. The host communicates via gRPC or REST. Suitable for:
- Multi-service platforms needing unified key management
- Applications requiring embedded KMS coordination

### Cloud Provider (Commercial)

Full deployment with protocol shims, HA clustering, and HSM pool.
Suitable for:
- Sovereign cloud providers
- Enterprises offering KMS-as-a-service to internal tenants

---

## FOSS / Commercial Split

The boundary rule: if a capability is needed for key lifecycle
coordination, it lives in the FOSS core. Commercial extensions add
protocol compatibility, operational tooling, and compliance reporting.

| Capability | FOSS | Commercial |
|------------|:----:|:----------:|
| Key hierarchy, LIDs, routing | Yes | — |
| Rotation orchestration + jobs | Yes | — |
| Dependency tracking ("what depends on this key?") | Yes | — |
| Encrypt/Decrypt/Sign/Verify | Yes | — |
| Self-describing ciphertext | Yes | — |
| PDP authorization | Yes | — |
| PKCS#11, KMIP, Software providers | Yes | — |
| Vault Transit provider | Yes | — |
| Audit events (structured, pluggable sinks) | Yes | — |
| gRPC + REST native API | Yes | — |
| AWS KMS pass-through proxy | Yes | — |
| AWS KMS compatibility shim (sovereign KMS) | — | Yes |
| Barbican compatibility shim | — | Yes |
| HA clustering | — | Yes |
| Compliance report generators | — | Yes |
| Management UI | — | Yes |
| Vendor HSM connectors + support | — | Yes |

---

## Modules and Crate Map

| Module | Description |
|--------|-------------|
| `keyrack-core` | Core library: crypto traits, key state machine, LID computation, canonicalization, PDP trait, audit types, encryption context |
| `keyrack-service` | Main server binary: gRPC + REST, PDP integration, background workers |
| `keyrack-cedar-pdp` | Cedar policy evaluation sidecar |
| `keyrack-cli` | Admin CLI: lint, provision, migrate |
| `keyrack-pkcs11` | PKCS#11 HSM provider |
| `keyrack-kmip` | KMIP HSM provider |
| `keyrack-parsec` | Parsec/PSA Crypto provider (IoT) |
| `keyrack-sqlite` | SQLite storage backend |
| `keyrack-postgres` | PostgreSQL storage backend |
| `keyrack-nats` | NATS audit/event publisher |
| `keyrack-pii` | PII tokenization helper |
| `keyrack-wasm` | WASM target for TS/JS |
| `keyrack` | High-level Rust client facade |
| `keyrack-aws-common` | AWS KMS JSON-RPC parsing |
| `keyrack-aws-proxy` | FOSS AWS KMS pass-through proxy |

---

## Use Cases

1. **Greenfield backend service** — embed `keyrack-core` or call
   `keyrack-service` via gRPC. Get key hierarchy, rotation, and audit
   from day one.

2. **Brownfield AWS KMS migration** — deploy `keyrack-aws-proxy`,
   point AWS SDK at it. Gain dependency tracking without changing
   crypto behavior.

3. **Sovereign cloud provider** — deploy FOSS core + commercial
   shims. Offer AWS KMS-compatible API to tenants. Enable BYOK/HYOK
   with customer-connected HSMs.

4. **OpenStack integration** — Barbican shim lets unmodified
   Cinder/Nova talk to KeyRack.

5. **IoT gateway KMS** — run KeyRack on Raspberry Pi (ARM64). Manage
   sensor encryption keys with automatic rotation.

6. **Compliance-driven enterprise** — scheduled rotation policies,
   audit trail, dependency queries for auditors.

7. **E2E encrypted applications** — WASM library in browser for
   client-side key hierarchy management.

---

## Competitive Position

| Solution | Key Storage | Lifecycle Coordination | Dependency Tracking | Open Source |
|----------|:-----------:|:---------------------:|:-------------------:|:-----------:|
| HashiCorp Vault | Yes | No | No | Yes (BSL) |
| AWS KMS | Yes | Partial (auto-rotate) | No | No |
| Azure Key Vault | Yes | Partial | No | No |
| Fortanix / IBM UKO | Yes | Automation | No | No |
| OpenStack Barbican | Yes | No | No | Yes |
| **KeyRack** | Delegates | **Yes** | **Yes** | **Yes (AGPL)** |

KeyRack is the only solution that answers "what depends on this key?"
and provides cooperative rotation orchestration. It is provider-agnostic,
self-hostable, and designed for sovereignty.
