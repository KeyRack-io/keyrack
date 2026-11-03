# KeyRack Product Overview

## What is KeyRack?

KeyRack is the coordination layer for cryptographic key lifecycle
management. It tracks logical key relationships and coordinates
rotation jobs while applications migrate their data. Ancestry implies
cryptographic wrapping only for children created under a `wrapping:` profile,
and in 0.5.0 that wrapping is software, not custody.

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
- Key hierarchies with parent-child dependency tracking. A parent on `CreateKey`
  creates a child wrapped under it: one level, opt-in through a `wrapping:`
  profile on a platform-custody provider. The only mechanism in 0.5.0 is the
  software one, which unwraps the child into service memory for each use, so
  this is not KEK-wrapped custody. Without a profile, `CreateKey` with a parent
  is refused; keys created before 0.5.0 that name a parent are refused as
  wrapping parents. Native PKCS#11 wrapping is not reachable through the
  service, for any token, SoftHSM included. How a child's use lease is closed,
  including on cancellation, is stated in
  [Using a child](KEY_MATERIAL_REPRESENTATION.md#using-a-child).
- Content-addressed key identity via Logical IDs (LIDs)
- Full key state machine: Creating → Enabled ⇄ Disabled →
  PendingDeletion → Destroyed
- Cascade disable: disable one key, all descendants instantly
  become inoperable
- LID aliasing for routing evolution stability

**Cooperative Key Rotation**
- Cooperative rotation protocol: KeyRack orchestrates, applications
  execute
- Rotation jobs with acknowledgement, completion, failure and expiry tracking
- Recursive dependency discovery: "what needs rotating?"
- Version coexistence: old versions remain available for decryption subject to
  key state and authorization. Applications migrate their data; job completion
  does not prove that all ciphertext has migrated or retire old versions.
- Rotation policy settings can be stored; automatic policy scheduling and
  cryptographic child rewrapping are not implemented.

**Pluggable Crypto Providers**
- Software (RustCrypto): development, non-regulated workloads
- PKCS#11: SoftHSM is a supported production software token. Its storage
  permissions and PIN protect keys; it provides no hardware boundary. Hardware
  HSMs over PKCS#11, including Thales, Entrust and Utimaco, are not yet qualified.
- KMIP: remote HSM via standardized network protocol
- Vault Transit: HashiCorp Vault-backed crypto operations
- Parsec: IoT/embedded via PSA Crypto API (stub — integration pending)

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
- Records selected key metadata and forwards calls using the proxy's configured
  AWS credentials
- Cryptography remains in AWS KMS; this is not a Core-backed AWS API shim
- Migration path to full KeyRack when ready

### Commercial Extensions (outside this repository)

The following describes separate extension scope, not features shipped in
KeyRack Core 0.5.0. This repository ships neither an AWS KMS compatibility shim
nor an OpenStack Barbican REST API. The AWS pass-through proxy above continues
to use AWS KMS for cryptography.

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

### Cloud Provider (Commercial, outside this repository)

A separate deployment with protocol shims, HA clustering, and HSM pool.
Suitable for:
- Sovereign cloud providers
- Enterprises offering KMS-as-a-service to internal tenants

---

## FOSS / Commercial Split

The boundary rule: if a capability is needed for key lifecycle
coordination, it lives in the FOSS core. Commercial extensions add
protocol compatibility, operational tooling, and compliance reporting. The
commercial column below describes extension scope outside this repository,
not a Core 0.5.0 delivery or availability claim.

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
   configure AWS SDK callers to use it. Record selected key metadata while
   cryptography remains in AWS KMS.

3. **Cloud provider** — expose the native gRPC or REST API. AWS KMS API
   compatibility requires a separate shim not shipped here; hardware HSM
   qualification remains provider-specific work.

4. **OpenStack integration** — requires a separate Barbican compatibility shim,
   which is not shipped in this repository. Core does not expose the Barbican
   REST API to Cinder/Nova.

5. **IoT gateway KMS** — run KeyRack on Raspberry Pi (ARM64). Manage
   sensor encryption keys and coordinate application-driven rotation.

6. **Compliance-driven enterprise** — rotation policy settings,
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
