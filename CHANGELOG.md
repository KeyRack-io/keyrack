# Changelog

All notable changes to KeyRack will be documented in this file.

## [0.1.0] — Unreleased

Full release — follows alpha once a partner integration tests pass.

## [0.1.0-alpha.1] — 2026-05-13

First alpha image. All core features functional and tested. Suitable
for integration testing and non-production deployments.

### Core (`keyrack-core`)

- Attribute canonicalization with versioned encoding (V1)
- LID (Logical ID) derivation via BLAKE3
- Rule engine with YAML-defined namespace hierarchies
- Resolver with lazy provisioning and single-flight deduplication
- Key state machine: creating → enabled → disabled → pending_deletion → compromised → destroyed
- `Compromised` key state per NIST SP 800-57
- Rotation-job state machine: pending → acknowledged → completed/failed/expired
- HSM connection lifecycle model (healthy/degraded/down)
- Cascade disable across key hierarchies
- Encryption context (AAD) with canonical BLAKE3 hashing
- Self-describing ciphertext header (80-byte, version-tagged, authenticated in AES-GCM AAD)
- `Sensitive<T>` wrapper with `zeroize`-on-drop
- Tags model: immutable identity tags + mutable user tags
- Audit event schema with versioned envelope
- Ed25519 audit log signing with hash-chain tamper evidence
- mTLS authenticator (X.509 cert parsing, CN/SPIFFE SAN extraction)
- JWT authenticator (JWKS fetching, RS/ES/EdDSA signature validation)

### Providers

- **Software provider** — pure-Rust AES-256-GCM, Ed25519, ECDSA P-256, RSA PKCS#1v1.5 (2048/3072/4096), RSA-PSS (2048/3072/4096)
- **In-memory provider** — ephemeral test fixture wrapper
- **PKCS#11 provider** — production HSM integration via `cryptoki`
- **KMIP provider** — TTLV wire protocol client with TLS/mTLS support
- **Vault Transit provider** — HashiCorp Vault Transit engine integration (new)

### Storage

- **SQLite** — single-node deployments
- **PostgreSQL** — production with optimistic concurrency control
- **In-memory** — test fixtures

### Service (`keyrack-service`)

- gRPC API: 45+ RPCs covering crypto, lifecycle, rotation, hierarchy, tags, aliases, HSM connections, namespaces
- REST API: full HTTP/1.1 surface mirroring gRPC
- `CreateKey` wires `parent_key_id` for hierarchy construction
- `RotateKey` recursively propagates to all descendants (BFS)
- Rotation policy persistence via key tags
- RSA-2048 deprecation warning on key creation
- `ReportKeyCompromise` RPC and REST endpoint
- TLS/mTLS on gRPC server (tonic `ServerTlsConfig`)
- gRPC HTTP/2 keepalive (configurable, 30s/10s defaults)
- TLS cert hot-reload watcher (polling, 30s interval)
- Authentication: insecure, bootstrap token, mTLS, JWT
- Authorization: external PDP via HTTP or gRPC (fail-closed)
- PDP wire format upgraded to PDP Service Contract v1.0 (typed `AttributeValue`, `PolicyReason`, `Obligation`, `BatchAuthorize`, `ExplainAuthorization`)
- PDP client TLS/mTLS support (HTTP and gRPC)
- Cedar PDP convenience config type
- `x-request-id` propagation: read from inbound headers (gRPC metadata / HTTP), forwarded to PDP, included in audit events, echoed in REST responses (UUIDv7 fallback)
- NATS: key state-change, rotation, and cascade events published
- Health endpoints: `/healthz`, `/readyz`
- Prometheus metrics: `/metrics`
- Graceful shutdown with 30s drain timeout
- Background workers: deletion worker, rotation expiry worker

### AWS KMS proxy (`keyrack-aws-proxy`)

- FOSS pass-through proxy for AWS KMS
- SigV4 request signing and forwarding
- Local metadata tracking
- Admin API for inspection

### CLI (`keyrack-cli`)

- `keyrack lint` — namespace YAML validation
- `keyrack provision` — eager hierarchy provisioning from CSV/JSON
- `keyrack admin` — operator queries (inspect, audit, rotate, cascade-disable)
- `keyrack migrate` — canonicalization and rule-change migrations

### Cedar PDP (`keyrack-cedar-pdp`)

- Standalone Cedar policy evaluator
- HTTP `/v1/authorize` endpoint
- Optional schema validation
- Hot-reloadable policy files

### WASM (`keyrack-wasm`)

- Software provider compiled to `wasm32-unknown-unknown`
- WebCrypto-backed provider for browser context
- JS/TS bindings via `wasm-bindgen` (scaffolding; functional module in v0.2.0)

### Documentation

- Operator guide with full config reference
- Quickstart guide
- Architecture and product overview documents
- Security model (AES-GCM nonce budget, zeroization posture)
- Crypto and compliance analysis
- SDK examples for Rust, Go, Python, Java, C, TypeScript
- Use-case writeups (greenfield, brownfield, crypto agility)

### Other

- Docker Compose development stack (standalone, E2E, Cedar PDP)
- Multi-arch Docker image (amd64 + arm64)
- E2E test suite with SoftHSM and PostgreSQL
- Property-based tests for canonicalization and LID determinism
- 233 tests (212 core + 21 service), zero warnings
