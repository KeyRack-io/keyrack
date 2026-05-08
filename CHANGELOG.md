# Changelog

All notable changes to KeyRack will be documented in this file.

## [0.1.0] — Unreleased

Initial release.

### Core (`keyrack-core`)

- Attribute canonicalization with versioned encoding (V1)
- LID (Logical ID) derivation via BLAKE3
- Rule engine with YAML-defined namespace hierarchies
- Resolver with lazy provisioning and single-flight deduplication
- Key state machine: creating → enabled → disabled → pending_deletion → destroyed
- Rotation-job state machine: pending → acknowledged → completed/failed/expired
- HSM connection lifecycle model (healthy/degraded/down)
- Cascade disable across key hierarchies
- Encryption context (AAD) with canonical BLAKE3 hashing
- Self-describing ciphertext header (80-byte, version-tagged)
- `Sensitive<T>` wrapper with `zeroize`-on-drop
- Tags model: immutable identity tags + mutable user tags
- Audit event schema with versioned envelope

### Providers

- **Software provider** — pure-Rust AES-256-GCM, Ed25519, ECDSA P-256, RSA (2048/3072/4096)
- **In-memory provider** — ephemeral test fixture wrapper
- **PKCS#11 provider** — production HSM integration via `cryptoki`
- **KMIP provider** — TTLV wire protocol client with TLS/mTLS support

### Storage

- **SQLite** — single-node deployments
- **PostgreSQL** — production with optimistic concurrency control
- **In-memory** — test fixtures

### Service (`keyrack-service`)

- gRPC API: 45 RPCs covering crypto, lifecycle, rotation, hierarchy, tags, aliases, HSM connections, namespaces
- REST API: full HTTP/1.1 surface mirroring gRPC
- Authentication: insecure, bootstrap token, mTLS (stub), JWT (stub)
- Authorization: external PDP via HTTP or gRPC (fail-closed)
- Health endpoints: `/healthz`, `/readyz`
- Prometheus metrics: `/metrics`
- Graceful shutdown with 30s drain timeout

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
- JS/TS bindings via `wasm-bindgen`

### Other

- Docker Compose development stack
- E2E test suite with SoftHSM and PostgreSQL
- Property-based tests for canonicalization and LID determinism
- Quickstart guide and example scripts
