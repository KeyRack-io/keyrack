# Changelog

All notable changes to KeyRack will be documented in this file.

## [Unreleased]

## [0.3.2] — 2026-07-03

Security patch: corrected false atomic re-wrap / data-key capability declarations
(no API or behavioral change).

### Security

- **Corrected false `supports_atomic_re_encrypt` / `supports_atomic_data_key`
  capability declarations.** The PKCS#11 and KMIP providers declared these
  capabilities `true` while relying on the trait-default `re_encrypt` /
  `generate_data_key` implementations, which compose `decrypt`+`encrypt`
  (respectively `generate_random`+`encrypt`) so that plaintext key material
  transits the coordinator process. No in-tree provider currently keeps plaintext
  inside the backend for these operations, so every provider now honestly declares
  `false`. Also corrected the misleading "plaintext never leaves the provider
  boundary" doc comments, added a contract on the capability fields, and added
  per-provider regression-guard tests that fail if a flag is set `true` without a
  custody-preserving override. No wire, API, or behavioral change.

## [0.3.1] — 2026-06-19

Security patch: the REST API now fails closed on authentication errors.

### Security

- **REST authentication fails closed.** On an authn error (missing / invalid /
  expired bootstrap token or JWT) the REST surface previously downgraded the
  caller to the `keyrack:anonymous` principal (fail-**open**); it now rejects with
  `401 Unauthorized` and a structured `{"error":"Unauthenticated", ...}` body,
  matching the gRPC surface (which already failed closed). Deployments with no
  authentication configured (insecure mode) are unaffected. Added in-process,
  docker-free mTLS identity integration tests (valid client cert → principal
  reaches PDP/audit; no cert → reject; untrusted CA → TLS-layer reject).

## [0.3.0] — 2026-06-17

Provider-resolution hardening and HSM connection governance for multi-tenant
HYOK deployments. All wire changes are **additive** (no proto breaks); existing
single-provider and `hsm_connection_id` callers are unaffected.

### Added

- **`backend_id` backend selector** — `CreateKey` accepts `backend_id`, an
  opaque id naming the crypto backend on which a key's material is created
  (software provider, static HSM, or dynamically-registered HSM connection —
  one shared id space). Read responses (`KeyMetadata`, gRPC + REST) echo the
  resolved `backend_id`.
- **Routing-policy actions `route` / `delegate` / `delegate *`** — in the
  `provider_routing` config block, operators can `route` a match to a pinned
  backend (authoritative), `delegate {set}` to let callers choose within a
  bounded set, or `delegate *` to allow any registered backend.
- **`scope_owner` on HSM connections** — `CreateHsmConnection` accepts an
  optional `scope_owner` (`platform` or `tenant:<id>`). When set, KeyRack
  enforces that the calling principal's scope matches before any operation
  (`CreateKey`, `Encrypt`, `Decrypt`, `Sign`, `Verify`, `GenerateMac`,
  `VerifyMac`) that resolves to that connection. Each evaluation emits a
  `scope_owner_check` audit event.
- **`ListHsmConnections` `scope_owner` filter** (additive proto field).

### Changed

- **Caller backend selection is default-deny when a routing policy is
  configured.** With a `provider_routing` block present, a caller-supplied
  `backend_id` is honored only where a `delegate` rule authorizes it; otherwise
  the request binds the default backend, and naming a non-default backend is
  rejected. **Backward-compatible:** with no `provider_routing` block, a
  caller-supplied `backend_id` selects any registered backend, exactly as before.
- **Selection error codes** — an unknown backend id returns `FailedPrecondition`;
  a backend the policy does not permit the caller to select returns
  `PermissionDenied`; a caller selection conflicting with an operator `route`
  pin returns `FailedPrecondition` (the error names both the pinned and the
  requested id, never secret material).

### Deprecated

- **`hsm_connection_id`** (request + metadata) is superseded by `backend_id` and
  retained as an alias for one release — both are accepted, and if both are set
  they must agree. The `keyrack.provider` assertion attribute likewise folds
  into `backend_id`.

### Security

- **Connection-scoped tenant isolation (`scope_owner`) is fail-closed** — a
  mismatched or absent principal scope yields `PermissionDenied`, never an
  authenticated downgrade. This is the primary KeyRack-side tenant-isolation
  control in deployments where an external gateway is the authoritative
  authorization layer and KeyRack's PDP is configured `always_allow`.

### Fixed

- **`DeleteHsmConnection` deregistration** — deleting a connection now also
  removes it from the live provider registry, so a deleted connection can no
  longer back new key creation until the next restart.

## [0.2.0-beta.2] — 2026-06-15

Proto alignment for the first design-partner integration: broader
signing-algorithm coverage, pre-hashed digest signing, MAC operations, and
additional key specs. One wire-breaking change (`KeyState` renumber), made now
while the integrator surface is small.

### Added

- **Signing algorithm coverage** — `RSA_PKCS1_V15_SHA{384,512}`,
  `RSA_PSS_SHA{384,512}`, `ECDSA_P256_SHA384`, and `ECDSA_P384_SHA384`
  (`ECC_NIST_P384` key spec) for CNSA-suite / PCI workloads.
- **Pre-hashed digest signing** — `SignRequest`/`VerifyRequest` gained a
  `message_type` (`RAW` | `DIGEST`). `DIGEST` signs a caller-supplied digest
  as-is (the standard KMS workflow; matches AWS/GCP/Azure). `RAW` (default)
  preserves the previous hash-on-server behaviour. `DIGEST` is rejected for
  `ED25519_PURE`.
- **MAC operations** — `GenerateMac`/`VerifyMac` RPCs over `HMAC_256` keys
  (`HMAC_SHA_{256,384,512}`), with constant-time verification.
- `AES_128` key spec.
- `CreateKey` `key_usage` and `namespace` are now optional; usage is derived
  from the key spec when unset.
- Documented the encryption-context → AES-GCM AAD derivation and the crypto
  operation semantics in `docs/INTEGRATION_GUIDE.md` §6.

### Changed

- **BREAKING (proto wire): `KeyState` renumbered** to the conventional ordering
  (`ENABLED=1, DISABLED=2, PENDING_DELETION=3, DESTROYED=4, CREATING=5,
  COMPROMISED=6`). gRPC clients must be recompiled against the current
  `key_service.proto`; enum field names are unchanged (REST/JSON unaffected).
  Done pre-1.0 while the integrator surface is small.

## [0.2.0-beta.1] — 2026-06-13

First beta. Adds provider routing, more differentiator demos, release-gated E2E
CI, an AGPL-3.0 relicense, and assorted hardening since `alpha.1`.

### Added

- **Provider routing** — multi-provider registry with tag-based routing and
  per-key/per-version provider binding (`ProviderRef`). Foundation for
  multi-tenant HYOK and per-node backends. Single-provider configs remain
  backward-compatible (serde-default `provider_ref`, no storage migration).
- `keyrack audit verify` CLI subcommand (Ed25519 + BLAKE3 hash-chain
  verification of an audit log).
- `dependent_key_id` on rotation-job metadata (additive gRPC/REST field).
- Demos: `06-provider-routing`, `07-k8s-sidecar` (native sidecar-in-a-pod),
  `08-cascade-rotation`, `09-audit-tamper-evidence`,
  `10-mtls-identity` (mTLS certificate identity → Cedar authorization).
- Release-gated E2E CI lane that runs the demo compose stacks on `v*` tags.

### Changed

- **License: relicensed to AGPL-3.0-or-later** (from BSL-1.1). Alternative
  commercial licensing remains available.
- Demo 04 now runs on PostgreSQL and demonstrates restart survival.
- Phase-2 hardening across the domain layer, authentication, audit, and cache;
  PKCS#11 fixes including shared-module-per-`lib_path` (enables multi-token).

### Security

- **mTLS identity is now enforced end to end (gRPC).** The peer certificate is
  propagated from the TLS connection to the authenticator, so
  `MtlsAuthenticator` derives the principal (CN / SPIFFE SAN) that the PDP and
  audit layers see. Authentication now **fails closed**: when the configured
  authenticators recognise no valid credential, the gRPC request is rejected
  with `Unauthenticated` rather than silently downgraded to an anonymous
  principal. (The insecure authenticator never errors, so dev/test deployments
  are unaffected.) Demonstrated and regression-tested by demo `10-mtls-identity`.

### Fixed

- **TLS/mTLS startup panic.** Install the rustls `aws_lc_rs` default
  `CryptoProvider` at service startup. Under rustls 0.23 the process-wide crypto
  provider must be installed before the first TLS handshake; without it
  `keyrack-service` panicked whenever a `tls` block was configured. TLS and mTLS
  handshakes now start correctly.
- PostgreSQL multi-statement schema initialization.

### Known limitations

- The REST surface (which does not carry mTLS) still falls back to an anonymous
  principal on authentication error; gRPC fail-closed semantics will be extended
  to REST in a follow-up. mTLS-gated authorization runs over gRPC.

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
