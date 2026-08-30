# Changelog

All notable changes to KeyRack will be documented in this file.

## [Unreleased]

## [0.4.0] — 2026-08-30

Exportable-key custody: an explicit, audited path for raw key material to leave
KeyRack, the BYOK import primitive that mirrors it, and an mTLS-bound delegated
identity profile for service-to-service callers. All wire changes are
**additive** (no proto breaks). Behaviour is not: this release closes several
authorization and key-state gaps, so a deployment that relied on the missing
checks will see requests rejected that 0.3.2 accepted. The breaking behaviour
changes are marked **BREAKING (behaviour)** below.

### Added

- **Exportable keys.** A key may now be marked exportable and its raw material
  retrieved through an audited `GetKeyMaterial` RPC. `KeyRecord` gains
  `exportability` (`non_exportable` | `exportable`, serde-default
  `non_exportable`) and a write-once `first_exported_at` latch set on the first
  successful export; both are `#[serde(default)]`, so records written by earlier
  versions load as non-exportable, and both are excluded from LID derivation, so
  marking a key exportable does not change its identity. Proto gains
  `CreateKeyRequest.exportable` (field 10), `KeyMetadata.exportable` (15), and
  `KeyMetadata.first_exported_at` (16). Guardrails: exportable keys are
  **leaf-only** (a key with dependents cannot be made exportable, and no child
  may be created under an exportable parent); creating a born-exportable key
  requires a **second PDP evaluation** for `kms:MakeKeyExportable` on top of
  `kms:CreateKey`, and a denial emits an `AuthorizationDenied` audit event;
  revocation is refused once `first_exported_at` is set. Both gRPC and REST
  `CreateKey` run this enforcement through the same
  `domain::enforce_born_exportable`, so the two surfaces cannot drift.
  New audit actions `kms:GetKeyMaterial`, `kms:MakeKeyExportable`, and
  `kms:RevokeKeyExportability`; `kms:GetKeyMaterial` records as a
  `SecretAccess` event. The `first_exported_at` latch is persisted only on the
  transition, so repeated exports of an already-exported key issue no versioned
  write and parallel `GetKeyMaterial` calls for one key do not contend on its
  OCC version.
- **`GetKeyMaterial`, `MakeKeyExportable`, and `RevokeKeyExportability` are
  gRPC-only.** There is no REST route for any of the three; REST participates in
  exportable keys only through `CreateKey`'s `exportable` field and the
  `exportable` / `first_exported_at` fields on read responses.
- **Key-material export is implemented by the software, in-memory, and Vault
  Transit providers only.** `CryptoProvider::export_key_material` defaults to a
  `Provider` error, and the PKCS#11, KMIP, and Parsec providers do not override
  it — export against a key held on those backends fails. Vault Transit exports
  via `GET /transit/export/encryption-key/{name}`, and marks a key exportable via
  `POST /transit/keys/{name}/config`.
- **`RevokeKeyExportability` is a policy-level soft revoke.** It flips the
  `KeyRecord` to `non_exportable`, which is the authoritative gate that
  `GetKeyMaterial` consults; it destroys nothing and re-keys nothing, so
  ciphertext produced under the key stays decryptable. On backends whose
  exportable flag is one-way — Vault Transit cannot unset it — the backend key
  keeps that flag, so this is a KeyRack-policy revocation and **not** a
  cryptographic one; material remains reachable by anyone with direct backend
  access. Cryptographic revocation requires a separate explicit destroy.
- **`ImportKey` — governed BYOK import.** Externally-generated material can be
  imported as a first-class governed key record, on gRPC (`ImportKey`) and REST
  (`POST /v1/keys/import`), authorized as `kms:ImportKeyMaterial` and recorded
  with `origin = External`. Material is carried as `Sensitive<Vec<u8>>`
  end-to-end. Gated on a new `supports_key_import` provider capability and
  **fail-closed**: only the Vault Transit provider implements
  `CryptoProvider::import_key_material` (wrapping the key with AES-KWP under an
  ephemeral AES-256 KEK, itself RSA-OAEP/SHA-256-encrypted to Vault's
  `wrapping_key`); the software, in-memory, PKCS#11, KMIP, and Parsec providers
  declare `supports_key_import: false` and reject the request. This is the
  import primitive a KMIP `Register` front-end needs — **no KMIP `Register`
  operation ships in this release**, and the KMIP provider does not support
  import. **Imported keys are non-exportable unless `exportable` is set
  explicitly**, on both surfaces (a plain proto3 bool on gRPC, `unwrap_or(false)`
  on REST); a keystore front-end that needs the material back must set the field
  itself. The proto comment previously claimed imported keys defaulted to
  exportable, which was never true of either surface; it has been corrected.
- **mTLS-bound delegated identity** (`authn.type: mtls_bound_forwarded_identity`).
  A new authenticator that accepts forwarded end-user identity headers
  (`x-keyrack-principal-id`, `x-keyrack-tenant-id`, and optional
  `x-keyrack-project-id` / `x-keyrack-domain-id`) **only** when the request also
  presents a client certificate issued by `trusted_ca_cert_path` and matching a
  `required_san` or `required_ou` pin. This composes the two proofs, which an
  `authn.type: chain` of `mtls` and `forwarded_identity` cannot do — a chain
  selects the first authenticator that succeeds and so never binds the header to
  the certificate. Presenting forwarded headers without a trusted peer is an
  error, not a silent skip. The tenant header becomes the
  `scope=tenant:<id>` principal attribute consumed by `scope_owner` enforcement,
  and the delegating workload is recorded as `delegating_peer_id`. Startup
  fails closed if `required_san`/`required_ou` is absent, if `tls.ca_cert` is
  unset, or if `trusted_ca_cert_path` is not byte-identical to `tls.ca_cert`;
  the check recurses into `chain`. Because certificate verification happens in
  the gRPC TLS layer, this profile is **gRPC-only** — REST requests under a
  chain that can only authenticate via peer certificate now return
  `501 Not Implemented` with `{"error":"AuthenticationTransportUnsupported"}`
  rather than a misleading credential error.
- **Formal-methods Tier 0** — `crates/keyrack-core/tests/formal_invariants.rs`
  adds proptest invariants (encrypt/decrypt round-trip across the symmetric key
  specs, wrong-AAD always fails, rotation preserves old-version decryptability,
  cascade-disable reaches all descendants, and no plaintext key bytes in
  serialized `AuditEvent` / `KeyRecord` JSON). Kani proof harnesses for
  `Sensitive<T>` redaction live in `crates/keyrack-core/src/kani_proofs.rs`
  behind `#[cfg(kani)]` and run under `cargo kani`, **not** in the default
  `cargo test` run. Documented in `docs/FORMAL_VERIFICATION.md`. No production
  code changed.

### Changed

- **BREAKING (behaviour): `ListKeys`, `ListAliases`, and `GenerateRandom` now
  authenticate the caller and go through the PDP.** All three previously ran as
  `OpContext::system` on gRPC, with no principal and no authorization
  evaluation. They now resolve the caller like every other operation, so a
  deployment whose policy does not permit these actions for real principals will
  start seeing denials. Trusted service-to-service callers that arrive as
  `keyrack:system` need an explicit permit; demo 10's Cedar policy adds one as a
  reference.
- **BREAKING (behaviour): `ListKeys` is scoped to the calling principal.**
  `KeyRecord` gains a server-set `owner_principal_id`, recorded at `CreateKey`
  and `ImportKey`, and listing now returns only keys owned by the requesting
  principal plus keys with no recorded owner. Records written by earlier versions
  have no owner and stay visible to every caller, so this narrows results only
  for keys created on 0.4.0 or later. The field is serde-default and excluded
  from the canonical form / LID. `GetKey` and the other per-key reads are
  unchanged — this is a listing filter, not an ownership authorization model.

### Security

- **BREAKING (behaviour): key-material export is now gated on key state.** A new
  `KeyState::permits_export()` returns true for `Enabled` only.
  `GetKeyMaterial` previously checked the `Exportability` flag alone and never
  the state, so a key in `PendingDeletion` — or one already marked `Destroyed` —
  still returned plaintext material. The privilege ordering was inverted: those
  states already fail `permits_decrypt()`, so a caller who could not decrypt
  with the key could still download the key and decrypt outside KeyRack forever.
  `permits_export()` is deliberately stricter than `permits_decrypt()`, which
  admits `Disabled` and `Compromised` for data recovery: export is a
  custody-boundary crossing, not a recovery operation, and exported bytes cannot
  be recalled. Refusal is a distinct `FailedPrecondition` naming the state, so an
  operator can tell it apart from "not exportable". A unit test asserts export is
  never broader than decrypt for any state. **Operator impact:** a keystore
  client that enumerates keys and fetches each one will now get an error for keys
  an operator has disabled or scheduled for deletion, where it previously
  received material.
- **BREAKING (behaviour): `ReEncrypt` is now gated on the state of both keys** —
  the source by `permits_decrypt()` and the destination by `permits_encrypt()`.
  Neither side had any state check, so a key refused for a direct `Decrypt` was
  still usable as a `ReEncrypt` source — including `PendingDeletion` and
  `Destroyed` keys — and re-wrapping was a supported way to keep using a key the
  operator had taken out of service. The two directions need separate predicates
  because `Disabled` permits decrypt but not encrypt, making it a legal source
  and an illegal destination. Enforced on **both** surfaces: the gRPC `ReEncrypt`
  RPC and the REST `POST /v1/keys/{key_id}/actions-re-encrypt` route. gRPC
  reports `FailedPrecondition` and REST `409 InvalidState`, each matching that
  surface's existing convention for a state refusal.
- **The deletion reaper now destroys backend key material.** `run_deletion_scan`
  marked keys `Destroyed`, persisted the record, and emitted a signed
  `kms:KeyDestroyed` audit event without ever calling
  `CryptoProvider::destroy_key`, which had no caller anywhere in
  `keyrack-service` — the Vault transit key, HSM object, or KMIP managed object
  survived indefinitely after KeyRack had reported and audited the key as
  destroyed. The reaper now resolves the provider for each key version and
  deletes the material before the state transition, and **fails closed**: on any
  provider-resolution or delete error the record stays in `PendingDeletion`, no
  `kms:KeyDestroyed` event is emitted — so the audit chain never asserts a
  destruction that did not happen — and the next scan retries. A new
  `kms:ProviderDestroyKey` audit action records the provider-side outcome per
  version, with an `Error` result meaning the material survives, so a divergence
  between the record and the backend is visible in the chain. Because a failed
  pass is retried, `CryptoProvider::destroy_key` implementations must be
  idempotent for a handle whose material is already gone.
- **Key-state gating and scope isolation reached the REST surface.** State gating
  via the shared `domain::enforce_state_for_key_op` was enforced only on gRPC for
  `Sign`, `Verify`, `GenerateMac`, and `VerifyMac`; REST ran those operations
  with no state check. Separately, `GenerateDataKey` and `ReEncrypt` had no
  `scope_owner` isolation on either surface. Both surfaces now call the same
  shared domain functions, and `ReEncrypt` evaluates scope against the source and
  destination keys independently.

### Fixed

- **`ListKeys` honours its `state_filter`.** The service layer hard-coded
  `state: None` when building the `KeyFilter`, so a caller narrowing a listing to
  one key state received every key regardless; the storage backends had
  implemented the filter all along. Now honoured on gRPC via the existing
  `ListKeysRequest.state_filter` field, and on REST via a new `?state=` query
  parameter on `GET /v1/keys` that uses the same vocabulary the response
  serializes (`enabled`, `pending_deletion`, …) — REST previously had no way to
  express the filter at all. A filter that is present but uninterpretable — an
  unknown enum value or an explicit `KEY_STATE_UNSPECIFIED` on gRPC, an unknown
  string on REST — is **rejected** (`InvalidArgument`, `400 InvalidKeyState`)
  rather than downgraded to "no filter": silently widening a narrowing request is
  the defect being fixed.
  On REST the value is parsed inside the authorization envelope, so an
  unauthorized caller cannot probe which state names exist. Callers that send no
  filter are unaffected.
- **Claim-integrity pass over the documentation.** Corrected assertions that the
  code does not support, with no code change: "never stores raw key material" is
  now scoped per provider (the software provider holds key bytes in process
  memory and is dev/test only); "deterministic key derivation trees" became
  "KEK-wrapping hierarchy", since no KDF exists and the LID is a
  content-addressed identifier; the HYOK "bounded lockout via cache TTL" claim
  was re-tiered, because an HSM disconnect is immediately fatal in FOSS and the
  TTL bounds cross-node staleness in the commercial HA tier only; and the audit
  chain is now described as strong interior tamper-evidence whose
  tail-truncation detection needs an external anchor, with signing opt-in and
  ephemeral by default. Also fixed non-canonical `git clone` URLs, a stale
  minimum Rust version, and several component statuses (`keyrack-pii` and Vault
  Transit shipped, Parsec a stub).
- **FOSS docs no longer reference commercial demo directories** by path or name;
  AWS KMS-compatible access is described neutrally as a commercial extension.

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
