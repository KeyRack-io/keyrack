# KeyRack Security Model

Threat model, security invariants, and vulnerability disclosure.

---

## Threat model

### Trust boundaries

1. **Client ↔ Service** — TLS-encrypted gRPC/REST. Clients authenticate via bearer tokens. The service trusts the PDP for authorization decisions.
2. **Service ↔ PDP** — The PDP is a trusted component. If the PDP is compromised, authorization is compromised. The service fails closed if the PDP is unreachable.
3. **Service ↔ Storage** — Storage holds encrypted key handles and metadata. Key material lives in the provider (HSM or software provider), not in storage.
4. **Service ↔ HSM** — The HSM is the root of trust for key material. PKCS#11 PIN is zeroized after session establishment.

### Assets

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Key material (CMK/DEK) | Critical | Critical | High |
| Ciphertext | Low (opaque) | Critical (tamper = corrupt) | High |
| Audit log | Medium | Critical (tamper = compliance loss) | Medium |
| Namespace rules | Low (public schema) | High (wrong rules = wrong hierarchy) | High |
| Identity tags | Medium (may contain PII tokens) | High | Medium |

### Threat categories

1. **Key exfiltration** — Mitigated by HSM isolation; software provider keys live in process memory and are zeroized on drop.
2. **Unauthorized operations** — Mitigated by PDP authorization on every RPC; fail-closed if PDP is unreachable.
3. **Privilege escalation** — Mitigated by per-operation authorization; no implicit admin role.
4. **Audit tampering** — Mitigated by append-only sinks; NATS provides durable, distributed audit distribution.
5. **Timing attacks** — Mitigated by constant-time comparison for authentication tokens (`subtle` crate).
6. **Ciphertext confusion** — Mitigated by self-describing ciphertext headers (key ID, version, algorithm embedded in ciphertext).

---

## Security invariants

These invariants are enforced structurally in the codebase, not by convention:

1. **Authorization on every operation** — The `ops::execute` wrapper ensures every gRPC/REST handler passes through PDP authorization before executing. No handler can bypass this.

2. **Audit on every operation** — The same `ops::execute` wrapper emits an audit event for every operation, including denied requests (`AuthorizationDenied` event type).

3. **Fail-closed on PDP unavailability** — If the PDP cannot be reached, the operation is denied. There is no "allow if PDP is down" mode.

4. **Fail-closed on KMS unavailability** — If the crypto provider cannot perform an operation, the error propagates to the caller. No fallback to a weaker algorithm.

5. **Sensitive data zeroization** — The `Sensitive<T>` wrapper zeroizes memory on drop. Key material, plaintext, and DEKs use this wrapper.

6. **Identity tags excluded from responses** — `KeyMetadata` in API responses only includes `user_tags`. Identity tags (which may contain PII tokens or tenant identifiers) are never returned to API callers.

7. **Opaque encryption context** — The encryption context (AAD) is BLAKE3-hashed before being stored in audit logs. Raw context values are never persisted.

8. **Cascade disable** — Disabling a parent key disables all descendants. This is enforced server-side and cannot be circumvented by client-side manipulation.

9. **Unique LIDs** — Every `CreateKey` call generates a unique LID by injecting a UUID into the attribute set before derivation. LID collisions are structurally impossible.

10. **Constant-time authentication** — Bootstrap token comparison uses `subtle::ConstantTimeEq` to prevent timing side-channel attacks.

---

## Deployment modes and threat model scope

`keyrack-service` supports two deployment modes controlled by the `crypto-endpoints` Cargo feature (default-on). Operators should select the mode that matches their threat model.

### Orchestration mode (`--no-default-features`)

The service manages key lifecycle (create, enable, disable, rotate, delete), dependency graphs, rotation scheduling, and audit. **No plaintext data transits through the service.** Applications use the `keyrack-core` library with direct HSM access for cryptographic operations.

| Property | Value |
|---|---|
| Plaintext exposure | None |
| Blast radius on compromise | Key metadata, state, hierarchy graph |
| HSM session usage | Lifecycle only (create, destroy, rotate) |
| Suitable for | Orchestration-only deployments where applications have direct HSM access |

### Crypto mode (default, `crypto-endpoints` feature enabled)

The service additionally exposes `Encrypt`, `Decrypt`, `GenerateDataKey`, `GenerateDataKeyWithoutPlaintext`, `ReEncrypt`, `Sign`, `Verify`, and `GenerateRandom`. Plaintext data transits through service memory during these operations.

| Property | Value |
|---|---|
| Plaintext exposure | Transient (in-flight, not cached) |
| Blast radius on compromise | Key metadata + plaintext data in flight + live HSM session |
| HSM session usage | All operations (lifecycle + data-plane crypto) |
| Suitable for | Centralized KMS deployments where applications call the service for crypto |

### AWS KMS shim (commercial, separate binary)

The shim adds a third deployment component with its own threat surface. It caches decrypted DEKs in-process (configurable TTL, default 60s, can be disabled).

| Property | Value |
|---|---|
| Plaintext exposure | Cached (configurable TTL) |
| Blast radius on compromise | Cached plaintext DEKs + gRPC-level access to core service |
| HSM access | None (delegates to core via gRPC) |
| Channel to core | Unix socket (monolith) or mTLS (cell mode) |

The separate binary boundary means: a SigV4-parsing vulnerability in the shim does not grant direct HSM session access.

---

## Cryptographic algorithms

| Operation | Algorithm | Parameters |
|---|---|---|
| Symmetric encryption | AES-256-GCM | 12-byte random nonce, 16-byte tag |
| Signing (default) | Ed25519 | RFC 8032, pure mode |
| Signing (FIPS) | ECDSA P-256 SHA-256 | FIPS 186-4 |
| Signing (legacy) | RSA PKCS#1 v1.5 SHA-256 | 2048–4096 bit keys |
| LID derivation | BLAKE3 | Keyed with canonicalization version |
| PII tokenization | BLAKE3 | Keyed with per-tenant salt |
| Canonicalization | Deterministic JSON-like | Version-tagged, forward-compatible |

---

## Ciphertext header format

Every ciphertext blob produced by KeyRack starts with a fixed 80-byte self-describing header:

| Offset | Length | Field |
|---|---|---|
| 0 | 4 | Magic bytes (`KRAC`) |
| 4 | 2 | Header version (LE u16) |
| 6 | 2 | Algorithm ID (LE u16) |
| 8 | 32 | Key LID (BLAKE3 hash) |
| 40 | 4 | Key version (LE u32) |
| 44 | 4 | Canonicalization version (LE u32) |
| 48 | 32 | Encryption context hash (BLAKE3) |

The header is authenticated (included in AES-GCM AAD) but not encrypted.

---

## AES-GCM nonce budget

AES-256-GCM uses a 96-bit (12-byte) random nonce. The birthday bound
gives a collision probability of approximately 2^{-32} after 2^{32}
encryptions under the same key. Beyond this threshold, nonce reuse
becomes probable, which is catastrophic for GCM (leaks the
authentication key and enables forgery).

**Practical implication**: a single KeyRack key version should not
encrypt more than ~4 billion ciphertexts. This is enforced
operationally rather than technically:

| Control | Status |
|---------|--------|
| Rotation policy (30d/90d/365d) resets the counter | Implemented |
| Monitoring: per-key-version encrypt counter | Planned (dashboard) |
| Hard cap: reject encrypt after 2^{31} operations per version | Not yet implemented |

For most workloads the rotation policy alone keeps usage well below
the bound. High-throughput scenarios (>1 billion encrypts per key
version) should use shorter rotation intervals or a deterministic
nonce scheme (AES-GCM-SIV), which KeyRack does not currently support.

The nonce is generated using the OS CSPRNG (`OsRng`) via the `aes-gcm`
crate's built-in nonce generation, not a counter. This means the
birthday bound applies rather than the stronger sequential bound.

---

## Zeroization posture

KeyRack uses the `zeroize` crate for memory cleanup of sensitive data.
Current coverage:

| Material | Zeroized on drop? | Mechanism |
|----------|:-----------------:|-----------|
| `Sensitive<Vec<u8>>` (plaintext, DEK) | Yes | `Zeroize` derive on `Sensitive<T>` |
| AES-256 key bytes (software provider) | Yes | Wrapped in `Sensitive` |
| Ed25519 signing key | Yes | `ed25519-dalek` zeroizes on drop |
| RSA private key | Partial | `rsa` crate does not guarantee zeroization of all internal `BigUint` limbs |
| ECDSA P-256 private key | Partial | `p256::SecretKey` implements `Zeroize` but intermediate scalars during signing may not be zeroized |
| PKCS#11 PIN | Yes | Zeroized after session open |
| Bootstrap token | No | `String` in config; lives for process lifetime |
| gRPC/REST request plaintext | No | Tonic/axum buffers are standard `Vec<u8>` |
| Provider-returned ciphertext | No | Not sensitive (ciphertext), but occupies memory until GC |

### Known gaps

1. **RSA limbs**: The `rsa` crate's `BigUint` values are heap-allocated
   and may leave residual copies during modular exponentiation. This is
   a known limitation of the RustCrypto RSA implementation. Mitigation:
   use PKCS#11 for RSA in production (HSM handles zeroization).

2. **Transport buffers**: Plaintext bytes in tonic/axum request buffers
   are not zeroized after the handler returns. The data is dropped
   normally (freed but not scrubbed). Mitigation: use orchestration
   mode (`--no-default-features`) to keep plaintext out of the service
   entirely.

3. **Stack copies**: The Rust compiler may create temporary copies of
   sensitive data on the stack during optimization. This is inherent to
   safe Rust and cannot be fully mitigated without `unsafe` and
   platform-specific memory barriers. The `zeroize` crate uses
   `core::sync::atomic::compiler_fence` to discourage (but not
   guarantee) elision of zeroing writes.

---

## Vulnerability disclosure

If you discover a security vulnerability in KeyRack:

1. **Do not open a public issue.**
2. Email `security@keyrack.dev` with:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Your contact information
3. We will acknowledge receipt within 48 hours.
4. We aim to provide a fix within 14 days for critical issues.
5. We will credit reporters in the advisory (unless they prefer anonymity).

### Scope

In scope:
- `keyrack-core`, `keyrack-service`, `keyrack-cedar-pdp`, `keyrack-cli`
- Authentication, authorization, cryptographic operations
- Key material handling and zeroization
- Audit integrity

Out of scope:
- Denial of service via resource exhaustion (unless trivially exploitable)
- Issues in third-party dependencies (report upstream)
- Social engineering

---

## Dependencies

KeyRack uses well-audited cryptographic libraries:

- `aes-gcm` — AES-256-GCM (RustCrypto project)
- `ed25519-dalek` — Ed25519 signatures
- `p256` — ECDSA P-256 (RustCrypto project)
- `rsa` — RSA PKCS#1 v1.5 (RustCrypto project)
- `blake3` — BLAKE3 hashing
- `subtle` — Constant-time operations
- `zeroize` — Memory zeroization

All cryptographic code is pure Rust (`#![forbid(unsafe_code)]` enforced workspace-wide).
