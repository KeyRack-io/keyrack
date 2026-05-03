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
