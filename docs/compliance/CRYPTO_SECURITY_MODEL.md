# KeyRack Cryptographic Security Model

**Last updated:** 2026-05-11
**Audience:** Cryptographers, security auditors, penetration testers

---

## Algorithms and rationale

### Symmetric encryption: AES-256-GCM

KeyRack uses AES-256-GCM (FIPS 197 + NIST SP 800-38D) for all symmetric encryption.

**Parameters:**
- 256-bit key
- 96-bit (12-byte) random nonce via OS CSPRNG (`OsRng`)
- 128-bit authentication tag (GCM default)
- AAD: encryption context serialized as canonical byte sequence

**Why AES-256-GCM:** It is the industry-standard authenticated encryption cipher. FIPS-approved. Hardware-accelerated on x86 (AES-NI + CLMUL) and ARM (ARMv8 Crypto Extensions). Provides both confidentiality and integrity in a single pass.

**What it does NOT provide:** Nonce-misuse resistance. A repeated (key, nonce) pair under GCM is catastrophic — it leaks the XOR of plaintexts and allows authentication key recovery. See the nonce management section below.

### Signing: Ed25519

Default signing algorithm. RFC 8032 pure mode (not pre-hashed). FIPS-approved since FIPS 186-5 (2023). Provides ~128-bit security.

Implementation: `ed25519-dalek` crate. Deterministic signatures (no per-signature randomness needed). Constant-time scalar multiplication.

### Signing: ECDSA P-256 SHA-256

FIPS-compatible signing. FIPS 186-4. Provides ~128-bit security.

Implementation: `p256` crate (RustCrypto). Constant-time field arithmetic. The ECDSA nonce `k` is generated per RFC 6979 internally by the `p256` crate, avoiding the catastrophic failure mode of biased or repeated `k` values.

### Signing: RSA PKCS#1v1.5 SHA-256

Legacy signing scheme. Included for interoperability with systems requiring RSA (OpenStack Barbican, AWS KMS compatibility). Key sizes: 2048–4096 bits.

**Known limitations:**
- PKCS#1v1.5 lacks a security proof (unlike RSA-PSS which reduces to the RSA problem).
- RSA-2048 provides only ~112-bit security — below the 128-bit recommendation of NIST SP 800-131A Rev 3. Migration deadline: 2030.
- RSA-PSS is not yet supported. This is a known gap; PSS is the recommended scheme per RFC 8017.

### Hashing: BLAKE3 (internal)

BLAKE3 is used for two internal purposes:

1. **LID derivation:** `LID = BLAKE3(canonicalization_version_le32 || canonical_form_bytes)`
2. **Encryption context hashing:** `BLAKE3(sorted key-value pairs)` — stored in the ciphertext header

**What BLAKE3 provides:**
- Collision resistance (256-bit output, ~128-bit birthday bound)
- Pre-image resistance (256-bit)
- Deterministic content addressing for keys (LID)
- Fast integrity binding for encryption context (AAD)

**What BLAKE3 does NOT provide:**
- FIPS compliance — BLAKE3 is not FIPS-approved and has no path to NIST approval
- Confidentiality — BLAKE3 is a hash, not an encryption function
- Key material derivation — BLAKE3 is never used to derive key material in KeyRack

BLAKE3 is not a security boundary. It provides integrity and collision resistance for internal identifiers. The security of encryption and signing does not depend on BLAKE3.

### Hashing: SHA-256 (wire boundary)

SHA-256 is used at the PDP wire interface for the `encryption_context_hash` field in authorization requests. This is JCS-canonicalized and hex-encoded.

**Why the dual-hash boundary exists:** BLAKE3 is faster and better suited for internal use (parallelizable, streaming). SHA-256 is required at the wire boundary because external systems (PDP, audit consumers, compliance tools) may operate under FIPS requirements. The boundary is at the point where data leaves KeyRack's process.

This means:
- Internal operations use BLAKE3 (fast, no compliance constraint)
- Anything serialized for external consumption uses SHA-256 (FIPS-approved)
- The two hashes are computed from different canonical forms (internal TLV vs JCS JSON), so they are not directly comparable

---

## The security boundary: software vs HSM providers

### Software provider boundary

```
┌─────────────────────────────────────────┐
│              Process memory              │
│                                          │
│  ┌──────────┐  ┌──────────────────────┐  │
│  │ Key       │  │ keyrack-core         │  │
│  │ Material  │  │ (encrypt, sign,      │  │
│  │ (in-mem)  │──│  decrypt, verify)    │  │
│  └──────────┘  └──────────────────────┘  │
│                                          │
│  Zeroized on drop. No persistence.       │
│  Vulnerable to process memory dump.      │
└─────────────────────────────────────────┘
```

An attacker with process memory access can extract all key material. The software provider is explicitly for development and testing.

### HSM provider boundary

```
┌────────────────────────┐     ┌───────────────────┐
│    keyrack-service     │     │   HSM (PKCS#11)   │
│                        │     │                   │
│  Key handles (opaque)  │────▶│  Key material     │
│  LID / metadata        │     │  (never leaves)   │
│  Header construction   │     │  Encrypt / Sign   │
│                        │◀────│  Decrypt / Verify  │
│  Ciphertext assembly   │     │                   │
└────────────────────────┘     └───────────────────┘
```

KeyRack never sees raw key material. The HSM performs all cryptographic operations. An attacker who compromises `keyrack-service` gains:
- Ability to invoke operations (encrypt/decrypt/sign) using existing keys through the HSM session
- Access to key metadata, hierarchy, and LIDs
- Access to plaintext data in flight (if crypto-endpoints feature is enabled)

An attacker does NOT gain:
- Key material (stays in HSM)
- Ability to extract keys for offline use
- Ability to use keys after the session is revoked

The HSM's FIPS 140-3 certificate defines the cryptographic boundary. KeyRack's orchestration layer (LID derivation, header parsing, PDP integration) is outside that boundary.

---

## Nonce management and per-key encryption budget

AES-256-GCM uses 96-bit random nonces generated via `OsRng`:

```
nonce = OsRng.fill_bytes(12)
```

**Per-key encryption budget:** With random 96-bit nonces, the birthday bound gives a nonce collision probability of ~2^-32 after 2^32 encryptions under the same key. This is the NIST SP 800-38D acceptability threshold.

| Encryption rate | Time to reach 2^32 | Risk |
|---|---|---|
| 1,000/sec | ~50 days | Acceptable with 90-day rotation |
| 10,000/sec | ~5 days | Safe with standard rotation |
| 100,000/sec | ~12 hours | Dangerous without aggressive rotation |

**Consequence of nonce reuse:** If two plaintexts are encrypted with the same (key, nonce) pair under GCM, an attacker recovers the XOR of the two plaintexts and the GCM authentication subkey H. This allows forging authentication tags for arbitrary ciphertexts under that key. The key itself is not revealed, but the integrity guarantee is destroyed.

**Mitigations:**
- Key rotation creates new key versions with fresh material, resetting the nonce counter
- The PKCS#11 provider delegates nonce generation to the HSM (HSMs may use counter-based nonces)
- KeyRack's payload size limit (≤4096 bytes for DEKs) means each encryption consumes one GCM block counter value

**Not currently implemented:** A per-key operation counter that enforces rotation at the nonce budget limit. This is a documented recommendation.

---

## Ciphertext header

### Layout

```
Offset  Len  Field
──────  ───  ─────
  0       4  Magic: 0x4B 0x52 0x43 0x4B ("KRCK")
  4       2  Header version (LE u16)
  6      32  Key LID (BLAKE3 hash, 32 bytes)
 38       8  Key version (LE u64)
 46      32  Encryption context hash (BLAKE3, or 32×0x00 if absent)
 78       2  Reserved (LE u16, currently 0)
 80     ...  Ciphertext payload (nonce ‖ ciphertext ‖ tag)
```

Total header: 80 bytes fixed.

### What the header leaks

| Field | Leaked information |
|---|---|
| Magic bytes | Identifies the blob as KeyRack ciphertext. An observer learns that KeyRack is in use. |
| Header version | Protocol version. |
| Key LID | Which logical key encrypted this data. Enables traffic analysis: an observer can determine which ciphertexts share a key without decrypting anything. The LID is a BLAKE3 hash of key attributes — not directly reversible, but linkable. |
| Key version | Which rotation version was used. Reveals rotation timing patterns. |
| Encryption context hash | BLAKE3 hash of the context. Enables equality testing (same context → same hash). If the context value space is small, brute-force inversion is feasible. |

**Accepted trade-off:** Self-describing ciphertext headers are the standard pattern for KMS systems (AWS KMS, GCP Cloud KMS, Azure Key Vault). The alternative — storing key/version mapping out-of-band — is operationally fragile. The traffic analysis exposure is documented and accepted.

### What the header authenticates

The header is included in AES-GCM AAD, meaning any tampering with the header causes decryption to fail with an authentication error. An attacker cannot:
- Swap the LID to cause decryption with a different key (authentication failure)
- Change the key version (authentication failure)
- Modify the encryption context hash (authentication failure)

The failure mode for header tampering is denial of service (decryption rejects), not confidentiality or integrity breach.

---

## Key material lifecycle

### Generation

```
keyrack-service receives CreateKey request
  → PDP authorizes the operation
  → CryptoProvider::generate_key(spec) called
    → Software: OsRng generates key material in process memory
    → PKCS#11: HSM generates key material internally
  → Key handle stored in metadata (sqlite/postgres)
  → Audit event emitted
  → Key enters "Creating" state (transitions to "Enabled" on confirmation)
```

Key material is generated using the OS CSPRNG (`OsRng`), which delegates to `getrandom(2)` on Linux, `SecRandomCopyBytes` on macOS, and `BCryptGenRandom` on Windows. For PKCS#11, the HSM's validated RNG is used.

### Storage

- **Software provider:** In-memory `HashMap<String, KeyMaterial>` behind a `RwLock`. No persistence. Process restart loses all keys.
- **PKCS#11:** Key material stored in HSM non-volatile storage. KeyRack stores an opaque handle.
- **Metadata:** Key attributes, state, version, LID stored in sqlite/postgres. No key material in the metadata store.

### Use

Every cryptographic operation (encrypt, decrypt, sign, verify) requires:
1. PDP authorization (fail-closed)
2. Key state check (must be `Enabled` for encrypt/sign; `Enabled` or `Disabled` for decrypt/verify)
3. Provider dispatch to perform the operation
4. Audit event emission

### Zeroization

| Key type | Software provider | HSM provider |
|---|---|---|
| AES-256 | `Vec<u8>::zeroize()` via `zeroize` crate | HSM handles |
| Ed25519 | Best-effort overwrite with zero key | HSM handles |
| ECDSA P-256 | Not zeroized (RustCrypto limitation) | HSM handles |
| RSA | Not zeroized (RustCrypto limitation) | HSM handles |

The `Sensitive<T>` wrapper enforces zeroization for types that implement `Zeroize`. For P-256 and RSA, the underlying RustCrypto types do not expose a zeroization path. This is acknowledged in code and acceptable because the software provider is not intended for production use with regulated data.

The `zeroize` crate uses `write_volatile` or compiler barriers to prevent the compiler from optimizing away the zeroization write. For `Vec<u8>`, this covers the current allocation but not any prior allocations if the Vec was grown (reallocation copies and frees the old buffer without zeroizing).

### Destruction

```
keyrack-service receives ScheduleKeyDeletion request
  → PDP authorizes
  → Key enters "PendingDeletion" state (grace period)
  → After grace period, key transitions to "Destroyed"
  → CryptoProvider::destroy_key(handle) called
    → Software: HashMap entry removed, KeyMaterial::drop() zeroizes
    → PKCS#11: HSM destroys key object
  → Cascade-disable triggers for all descendant keys
  → Audit event emitted
```

Cascade-disable ensures that destroying a parent key immediately renders all descendant keys inoperable. This is the mechanism behind crypto-shredding for GDPR Article 17 compliance.

---

## PDP trust boundary

KeyRack uses an external Policy Decision Point (PDP) for authorization, implemented as a Cedar policy engine sidecar (`keyrack-cedar-pdp`).

### Why external by default

The PDP is a separate process for several reasons:
1. **Separation of concerns:** Policy evaluation is independent of cryptographic operations. A bug in the policy engine cannot corrupt key material.
2. **Policy updates without service restart:** Cedar policies can be updated without restarting `keyrack-service`.
3. **Audit independence:** PDP decisions are logged separately from crypto operations.
4. **Fail-closed:** If the PDP is unreachable, all operations are denied. There is no "allow if PDP is down" fallback.

### Trust model

```
Client → keyrack-service → keyrack-cedar-pdp
           │                     │
           │  "Can principal X   │
           │   perform action Y  │
           │   on resource Z?"   │
           │                     │
           │  ← Allow / Deny     │
           │                     │
           └── Proceed or reject
```

**If the PDP is compromised:** An attacker can authorize any operation. This is equivalent to compromising the access control layer. However, the attacker still cannot extract key material from an HSM — they can only invoke operations through KeyRack's API.

**If the PDP is unavailable:** All operations are denied. The service is effectively down for key operations but is not in an insecure state.

**The PDP does not see key material.** Authorization requests contain key attributes, action type, and principal identity. Plaintext data never transits through the PDP.

---

## Attacker capabilities by access level

### Access to ciphertext blobs only

**Can:**
- Determine that KeyRack is in use (magic bytes)
- Link ciphertexts encrypted under the same key (LID comparison)
- Determine rotation timing (key version comparison)
- Test encryption context equality (context hash comparison)

**Cannot:**
- Decrypt any ciphertext
- Determine key attributes from the LID (BLAKE3 is pre-image resistant)
- Forge ciphertexts (no key material)
- Modify ciphertexts without detection (GCM authentication tag)

### Access to keyrack-service process (software provider)

**Can:**
- Extract all key material from process memory
- Decrypt any ciphertext encrypted by keys in memory
- Sign arbitrary messages with any signing key
- Read key metadata, hierarchy, LIDs

**Cannot:**
- Access keys that have been destroyed (zeroized on drop)
- Access keys from other KeyRack instances (in-memory only, no persistence)

This is why the software provider is for development only.

### Access to keyrack-service process (PKCS#11 provider)

**Can:**
- Invoke encrypt/decrypt/sign/verify through the live HSM session
- Read key metadata, hierarchy, LIDs
- Intercept plaintext in flight (if crypto-endpoints are enabled)

**Cannot:**
- Extract key material from the HSM
- Use keys after the HSM session is revoked
- Use keys offline or from another host

### Access to the metadata store (sqlite/postgres)

**Can:**
- Read key attributes, states, hierarchy, LIDs
- Determine which keys exist and their rotation history
- Correlate LIDs with ciphertexts for traffic analysis

**Cannot:**
- Decrypt anything (no key material in metadata store)
- Modify key state to bypass access controls (state transitions are enforced server-side)

### Access to the PDP (Cedar policies)

**Can:**
- Read authorization policies
- Understand who can access which keys
- If writable: grant themselves access to any operation

**Cannot:**
- Extract key material
- Bypass HSM protections
- Decrypt ciphertexts without going through keyrack-service

---

## Post-quantum exposure and mitigation

### Vulnerable algorithms

| Algorithm | Attack | Impact |
|---|---|---|
| Ed25519 | Shor's algorithm (ECDLP) | Private key recovery; signature forgery |
| ECDSA P-256 | Shor's algorithm (ECDLP) | Private key recovery; signature forgery |
| RSA (all sizes) | Shor's algorithm (factoring) | Private key recovery; signature forgery |

### Safe algorithms

| Algorithm | Attack | Impact |
|---|---|---|
| AES-256-GCM | Grover's algorithm | Effective security reduced from 256-bit to 128-bit; still computationally infeasible |
| BLAKE3 | Grover's algorithm | Collision resistance reduced from ~2^128 to ~2^85; still infeasible |
| SHA-256 | Grover's algorithm | Same as BLAKE3 |

### "Harvest now, decrypt later" exposure

Ciphertexts encrypted with AES-256-GCM are safe against quantum adversaries (128-bit post-quantum security). Signed data is exposed: a quantum adversary could forge signatures on historical data if they recover the signing key.

For a KMS, the primary risk is to signing keys, not encryption keys. Organizations with long-term signature verification requirements should plan migration to post-quantum signatures.

### Mitigation path

KeyRack's `CryptoProvider` trait is algorithm-agnostic. Adding PQC requires:

1. **New `KeySpec` variants:** `MlKem768`, `MlDsa65`, `SlhDsa128s`
2. **New `SigningAlgorithm` variants:** `MlDsa65`, `SlhDsa128s`
3. **New trait method:** `encapsulate/decapsulate` for ML-KEM (KEM paradigm differs from direct encryption)
4. **Ciphertext header v2:** The version field (u16) allows a v2 header with PQC algorithm identifiers
5. **Provider implementations:** Software provider needs `ml-kem`/`ml-dsa` crates; PKCS#11 needs HSM firmware support

**Timeline:** NIST's deprecation schedule targets 2030 for 112-bit classical algorithms and 2035 for all quantum-vulnerable algorithms. KeyRack's PQC roadmap targets ML-DSA and ML-KEM support in V2, with hybrid schemes (e.g., X25519+ML-KEM) as a transitional option.

The LID derivation and ciphertext header format do not need changes for PQC — they use hash functions, which are post-quantum safe at current output sizes.
