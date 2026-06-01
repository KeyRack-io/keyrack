# KeyRack Cryptographic and Compliance Analysis

**Author:** Security engineering analysis  
**Date:** 2026-05-11  
**Status:** Working draft for review  
**Audience:** Cryptographers, compliance officers, academic reviewers, KeyRack engineering

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Part I: Compliance Framework Analysis](#2-part-i-compliance-framework-analysis)
   - [FIPS 140-3](#21-fips-140-3)
   - [SOC 2 Type II](#22-soc-2-type-ii)
   - [PCI-DSS v4.0](#23-pci-dss-v40)
   - [HIPAA](#24-hipaa)
   - [GDPR / Privacy](#25-gdpr--privacy)
   - [eIDAS](#26-eidas)
   - [Common Criteria](#27-common-criteria)
   - [NIST SP 800-57](#28-nist-sp-800-57)
   - [Compliance Summary Matrix](#29-compliance-summary-matrix)
3. [Part II: Cryptographic Choices Analysis](#3-part-ii-cryptographic-choices-analysis)
   - [Algorithm Analysis](#31-algorithm-analysis)
   - [Key Derivation and Addressing](#32-key-derivation-and-addressing-lid)
   - [Ciphertext Header](#33-ciphertext-header-format)
   - [Random Number Generation](#34-random-number-generation)
   - [Post-Quantum Considerations](#35-post-quantum-considerations)
   - [Security Model Concerns](#36-security-model-concerns)
   - [Defensibility Assessment Summary](#37-defensibility-assessment-summary)
4. [Appendix A: Code References](#appendix-a-code-references)
5. [Appendix B: Recommendations Priority Matrix](#appendix-b-recommendations-priority-matrix)

---

## 1. Executive Summary

KeyRack is an attribute-based key management service with a pluggable cryptographic provider architecture. It supports a pure-Rust software provider (for development/testing) and delegates to PKCS#11 and KMIP backends (for production HSM-grade security). This analysis evaluates both the cryptographic soundness of the design and its alignment with major compliance frameworks.

**Key findings:**

1. **FIPS 140-3 compliance is partial and provider-dependent.** The PKCS#11 path can achieve FIPS compliance if the underlying HSM holds a FIPS 140-3 certificate. The software provider uses non-validated RustCrypto crates and BLAKE3 (not FIPS-approved), which breaks FIPS compliance. The dual-hash strategy (BLAKE3 internal, SHA-256 on wire) is a pragmatic but incomplete bridge.

2. **The cryptographic algorithm choices are sound for a KMS in 2026**, with two notable exceptions: RSA PKCS#1v1.5 is included for legacy compatibility but should be flagged as deprecated, and the absence of RSA-PSS will draw scrutiny from auditors.

3. **AES-256-GCM nonce management uses random nonces**, which is standard but imposes a per-key encryption count limit of ~2^32 operations (NIST SP 800-38D). For a KMS where keys are rotated, this is acceptable but must be documented.

4. **Post-quantum readiness is architecturally sound but operationally absent.** The `CryptoProvider` trait can accommodate PQC algorithms, but no PQC key specs exist today. With NIST's 2030 deprecation deadline for 112-bit classical algorithms, this is not yet urgent but warrants a roadmap.

5. **Zeroization is inconsistent.** AES key material and Ed25519 keys are zeroized on drop, but ECDSA P-256 and RSA keys are not (RustCrypto types don't expose zeroization). This is acknowledged in code comments but would be flagged by any security auditor.

6. **Compliance readiness varies.** KeyRack's architecture is well-suited for SOC 2, HIPAA, and GDPR (with its audit trail, access control, and crypto-shredding capabilities). PCI-DSS compliance requires operational controls (split knowledge, dual control) that are not purely software concerns. eIDAS and Common Criteria certification would require the HSM-backed deployment mode and formal evaluation processes.

---

## 2. Part I: Compliance Framework Analysis

### 2.1 FIPS 140-3

#### What it requires

FIPS 140-3 (effective since September 2019, mandatory for US federal agencies) requires that cryptographic modules:

- Use only FIPS-approved algorithms (SHA-2/SHA-3, AES, ECDSA, RSA, Ed25519 via FIPS 186-5, HMAC, etc.)
- Be validated through the CMVP (Cryptographic Module Validation Program)
- Meet one of four security levels (Level 1–4) for physical security, key management, self-tests, etc.
- Implement approved RNG (NIST SP 800-90A DRBG)

BLAKE3 is **not** a FIPS-approved hash algorithm. FIPS-approved hash functions are defined in FIPS 180-4 (SHA-1, SHA-2 family) and FIPS 202 (SHA-3 family). As of May 2026, BLAKE3 has no NIST approval and no indication of a path toward approval.

#### What KeyRack provides today

| Component | Algorithm | FIPS-Approved? | Notes |
|---|---|---|---|
| Symmetric encryption | AES-256-GCM | Yes (FIPS 197 + SP 800-38D) | Algorithm approved; implementation not validated |
| Signing (Ed25519) | Ed25519 | Yes (FIPS 186-5, 2023) | Algorithm approved; `ed25519-dalek` not validated |
| Signing (ECDSA) | ECDSA P-256 SHA-256 | Yes (FIPS 186-4) | Algorithm approved; `p256` crate not validated |
| Signing (RSA) | RSA PKCS#1v1.5 SHA-256 | Yes (FIPS 186-4) | Algorithm approved; `rsa` crate not validated |
| LID derivation | BLAKE3 | **No** | Not FIPS-approved; used internally |
| Encryption context hash (internal) | BLAKE3 | **No** | Not FIPS-approved; stored in ciphertext header |
| Encryption context hash (PDP wire) | SHA-256 (JCS canonical) | Yes | FIPS-compliant boundary |
| RNG | `OsRng` (OS-provided CSPRNG) | Depends on OS | Linux: `/dev/urandom` seeded by DRBG |

**Two-tier FIPS story:**

1. **PKCS#11 provider path (production):** Key material lives in an HSM. If the HSM holds a FIPS 140-3 certificate (e.g., Thales Luna, AWS CloudHSM), then the cryptographic boundary for key generation, encryption, signing, and decryption is FIPS-validated. KeyRack acts as an orchestrator — it never touches raw key material. This path is the strongest FIPS story.

2. **Software provider path (dev/test):** Uses RustCrypto crates. No RustCrypto crate has undergone CMVP validation as of May 2026. The `aes-gcm` crate has received a security audit by NCC Group, but a security audit is not FIPS validation. This path is explicitly **not FIPS-compliant**.

#### Where are the gaps?

| Gap | Severity | Scope |
|---|---|---|
| BLAKE3 used for LID derivation | **High** for FIPS; Low for security | Both FOSS and commercial. LID is a content-addressable identifier, not a security boundary — but FIPS auditors evaluate the entire module. |
| BLAKE3 used for encryption context hash in ciphertext header | **High** for FIPS | Both. The hash is stored in the ciphertext header and used for AAD binding. |
| RustCrypto crates not CMVP-validated | **Critical** for FIPS | Software provider only. PKCS#11 path delegates to validated modules. |
| No FIPS self-tests at startup | **High** for FIPS | Both. FIPS 140-3 Level 1+ requires power-up self-tests (known-answer tests). |
| `OsRng` not explicitly a FIPS-approved DRBG | **Medium** | Software provider. HSMs have their own validated RNG. |

#### What would be needed to close them?

1. **Replace BLAKE3 with SHA-256 for all internal hashing** — or provide a build-time feature flag (`fips`) that switches LID derivation and encryption context hashing to SHA-256. This is a breaking change for LID values and would require the alias-based migration path documented in `MIGRATION.md`.

2. **CMVP validation for the software provider** — either validate the RustCrypto crates (extremely expensive, ~$100K–$500K, 12–18 months) or switch to a FIPS-validated library like AWS-LC (`aws-lc-rs`), which has a FIPS 140-3 certificate.

3. **Add FIPS self-tests** — implement known-answer tests for each algorithm at startup. The `CryptoProvider` trait could include a `self_test()` method.

4. **Document the FIPS boundary clearly** — the PKCS#11 provider delegates to a FIPS-validated module for all cryptographic operations. KeyRack's orchestration layer (LID derivation, header parsing) is outside the FIPS boundary. This is architecturally defensible if documented.

#### FOSS or commercial concern?

**Both.** FIPS compliance is a deployment-mode question. FOSS users deploying KeyRack with SoftHSM in development don't need FIPS. Commercial deployments targeting US federal agencies or regulated industries (healthcare, finance) need the PKCS#11 path with a validated HSM. The BLAKE3 usage is a concern for both because it appears in the core library, not just the software provider.

---

### 2.2 SOC 2 Type II

#### What it requires

SOC 2 Type II evaluates the operating effectiveness of controls over a period (6–12 months) across five Trust Service Criteria:

1. **Security** (mandatory): Access controls, encryption, key management, vulnerability management
2. **Availability**: System uptime, disaster recovery
3. **Processing Integrity**: Data processing accuracy
4. **Confidentiality**: Protection of confidential information
5. **Privacy**: PII handling

For a KMS, the Security and Confidentiality criteria are primary. Auditors expect:

- Documented key management policies
- Key lifecycle management (generation, storage, rotation, revocation, destruction)
- Audit trail of all key operations
- Role-based access control
- Secure key storage (HSM or equivalent)
- Encryption using industry-standard algorithms (AES-256, RSA-2048+)

#### What KeyRack provides today

| SOC 2 Control | KeyRack Implementation | Status |
|---|---|---|
| Key generation | `CryptoProvider::generate_key()` with OsRng | ✅ Implemented |
| Key storage | HSM via PKCS#11/KMIP; software provider for dev | ✅ Architecture exists |
| Key rotation | Versioned keys, cooperative rotation protocol, policy-driven auto-rotation | ✅ Implemented |
| Key destruction | `destroy_key()` with zeroization; HSM destruction via provider | ✅ Implemented |
| Key state machine | `creating → enabled ↔ disabled → pending_deletion → destroyed` | ✅ Implemented |
| Audit trail | Every operation emits audit events via NATS; PDP authorization logged | ✅ Implemented |
| Access control | PDP authorization on every operation; fail-closed | ✅ Implemented |
| Encryption standards | AES-256-GCM, Ed25519, ECDSA P-256, RSA 2048–4096 | ✅ Industry-standard |
| Sensitive data protection | `Sensitive<T>` wrapper with `[REDACTED]` in logs | ✅ Implemented |
| Identity tag isolation | Identity tags excluded from API responses | ✅ Implemented |

#### Where are the gaps?

| Gap | Severity | Notes |
|---|---|---|
| No built-in key management policy documentation generator | Low | SOC 2 requires documented policies; KeyRack provides the technical controls but policy documents are an organizational concern |
| Audit log tamper-evidence | Medium | NATS provides durable delivery, but the audit trail itself is not cryptographically signed by KeyRack (the commercial audit service adds receipt signing). FOSS deployments lack this. |
| Continuous monitoring / alerting | Low | KeyRack emits metrics and events, but SOC 2 Type II requires evidence of monitoring over time. This is an operational concern. |

#### What would be needed to close them?

1. **FOSS audit integrity** — add an optional audit log signing feature (e.g., hash chain or Ed25519 signature on audit events) for FOSS deployments without the commercial audit pipeline.
2. **Policy template generation** — ship a template key management policy document with the FOSS distribution.
3. **Operational runbooks** — document key rotation procedures, incident response for compromised keys, and destruction verification.

#### FOSS or commercial concern?

**Both, but primarily commercial.** SOC 2 Type II is relevant for commercial SaaS offerings. FOSS users self-hosting don't typically undergo SOC 2 audits, but the technical controls KeyRack provides are the foundation. The audit trail completeness is strong for commercial deployments with the full commercial stack; FOSS deployments may need the signed audit log feature.

---

### 2.3 PCI-DSS v4.0

#### What it requires

PCI-DSS v4.0/4.0.1 (mandatory since March 2024, future-dated requirements since March 2025) has extensive key management requirements:

- **Req 3.6.1.1**: Documented key management procedures covering generation, distribution, storage, rotation, retirement, and destruction
- **Req 3.5.1.1**: Keyed cryptographic hashing (not standard hashing) for PAN rendering
- **Req 3.6.1**: Cryptographic key generation using approved methods with sufficient key strength
- **Req 3.7.1–3.7.9**: Key lifecycle management including:
  - Strong cryptographic key generation
  - Secure key distribution
  - Secure key storage
  - Periodic key rotation (cryptoperiod definition required)
  - Retirement/replacement of compromised keys
  - Split knowledge and dual control for key management operations
  - Prevention of unauthorized key substitution
  - Key custodian acknowledgment of responsibilities
  - Crypto-agility (Req 12.3.3): ability to update/replace algorithms
- **Req 4.2.1**: Certificate and key inventory
- **Req 12.3.3**: Cryptographic cipher suite and protocol inventory

#### What KeyRack provides today

| PCI-DSS Requirement | KeyRack Implementation | Status |
|---|---|---|
| Strong key generation (3.6.1) | OsRng (CSPRNG) for software provider; HSM RNG for PKCS#11 | ✅ |
| Secure key storage (3.7.3) | HSM-backed (PKCS#11/KMIP) in production | ✅ |
| Key rotation (3.7.4) | Versioned rotation with cooperative protocol, policy-driven intervals | ✅ |
| Key retirement/destruction (3.7.5–6) | Scheduled deletion with grace period, HSM material erasure | ✅ |
| Crypto-agility (12.3.3) | `CryptoProvider` trait + `KeySpec` enum allows algorithm addition | ✅ Architecture |
| Key inventory | `ListKeys`, `DescribeKey`, `ListKeyVersions` APIs | ✅ |
| Split knowledge / dual control (3.7.6) | **Not implemented in software** | ❌ |
| Key custodian acknowledgment (3.7.9) | Not a software feature | N/A |
| Certificate inventory (4.2.1) | Not KeyRack's responsibility (TLS termination is external) | N/A |

#### Where are the gaps?

| Gap | Severity | Notes |
|---|---|---|
| Split knowledge / dual control | **High** for PCI | PCI requires that no single person has access to the full cleartext key. This is an HSM/operational control, not purely software. |
| Cryptoperiod documentation | Medium | KeyRack supports rotation policies (90–2560 days) but doesn't enforce minimum cryptoperiods per PCI guidance |
| Key custodian workflow | Low | Organizational, not software |
| Keyed hash for PAN (3.5.1.1) | N/A | KeyRack is a KMS, not a PAN tokenization system. Consumers are responsible for this. |

#### What would be needed to close them?

1. **Split knowledge / dual control** — this is primarily an HSM operational control. PKCS#11 HSMs support multi-party authentication (M-of-N). KeyRack could surface this via the HSM connection configuration. For the software provider, split knowledge is not achievable (and the software provider should not be used in PCI scope).

2. **Cryptoperiod enforcement** — add configurable minimum cryptoperiods per key spec with enforcement at the rotation policy level.

3. **Key custodian workflow** — add an optional "key custodian acknowledgment" field on key creation (metadata, not crypto).

#### FOSS or commercial concern?

**Primarily commercial.** PCI-DSS applies to entities handling cardholder data. A FOSS user self-hosting KeyRack for their own PCI environment would need the HSM-backed deployment. The split knowledge gap is the most significant — it's achievable with HSM M-of-N but KeyRack doesn't surface it.

---

### 2.4 HIPAA

#### What it requires

As of 2026, HIPAA encryption requirements have shifted from "addressable" to **mandatory**:

- **Encryption at rest**: AES-256 or equivalent NIST-approved cipher for all ePHI
- **Encryption in transit**: TLS 1.2+ (TLS 1.3 recommended)
- **Key management**: Compliant with NIST SP 800-57
- **Audit logging**: Tamper-evident logs of encryption/decryption events for all ePHI access
- **Access controls**: Role-based access to encryption keys
- **Annual assessment**: Documented assessment of encryption posture

#### What KeyRack provides today

| HIPAA Requirement | KeyRack Implementation | Status |
|---|---|---|
| AES-256 encryption at rest | AES-256-GCM via `CryptoProvider` | ✅ |
| Key management per SP 800-57 | Full key lifecycle with states aligned to NIST | ✅ (see §2.8) |
| Audit logging | Every operation audited; PDP decisions logged | ✅ |
| Access controls | PDP authorization on every operation | ✅ |
| Tamper-evident logs | NATS durable delivery; commercial receipt chain signing | ⚠️ Partial (commercial only) |
| No plaintext in logs | `Sensitive<T>` wrapper enforced | ✅ |

#### Where are the gaps?

| Gap | Severity | Notes |
|---|---|---|
| Tamper-evident audit logs (FOSS) | Medium | FOSS deployments without the commercial audit pipeline lack cryptographic audit chain signing |
| Annual assessment tooling | Low | Organizational, not software |
| BAA (Business Associate Agreement) considerations | N/A | Legal, not technical |

#### What would be needed to close them?

1. **Signed audit events for FOSS** — same recommendation as SOC 2 §2.2.
2. **HIPAA deployment guide** — document which deployment mode (HSM-backed, PDP-enabled, audit pipeline) meets HIPAA requirements.

#### FOSS or commercial concern?

**Both.** Healthcare organizations using KeyRack FOSS in self-hosted environments need HIPAA compliance. The technical controls are strong; the gap is audit log integrity for FOSS deployments.

---

### 2.5 GDPR / Privacy

#### What it requires

GDPR does not mandate specific encryption algorithms but establishes principles relevant to key management:

- **Article 5(1)(f)**: Appropriate security measures including encryption
- **Article 32**: Encryption as a security measure; pseudonymization
- **Article 17**: Right to erasure ("right to be forgotten") — achievable via crypto-shredding
- **Article 25**: Data protection by design and by default
- **Article 33–34**: Breach notification (encryption status affects notification requirements)
- **Recital 83**: Encryption to ensure confidentiality

#### What KeyRack provides today

| GDPR Principle | KeyRack Implementation | Status |
|---|---|---|
| Encryption at rest | AES-256-GCM | ✅ |
| Crypto-shredding (Art. 17) | `destroy_key()` → HSM material erasure; cascade-disable for hierarchy | ✅ Strong |
| Data protection by design | Mandatory encryption, fail-closed, PDP authorization | ✅ |
| Identity tag isolation | Identity tags (potential PII) excluded from API responses | ✅ |
| Encryption context opacity | AAD pre-image not stored; only BLAKE3 hash in header | ✅ |
| Breach notification relevance | Encrypted data at rest reduces notification obligations | ✅ |

**Crypto-shredding** is KeyRack's strongest GDPR story. When a tenant's root key is destroyed:

1. All descendant keys become permanently unusable
2. All data encrypted under the hierarchy becomes permanently unrecoverable
3. The cascade-disable mechanism ensures immediate operational shutdown of the hierarchy
4. HSM material is physically erased (hardware HSM) or zeroized (SoftHSM)

This is a textbook implementation of GDPR-compliant right-to-erasure via cryptographic means.

#### Where are the gaps?

| Gap | Severity | Notes |
|---|---|---|
| No "key deletion certificate" | Low | Some GDPR auditors request proof of key destruction. KeyRack's audit log records the destruction event, but a signed destruction certificate would be stronger. |
| BLAKE3 hash of encryption context in header | Low | If the encryption context contains PII-derived values, the BLAKE3 hash is not reversible, but its presence may require documentation under DPIA. |
| Data residency of key metadata | Low | KeyRack stores metadata in PostgreSQL; data residency depends on deployment. |

#### What would be needed to close them?

1. **Key destruction certificate** — emit a signed audit event specifically for key destruction that serves as a verifiable certificate.
2. **DPIA template** — provide a Data Protection Impact Assessment template for KeyRack deployments.

#### FOSS or commercial concern?

**Both.** GDPR applies to any organization processing EU personal data. The crypto-shredding capability is equally valuable in FOSS and commercial contexts.

---

### 2.6 eIDAS

#### What it requires

eIDAS 2 (EU Regulation 2024/1183) establishes requirements for qualified electronic signatures and seals:

- **Qualified Signature Creation Devices (QSCD)**: Must be Common Criteria certified (EAL 4+ for hardware)
- **HSM requirements**: Signing keys must be held in tamper-protected hardware
- **Sole control**: The signer must have sole control over the signing key
- **Signature Activation Module (SAM)**: Verification of consent before signing
- **Audit logging**: All key usage must be logged
- **Algorithm requirements**: ETSI-approved algorithms (RSA-PSS, ECDSA, Ed25519); post-quantum readiness becoming relevant
- **Qualified Trust Service Provider (QTSP)**: Organizational certification required

#### What KeyRack provides today

| eIDAS Requirement | KeyRack Implementation | Status |
|---|---|---|
| HSM-backed signing | PKCS#11 provider with Ed25519, ECDSA P-256, RSA | ✅ Architecture |
| Audit logging | Every sign operation audited | ✅ |
| Sole control | PDP authorization per-operation | ⚠️ Partial — no SAM integration |
| ETSI-approved algorithms | Ed25519, ECDSA P-256, RSA available | ⚠️ RSA-PSS absent |
| PQC readiness | Architecture supports extension; no PQC algorithms today | ❌ |

#### Where are the gaps?

| Gap | Severity | Notes |
|---|---|---|
| No RSA-PSS support | **High** for eIDAS | eIDAS/ETSI standards prefer RSA-PSS over PKCS#1v1.5. KeyRack only supports PKCS#1v1.5. |
| No SAM integration | **High** for eIDAS | Qualified signatures require a Signature Activation Module. KeyRack's PDP provides authorization but is not a SAM. |
| No QSCD certification | **Critical** | Would require formal Common Criteria evaluation of the HSM + KeyRack combination |
| No PQC signature algorithms | Medium | eIDAS 2 is moving toward PQC readiness requirements |

#### What would be needed to close them?

1. **Add RSA-PSS** — extend `SigningAlgorithm` and `KeySpec` enums with PSS variants.
2. **SAM integration** — this is likely out of scope for KeyRack. A QTSP would wrap KeyRack with a SAM layer.
3. **QSCD certification** — requires formal Common Criteria evaluation. This is a commercial concern (12–18 months, significant cost).
4. **PQC signatures** — add ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) key specs.

#### FOSS or commercial concern?

**Primarily commercial.** eIDAS certification is relevant for Trust Service Providers operating in the EU. FOSS KeyRack could be a component in a QTSP's stack, but the certification is organizational. The RSA-PSS gap affects both FOSS and commercial.

---

### 2.7 Common Criteria

#### What it requires

Common Criteria (ISO/IEC 15408) evaluates IT products against Protection Profiles (PPs) at Evaluation Assurance Levels (EAL 1–7). For key management systems, relevant functional families include:

- **FCS_CKM.1**: Cryptographic key generation
- **FCS_CKM.2**: Cryptographic key distribution
- **FCS_CKM.5**: Cryptographic key derivation
- **FCS_CKM.6**: Cryptographic key destruction
- **FCS_CKM_EXT.3**: Cryptographic key access
- **FCS_CKM_EXT.7**: Cryptographic key transport
- **FCS_COP.1**: Cryptographic operation
- **FAU_GEN.1**: Audit data generation
- **FIA_UAU**: User authentication
- **FDP_ACC**: Access control policy

The Encryption Key Management (EKM) PP Module (2023) specifically addresses KMS components.

#### What KeyRack provides today

| CC Functional Family | KeyRack Implementation | Status |
|---|---|---|
| FCS_CKM.1 (Key generation) | `generate_key()` with CSPRNG; HSM-delegated | ✅ |
| FCS_CKM.5 (Key derivation) | LID derivation (BLAKE3); not used for key material derivation | ⚠️ N/A (LID is not key material) |
| FCS_CKM.6 (Key destruction) | `destroy_key()` with zeroization; HSM destruction | ✅ |
| FCS_COP.1 (Crypto operations) | AES-256-GCM, Ed25519, ECDSA P-256, RSA | ✅ |
| FAU_GEN.1 (Audit) | Comprehensive audit on every operation | ✅ |
| FIA_UAU (Authentication) | PDP authorization; mTLS/bearer auth | ✅ |
| FDP_ACC (Access control) | PDP-based per-operation authorization | ✅ |

#### Where are the gaps?

| Gap | Severity | Notes |
|---|---|---|
| No formal Security Target document | **Critical** for CC | CC evaluation requires a formal Security Target mapping to a PP |
| No EAL evaluation | **Critical** | Would require 6–18 months of formal evaluation |
| Incomplete zeroization | Medium | P-256 and RSA key material not zeroized in software provider |
| No power-up self-tests | Medium | CC functional requirement FCS_COP may require self-tests |

#### What would be needed to close them?

1. **Security Target authoring** — map KeyRack's security functions to CC functional requirements.
2. **Formal evaluation** — engage a Common Criteria evaluation lab. Target EAL 2+ for software, relying on HSM's existing CC certification for the crypto boundary.
3. **Fix zeroization gaps** — ensure all key material types are zeroized in the software provider.
4. **Self-test infrastructure** — add KAT (Known Answer Test) support.

#### FOSS or commercial concern?

**Commercial only.** CC certification is relevant for government procurements and regulated industries. The evaluation is per-product and per-version, making it a commercial investment.

---

### 2.8 NIST SP 800-57

#### What it requires

NIST SP 800-57 Part 1 (Revision 5, current; Revision 6 in IPD as of December 2025) provides key management recommendations:

**Key states:**
- Pre-activation, Active, Deactivated, Compromised, Destroyed, Destroyed-Compromised

**Key lifecycle:**
- Generation with approved RNG
- Distribution via secure channels
- Storage with appropriate protection
- Use within defined cryptoperiods
- Archival for verification-only access
- Destruction via approved methods

**Algorithm strength (2026):**
- Minimum 128-bit security strength recommended
- 112-bit security deprecated after 2030 (per SP 800-131A Rev 3)
- RSA-2048 provides ~112 bits (will be deprecated); RSA-3072 provides ~128 bits

**Revision 6 additions (IPD):**
- PQC algorithms from FIPS 203, 204, 205
- Ascon (SP 800-232) for lightweight crypto
- New section on keying material storage mechanisms

#### What KeyRack provides today

| SP 800-57 Recommendation | KeyRack Implementation | Alignment |
|---|---|---|
| **Key states** | `Creating → Enabled ↔ Disabled → PendingDeletion → Destroyed` | ⚠️ Partial (see below) |
| **Approved RNG** | `OsRng` (OS CSPRNG) for software; HSM RNG for PKCS#11 | ✅ |
| **Key generation** | Per-algorithm generation via `CryptoProvider` | ✅ |
| **Key rotation** | Versioned rotation with policy-driven intervals (90–2560 days) | ✅ |
| **Key destruction** | Zeroization on drop; HSM material erasure | ✅ |
| **Cryptoperiods** | Configurable rotation policies | ✅ |
| **Algorithm strength** | AES-256 (256-bit), Ed25519 (128-bit), P-256 (128-bit), RSA-2048 (112-bit) | ⚠️ RSA-2048 is borderline |
| **PQC** | Not yet implemented | ❌ |

**Key state mapping:**

| NIST SP 800-57 State | KeyRack State | Notes |
|---|---|---|
| Pre-activation | `Creating` | KeyRack's `Creating` state covers async HSM provisioning |
| Active | `Enabled` | Full encrypt + decrypt |
| Deactivated | `Disabled` | Decrypt only (data recovery); new encrypt blocked |
| Compromised | _(not modeled)_ | **Gap**: KeyRack lacks a distinct "compromised" state |
| Destroyed | `Destroyed` | Material erased |
| Destroyed-Compromised | _(not modeled)_ | **Gap** |

#### Where are the gaps?

| Gap | Severity | Notes |
|---|---|---|
| No "Compromised" key state | **Medium** | SP 800-57 distinguishes compromised keys from deactivated keys. KeyRack would need a `Compromised` state that blocks all operations (not just encrypt). |
| RSA-2048 offers only 112-bit security | **Medium** | Per SP 800-131A Rev 3, 112-bit algorithms face deprecation by 2030. RSA-2048 should be flagged with a warning. |
| No PQC algorithm support | **Medium** | SP 800-57 Rev 6 adds PQC; KeyRack should add ML-KEM, ML-DSA, SLH-DSA. |
| No key archival state | Low | SP 800-57 has an archival state for verification-only. KeyRack's `Disabled` partially covers this. |

#### What would be needed to close them?

1. **Add `Compromised` key state** — a state that blocks all operations and triggers immediate cascade-disable of the hierarchy.
2. **RSA-2048 deprecation warning** — emit a warning when RSA-2048 keys are created; recommend RSA-3072+.
3. **PQC key specs** — add ML-KEM, ML-DSA, SLH-DSA to `KeySpec` and implement in providers.
4. **Key archival** — consider adding an `Archived` state (verification-only, no encrypt/decrypt).

#### FOSS or commercial concern?

**Both.** SP 800-57 alignment is expected for any KMS. The compromised state gap is relevant for both FOSS and commercial deployments.

---

### 2.9 Compliance Summary Matrix

| Framework | Current Readiness | Primary Gaps | Effort to Close | Scope |
|---|---|---|---|---|
| **FIPS 140-3** | ⚠️ Partial (PKCS#11 path only) | BLAKE3 internal use; RustCrypto not validated; no self-tests | High (BLAKE3 migration or feature flag; CMVP validation or aws-lc-rs switch) | Both |
| **SOC 2 Type II** | ✅ Strong | Audit log signing for FOSS; policy documentation | Low–Medium | Primarily commercial |
| **PCI-DSS v4.0** | ⚠️ Partial | Split knowledge/dual control; RSA-PSS absent | Medium (operational + HSM M-of-N) | Primarily commercial |
| **HIPAA** | ✅ Strong | Audit log integrity for FOSS | Low | Both |
| **GDPR** | ✅ Strong | Key destruction certificate; DPIA template | Low | Both |
| **eIDAS** | ❌ Significant gaps | RSA-PSS; SAM; QSCD certification; PQC | High (formal certification) | Commercial |
| **Common Criteria** | ❌ Not evaluated | Formal Security Target; EAL evaluation; zeroization | Very High (formal evaluation) | Commercial |
| **NIST SP 800-57** | ⚠️ Mostly aligned | Compromised state; RSA-2048 deprecation; PQC | Medium | Both |

---

## 3. Part II: Cryptographic Choices Analysis

### 3.1 Algorithm Analysis

#### 3.1.1 AES-256-GCM

**Implementation:** `crates/keyrack-core/src/provider/software.rs` lines 152–189 (encrypt), 192–232 (decrypt).

**Parameters:**
- 256-bit key
- 12-byte (96-bit) random nonce generated via `OsRng`
- 16-byte (128-bit) authentication tag (GCM default)
- AAD: encryption context serialized as canonical byte sequence

**Nonce generation strategy:**

```rust
let mut nonce_bytes = [0u8; 12];
OsRng.fill_bytes(&mut nonce_bytes);
```

This is a **random nonce** strategy. The nonce is generated fresh for each encryption operation using the OS CSPRNG. This is the standard approach and aligns with NIST SP 800-38D §8.2.2.

**Nonce reuse prevention:**

Random nonces rely on the birthday bound for collision resistance. With 96-bit random nonces:

- After 2^32 encryptions with the same key, the probability of a nonce collision reaches approximately 2^-32 (the NIST limit for acceptability per SP 800-38D).
- After 2^48 encryptions, collision becomes probable.

For a KMS where keys are routinely rotated (creating new key versions with fresh material), the per-key encryption count is bounded by the rotation interval. If a key encrypts fewer than 2^32 messages before rotation, the random nonce strategy is safe.

**Risk assessment:**

- **Normal KMS workload**: A key encrypting 1,000 messages/second would reach 2^32 (~4.3 billion) in approximately 50 days. For keys with 90-day rotation, this is borderline but acceptable for most workloads.
- **High-throughput workload** (e.g., per-object encryption for object storage): A key encrypting 100,000 messages/second would reach 2^32 in approximately 12 hours. This is dangerous without aggressive rotation.

**Ciphertext size limit:**

AES-GCM with a 32-bit block counter limits a single encryption to 2^32 blocks × 16 bytes = 64 GiB. For a KMS encrypting DEKs (32 bytes) or small payloads (≤4096 bytes per spec), this is not a practical concern.

**Auditor assessment:** An auditor would flag:
1. The absence of a per-key encryption counter or nonce reuse detection mechanism.
2. The lack of a documented nonce budget per key with enforcement at rotation time.
3. The absence of AES-GCM-SIV or AES-256-CTR-HMAC as a nonce-misuse-resistant alternative.

**Recommendation:** Add a per-key operation counter and enforce rotation when approaching 2^32 encryptions. Consider offering AES-256-GCM-SIV as an optional algorithm for high-throughput use cases.

**Defensibility:** AES-256-GCM is the standard choice for authenticated encryption in 2026. The random nonce strategy is the most common approach. The 2^32 limit per key is well-understood and manageable with rotation. This would pass audit scrutiny with proper documentation.

---

#### 3.1.2 Ed25519

**Implementation:** `ed25519-dalek` crate, RFC 8032 pure mode.

**Why Ed25519 (vs Ed448):**
- Ed25519 provides ~128-bit security, matching AES-256's effective security level for most threat models
- Ed448 provides ~224-bit security but is significantly slower and less widely supported
- Ed25519 is the de facto standard for modern signing in 2026 (used by SSH, TLS 1.3, WireGuard, age, minisign)
- Ed25519 was added to FIPS 186-5 in 2023, making it FIPS-approved
- Ed448 is also in FIPS 186-5 but has much lower ecosystem adoption

**Signing model:** Pure Ed25519 (the entire message is signed, not a hash). This is the recommended mode; pre-hashed Ed25519 (Ed25519ph) is less commonly used and has subtle security caveats.

**Auditor assessment:** Ed25519 as the default signing algorithm is the expected choice for a modern KMS. No known weaknesses. An auditor might note:
1. `ed25519-dalek`'s zeroization of the signing key uses a best-effort overwrite with a zero key (line 63 of `software.rs`) rather than the `Zeroize` trait, because the `ed25519_dalek::SigningKey` type doesn't implement `Zeroize`.
2. The absence of Ed448 as an option (minor — market demand is low).

**Defensibility:** Strong. Ed25519 is the standard modern signing algorithm. No credible attacks. Well-supported by HSMs.

---

#### 3.1.3 ECDSA P-256 SHA-256

**Implementation:** `p256` crate from RustCrypto, FIPS 186-4 compliant.

**Why P-256 (vs P-384, P-521):**
- P-256 provides ~128-bit security, matching the system's overall security target
- P-256 is the most widely deployed NIST curve (TLS certificates, WebAuthn, FIDO2)
- P-384 (192-bit security) and P-521 (256-bit security) are available but less commonly used
- P-256 has the broadest HSM support
- P-256 is required by FIPS 186-4 and expected by compliance frameworks

**NIST curve concerns:**

The NIST P-256 curve has a long history of scrutiny:

1. **Curve constant controversy**: The seed used to generate P-256's parameters was never convincingly justified. In the post-Snowden era, this led to concerns about potential backdoors. However, no exploitable weakness has been found, and extensive analysis by multiple independent research groups has not revealed any structural vulnerability.

2. **Side-channel resistance**: ECDSA on NIST curves is more susceptible to side-channel attacks than EdDSA (which uses Edwards curves with complete addition formulas). The `p256` crate uses constant-time field arithmetic, but the signing operation inherently involves a random nonce `k` whose leakage would reveal the private key.

3. **Alternatives**: Curve25519/Ed25519 avoids the NIST curve concerns entirely. KeyRack already supports Ed25519 as the default. P-256 is offered for FIPS compatibility and interoperability with systems that require NIST curves.

**Auditor assessment:** P-256 is the expected NIST curve. An auditor might note:
1. The absence of P-384 and P-521 options limits flexibility for organizations requiring higher security margins.
2. ECDSA signatures are non-deterministic (randomized `k`), making testing harder. RFC 6979 (deterministic ECDSA) is not used.

**Defensibility:** Strong. P-256 is the industry standard NIST curve. The inclusion alongside Ed25519 provides both modern-best-practice and FIPS-compatible options.

---

#### 3.1.4 RSA PKCS#1v1.5 SHA-256

**Implementation:** `rsa` crate from RustCrypto, key sizes 2048–4096 bits.

**Why PKCS#1v1.5 (vs PSS):**

This is the weakest cryptographic choice in KeyRack and will draw scrutiny.

- **PKCS#1v1.5** is the legacy RSA signature padding scheme. RFC 8017 (PKCS#1 v2.2) states: "RSASSA-PSS is REQUIRED in new applications. RSASSA-PKCS1-v1_5 is included only for compatibility with existing applications."
- **RSA-PSS** (Probabilistic Signature Scheme) has a security proof (reducing to RSA problem hardness) and is more robust against padding oracle attacks. TLS 1.3 dropped PKCS#1v1.5 support entirely.
- KeyRack's inclusion of PKCS#1v1.5 appears to be driven by interoperability with legacy systems (Barbican compatibility, AWS KMS compatibility, OpenStack ecosystem).

**Known concerns:**

1. **Bleichenbacher-style attacks**: While primarily relevant to encryption (not signing), PKCS#1v1.5 padding for signatures has a history of implementation vulnerabilities (e.g., Bleichenbacher '06 signature forgery against certain implementations that don't properly validate padding).
2. **No security proof**: Unlike PSS, PKCS#1v1.5 signatures lack a reduction to the RSA problem.
3. **Industry direction**: PKCS#1v1.5 is being phased out across the industry. TLS 1.3 removed it. NIST SP 800-131A permits it but recommends PSS.

**Key sizes:**

| Key Size | Security Level | Status (2026) |
|---|---|---|
| RSA-2048 | ~112 bits | Still permitted but NIST recommends migration by 2030 |
| RSA-3072 | ~128 bits | Recommended minimum for new deployments |
| RSA-4096 | ~152 bits | Strong but slow |

**Auditor assessment:** An auditor would:
1. **Flag the absence of RSA-PSS** as a significant omission.
2. Question why a new KMS in 2026 supports only the legacy padding scheme.
3. Recommend adding RSA-PSS and making it the default, with PKCS#1v1.5 as a legacy option.
4. Note that RSA-2048 provides only 112-bit security, below the 128-bit recommendation.

**Defensibility:** Weak. Including PKCS#1v1.5 for backward compatibility is understandable, but not offering PSS as an alternative is a gap. An academic reviewer would note this as a design shortcoming.

**Recommendation:** Add `RsaPssSha256` to `SigningAlgorithm` and `KeySpec`. Make PSS the default RSA scheme; keep PKCS#1v1.5 as `RsaPkcs1v15Sha256Legacy`.

---

#### 3.1.5 BLAKE3

**Usage in KeyRack:**
1. **LID derivation**: `LID = BLAKE3(canonicalization_version_le32 || canonical_form_bytes)` (`lid.rs` lines 36–40)
2. **Encryption context hash**: `BLAKE3(sorted key-value pairs)` (`encryption_context.rs` lines 83–90)
3. **PII tokenization**: BLAKE3 with per-tenant salt (per `SECURITY.md`)

**Why BLAKE3:**
- Extremely fast: 2–10× faster than SHA-256 in software, parallelizable
- 256-bit output (same as SHA-256)
- Strong security margins (based on BLAKE, a SHA-3 finalist)
- No known vulnerabilities
- Excellent Rust ecosystem support (`blake3` crate is highly optimized)

**FIPS non-compliance:**

BLAKE3 is not approved under FIPS 140-3. FIPS-approved hash functions are limited to:
- SHA-1 (deprecated for most uses)
- SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
- SHA-3 family (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256)

There is no indication that NIST plans to approve BLAKE3.

**Defensibility of the dual-hash strategy:**

KeyRack uses BLAKE3 internally and SHA-256 on the PDP wire. The rationale (documented in `PDP_INTEGRATION_GUIDE.md`) is:

| Hash | Algorithm | Where | Purpose |
|---|---|---|---|
| Internal | BLAKE3 | Ciphertext header, LID | Performance-optimized AAD binding and content addressing |
| Wire | SHA-256 (JCS canonical) | PDP AuthzRequest | FIPS-compliant boundary for external systems |

This is a defensible architecture:

1. The FIPS boundary is at the PDP wire interface, where SHA-256 is used.
2. BLAKE3 is used internally where FIPS compliance is not required (content addressing, AAD binding).
3. The BLAKE3 usage does not affect the security of the encryption or signing (which are AES-GCM and Ed25519/ECDSA/RSA, all FIPS-approved).
4. LID derivation is not a cryptographic security function — it's a content-addressable identifier. Even if BLAKE3 had a collision vulnerability (it doesn't), the impact would be LID collisions, not key compromise. KeyRack further injects a UUID into the attribute set before LID derivation (per `SECURITY.md` invariant 9), making collisions structurally impossible.

**Academic assessment:** An academic reviewer would:
1. Acknowledge BLAKE3's strong security properties (based on ChaCha/BLAKE lineage)
2. Note the FIPS non-compliance and ask whether a FIPS-mode feature flag exists
3. Appreciate the dual-hash strategy as a pragmatic boundary separation
4. Potentially question whether SHA-3 would have been a better choice (FIPS-approved, good performance with SHA3-256, and similar security margins)

**Recommendation:** Consider a `--fips` build flag that replaces BLAKE3 with SHA-256 or SHA3-256 throughout. Document that BLAKE3 is used only for non-security-critical derivations (content addressing, not key material derivation).

---

#### 3.1.6 SHA-256

**Usage:** PDP wire format for `encryption_context_hash` (JCS-canonicalized, hex-encoded).

**Assessment:** SHA-256 is the gold standard for compliance-facing hash functions. No known vulnerabilities. 128-bit collision resistance. FIPS-approved. This is the correct choice for the external boundary.

---

### 3.2 Key Derivation and Addressing (LID)

#### LID Construction

```
LID = BLAKE3(canonicalization_version_le32 || canonical_form_bytes)
```

Where `canonical_form_bytes` is a deterministic TLV encoding of an `AttributeSet` with:
- Keys sorted by BTreeMap (lexicographic byte order)
- String values NFC-normalized
- Tagged value encoding (TAG_STRING=0x01, TAG_I64=0x02, TAG_BOOL=0x03, TAG_LIST_OF_STRING=0x04, TAG_RECORD=0x05)
- Length-prefixed (u32 LE) payloads

**Collision resistance:**

BLAKE3 produces a 256-bit hash. Birthday-bound collision probability:
- After 2^128 distinct inputs: probability of collision ≈ 50%
- This is the same collision resistance as SHA-256

For KeyRack's use case (each LID is derived from a unique attribute set with an injected UUID), collisions are structurally impossible — the UUID ensures uniqueness regardless of hash function collision resistance. The BLAKE3 hash provides a compact, fixed-size identifier.

**Birthday-bound implications for a KMS:**

Even without the UUID injection, a system would need to create 2^128 keys before a birthday collision becomes probable. At 1 billion keys per second, this would take approximately 10^19 years. This is not a practical concern.

**Canonicalization versioning:**

The `CanonicalizationVersion` enum (currently only `V1`) is included in the hash input, domain-separating different versions:

```rust
pub enum CanonicalizationVersion {
    V1 = 1,
}
```

The version is encoded as `u32 LE` and prepended to the canonical form before hashing. This ensures that a future V2 canonicalization produces different LIDs even for the same attribute set.

**Migration path:** If canonicalization changes (e.g., adding new attribute types, changing sort order, or addressing a security issue), the alias-based migration documented in `MIGRATION.md` allows coexistence of old and new LIDs via aliases. This is a sound migration strategy.

**Auditor assessment:**
1. The TLV encoding is deterministic and unambiguous (tag-length-value prevents extension/truncation attacks).
2. NFC normalization prevents Unicode equivalence issues.
3. BTreeMap ordering ensures sort-order determinism.
4. Version domain separation is correctly implemented.
5. The UUID injection (invariant 9 in `SECURITY.md`) makes the LID more of a unique identifier than a content hash — this is safe.

**One concern:** The canonicalization format does not include a total-entry-count field or a terminal sentinel. While the BTreeMap's deterministic ordering prevents ambiguity, adding a count prefix would provide defense-in-depth against potential parsing ambiguities in future versions.

---

### 3.3 Ciphertext Header Format

#### Layout (from `header.rs`)

```
Offset  Len  Field
──────  ───  ─────
  0       4  Magic: 0x4B 0x52 0x43 0x4B ("KRCK")
  4       2  Header version (LE u16)
  6      32  Key LID (raw 32 bytes)
 38       8  Key version (LE u64)
 46      32  Encryption context hash (BLAKE3, or 32×0x00 if none)
 78       2  Reserved (LE u16, currently 0)
 80     ...  Ciphertext payload (nonce || ciphertext || tag)
```

Total header: 80 bytes fixed.

#### Information leakage analysis

| Field | Sensitive? | Analysis |
|---|---|---|
| Magic bytes | No | Public constant, identifies KeyRack ciphertext |
| Header version | No | Public protocol version |
| Key LID | **Low risk** | The LID is derived from attributes via BLAKE3. It's a 256-bit hash — not directly reversible to attributes. However, knowing the LID reveals which key was used, enabling traffic analysis (which ciphertexts share a key). |
| Key version | **Low risk** | Reveals which rotation version encrypted this ciphertext. Could reveal rotation timing patterns. |
| Encryption context hash | **Low risk** | BLAKE3 hash of the context. Not reversible, but enables equality testing (same context → same hash). If the encryption context space is small, brute-force inversion is possible. |
| Reserved | No | Zero bytes |

**Overall leakage:** The header leaks key identity and version, which is necessary for decryption routing. This is the standard trade-off in self-describing ciphertext formats (AWS KMS, GCP KMS, Azure Key Vault all have similar headers). The leakage enables traffic analysis but does not compromise confidentiality or integrity.

#### Header authentication

**Is the header authenticated?** Per `SECURITY.md` line 132: "The header is authenticated (included in AES-GCM AAD) but not encrypted."

This is confirmed by the encrypt implementation: the encryption context's `to_aad_bytes()` output is passed as AAD to AES-GCM. However, examining `software.rs` more carefully, the AAD passed to `encrypt()` is the `aad` parameter from the caller — it's the encryption context bytes, not the header itself.

**Critical question:** Is the full header (LID, version, context hash) bound into the AES-GCM AAD? Or only the encryption context?

Looking at the code flow: the `CryptoProvider::encrypt()` receives `aad: &[u8]` which is the encryption context bytes. The ciphertext header is constructed _around_ the encrypted output by `CiphertextHeader::wrap_payload()`. The header fields (LID, key version) are written to the header bytes but may not be included in the AES-GCM AAD.

**If the header is not fully authenticated:** An attacker could modify the LID or key version in the header, causing decryption to attempt with a wrong key (which would fail due to GCM authentication failure) or a wrong version of the correct key (which would also fail due to different key material). The impact is denial-of-service (decryption fails) rather than confidentiality or integrity breach.

**Recommendation:** Explicitly include the full 80-byte header in the AES-GCM AAD to prevent header tampering. This binds the header to the ciphertext cryptographically, not just logically. Currently, the AES-GCM authentication tag only covers the plaintext and the encryption-context-derived AAD.

---

### 3.4 Random Number Generation

#### RNG source

```rust
use rand::rngs::OsRng;
```

`OsRng` delegates to the operating system's CSPRNG:
- **Linux**: `getrandom(2)` system call (seeded by kernel entropy pool)
- **macOS**: `SecRandomCopyBytes` (equivalent)
- **Windows**: `BCryptGenRandom`

This is the correct choice for a cryptographic application. `OsRng` is guaranteed to be cryptographically secure and properly seeded.

#### Nonce generation

All nonces are generated via `OsRng.fill_bytes(&mut nonce_bytes)`:
- AES-GCM: 12-byte random nonce
- No counter-based nonce generation
- No nonce derivation (e.g., HKDF-based)

**Counter-based vs random nonces for AES-GCM:**

| Approach | Pros | Cons |
|---|---|---|
| Random (current) | Stateless; no coordination needed; works in distributed systems | Birthday bound at 2^48 for collision; NIST limit at 2^32 per key |
| Counter-based | Deterministic; no birthday bound; supports 2^96 operations | Requires persistent state; coordination in distributed systems; state loss = nonce reuse |
| Derived (HKDF) | Deterministic from (key, message_id); no state | Requires unique message identifiers; adds a hash computation |

For a KMS that operates as a centralized service (or via PKCS#11 to a centralized HSM), a counter-based approach would be safer for high-throughput workloads. However, the random approach is simpler and adequate for the documented per-key encryption limits.

**Recommendation:** For the software provider (dev/test), random nonces are appropriate. For production via PKCS#11, nonce generation is delegated to the HSM. Document the 2^32 per-key limit explicitly and enforce it via rotation policy.

---

### 3.5 Post-Quantum Considerations

#### PQC-vulnerable algorithms in KeyRack

| Algorithm | PQC Vulnerability | Threat |
|---|---|---|
| AES-256-GCM | **Grover's algorithm** reduces effective security from 256-bit to 128-bit | 128-bit post-quantum security is sufficient; no migration needed |
| Ed25519 | **Shor's algorithm** breaks elliptic curve discrete log | Private key recovery from public key; signatures become forgeable |
| ECDSA P-256 | **Shor's algorithm** | Same as Ed25519 |
| RSA (all sizes) | **Shor's algorithm** breaks integer factoring | Private key recovery; all RSA key sizes are equally vulnerable |
| BLAKE3 | **Grover's algorithm** reduces collision resistance from 2^128 to 2^85 | Still computationally infeasible; no practical threat |
| SHA-256 | **Grover's algorithm** reduces collision resistance from 2^128 to 2^85 | Same as BLAKE3 |

**Summary:** AES-256 and hash functions are post-quantum safe at current key sizes. All asymmetric algorithms (Ed25519, ECDSA P-256, RSA) are vulnerable to Shor's algorithm on a cryptographically relevant quantum computer.

#### NIST PQC migration timeline

Per NIST IR 8547 (2024):
- **By 2030**: Deprecation of algorithms with ~112-bit classical security (RSA-2048, P-256 in some interpretations)
- **By 2035**: Complete removal of all quantum-vulnerable algorithms from NIST standards

NIST has published:
- **FIPS 203**: ML-KEM (key encapsulation, replaces RSA/ECDH for key establishment)
- **FIPS 204**: ML-DSA (digital signatures, replaces RSA-PSS/ECDSA)
- **FIPS 205**: SLH-DSA (hash-based signatures, alternative to ML-DSA)
- **FIPS 206**: FN-DSA (lattice-based signatures with smaller signatures)

#### Does KeyRack's architecture support PQC?

**Yes, with modifications.** The `CryptoProvider` trait is algorithm-agnostic:

```rust
pub trait CryptoProvider: Send + Sync {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle>;
    async fn sign(&self, handle: &KeyHandle, algorithm: SigningAlgorithm, message: &[u8]) -> Result<Vec<u8>>;
    // ...
}
```

Adding PQC requires:

1. **Extend `KeySpec`**: Add `MlKem768`, `MlDsa65`, `SlhDsa128s`, etc.
2. **Extend `SigningAlgorithm`**: Add `MlDsa65`, `SlhDsa128s`, etc.
3. **Add `EncapsulationAlgorithm`**: ML-KEM uses a KEM (Key Encapsulation Mechanism) paradigm, not direct encryption. The `CryptoProvider` trait would need an `encapsulate/decapsulate` method pair.
4. **Update ciphertext header**: The header version field (u16) allows versioning. A v2 header could accommodate PQC algorithm identifiers.
5. **Implement in providers**: The software provider needs `pqcrypto` or `ml-kem`/`ml-dsa` crates. PKCS#11 HSMs need firmware support (some HSMs already support ML-KEM/ML-DSA in 2026).

**Assessment:** The architecture is extensible for PQC. The main work is in the `KeySpec`/`SigningAlgorithm` enums and provider implementations. The LID derivation and ciphertext header format do not need changes (they use hash functions, which are PQC-safe).

**Recommendation:** Begin PQC integration in V2. Add ML-DSA as a signing algorithm and ML-KEM for key establishment. Support hybrid schemes (e.g., X25519+ML-KEM) for defense-in-depth during the transition period.

---

### 3.6 Security Model Concerns

#### 3.6.1 Key material zeroization

The `Sensitive<T>` wrapper (`sensitive.rs`) correctly zeroizes on drop:

```rust
impl<T: Zeroize> Drop for Sensitive<T> {
    fn drop(&mut self) {
        if let Some(ref mut v) = self.0 {
            v.zeroize();
        }
    }
}
```

The `KeyMaterial` enum in `software.rs` has explicit `Drop` implementation:

| Key Type | Zeroization | Assessment |
|---|---|---|
| `Aes256(Vec<u8>)` | ✅ `bytes.zeroize()` via `zeroize` crate | Correct; Vec<u8> implements Zeroize |
| `Ed25519(SigningKey)` | ⚠️ Best-effort: overwrites with zero key | `ed25519_dalek::SigningKey` doesn't implement `Zeroize`; the overwrite is correct for the 32-byte internal array but relies on compiler not optimizing it away |
| `EcdsaP256(P256SigningKey)` | ❌ "RustCrypto types don't expose a zeroize path" | Key material remains in memory until freed |
| `Rsa(Box<RsaPrivateKey>)` | ❌ Same as P-256 | RSA private key (multi-precision integers) remains in memory |

**Assessment:** The code comments honestly acknowledge this gap:

```rust
Self::EcdsaP256(_) | Self::Rsa(_) => {
    // RustCrypto types don't expose a zeroize path;
    // memory is freed on drop. HSM providers handle
    // this properly; software provider is dev/test only.
}
```

This is acceptable for the software provider's stated purpose (dev/test), but an auditor would flag it. The comment correctly points out that HSM providers (the production path) handle zeroization in hardware.

**Rust-specific concern:** Even for `Aes256` zeroization, the Rust compiler is not prevented from optimizing away the zeroization if it can prove the memory is never read after the write. The `zeroize` crate addresses this with `write_volatile` or compiler barriers, which is correct. However, `Vec<u8>` zeroization may not cover previously allocated-then-reallocated memory if the Vec was grown. The `zeroize` crate's Vec implementation handles the current allocation but not prior allocations (if the Vec was resized).

**Recommendation:** For a production-quality software provider (if one is ever used beyond dev/test):
1. Use `Zeroizing<Vec<u8>>` from the `zeroize` crate instead of manual zeroization.
2. Pre-allocate Vecs to their final size to avoid reallocation.
3. Consider `secrecy::Secret<T>` which wraps `Zeroize` types with additional protections.
4. Investigate using `mlock()` to prevent key material from being swapped to disk.

#### 3.6.2 Side-channel resistance

**Constant-time comparison:**

`SECURITY.md` documents: "Timing attacks — Mitigated by constant-time comparison for authentication tokens (`subtle` crate)."

The `subtle` crate is listed in `Cargo.toml` dependencies, confirming constant-time comparison is available. Per `SECURITY.md` invariant 10: "Constant-time authentication — Bootstrap token comparison uses `subtle::ConstantTimeEq` to prevent timing side-channel attacks."

**Assessment:** Constant-time comparison is correctly used for authentication token comparison. For cryptographic operations (encryption, signing, verification), the underlying crates handle constant-time internally:

- `aes-gcm`: Uses constant-time GCM implementation
- `ed25519-dalek`: Uses constant-time scalar multiplication
- `p256`: Uses constant-time field arithmetic
- `rsa`: The `rsa` crate's signature verification uses constant-time comparison for the final check

**Remaining concerns:**
1. **ECDSA nonce generation**: If the random `k` value in ECDSA signing is biased or leaked through timing, the private key can be recovered. The `p256` crate generates `k` using RFC 6979 deterministic generation internally (avoiding this issue).
2. **RSA key operations**: RSA private key operations (modular exponentiation with CRT) are notoriously difficult to make constant-time. The `rsa` crate uses blinding to mitigate timing side-channels.
3. **Hash computation**: BLAKE3 is not designed for constant-time operation (it uses data-dependent memory access patterns). This is fine for LID derivation (no secret input) but should be noted.

#### 3.6.3 Software provider in production

The software provider is explicitly documented as "Not for production HSM-grade security" (line 19 of `software.rs`). This is correct and well-communicated.

**When is the software provider acceptable?**
- Development and testing
- Single-node deployments without compliance requirements
- FOSS self-hosted deployments with a risk acceptance for in-memory key storage
- Edge/embedded deployments where HSM hardware is unavailable (with documented risk acceptance)

**When is it not acceptable?**
- Any FIPS-compliant deployment
- Any PCI-DSS scope
- Multi-tenant production deployments
- Environments processing regulated data (healthcare, finance)

The `KMS_PROVIDER_DENY` configuration (from `KEYRACK_SPEC.md` §6 invariant 11) correctly enforces this at the deployment level.

---

### 3.7 Defensibility Assessment Summary

| Choice | Standard/Expected in 2026? | Known Weaknesses | Auditor Flags |
|---|---|---|---|
| **AES-256-GCM** | ✅ Yes, industry standard | Random nonce birthday bound at 2^32 per key | Document nonce budget; consider AES-GCM-SIV for misuse resistance |
| **Ed25519** | ✅ Yes, modern standard | None known; PQC-vulnerable long-term | Add ML-DSA for PQC readiness |
| **ECDSA P-256** | ✅ Yes, FIPS standard | NIST curve constant controversy (theoretical, no exploit); PQC-vulnerable | Note curve controversy in security documentation |
| **RSA PKCS#1v1.5** | ⚠️ Legacy, not recommended for new systems | No security proof; Bleichenbacher-style attacks on implementations | **Add RSA-PSS**; flag PKCS#1v1.5 as legacy |
| **RSA-2048** | ⚠️ Borderline in 2026 | Only 112-bit security; NIST deprecation by 2030 | Warn on creation; recommend RSA-3072+ |
| **BLAKE3 (internal)** | ✅ Sound for non-FIPS | Not FIPS-approved | Add FIPS mode with SHA-256/SHA3-256 fallback |
| **SHA-256 (wire)** | ✅ Gold standard | None known | None |
| **OsRng** | ✅ Correct choice | OS-dependent; no FIPS DRBG validation | Document OS CSPRNG delegation |
| **Random nonces** | ✅ Standard approach | 2^32 per-key limit | Document and enforce via rotation |
| **Zeroization** | ⚠️ Incomplete | P-256 and RSA keys not zeroized in software provider | Fix for completeness; document HSM is production path |
| **No PQC** | ⚠️ Expected by 2028–2030 | All asymmetric algorithms PQC-vulnerable | Roadmap PQC integration |
| **No RSA-PSS** | ❌ Gap | PKCS#1v1.5 is legacy-only per RFC 8017 | Add PSS as primary RSA scheme |
| **Self-describing header** | ✅ Standard KMS pattern | Leaks key identity (traffic analysis) | Document as acceptable trade-off |

---

## Appendix A: Code References

| Component | File | Key Lines | Notes |
|---|---|---|---|
| Software crypto provider | `crates/keyrack-core/src/provider/software.rs` | All | AES-GCM, Ed25519, ECDSA, RSA implementations |
| CryptoProvider trait | `crates/keyrack-core/src/provider.rs` | 127–225 | Algorithm-agnostic async trait |
| Key specs and state machine | `crates/keyrack-core/src/key.rs` | 44–85 | KeyState, KeySpec, KeyUsage |
| LID derivation | `crates/keyrack-core/src/lid.rs` | 35–41 | BLAKE3 hash of versioned canonical form |
| Canonicalization | `crates/keyrack-core/src/canon.rs` | 83–142 | V1 TLV encoding with NFC normalization |
| Encryption context | `crates/keyrack-core/src/encryption_context.rs` | 78–91 | BLAKE3 hash of sorted key-value pairs |
| Ciphertext header | `crates/keyrack-core/src/header.rs` | 49–143 | 80-byte self-describing header |
| Sensitive wrapper | `crates/keyrack-core/src/sensitive.rs` | 32–61 | Zeroize-on-drop with redacted Debug/Display |
| Zeroization (incomplete) | `crates/keyrack-core/src/provider/software.rs` | 56–73 | KeyMaterial Drop impl; P-256/RSA not zeroized |
| Security model | `docs/SECURITY.md` | All | Threat model, invariants, algorithms |
| PDP integration | `docs/PDP_INTEGRATION_GUIDE.md` | 92–108 | Dual-hash strategy (BLAKE3/SHA-256) |
| Integration spec | `KEYRACK_SPEC.md` | All | V1 platform requirements |

---

## Appendix B: Recommendations Priority Matrix

### Critical (address before production deployment)

| # | Recommendation | Effort | Impact |
|---|---|---|---|
| C1 | Add RSA-PSS signing algorithm | Medium (add enum variant + provider impl) | Closes eIDAS gap; addresses RFC 8017 recommendation |
| C2 | Document AES-GCM nonce budget per key | Low (documentation) | Prevents operational security incidents |
| C3 | Fix or document zeroization gaps for P-256 and RSA in software provider | Low (documentation) or Medium (upstream contribution) | Addresses audit finding |

### High (address in V1 or early V2)

| # | Recommendation | Effort | Impact |
|---|---|---|---|
| H1 | Add FIPS build mode (`--features fips`) replacing BLAKE3 with SHA-256/SHA3-256 | High (LID migration) | Opens US federal market |
| H2 | Add `Compromised` key state | Medium | NIST SP 800-57 alignment |
| H3 | Emit RSA-2048 deprecation warning | Low | Forward-looking compliance |
| H4 | Add audit log signing for FOSS deployments | Medium | SOC 2 / HIPAA audit trail integrity |
| H5 | Explicitly authenticate full ciphertext header in AES-GCM AAD | Low–Medium | Defense-in-depth against header tampering |

### Medium (V2 roadmap)

| # | Recommendation | Effort | Impact |
|---|---|---|---|
| M1 | Add ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) signing algorithms | High | PQC readiness |
| M2 | Add ML-KEM (FIPS 203) for key encapsulation | High | PQC readiness |
| M3 | Add P-384 and P-521 ECDSA options | Medium | Broader compliance coverage |
| M4 | Add per-key encryption operation counter with rotation enforcement | Medium | Nonce budget enforcement |
| M5 | Consider AES-256-GCM-SIV as optional algorithm | Medium | Nonce-misuse resistance for high-throughput |
| M6 | Add FIPS self-tests (KAT at startup) | Medium | FIPS 140-3 Level 1 requirement |

### Low (nice-to-have)

| # | Recommendation | Effort | Impact |
|---|---|---|---|
| L1 | Key destruction certificate (signed audit event) | Low | GDPR audit evidence |
| L2 | HIPAA/SOC 2 deployment guide | Low | Customer enablement |
| L3 | Key archival state (verification-only) | Low | SP 800-57 completeness |
| L4 | DPIA template for GDPR | Low | Customer enablement |
| L5 | Add Ed448 signing option | Low | Completeness |
