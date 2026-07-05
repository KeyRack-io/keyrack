# KeyRack Compliance Posture

**Last updated:** 2026-05-11

---

## What is KeyRack?

KeyRack is an attribute-based key management service (KMS) with a pluggable cryptographic provider architecture. It manages the full key lifecycle — generation, storage, rotation, access control, audit, and destruction — while delegating actual cryptographic operations to configurable backend providers.

KeyRack is open-source (AGPL-3.0-or-later; the Protocol Buffers definitions and client SDK are Apache-2.0) with commercial extensions for high availability, AWS KMS compatibility, management UI, and compliance tooling.

### Core components

| Component | Role |
|---|---|
| `keyrack-core` | Crypto traits, key state machine, LID derivation, ciphertext header, audit events, canonicalization, encryption context |
| `keyrack-service` | gRPC/REST API server, PDP integration, health checks, metrics |
| `keyrack-pkcs11` | PKCS#11 HSM provider (production) |
| `keyrack-kmip` | KMIP HSM provider (HYOK / multi-cloud) |
| `keyrack-cedar-pdp` | Cedar policy engine sidecar for authorization |
| `keyrack-nats` | NATS-based event distribution for audit and coordination |
| `keyrack-cli` | CLI tools for provisioning, admin, migration |
| `keyrack-sqlite` / `keyrack-postgres` | Metadata storage backends |

---

## Deployment model determines compliance scope

KeyRack's compliance posture is fundamentally determined by which cryptographic provider is deployed. The same KeyRack binary behaves differently depending on its backend:

### Software provider (development / testing)

- Key material lives in process memory (zeroized on drop)
- Uses RustCrypto crates (`aes-gcm`, `ed25519-dalek`, `p256`, `rsa`)
- No CMVP validation — **not FIPS-compliant**
- Suitable for development, CI/CD, single-node non-regulated deployments
- Explicitly documented as "not for production HSM-grade security"

### PKCS#11 provider (production / regulated)

- Key material lives in an HSM (Thales Luna, AWS CloudHSM, SoftHSM, etc.)
- Cryptographic boundary is the HSM's FIPS 140-3 certificate
- KeyRack acts as an orchestrator — raw key material stays in the HSM
- This is the path for FIPS, PCI-DSS, HIPAA, and SOC 2 deployments

### KMIP provider (HYOK / multi-cloud)

- Key material lives in a remote KMIP-compliant server
- Enables Hold Your Own Key (HYOK) deployments
- Compliance depends on the KMIP server's certifications
- Used for multi-cloud key management and sovereign cloud deployments

---

## Relevant frameworks

| Framework | Why it matters for KeyRack |
|---|---|
| **FIPS 140-3** | US federal mandate for cryptographic modules. Relevant for government and regulated-industry deployments. |
| **SOC 2 Type II** | Trust services audit for SaaS/service providers. Relevant for commercial KeyRack offerings. |
| **PCI-DSS v4.0** | Payment card industry standard. Relevant when KeyRack manages keys protecting cardholder data. |
| **HIPAA** | US healthcare regulation. Relevant when KeyRack encrypts ePHI. |
| **GDPR** | EU data protection. Relevant for crypto-shredding (right to erasure) and data protection by design. |
| **NIST SP 800-57** | Key management best practices. The baseline reference for any KMS design. |
| **eIDAS** | EU electronic signatures regulation. Relevant if KeyRack is used for qualified electronic signatures. |
| **Common Criteria** | IT product security evaluation. Relevant for government procurement and formal certification. |

---

## Compliance readiness summary

| Framework | Readiness | Deployment mode | Primary gaps | Effort to close |
|---|---|---|---|---|
| **FIPS 140-3** | Partial | PKCS#11 path only | BLAKE3 used internally (not FIPS-approved); RustCrypto not CMVP-validated; no power-up self-tests | High |
| **SOC 2 Type II** | Strong | Both | Policy documentation templates | Low |
| **PCI-DSS v4.0** | Partial | PKCS#11 path required | Split knowledge / dual control not surfaced in software; cryptoperiod enforcement | Medium |
| **HIPAA** | Strong | Both | — | Low |
| **GDPR** | Strong | Both | Key destruction certificate; DPIA template | Low |
| **NIST SP 800-57** | Mostly aligned | Both | No "Compromised" key state; RSA-2048 deprecation; no PQC algorithms | Medium |
| **eIDAS** | Significant gaps | PKCS#11 path required | RSA-PSS absent; no SAM integration; no QSCD certification; no PQC | High |
| **Common Criteria** | Not evaluated | PKCS#11 path required | Formal Security Target; EAL evaluation; zeroization completeness | Very High |

---

## How the modular architecture affects compliance

KeyRack's pluggable architecture means compliance assessments apply differently to different components:

### Components that are always in scope

- **`keyrack-core`**: Defines key states, LID derivation (uses BLAKE3), ciphertext header format, encryption context hashing. Any FIPS assessment must evaluate this module because BLAKE3 appears here.
- **`keyrack-service`**: The API surface, PDP integration, and audit event emission. SOC 2, HIPAA, and PCI-DSS auditors will evaluate access controls and logging here.
- **`keyrack-cedar-pdp`**: Authorization decisions. Every framework that requires access control relies on this component.

### Components that shift the compliance boundary

- **`keyrack-pkcs11` / `keyrack-kmip`**: When deployed, these move the cryptographic boundary to the HSM. FIPS compliance depends on the HSM's certificate, not KeyRack's software.
- **Software provider**: When deployed, the entire cryptographic implementation is in-scope for compliance. This path cannot achieve FIPS compliance.

### Components that are operational concerns

- **`keyrack-sqlite` / `keyrack-postgres`**: Storage backends hold metadata, not key material. Data residency and backup controls are operational.
- **`keyrack-nats`**: Audit distribution. Tamper-evidence of the audit trail is an operational concern.
- **`keyrack-cli`**: Administrative tooling. Relevant for key custodian workflows (PCI-DSS) and provisioning procedures.

### The BLAKE3 boundary

BLAKE3 is used in `keyrack-core` for two purposes:

1. **LID derivation** — content-addressable key identifiers
2. **Encryption context hashing** — AAD binding in the ciphertext header

BLAKE3 is *not* FIPS-approved. This means even PKCS#11 deployments cannot claim full FIPS compliance for the end-to-end system — the orchestration layer uses a non-approved hash function. However, BLAKE3 is not used for encryption, signing, or key material derivation. The security properties of the system do not depend on BLAKE3's FIPS status.

A `--features fips` build flag that replaces BLAKE3 with SHA-256 or SHA3-256 is on the roadmap. This would require a LID migration (documented alias-based migration path exists).

---

## FOSS vs Commercial compliance split

| Capability | FOSS | Commercial |
|---|---|---|
| Core key lifecycle (create, rotate, disable, destroy) | Yes | Yes |
| PDP authorization (fail-closed) | Yes | Yes |
| Audit event emission (NATS) | Yes | Yes |
| PKCS#11 / KMIP HSM integration | Yes | Yes |
| Cryptographic operations (AES-256-GCM, Ed25519, ECDSA, RSA) | Yes | Yes |
| Crypto-shredding (GDPR Art. 17) | Yes | Yes |
| High availability / clustering | No | `commercial:keyrack-ha` |
| AWS KMS compatibility shim | No | `commercial:keyrack-aws-kms-shim` |
| Management UI | No | `commercial:keyrack-ui` |
| Compliance templates and reporting | No | `commercial:compliance` |
| Signed audit trail (tamper-evidence) | Yes (Ed25519 hash-chain, ephemeral or persistent key) | Yes (commercial receipt chain) |

### What this means for compliance

- **SOC 2 / HIPAA**: FOSS provides the technical controls including Ed25519 signed audit trails with hash-chaining. Commercial adds compliance documentation templates and the commercial receipt chain. An FOSS deployment can pass a SOC 2 audit with `sign_audit_events: true` and a persistent signing key.
- **PCI-DSS**: FOSS provides key lifecycle and HSM integration. Commercial adds compliance templates and potentially the HA deployment required for availability. Split knowledge / dual control is an HSM operational concern regardless.
- **FIPS 140-3**: Same story for both — depends on the HSM certificate. The BLAKE3 internal usage affects both.
- **GDPR**: FOSS crypto-shredding is the strongest feature. Commercial adds a key destruction certificate and DPIA template.
- **eIDAS / Common Criteria**: Exclusively commercial concerns due to formal certification requirements.

---

## Detailed control mappings

Per-framework control mappings are available as CSV files in `docs/compliance/controls/`:

- `fips-140-3.csv` — FIPS 140-3 cryptographic module requirements
- `soc2-type2.csv` — SOC 2 Trust Services Criteria
- `pci-dss-v4.csv` — PCI-DSS v4.0 key management controls
- `hipaa.csv` — HIPAA Security Rule technical safeguards
- `gdpr.csv` — GDPR Articles 17, 25, and 32
- `nist-sp-800-57.csv` — NIST SP 800-57 key management lifecycle

---

## Cryptographic security model

For a detailed analysis of KeyRack's cryptographic design decisions, security boundaries, and threat model, see `docs/compliance/CRYPTO_SECURITY_MODEL.md`.
