# Why KeyRack

KeyRack is an open-source key management service (KMS) that runs in your infrastructure, on your terms.

This document explains the problems KeyRack solves and why it exists.

---

## The Problem with Cloud KMS

Every major cloud provider ships a KMS: AWS KMS, Azure Key Vault, GCP Cloud KMS. They work well — until they don't. The following concerns motivate KeyRack.

### 1. Vendor lock-in

Cloud KMS ties your encryption keys to the provider's platform. Keys generated in AWS KMS cannot be exported to Azure Key Vault. Migrating means re-encrypting every piece of data — every volume, every object, every backup — with new keys on the new platform. For organizations with petabytes of encrypted data, this is a multi-month project that often becomes the single biggest blocker to cloud migration.

### 2. No real key custody

Cloud providers manage the HSMs. You can configure policies, but you cannot hold your own key material. "Customer-managed keys" in cloud KMS still means the provider's HSM, the provider's firmware, the provider's physical security. You delegate trust to the provider for the most sensitive asset in your infrastructure.

For regulated industries under DORA, NIS2, or national sovereignty requirements, delegation is not always acceptable.

### 3. No instant revocation

When a tenant needs to cut off platform access to their data — during an incident, a contract termination, or a compliance event — there is no guaranteed mechanism for immediate key revocation. Keys may be cached in memory, replicated across regions, or subject to eventual-consistency delays. The gap between "revoke" and "actually unusable" is undefined and provider-controlled.

### 4. API fragmentation

Each cloud KMS has its own API. Applications written for AWS KMS cannot use Azure Key Vault without code changes. There is no portable KMS interface. Multi-cloud architectures end up with per-provider encryption code, per-provider key management, and per-provider audit trails.

---

## KeyRack's Answer

### Data-plane KMS you deploy yourself

KeyRack is a KMS that runs in your infrastructure. You deploy it. You control it. It handles key lifecycle management (creation, rotation, disable, destruction) and cryptographic operations (encrypt, decrypt, sign, verify) without giving a third party access to your keys.

KeyRack is not a hosted service — it is software you operate. The security boundary is yours to define.

### Pluggable crypto providers

KeyRack separates key management logic from cryptographic operations through a provider abstraction. Supported backends:

- **PKCS#11** — SoftHSM is a supported production software token. Storage
  permissions and its PIN protect keys; there is no hardware boundary. Hardware
  HSMs over PKCS#11 are not yet qualified; the interface is not a vendor-support
  or FIPS certification claim.
- **KMIP** — remote key servers and HSMs speaking the OASIS standard
- **Software** — in-process RustCrypto implementation for development and testing

Switch providers without changing application code. Your key hierarchy, policies, and audit trail remain intact.

### Hold Your Own Key (HYOK)

Tenants provision their own supported crypto backend. KeyRack tracks logical
parent-child relationships on top. Wrapped-child creation is not reachable
through the service API in 0.5.0, so these relationships do not establish a
root → KEK → DEK wrapping chain. The backend relationship operates in one of two modes:

- **Custody / managed mode** — the database or application uses server-side Encrypt/Decrypt via KMIP; key material never leaves the HSM or Vault (e.g. MongoDB KMIP default). KeyRack holds only opaque handles.
- **Sovereign / keystore mode** — for appliances that pull raw keys (MySQL/Percona, vSphere), KeyRack serves an exportable key. Material intentionally leaves the backend, so the value proposition is governance (hierarchy, policy, audit, per-key exportability), not "keys never leave."

Disconnect the HSM and crypto operations against that backend fail immediately. The FOSS cache stores lifecycle metadata, not key material — disable propagates on the node without delay. Cross-node cache staleness in the commercial HA tier is bounded by a configurable TTL.

Three deployment patterns:

- **Operator-managed HSM** — central hardware HSM under platform operator control
- **Tenant-managed HYOK (custody)** — tenant controls the HSM; crypto stays server-side; disconnect is an immediate kill switch
- **Tenant-managed HYOK (sovereign)** — tenant controls an exportable-key backend for appliances that require raw key access

### Cryptographic audit trail

Every KeyRack operation emits an audit event containing:

- Ed25519 signature over the event payload (opt-in; enabling it requires a persistent `audit_signing_key_path`, or an explicit `audit_signing_key_ephemeral: true` for throwaway development keys)
- BLAKE3 hash-chain linking each event to its predecessor
- Full operation metadata (principal, action, key ID, timestamp)

The chain provides interior tamper-evidence: an in-place modification or interior deletion of events is detectable by replaying the hash chain, with no key. There are two bounds on that. Repairing the chain after an edit only means recomputing every link from that point forward, so an attacker able to rewrite the whole log defeats the keyless check — that is the gap Ed25519 signing closes, and why an audit-grade deployment enables it. And tail-truncation (dropping the latest N events) is not detectable without an external anchor such as a signed checkpoint or independent witness; signing does not address that one either. Events are delivered via NATS for real-time consumption.

### Lockout behavior

When a tenant disconnects their HSM or an operator disables a root key:

1. On the local node, the key state change propagates immediately — the FOSS cache stores lifecycle metadata, not key material, so disable is instant.
2. HSM disconnect is immediately fatal: every crypto operation calls the provider unconditionally; a disconnected KMIP/PKCS#11 backend fails at the transport layer.
3. In the commercial HA tier, cross-node cache-invalidation staleness is bounded by a configurable TTL — this is the upper bound on "time until lockout" across replicas.

### AWS KMS API compatibility (outside this repository)

Core 0.5.0 does not ship an AWS KMS compatibility shim. Its in-tree
`keyrack-aws-proxy` forwards requests to real AWS KMS and tracks metadata;
it does not translate them to native KeyRack operations or remove the AWS
dependency. Applications using Core directly use its gRPC or REST API.

### OpenStack Barbican compatibility (outside this repository)

Core 0.5.0 does not expose the Barbican REST API or ship a Barbican shim.
Connecting unmodified Cinder or Nova requires a separate compatibility
implementation; pointing them at the Core service is not sufficient.

---

## Architecture in Brief

```
┌──────────────────────────────────────────────────────────────┐
│                        Clients                               │
│   (native gRPC / REST clients)                                │
└──────────────┬───────────────────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────────────┐
│                     keyrack-service                          │
│  Key lifecycle · Crypto operations · Key hierarchy           │
│  Ciphertext headers · Encryption context (AAD)               │
├──────────────┬──────────────────┬────────────────────────────┤
│   PDP (Cedar)│   Crypto Provider│   Event Bus (NATS)         │
│   AuthZ on   │   PKCS#11, KMIP, │   Audit events, cache      │
│   every op   │   or Software    │   invalidation, rotation   │
└──────────────┘──────────────────┘────────────────────────────┘
```

### Components

| Component | Role | License |
|-----------|------|---------|
| **keyrack-oss** | Core KMS: key lifecycle, crypto operations, gRPC + REST APIs, pluggable providers, Cedar authorization, NATS eventing | AGPL-3.0-or-later (proto + client SDK: Apache-2.0) |
| Separate extensions (not shipped here) | AWS KMS and Barbican compatibility, HA clustering and operational tooling are outside the Core 0.5.0 release | Separate licensing |

### Logical key hierarchy

The service records ancestry and enforces lifecycle checks along it. The
following is a logical layout, not a shipped wrapping chain; wrapped children
are not reachable through the API.

```
Selected provider
  └── Tenant Root Key
        └── Tenant KEK (logical parent: root)
              └── Application KEK (logical parent: tenant KEK)
                    ├── DEK (volume encryption)
                    ├── DEK (object encryption)
                    ├── DEK (backup encryption)
                    └── Signing Key (image manifests)
```

Disabling an ancestor makes descendants unusable through service lifecycle
checks. Logical ancestry alone does not cryptographically destroy independently
stored descendant material, and is not evidence of crypto-shredding or
regulatory compliance.

### Authentication

JWT/OIDC, mTLS, and chained authenticators. Integrate with your existing identity provider. No proprietary identity system required.

### Authorization

External Cedar Policy Decision Point (PDP) for fine-grained, policy-as-code access control. Fail-closed: if the PDP is unreachable, all operations are denied. The PDP never sees key material — it evaluates access based on principal identity, action, and key attributes.

### Cryptography

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Symmetric encryption | AES-256-GCM | FIPS 197, NIST SP 800-38D |
| Signing | Ed25519, ECDSA P-256, RSA PKCS#1v1.5 | FIPS 186-5, RFC 8032 |
| Internal hashing | BLAKE3 | — |
| Wire-boundary hashing | SHA-256 | FIPS 180-4 |

---

## Who Should Use KeyRack

**Regulated industries** — Organizations under DORA, NIS2, HIPAA, PCI-DSS, or national data sovereignty requirements that need demonstrable key custody. KeyRack with a certified HSM provides the technical controls; the pluggable architecture keeps the compliance boundary clean.

**Multi-cloud platforms** — Teams running workloads across AWS, Azure, GCP, or private cloud that want a single KMS interface, a single key hierarchy, and a single audit trail instead of per-provider encryption silos.

**SaaS providers** — Platforms offering enterprise customers the ability to hold their own encryption keys. KeyRack's HYOK model lets each tenant bring their own HSM while the platform manages the key hierarchy on top.

**OpenStack operators** — Core supplies lifecycle and authorization primitives,
but integration with existing OpenStack services requires a separate Barbican
compatibility shim, not included in this release.

---

## Comparison

| Feature | Cloud KMS | KeyRack |
|---------|-----------|---------|
| Key sovereignty | Provider-controlled HSM | Customer-controlled supported backend |
| HSM choice | Provider's hardware only | SoftHSM supported; hardware PKCS#11 HSMs not yet qualified |
| Instant revocation | No guarantee; provider-dependent | Immediate on the local node; cross-node staleness bounded by configurable TTL (commercial HA) |
| Multi-cloud portable | No (proprietary APIs) | Yes (single KMS across all environments) |
| HYOK | Limited (CloudHSM-only in AWS) | Full: tenant-managed HSM with unilateral revocation |
| API compatibility | Proprietary per provider | Native gRPC/REST; AWS KMS and Barbican shims not shipped here |
| Authorization model | IAM policies (provider-specific) | Cedar policy-as-code (portable, auditable) |
| Lifecycle enforcement | Provider-specific | Logical hierarchy with cascade-disable; not proof of cryptographic child destruction |
| Open source | No | Core is AGPL-3.0-or-later (OSI/FSF-approved) |

---

## Getting Started

KeyRack's core is open source under AGPL-3.0-or-later (the Protocol Buffers
definitions and the client SDK are Apache-2.0). Commercial licensing is
available for embedding without AGPL reciprocity.

- **Repository:** [keyrack-oss](https://github.com/KeyRack-io/keyrack)
- **Security model:** [`docs/compliance/CRYPTO_SECURITY_MODEL.md`](compliance/CRYPTO_SECURITY_MODEL.md)
- **Compliance posture:** [`docs/compliance/COMPLIANCE_POSTURE.md`](compliance/COMPLIANCE_POSTURE.md)

For commercial extensions (AWS KMS shim, Barbican shim, HA, management UI), contact the KeyRack team.
