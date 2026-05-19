# Why KeyRack

KeyRack is an open-source key management service (KMS) that runs in your infrastructure, on your terms.

This document explains the problems KeyRack solves and why it exists.

---

## The Problem with Cloud KMS

Every major cloud provider ships a KMS: AWS KMS, Azure Key Vault, GCP Cloud KMS. They work well — until they don't. Five structural problems affect all of them.

### 1. Vendor lock-in

Cloud KMS ties your encryption keys to the provider's platform. Keys generated in AWS KMS cannot be exported to Azure Key Vault. Migrating means re-encrypting every piece of data — every volume, every object, every backup — with new keys on the new platform. For organizations with petabytes of encrypted data, this is a multi-month project that often becomes the single biggest blocker to cloud migration.

### 2. No real key custody

Cloud providers manage the HSMs. You can configure policies, but you cannot hold your own key material. "Customer-managed keys" in cloud KMS still means the provider's HSM, the provider's firmware, the provider's physical security. You delegate trust to the provider for the most sensitive asset in your infrastructure.

For regulated industries under DORA, NIS2, or national sovereignty requirements, delegation is not always acceptable.

### 3. No audit verifiability

Cloud KMS providers generate audit logs. You receive them. But you cannot independently verify their completeness or integrity. There is no cryptographic proof that the log you received is the same log the provider recorded, or that no entries were omitted. You trust the provider's logging pipeline end-to-end.

### 4. No instant revocation

When a tenant needs to cut off platform access to their data — during an incident, a contract termination, or a compliance event — there is no guaranteed mechanism for immediate key revocation. Keys may be cached in memory, replicated across regions, or subject to eventual-consistency delays. The gap between "revoke" and "actually unusable" is undefined and provider-controlled.

### 5. API fragmentation

Each cloud KMS has its own API. Applications written for AWS KMS cannot use Azure Key Vault without code changes. There is no portable KMS interface. Multi-cloud architectures end up with per-provider encryption code, per-provider key management, and per-provider audit trails.

---

## KeyRack's Answer

### Data-plane KMS you deploy yourself

KeyRack is a KMS that runs in your infrastructure. You deploy it. You control it. It handles key lifecycle management (creation, rotation, disable, destruction) and cryptographic operations (encrypt, decrypt, sign, verify) without giving a third party access to your keys.

KeyRack is not a hosted service — it is software you operate. The security boundary is yours to define.

### Pluggable crypto providers

KeyRack separates key management logic from cryptographic operations through a provider abstraction. Supported backends:

- **PKCS#11** — any FIPS 140-3 certified HSM (Thales Luna, Entrust nShield, YubiHSM, AWS CloudHSM, SoftHSM for development)
- **KMIP** — remote key servers and HSMs speaking the OASIS standard
- **Software** — in-process RustCrypto implementation for development and testing

Switch providers without changing application code. Your key hierarchy, policies, and audit trail remain intact.

### Hold Your Own Key (HYOK)

Tenants provision their own HSM or KMIP-compatible crypto backend. KeyRack manages the key hierarchy on top — tenant root key, KEKs, DEKs — but the root key never leaves the tenant's HSM. KeyRack holds only opaque handles.

Disconnect the HSM and all derived keys become immediately unusable, bounded by a configurable cache TTL. This is a cryptographic kill switch, not an administrative one.

Two deployment modes are first-class:

- **Operator-managed HSM** — central hardware HSM under platform operator control
- **Tenant-managed HYOK** — tenant controls the HSM and can revoke cloud access unilaterally by updating their KMIP policy

### Cryptographic audit trail

Every KeyRack operation emits an audit event containing:

- Ed25519 signature over the event payload
- BLAKE3 hash-chain linking each event to its predecessor
- Full operation metadata (principal, action, key ID, timestamp)

The audit trail is independently verifiable. Any party with the public key can validate the chain without trusting the KMS operator. Events are delivered via NATS for real-time consumption.

### Bounded lockout guarantee

KeyRack's cache TTL is a security property, not just a performance knob. When a tenant disconnects their HSM or an operator disables a root key:

1. The key state change propagates immediately.
2. Any cached key material expires within the configured TTL window.
3. After TTL expiry, no cryptographic operation can succeed against the affected key hierarchy.

The TTL is configurable and documented. The upper bound on "time until lockout" is a contract, not a best-effort estimate.

### AWS KMS API compatibility (commercial)

Existing applications using the AWS SDK (`aws-sdk`, `boto3`, `aws-sdk-go`) can point to KeyRack by changing a single endpoint URL. The AWS KMS compatibility shim translates JSON-RPC requests to native KeyRack gRPC calls. SigV4 authentication is handled transparently.

No SDK modifications. No code changes. Supported V1 operations include `CreateKey`, `Encrypt`, `Decrypt`, `GenerateDataKey`, `Sign`, `Verify`, `RotateKey`, and the full key lifecycle surface.

### OpenStack Barbican compatibility (commercial)

KeyRack's Barbican shim is a drop-in replacement for OpenStack Barbican's key management API. Unmodified Cinder and Nova talk to KeyRack as if it were Barbican:

```ini
# cinder.conf
[key_manager]
backend = barbican
barbican_endpoint = http://keyrack:9311
```

Unlike Barbican, KeyRack provides actual HYOK semantics, a proper key hierarchy, and PDP-based authorization on every operation — including the Barbican path. No OpenStack code is modified.

---

## Architecture in Brief

```
┌──────────────────────────────────────────────────────────────┐
│                        Clients                               │
│   (gRPC / REST / AWS SDK / OpenStack Barbican)               │
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
| **keyrack-oss** | Core KMS: key lifecycle, crypto operations, gRPC + REST APIs, pluggable providers, Cedar authorization, NATS eventing | MIT / Apache-2.0 |
| **keyrack-commercial** | AWS KMS shim, Barbican shim, HA clustering, key pooling, vendor HSM adapters, management UI | BUSL-1.1 |

### Key hierarchy

```
Tenant HSM (HYOK) or Operator HSM
  └── Tenant Root Key (never leaves HSM)
        └── Tenant KEK (wrapped by root)
              └── Application KEK (wrapped by tenant KEK)
                    ├── DEK (volume encryption)
                    ├── DEK (object encryption)
                    ├── DEK (backup encryption)
                    └── Signing Key (image manifests)
```

Disabling any key in the chain cascades downward. Destroying a key permanently renders all descendants inoperable — this is the mechanism behind crypto-shredding for GDPR Article 17 compliance.

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

FIPS 140-3 compliance is achieved through the HSM provider path. The HSM's certificate defines the cryptographic boundary; KeyRack acts as an orchestrator.

---

## Who Should Use KeyRack

**Regulated industries** — Organizations under DORA, NIS2, HIPAA, PCI-DSS, or national data sovereignty requirements that need demonstrable key custody. KeyRack with a certified HSM provides the technical controls; the pluggable architecture keeps the compliance boundary clean.

**Multi-cloud platforms** — Teams running workloads across AWS, Azure, GCP, or private cloud that want a single KMS interface, a single key hierarchy, and a single audit trail instead of per-provider encryption silos.

**SaaS providers** — Platforms offering enterprise customers the ability to hold their own encryption keys. KeyRack's HYOK model lets each tenant bring their own HSM while the platform manages the key hierarchy on top.

**OpenStack operators** — Deployments that need real tenant key isolation, not Barbican's flat key-per-volume model. KeyRack provides a proper key hierarchy with cascade-disable, HYOK support, and PDP-based authorization — while remaining a transparent Barbican replacement for existing OpenStack services.

---

## Comparison

| Feature | Cloud KMS | KeyRack |
|---------|-----------|---------|
| Key sovereignty | Provider-controlled HSM | Customer-controlled (any PKCS#11/KMIP device) |
| HSM choice | Provider's hardware only | Bring any certified HSM |
| Audit verifiability | Provider-generated logs | Ed25519-signed hash chain, independently verifiable |
| Instant revocation | No guarantee; provider-dependent | Bounded by configurable cache TTL |
| Multi-cloud portable | No (proprietary APIs) | Yes (single KMS across all environments) |
| HYOK | Limited (CloudHSM-only in AWS) | Full: tenant-managed HSM with unilateral revocation |
| API compatibility | Proprietary per provider | Native gRPC/REST + AWS KMS shim + Barbican shim |
| Authorization model | IAM policies (provider-specific) | Cedar policy-as-code (portable, auditable) |
| Crypto-shredding | Manual, no cascade guarantee | Key hierarchy with cascade-disable and cascade-destroy |
| Open source | No | Core is MIT/Apache-2.0 |

---

## Getting Started

KeyRack's core is open source under MIT/Apache-2.0.

- **Repository:** [keyrack-oss](https://github.com/Keyrack-io/keyrack)
- **Security model:** [`docs/compliance/CRYPTO_SECURITY_MODEL.md`](compliance/CRYPTO_SECURITY_MODEL.md)
- **Compliance posture:** [`docs/compliance/COMPLIANCE_POSTURE.md`](compliance/COMPLIANCE_POSTURE.md)

For commercial extensions (AWS KMS shim, Barbican shim, HA, management UI), contact the KeyRack team.
