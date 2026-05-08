# Use Case: Crypto Agility and Post-Quantum Readiness

## Who

Any organization that needs to prepare for algorithm migration —
whether driven by compliance mandates (NIST PQC timeline), security
incidents (algorithm compromise), or regulatory requirements (FIPS
transitions).

## The problem

Most systems today have crypto assumptions baked deep into the code:

- AES key sizes are hardcoded
- RSA is assumed everywhere
- Key material is scattered across services with no central inventory
- There's no way to answer "what algorithm does this data use?" without
  reading code
- Migrating to a new algorithm means touching every service

The NIST post-quantum cryptography timeline means organizations need
to migrate from RSA/ECDSA to PQC algorithms within the next 5-10
years. Most have no plan for this.

## How KeyRack helps

### 1. Algorithm abstraction

KeyRack's `key_spec` model abstracts the algorithm:

```json
{"key_spec": "AES_256", "description": "user-data-dek"}
```

When a new algorithm is available (e.g., `ML-KEM_768`), you:
1. Create new keys with the new spec
2. Use KeyRack's rotation protocol to re-wrap existing data
3. Old keys remain for decrypt of existing ciphertext

Application code doesn't change — it calls `encrypt`/`decrypt` and
KeyRack handles which algorithm to use.

### 2. Centralized key inventory

KeyRack tracks every key, its algorithm, creation date, rotation
status, and dependencies. You can answer:

- "How many RSA-2048 keys do we have in production?"
- "Which services depend on this key?"
- "What happens if we disable this key?"

### 3. Key dependency graph

```
GET /v1/keys/{id}/dependents/recursive
```

Returns the full tree of keys and resources that depend on a given
key. Essential for planning algorithm migration — you need to know
what breaks if you rotate a root key.

### 4. Cooperative rotation protocol

KeyRack doesn't just rotate keys — it tracks whether every dependent
service has re-wrapped its data:

```
pending → acknowledged → completed | failed | expired
```

This gives you a dashboard of migration progress: "12 of 15 services
have completed re-wrapping under the new algorithm."

### 5. Provider abstraction

The same key hierarchy can span multiple providers:

- Software provider for dev/test
- SoftHSM for staging
- Hardware HSM (PKCS#11 / KMIP) for production
- Future PQC provider when hardware supports it

## Fit rating

**Good conceptually. The framework is right; PQC algorithms aren't
implemented yet.**

KeyRack's architecture is designed for crypto agility — the provider
trait, key spec enum, and rotation protocol all support algorithm
migration. However, no PQC algorithms are implemented today. When
`ml-kem` and `ml-dsa` Rust crates stabilize, adding them as a new
`KeySpec` variant and provider implementation is straightforward.

## What's ready today

- Algorithm-agnostic key model
- Key dependency tracking
- Cooperative rotation protocol
- Provider abstraction (swap algorithms without code changes)
- Key inventory and audit trail
- AES-256, Ed25519, ECDSA P-256, RSA 2048/3072/4096

## What's needed for PQC

| Item | Effort | Impact |
|---|---|---|
| ML-KEM-768 key spec + software provider | 1-2 weeks | High — first PQC support |
| ML-DSA-65 key spec + software provider | 1-2 weeks | High |
| Hybrid mode (classical + PQC) | 2-3 weeks | Very high — transition period |
| PQC migration guide | 1 week | High — thought leadership |
| PKCS#11 PQC support (when HSMs ship it) | Depends on HSM vendor | Critical for production |

## Strategic note

Crypto agility is a compliance-driven purchase decision. Organizations
that need to demonstrate PQC readiness to auditors or regulators will
look for a KMS that supports algorithm migration. KeyRack's architecture
is already right for this — the main work is implementing the algorithms
when the Rust ecosystem is ready and writing a credible migration guide.

This is a medium-term differentiator (12-24 months) but worth
positioning for now.
