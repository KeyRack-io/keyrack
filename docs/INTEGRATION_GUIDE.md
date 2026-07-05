# KeyRack Integration Guide

Integrating KeyRack into your production infrastructure.

---

## 1. Authentication (AuthN)

KeyRack does **not** bundle an identity provider. It integrates with your existing IdP
and validates credentials on every request. Pick the method that matches your environment.

### JWT / OIDC

Works with any OIDC-compliant IdP (Keycloak, Auth0, Okta, Azure AD, Google Identity Platform).

```yaml
authn:
  type: jwt
  jwks_url: https://idp.example.com/.well-known/jwks.json
  issuer: https://idp.example.com
  audience: keyrack-api
  claims_namespace: "https://keyrack.io/"
```

| Field | Purpose |
|---|---|
| `jwks_url` | Your IdP's JWKS endpoint for signature verification |
| `issuer` | Expected `iss` claim — validates token origin |
| `audience` | Extracted to principal attributes; enforcement happens in the PDP |
| `claims_namespace` | Prefix for custom claims mapped into principal attributes |

### mTLS

Identity is extracted from the client certificate:

1. **SPIFFE ID** (SAN URI `spiffe://...`) — preferred
2. **Subject CN** — fallback

Requires TLS configuration on the server:

```yaml
tls:
  server_cert: /path/to/server.crt
  server_key: /path/to/server.key
  ca_cert: /path/to/client-ca.crt
authn:
  type: mtls
```

### Chained Authenticators

Use `type: chain` to accept multiple credential types. First match wins.
If a credential is present but invalid, the chain **short-circuits with an error**
(it does not fall through to the next authenticator).

```yaml
authn:
  type: chain
  authenticators:
    - type: mtls
    - type: jwt
      jwks_url: https://idp.example.com/.well-known/jwks.json
      issuer: https://idp.example.com
    - type: bootstrap_token
      max_age_secs: 3600
```

### Forwarded Identity

For service-to-service calls where a trusted gateway has already authenticated the
caller (e.g., a Barbican shim in front of KeyRack):

```yaml
authn:
  type: chain
  authenticators:
    - type: mtls
    - type: forwarded_identity
```

The upstream service sets these headers:
- `x-keyrack-principal-id`
- `x-keyrack-project-id`
- `x-keyrack-domain-id`

Only trust this behind mTLS or a network perimeter you control.

### Bootstrap Token

For initial setup only. Time-bounded, single-use-class.

```yaml
authn:
  type: bootstrap_token
  max_age_secs: 900
```

Set the `KMS_BOOTSTRAP_TOKEN` environment variable. Remove or rotate it once
bootstrapping is complete.

### SAML

KeyRack does not directly support SAML. Use your IdP's SAML-to-OIDC bridge
(most enterprise IdPs support this) and configure JWT auth as shown above.

---

## 2. Authorization (AuthZ)

KeyRack delegates every authorization decision to an external Policy Decision Point
(PDP) using the **Cedar** policy language.

### PDP Configuration

```yaml
pdp:
  type: http
  url: http://cedar-pdp:8180/v1/is_authorized
```

For dev/test only:

```yaml
pdp:
  type: always_allow
```

### What the PDP Receives

| Field | Content |
|---|---|
| `principal` | id, type, attributes (populated from AuthN) |
| `action` | KMS operation — e.g., `kms:Encrypt`, `kms:CreateKey` |
| `resource` | id (LID), type, attributes |
| `context` | Request context (timestamp, source IP, etc.) |

### Example Cedar Policy

```cedar
permit(
  principal == User::"tenant-admin@example.com",
  action in [Action::"kms:CreateKey", Action::"kms:RotateKey"],
  resource
) when { resource.tenant == principal.tenant_id };
```

See [`PDP_ACTION_CROSSREF.md`](PDP_ACTION_CROSSREF.md) for the full action list and
[`CEDAR_STARTER_SCHEMA.md`](CEDAR_STARTER_SCHEMA.md) for a ready-to-use schema.

---

## 3. Audit

### Audit Sinks

```yaml
# stdout — dev only
audit: { type: stdout }

# File — single-node deployments
audit: { type: file, path: /var/log/keyrack/audit.jsonl }

# NATS — production, multi-consumer
audit: { type: nats, url: nats://nats:4222 }
```

### Signed Audit Events

Enable tamper-evident logging with Ed25519-signed, BLAKE3-chained events:

```yaml
sign_audit_events: true
audit_signing_key_path: /var/lib/keyrack/audit-signing-key
```

Without `audit_signing_key_path`, a fresh Ed25519 key is generated each startup
(the verifying key is logged at boot). With the path set, the same key persists
across restarts, enabling continuous hash-chain verification.

### Event Schema (v1)

```json
{
  "schema_version": 1,
  "event_id": "uuid",
  "timestamp": "iso8601",
  "action": "kms:Encrypt",
  "principal": { "id": "user@example.com", "type": "User" },
  "resource": { "id": "lid-hex", "type": "key" },
  "result": "success",
  "tenant": "tenant-123",
  "project": "project-456",
  "signature": "ed25519-hex",
  "previous_hash": "blake3-hex"
}
```

### Verifying the Audit Chain

1. Obtain the verifying key (logged at startup, or derive from stored public key).
2. For each event: clear the `signature` field, serialize to canonical JSON, verify the Ed25519 signature.
3. Verify chain continuity: `blake3(signature_hex_of_previous) == current.previous_hash`.

### NATS Subjects

| Subject pattern | Default prefix | Purpose |
|---|---|---|
| `{prefix}.{event_id}` | `kms.audit` | Audit events |
| `{prefix}.{lid}` | `kms.key.state-changed` | Key lifecycle state changes |

Configure both:

```yaml
nats_notify:
  url: nats://nats:4222
  audit_subject_prefix: kms.audit
  state_changed_subject_prefix: kms.key.state-changed
```

KeyRack publishes to core NATS. For durability, create JetStream streams and
consumers on the subscriber side.

---

## 4. Caching

```yaml
cache:
  max_capacity: 10000
  ttl_secs: 300
```

The cache TTL is a **security property** in HA/multi-node HYOK deployments: after
you disconnect an external HSM, cross-node cache-invalidation staleness means
other replicas may not learn of the disconnect for up to one TTL window. On the
local node, the crypto provider call fails immediately at the transport layer
(no grace period). Set the TTL based on your cross-replica lockout SLA — shorter
TTL means faster convergence at the cost of more backend lookups.

---

## 5. Production Checklist

- [ ] TLS enabled (`tls:` with server cert + CA for mTLS)
- [ ] AuthN configured (not `insecure` or `bootstrap_token` alone)
- [ ] PDP configured (not `always_allow`)
- [ ] Audit sink set to NATS or file (not stdout)
- [ ] `sign_audit_events: true` with `audit_signing_key_path` set
- [ ] Cache enabled with TTL matched to your lockout SLA
- [ ] NATS configured for lifecycle events (`nats_notify:`)
- [ ] `KMS_BOOTSTRAP_TOKEN` rotated or removed after initial setup
- [ ] Log level set appropriately (`RUST_LOG=keyrack_service=info`)
- [ ] Metrics endpoint exposed for Prometheus scraping
- [ ] Backup strategy for storage (SQLite/Postgres) and audit signing key

---

## 6. Cryptographic operation semantics (gRPC/REST clients)

This section pins down the wire-level details that an adapter author needs to
get byte-for-byte correct. They are part of the `keyrack.v1` proto contract.

### 6.1 Sign / Verify — message vs. digest

`SignRequest`/`VerifyRequest` carry a `message` field plus a `message_type`:

| `message_type` | Meaning |
|---|---|
| `RAW` (or unset) | `message` is the full message. **KeyRack hashes it server-side** with the algorithm's hash, then signs. |
| `DIGEST` | `message` is a **pre-computed digest**. KeyRack signs it as-is (no hashing). Its length must equal the algorithm's hash output (SHA-256→32, SHA-384→48, SHA-512→64 bytes). |

Use `DIGEST` for the standard KMS workflow where the (potentially large) message
is hashed by the caller and only the digest reaches the KMS — this matches AWS
KMS, GCP Cloud KMS, and Azure Key Vault.

`DIGEST` is **invalid for `ED25519_PURE`** (Ed25519 signs the full message by
construction); such a request is rejected with `INVALID_ARGUMENT`. For Ed25519,
always send the full message with `message_type = RAW`.

Migration note for adapters that previously sent a pre-hashed value in `message`
with the default (RAW) type: that produced a hash-of-a-hash. Set
`message_type = DIGEST`.

### 6.2 Encryption context (AAD)

`encryption_context` is a `map<string,string>`. **Pass the structured map; do not
pre-hash it.** KeyRack canonicalizes the map and uses it directly as AES-GCM AAD,
and stores a BLAKE3 hash of the same canonical form in the ciphertext header for
decrypt-time verification.

Canonical encoding (entries **sorted by key**, lexicographic byte order; all
lengths little-endian `u32`):

```text
for each (key, value) in sorted(context):
    u32_le(key.len()) || key_bytes || u32_le(value.len()) || value_bytes
```

- The concatenation above is the **AES-GCM AAD**.
- The **header hash** is `BLAKE3(AAD_bytes)`; an **empty** context hashes to the
  all-zero 32-byte sentinel (distinct from `BLAKE3("")`).
- Decrypt must supply the **same** context (same pairs); a mismatch fails with
  `EncryptionContextMismatch` (`INVALID_ARGUMENT`).

If your envelope layer historically hashed the context into a 32-byte AAD before
the backend call, drop that step and forward the map — KeyRack owns the binding.

### 6.3 MAC (HMAC)

`GenerateMac` / `VerifyMac` operate on `HMAC_256` keys (`KeyUsage =
GENERATE_VERIFY_MAC`). `mac_algorithm` selects `HMAC_SHA_256/384/512`. `VerifyMac`
compares in constant time and returns `mac_valid`.

### 6.4 Algorithm & key-spec coverage

| KeySpec | Usage | Algorithms |
|---|---|---|
| `AES_256`, `AES_128` | Encrypt/Decrypt | AES-GCM |
| `ED25519` | Sign/Verify | `ED25519_PURE` (RAW only) |
| `ECDSA_P256` | Sign/Verify | `ECDSA_P256_SHA256`, `ECDSA_P256_SHA384` |
| `ECC_NIST_P384` | Sign/Verify | `ECDSA_P384_SHA384` |
| `RSA_*` | Sign/Verify | `RSA_PKCS1_V15_SHA{256,384,512}` |
| `RSA_PSS_*` | Sign/Verify | `RSA_PSS_SHA{256,384,512}` |
| `HMAC_256` | MAC | `HMAC_SHA_{256,384,512}` |

Provider support varies (the software provider implements all of the above; the
PKCS#11/KMIP/Vault providers implement a subset). Query `ProviderCapabilities`
to discover what a given deployment supports.

### 6.5 `CreateKey` minimal form

`key_usage` and `namespace` are optional. With only `key_spec` set, KeyRack
derives usage from the spec (`AES_*`→ENCRYPT_DECRYPT, `HMAC_256`→GENERATE_VERIFY_MAC,
asymmetric→SIGN_VERIFY) and treats an empty namespace as "no namespace". A
provided `key_usage` that conflicts with the spec is rejected.

### 6.6 `KeyState` enum numbering (proto ≥ 0.2)

`KeyState` was renumbered to the conventional ordering
(`ENABLED = 1, DISABLED = 2, PENDING_DELETION = 3, DESTROYED = 4, CREATING = 5,
COMPROMISED = 6`). gRPC clients compiled against an earlier proto **must be
recompiled** against the current `key_service.proto` — the numeric values changed
on the wire. (Field names are unchanged, so JSON/REST clients keying off the
state string are unaffected.)
