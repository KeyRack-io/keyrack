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

The cache TTL is a **security property** in HYOK deployments: after you disconnect
an external HSM, cached key records remain usable for at most one TTL window.
Set the TTL based on your lockout SLA — shorter TTL means faster revocation at
the cost of more backend lookups.

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
