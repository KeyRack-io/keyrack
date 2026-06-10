# Use Case: Brownfield Migration (Existing Services)

## Who

Teams with existing services that already use AWS KMS, GCP KMS, Azure
Key Vault, or HashiCorp Vault for key management and want to:

- Reduce cloud vendor lock-in
- Add crypto agility (algorithm migration path)
- Get centralized key rotation tracking across providers
- Run on-prem or hybrid without rewriting application code
- Prepare for post-quantum cryptography migration

## The problem

Migrating away from a cloud KMS is painful:

- Application code is tightly coupled to the provider SDK
- Key material can't be exported from cloud KMS
- Re-encrypting all data at rest is a massive operation
- The migration must be gradual — not big-bang

## How KeyRack enables brownfield migration

### Phase 1: Drop-in shim (zero code changes)

The AWS KMS compatibility shim accepts standard AWS SDK requests and
forwards them to KeyRack:

```yaml
# Before: point at AWS
AWS_ENDPOINT_URL: https://kms.us-east-1.amazonaws.com

# After: point at KeyRack's AWS KMS shim
AWS_ENDPOINT_URL: http://keyrack-aws-shim:8080
```

That's it. No code changes. The application still uses `aws-sdk`,
`boto3`, `aws-sdk-go-v2`, or any other AWS SDK. It now talks to
KeyRack.

**What you get immediately:**

- Centralized audit log of all KMS operations
- Key rotation tracking (which keys were rotated, when, by whom)
- Dependency graph (which service uses which key)
- PDP authorization (who can use which key)
- The ability to run fully on-prem

**What you don't lose:**

- Application code remains unchanged
- Existing AWS SDK patterns (aliases, encryption context, tags) work
- SigV4 authentication is handled by the shim

### Phase 2: Hybrid mode

Run KeyRack alongside the cloud KMS during migration:

```
App → AWS KMS shim → KeyRack (new keys)
App → AWS KMS (existing keys, read-only)
```

New keys are created in KeyRack. Existing keys are gradually migrated
using `ReEncrypt` as data is naturally accessed or during maintenance
windows.

### Phase 3: Full migration

Once all active data is re-encrypted under KeyRack-managed keys, remove
the cloud KMS dependency entirely.

### For OpenStack / Barbican users

Same pattern via the Barbican shim:

```ini
# cinder.conf
[key_manager]
backend = barbican
barbican_endpoint = http://keyrack-barbican-shim:9311
```

Cinder, Nova, and Manila talk to what they think is Barbican. No
OpenStack code is modified.

## Backend / provider migration (BYOK ↔ HYOK)

The shim phases above move your *callers*. A separate axis moves where a key's
*material* lives — e.g. from a KeyRack-managed software/Vault backend (BYOK) to
a customer-owned HSM (HYOK), or between HSM partitions. KeyRack treats logical
key identity (LID) as independent of the physical backend, so a key can change
providers without its `key_id` — or the header-pinned references in existing
ciphertext — changing.

What ships today (see [OPERATOR.md → Multiple providers and routing](../OPERATOR.md)):

- **Multiple named providers + routing rules.** One service fronts many
  backends; new keys are routed to a provider by their identity tags
  (e.g. `tenant`), with a fail-closed `keyrack.provider` assertion for callers
  that want to pin a target. Runnable reference:
  [`demos/06-provider-routing`](../../demos/06-provider-routing/) routes across
  two SoftHSM tokens.
- **Per-version provider binding.** Each key *version* records its backend, so a
  single logical key can straddle two providers (old versions on A, new on B) —
  the foundation for re-key-style migration.
- **Cross-provider `ReEncrypt`.** When source and destination keys live on
  different providers, KeyRack decrypts on the source and re-encrypts on the
  destination (same-provider stays a single in-provider op).

Because HSM key material is non-extractable, "move key A → HSM B" is a **re-key**,
not a byte-copy: a new version is generated on B and becomes primary; old
ciphertext keeps decrypting on A (its header pins the version); data is
re-wrapped/re-encrypted over time, then A is retired — no big-bang re-encryption.
Literal byte-movement is only possible for explicitly wrapped/extractable
material via the BYOK import path.

Next step (not yet shipped): `rotate_key` with an optional target provider so an
in-place re-key onto a different backend is a single primitive; today the new
version inherits the key's current provider. A bulk re-wrap/re-encrypt sweep
builds on that.

## Fit rating

**Excellent for AWS KMS users. Good for OpenStack/Barbican users.
Not yet available for GCP/Azure.**

The AWS KMS shim is the strongest brownfield wedge. It's already
implemented and covers the most common operations. The Barbican shim
covers the OpenStack ecosystem.

GCP KMS and Azure Key Vault shims do not exist today but could follow
the same pattern.

## What's ready today

- AWS KMS shim with SigV4 authentication
- Supported operations: CreateKey, DescribeKey, ListKeys, Encrypt,
  Decrypt, GenerateDataKey, GenerateDataKeyWithoutPlaintext,
  GenerateRandom, ReEncrypt, Sign, Verify, Enable/DisableKey,
  Enable/DisableKeyRotation, GetKeyRotationStatus,
  ScheduleKeyDeletion, CancelKeyDeletion, CreateAlias, DeleteAlias,
  ListAliases, TagResource, UntagResource, ListResourceTags
- Barbican shim with Keystone authentication
- Supported: POST/GET/DELETE /v1/secrets, GET /v1/secrets/{id}/payload

## What's missing

| Item | Effort | Impact |
|---|---|---|
| AWS shim: NATS cache invalidation | 2-3 days | Medium — performance for high-throughput |
| AWS shim: published container image | 0.5 days | High — deployment ease |
| GCP KMS shim | 2-3 weeks | Medium — smaller target audience |
| Azure Key Vault shim | 2-3 weeks | Medium — smaller target audience |
| Vault Transit shim | 1-2 weeks | Medium — HashiCorp users |
| `rotate_key` with target provider (in-place re-key onto a different backend) | days | High — completes the BYOK↔HYOK primitive |
| Bulk re-wrap / re-encrypt sweep (orchestrate phase 2→3) | 1-2 weeks | High — needed at scale |

Already shipped (previously listed as missing): multiple named providers +
routing, per-version provider binding, and cross-provider `ReEncrypt` — the
foundations for backend/provider migration. See the section above.

## Strategic note

**The AWS KMS shim is KeyRack's most powerful adoption wedge.**

Consider this positioning:

> "Switch from AWS KMS to KeyRack in 5 minutes. Change one environment
> variable. Keep all your existing code. Get on-prem capability, crypto
> agility, and centralized key management."

This is a real, demonstrable value proposition with near-zero adoption
friction. It should be prominently featured on the website and be the
primary call-to-action for brownfield users.

The commercial angle: the shim itself could be OSS (encouraging
adoption), while HA clustering, vendor HSM adapters, and the management
UI remain commercial. Users who migrate via the shim and scale up
become natural commercial customers.
