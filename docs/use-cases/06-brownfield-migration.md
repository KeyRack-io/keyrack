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

### AWS KMS pass-through versus migration

This repository ships `keyrack-aws-proxy`, which forwards requests to real
AWS KMS using the proxy's configured credentials and records selected key
metadata. It does not translate AWS SDK operations onto Core providers, add
Core PDP enforcement, or remove the AWS dependency.

The AWS KMS compatibility shim and OpenStack Barbican shim are not shipped
in this repository. Core 0.5.0 does not provide their APIs, so changing an
AWS SDK or Cinder endpoint to the Core service is not a migration procedure.

### Moving applications to the native API

Use Core's gRPC or REST API for new keys and cryptographic operations.
Applications can keep reading existing ciphertext through their original
provider while writing new data through Core. Migrating old data requires
an application-managed decrypt-and-encrypt process with access to both keys;
Core cannot decrypt arbitrary AWS KMS ciphertext through its native providers.
Verify data migration before removing the old provider dependency.

Native REST and gRPC coverage differs; consult the
[API surface inventory](../generated/api-surface-parity.md) when selecting
operations. OpenStack integration requires a separate Barbican compatibility
implementation and is not included in this release.

## Backend / provider migration (BYOK ↔ HYOK)

Moving callers to the native API is separate from changing where a key's
*material* lives — e.g. from a KeyRack-managed software/Vault backend (BYOK) to
a customer-owned HSM (HYOK), or between HSM partitions. KeyRack treats logical
key identity (LID) as independent of the physical backend. Per-version
bindings provide a foundation for changing providers while retaining identity;
`RotateKey` does not yet accept a target provider.

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
  destination. Both same-provider and cross-provider paths currently expose
  plaintext in service memory during decrypt-and-encrypt processing. This
  migrates data ciphertext, not wrapped keys, and is not custody-preserving
  wrapped-key transport.

For non-extractable keys, migration requires generating new material at the
destination and re-encrypting data, rather than copying the original key.
Today applications can create a separate destination key and use data
`ReEncrypt`; old ciphertext still needs the original key and backend until
migration is complete.

Next step (not yet shipped): `rotate_key` with an optional target provider so an
in-place re-key onto a different backend is a single primitive; today the new
version inherits the key's current provider. A bulk re-wrap/re-encrypt sweep
builds on that.

## What is ready and what remains

Core 0.5.0 includes multiple named providers, routing, per-version provider
bindings and data `ReEncrypt` between existing Core-managed keys. SoftHSM is
a supported production software token, protected by storage permissions and
its PIN, with no hardware boundary. Hardware HSMs over PKCS#11 are not yet
qualified.

Remaining migration work includes:

- Adapting applications to Core's native API, or obtaining a separate protocol
  compatibility implementation. AWS KMS and Barbican shims are not in this repo.
- Selecting a different provider during `RotateKey`; the operation currently
  uses the existing primary version's provider.
- Orchestrating and verifying bulk data re-encryption before retiring old keys.
- Cross-provider wrapped-key transport; data `ReEncrypt` does not provide it.

Parent-child relationships recorded before 0.5.0 do not establish a wrapping
chain. From 0.5.0, `CreateKey` with a
parent creates a wrapped child only under a `wrapping:` profile on a
platform-custody provider, one level deep, and is refused without one; the only
mechanism in this release is software, which unwraps the child into service
memory, so it is not custody. Keys created before 0.5.0 that name a parent carry
the earlier, logical meaning and are refused as wrapping parents. Native PKCS#11
wrapping is not reachable through the service, for any token, SoftHSM included.
See [Using a child](../KEY_MATERIAL_REPRESENTATION.md#using-a-child) for how a
wrapped child's use lease is closed.
