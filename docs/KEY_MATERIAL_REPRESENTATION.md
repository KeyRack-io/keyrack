# Key-version material representation

Status: implementation foundation on the hierarchy feature branch. Creating a
parent-wrapped child is now reachable from `CreateKey`, on a provider the
deployment explicitly activated, and is refused everywhere else; see
[Wrapping operations](#wrapping-operations) for the provider contract and
[Creating a child](#creating-a-child) for the service path. A created child is
**not yet usable**: the data plane still refuses wrapped versions, so the lease
path is the next increment and the two ship together. No production wrapping
profile, rewrap saga, or hierarchical erasure guarantee is implemented, and the
only implementation of the operations is software, which is not custody.

## Exclusive representation

`KeyVersionRecord.material` is either `ProviderResident` (a handle plus optional
legacy provider binding) or `ParentWrapped` (a structurally validated descriptor).
The wrapped variant has an explicit provider, security domain, exact parent LID
and nonzero version, context version, format, mechanism/profile identifier, and a
bounded opaque envelope reference. That reference is not a path or URL to load,
and is never passed to an ordinary provider operation as a key handle.

The descriptor has no resident-handle field. This enforces representation
exclusivity in the Rust type, **not** the absence of independent provider objects,
exports or backups. Its metadata is not authenticated merely by parsing it.
The eventual profile must authenticate the enclosing child's identity, version,
specification and purpose together with the descriptor's bindings, and separately
enforce currentness, authority and lifecycle.

## Compatibility and rollout

Resident versions retain the flat legacy wire shape, including `key_handle` and
optional `provider_ref`; legacy data is never upgraded implicitly to wrapped.
New resident versions are constructed explicitly. Actual version binding takes
precedence over the record default, then the registry default.

Wrapped versions use a mandatory `material` object with `kind: parent_wrapped`
and `format_version: 1`. They omit both flat legacy fields. The format and context
versions are independent. The exact wire fixture is tested in `material.rs`.

The decoder rejects unknown fields, unknown versions/kinds, null markers, mixed
representations, incomplete bindings, zero wrapped versions, and invalid or
oversized identifiers. It does not try the new format and then fall back to the
old one. Raw JSON duplicate fields are rejected; duplicates already collapsed by
a JSON value or PostgreSQL JSONB cannot be recovered by this decoder.

Old readers require `key_handle` and consequently reject a wrapped version,
including within a mixed history. Upgrade every reader before eventually enabling
wrapped writes. Rolling back to an old binary after such writes is not supported.
No SQL DDL change is needed for this representation-only migration. The Rust
`KeyVersionRecord` API has changed; downstream struct literals must use the new
constructor or material enum. This is unreleased feature-branch work.

## Current fail-closed behavior

All ordinary handle access and provider resolution refuse wrapped versions.
Rotation and exportability mutations preflight the complete history. The deletion
worker rejects a mixed history before deleting any resident sibling, leaving it
pending rather than claiming completion. CLI identity/reparent migrations and
rollbacks refuse wrapped records. ReEncrypt checks both representations before
calling either provider; it remains ordinary payload decrypt/encrypt, not a
custody-preserving hierarchy operation.

Crypto selects the version named by `current_key_version`, not a potentially
stale `is_primary` flag. Both REST and gRPC rotation use the shared domain path
and persist the binding actually used for generation. Logical descendant traversal
is preflighted before rotation; logical rotation jobs are not cryptographic rewrap.

Still required before activation: a service path that creates wrapped children,
authoritative per-version lifecycle, dependency indexing, rewrap/retirement
semantics, metadata API exposure, and real-provider restart/crash/erasure
acceptance. The primitive SoftHSM experiment is described separately in
[PKCS11_WRAPPING_PROBE.md](PKCS11_WRAPPING_PROBE.md).

## Wrapping operations

`CryptoProvider` has the three ADR-0005 operations: `generate_wrapped_key`
returns a wrapped envelope plus an open lease, `open_wrapped_key` turns stored
material back into a lease, and `close_wrapped_key` closes the exact object
idempotently. The defaults refuse, so a provider that does not implement them
fails closed without being touched; `wrapping_capabilities()` declares the exact
tuples a provider will serve, and `WrappingCapabilities::require()` matches every
field with no fallback, so an undeclared request is refused rather than
downgraded. A lease is not durable, not portable between providers or processes,
and never stored on a version: a wrapped version keeps its descriptor, and
opening is repeated per use.

`WrappingCreationProvider` drives the existing creation journal from those
operations. It contributes no evidence: a closure fact is verified by the
provider's own `wrapping_closure_verifier()`, and a provider without one cannot
be installed, so no adapter can turn a successful call into proof of cleanup.
Preflight requires Generate, Open and Close together, because a child that
cannot be opened again must not be created.

**The software provider implements these, and that is not custody.** Its
mechanism is named `software:aes-256-gcm:v1` so a capability dump says so on
sight. It wraps a child under an AES-256 parent held in the same process heap
and unwraps it back into that heap for the life of a lease, which is why it
declares the `SessionObject` lifetime rather than a backend-held one. A
software-wrapped child is exactly as contained as the parent wrapping it, which
is not at all. Nothing in this tranche makes a wrapped child provider-contained,
and no provider with a custody boundary implements these operations yet:
`keyrack-pkcs11` has no wrap or unwrap at all, and by ADR-0007 D4 Vault's
hierarchy is worker-mediated rather than provider-native.

## Creating a child

From 0.5.0, `parent_key_id` on `CreateKey` means the child's material is wrapped
under that parent. It is not a lineage annotation, and there is no separate
field that carries the old meaning: a caller that sends a parent is asking for
wrapped material and gets it or gets a refusal. All three surfaces — the domain
path, gRPC and REST — take the same branch, so the semantics cannot hold on one
surface and not another.

Wrapping is activated per provider in configuration, never inferred:

```yaml
wrapping:
  - provider: default
    mechanism: software:aes-256-gcm:v1
    security_domain: dev-single-process
```

Both values are written into every child's descriptor, which is why they are
declared rather than derived from a provider name that a later reconfiguration
could reuse. Startup checks the named provider against the profile and refuses
to start if it does not declare that mechanism for generate, open and close, or
cannot evidence its own closures; a software mechanism logs that the hierarchy
it forms is shape only. With no `wrapping:` block — the default — creating a key
with a parent is refused everywhere.

A child is then created through the crash-safe creation journal: reserve, stage
the wrapped envelope, resolve against verified closure evidence, publish. The
envelope lives in the journal row, which is what the descriptor's opaque
reference names, and the version records the exact parent version it was wrapped
under. A creation that ends unresolved is reported as such rather than as
failure, because its durable claim needs reconciliation, not a retry.

The refusals are deliberate, and each is tested separately: a provider with no
profile, a provider that does not implement the profile, a child that is not a
symmetric encryption key, an exportable child, an exportable parent, a parent
that is not enabled, a parent that is itself wrapped, a parent with no explicit
provider binding, and a parent in another security domain — ADR-0004 A2 requires
one domain, and this is a refusal, not a deferred feature.

Keys created before 0.5.0 that name a parent while holding independently
resident material carry the earlier meaning. That material is what identifies
them: they are refused as wrapping parents with a message naming the change, and
listed at startup so an operator learns that migration is needed before traffic
arrives rather than from a first failed use.
There is no migration script until someone needs one.
