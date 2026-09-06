# Key-version material representation

Status: implementation foundation on the hierarchy feature branch. This does
**not** enable parent-wrapped key creation or operations. No production wrapping
profile, authenticated envelope store, materialization lease, rewrap saga, or
hierarchical erasure guarantee is implemented by this tranche.

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

Still required before activation: authenticated provider profile and envelope
persistence, authoritative per-version lifecycle, dependency indexing, creation
and cleanup journals, owned bounded leases, rewrap/retirement semantics, metadata
API exposure, and real-provider restart/crash/erasure acceptance. The primitive
SoftHSM experiment is described separately in [PKCS11_WRAPPING_PROBE.md](PKCS11_WRAPPING_PROBE.md).
