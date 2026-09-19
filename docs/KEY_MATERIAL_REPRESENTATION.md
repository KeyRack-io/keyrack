# Key-version material representation

Status: implementation foundation on the hierarchy feature branch. Creating a
parent-wrapped child is **not** reachable from the API: no service path builds
one. What now exists below that line is the provider contract and one
unqualified software implementation of it, described in
[Wrapping operations](#wrapping-operations). No production wrapping profile,
rewrap saga, or hierarchical erasure guarantee is implemented.

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

Generation additionally takes a `CreationBinding`: the operation, attempt,
owner, correlation and request fingerprint of the one creation it is allowed to
have an effect for. It arrives before the call because the owner of a cleanup
has to exist before there is anything to clean up, and the provider keeps it
with the object, because context cannot tell two creations apart — two attempts
at the same child under the same parent produce byte-identical canonical
context. A verifier that matched on context alone would accept a genuine
closure of one attempt as evidence for another. A binding is only obtainable
from a validated `CreationRequest` in-process and cannot be deserialized, so
nothing reconstructs one at close time. Opening an existing child takes no
binding: ordinary use is not creation and closing a use lease certifies nothing
about one.

Closing is idempotent for as long as the provider can still account for the
object, and no longer: past that bound a close is an error, never a success and
never permission to create the child again. A closure fact may only follow an
explicit close of the exact object in the session that produced it. An
ambiguous error, a destructor, an expiry or an empty search from a new session
is not closure.

`WrappingCreationProvider` drives the existing creation journal from those
operations. It contributes no evidence: a closure fact is verified by the
provider's own `wrapping_closure_verifier()`, and a provider without one cannot
be installed, so no adapter can turn a successful call into proof of cleanup.
Preflight requires Generate, Open and Close together, because a child that
cannot be opened again must not be created. It owns one creation, reserved
before Generate and never displaced: a second generation is refused whichever
request it carries, and errors, wrong-context responses and caller cancellation
all leave the reservation standing, because each of them can leave an object
that nothing else can close. Where it cannot close what it owns, it says the
attempt is unresolved rather than producing a closure from the absence of one.

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
