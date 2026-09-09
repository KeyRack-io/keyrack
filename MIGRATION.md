# KeyRack migration status

This baseline supports only canonicalization V2. It rejects records carrying
`"canonicalization_version":"V1"`; it never relabels them or supplies a fallback.
The canonicalization planner cannot plan V1 transitions. Apply and rollback
reject unsupported plan versions before opening storage or changing a plan.

This is a breaking baseline, **not an in-place upgrade for a V1 database**.
Do not point this binary at an existing V1 metadata store as an upgrade procedure.

## Why stored primary keys are not sufficient

Ordinary key operations read a stored LID. However, hierarchy resolution and
provisioning derive LIDs from attributes, the migration helper rederives from
stored identity tags, and CLI/WASM tools can compute LIDs. Changing the version
prefix changes these recomputed identities. Deserializing a V1 record also fails
before its stored LID can be used. Keeping the primary-key column intact does
not provide compatibility or preserve recovery on its own.

A deployed-data transition would require a separately reviewed procedure covering
record semantics, parent references, ciphertext headers, recovery and callers
that recompute identity. This change supplies no such procedure and performs no
live-data migration. [Canonical identity](docs/CANONICAL_IDENTITY.md) defines V2.

## Rule changes are a separate operation

Existing records store their parent references. Changing routing rules changes
future resolution; it does not itself rewrap existing children. The rule-change
CLI is separate from canonicalization and is not a V1 recovery mechanism.

Earlier revisions of this document described transparent aliases, transactional
rewrapping, resumable checkpoints and an operational V1-to-V2 runbook. Those
were design proposals, not supported guarantees. They are withdrawn here to
avoid presenting them as a safe upgrade path. Any future migration design must
provide implementation and recovery evidence before becoming an operator runbook.
