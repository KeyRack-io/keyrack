# Canonical identity V2

V2 is the only supported logical-identity canonicalization. It replaces V1
without a compatibility decoder, alias or default. This is a breaking baseline;
V1 records fail deserialization. It is not an in-place upgrade for a V1 metadata
store. See [migration status](../MIGRATION.md) before considering deployed data.

## Accepted identities

Normalize Unicode text to NFC before validation, sorting, duplicate detection,
identity-tag storage and routing-rule matching. Apply this to map keys and
string values, nested record keys and values, and string-list elements. Reject
two names that normalize to the same key, even when their values agree. JSON
and YAML input visitors detect duplicate names before map collection can discard
them. Protobuf maps reach the service after protobuf decoding; repeated identical
wire keys cannot be recovered at that boundary.

Identity tags and routing attributes are flat string maps. General typed
`AttributeSet` canonicalization remains available, but converting typed values
into identity tags fails instead of erasing their types. Builder methods may
hold raw input; fallible canonicalization and identity-tag constructors validate
it before use. Validated maps are limited by a 16 MiB encoding budget (conservative for lists) and
64 nested record levels. Text normalization does not case-fold or apply compatibility
normalization.

Namespace names, rule patterns, parent substitutions and provider-routing match
attributes use the same normalization. Duplicate variable bindings and unbound
parent variables are rejected. Opaque provider references remain byte-exact and
outside logical identity. Malformed identity input cannot select a routing default
by disappearing during parsing.

The TLV type numbers and length encoding are specified in [SPEC.md](SPEC.md).
Pairs sort by normalized UTF-8 key bytes. LID derivation is unkeyed
`BLAKE3(02 00 00 00 || canonical_bytes)`. The stored version is `"V2"`.
Parent, key version, provider reference and authenticated ownership are not added
to this preimage. Normalization does not authenticate a tenant assertion, and a
LID is not an enforced wrapping context.

## Named invariant: canonical identity and rule observations agree

For accepted flat attribute maps A and B:

```
canonical_bytes(A) == canonical_bytes(B)
    if and only if
complete_rule_observations(A) == complete_rule_observations(B)
```

An observation includes attribute presence and captured values. A separating
family contains a presence-and-capture rule for each normalized key in the union
of A and B. This observes every accepted identity distinction, including literal
values beginning with `$`, which otherwise have variable syntax in patterns.
Rules receive the original raw maps so the test exercises the matching boundary.

A single rule's boolean outcome cannot provide the reverse implication: two
different maps can both fail that rule. The additional forward property checks
that equal canonical bytes imply equal matches, captures and resolved parents
for arbitrary generated rules. These properties are sampled over generated
inputs, not a formal proof over all possible maps or hash collision resistance.

## Independent NFC oracle and regression controls

`crates/keyrack-core/tests/canonical_identity.rs` reads the complete official
Unicode 17.0.0 normalization corpus. Expected strings come from its published
columns, not the Rust normalizer. Expected TLV bytes are framed independently
from those strings. The test pins corpus and license SHA-256 hashes and verifies:

- All 20,034 reference rows and their five NFC relations through text, flat-map
  and canonical-byte production paths.
- Reference source strings in list and nested-record values.
- NFC identity for every scalar outside the corpus's Part 1 source set.
- Three generated properties with 512 cases each, including the named invariant,
  equivalent spellings, independent maps and ambiguous normalized names.
- Nine regressions from the identity/context investigation.

The production dependency is pinned to `unicode-normalization` 0.1.25,
Unicode 17.0.0. [Corpus provenance](../crates/keyrack-core/tests/data/unicode/README.md)
records sources, hashes and license. Changing Unicode data requires updating
this explicit contract and checking the independent oracle.

Service tests exercise create, import and routing explanation input boundaries;
SQLite tests prove legacy records fail without relabeling or changing stored
JSON. These tests run in the workspace test suite used by CI. They establish
identity semantics; separate custody integration and provider qualification
remain outside this change.
