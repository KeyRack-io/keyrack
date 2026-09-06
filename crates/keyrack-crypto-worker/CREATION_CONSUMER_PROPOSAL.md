# Native creation consumer proposal against custody contract a74f884

Status: implemented in the unpublished development harness; request transcript,
profile qualification, and production integration require A2 contract-owner review.
No canonical type, V1 byte encoding, A2 journal rule or CI workflow is changed.

## Proposed generation request transcript

The canonical `RequestBinding` comes from the trusted launcher reservation and
worker-created executor incarnation, not by copying fields from a submitted grant.
Its `context_sha256` hashes the entire canonical `CustodyContext` frame. Its
`request_sha256` hashes this exact proposed byte sequence:

| Order | Bytes |
|---|---|
| 1 | ASCII `KeyRack:PROPOSED-worker-generate-request-v1` followed by NUL |
| 2 | Complete canonical custody context SHA-256, 32 bytes |
| 3 | Operation UUID, then attempt UUID, 16 bytes each |
| 4 | Storage-owner instance UUID, 16 bytes |
| 5 | Storage-owner generation, unsigned 64-bit big-endian |
| 6 | Envelope reference: unsigned 32-bit big-endian UTF-8 byte length, then bytes |
| 7 | Principal: unsigned 32-bit big-endian UTF-8 byte length, then bytes |
| 8 | Key bits, unsigned 16-bit big-endian, exactly 256 |

Identifiers use the contract's bounds. Nil operation/attempt/owner and zero owner
generation are rejected. The canonical grant separately binds the operation kind,
executor, independently trusted authority identity/scope/generation, sequence,
principal and clock/ancestor limits. The harness supports only the exact configured
provider/domain and generation 1; arbitrary signed context scopes are rejected.
There are no caller-specified generation options or data/AAD inputs in this operation.

This transcript is harness-local and **PROPOSED**, not another canonical contract
codec. A2 may accept or revise it before any production consumer depends on it.
Encrypt/decrypt operation transcripts and canonical lease/revocation adoption are
subsequent work; their old private adapters do not become contract-compliant here.

## Profile and native adapter

The explicit `TrustedHostWorkerMemory` profile identifier is
`UNQUALIFIED-vault-derived-worker-fixture-v1`. The fixed fixture context/profile is
an exact allowlist inside a binary requiring `--provisional-harness`; no enabled
provider capability advertises it. Vault generation and decrypt receive the entire
canonical custody frame as the derived-parent `context`, including the profile.
The legacy wrapping encoder is unchanged. This cannot read old V1-only envelopes
as though they had the new profile; no persistence migration is attempted.

This adopts the shared representation, **not a qualification of native Vault
context derivation**. Independent A2/A3 acceptance must establish that construction,
parent resolution, settings, versions and full semantic authentication before any
production profile is enabled. The fixture's configured Vault parent is not a
production resolver for its synthetic versioned parent identity.

## Creation evidence and authority provenance

The private JSON transport carries base64 of the unchanged canonical evidence and
descriptor formats. The success bundle contains:

- Independently signed `Evidence<AuthorityGrant>` used for admission, exact bytes.
- Worker-signed `Evidence<CreationResult>` with the same complete `RequestBinding`,
  the trusted reservation owner, `material_sha256`, and `NativeWrappedOnlyGenerated`.
- `CustodyMaterialDescriptor` containing full context, reserved envelope reference,
  and SHA-256 of the exact Vault ciphertext string bytes.

A verifier must authenticate the authority against its independently configured
issuer/scope policy, authenticate the observer against a trusted executor/profile
mapping, compare both request bindings to the trusted reservation, and run
`CreationResult::check_attempt`. The receipt alone does not authenticate the
companion authority bytes or establish their freshness: the bundle and matching
rule remain private consumer behavior, not a new shared signed bundle type.
Production observer-key distribution is UNMET; the subprocess test trusts its own
spawned process channel and does not accept a caller-provided verification key.

The generated wrapped ciphertext is retained only inside the fixture adapter. Its
opaque envelope reference simulates intended storage and is not a committed object.
No `VerifiedA2Closure`, storage publication, provider-object cleanup receipt, lease
cleanup receipt or global fence result is fabricated.

## Attempt state and remaining acceptance gates

One trusted reservation is installed before admission. Generation consumes it
before the first provider request. Metadata completion, native-call completion and
receipt signing each precede a fresh authority check. Any failure leaves it consumed;
no subsequent sequence can generate again. Generated material is inactive until all
checks succeed. The synchronous engine shares sequence/generation/fence state with
its provisional crypto path; old or terminally fenced authority cannot create.

An in-memory consumed state is not crash recovery. A new process rejects old grants
because its incarnation differs, but an external authority could still sign a new
incarnation for the same unresolved storage attempt. Production must obtain a
current, durable reservation and reconcile lost responses before issuing another
generation authorization. Durable owner currentness, restart reuse prevention,
publication and qualification are **UNMET**, not implied by typed evidence.
Distinct-UID deployment credential isolation and A2-owned CI hook wiring also remain
UNMET. The earlier credential file ownership/mode enforcement remains intact.
