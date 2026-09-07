# Shared custody contract, version 1

Status: implemented boundary vocabulary, codec and conformance tests. **Not an
activated hierarchy, qualified provider, authority service or production worker.**
The owner of `keyrack_core::custody` owns this encoding. Consumers propose concrete
diffs here; they must not publish a competing canonical worker/coordinator format.

## What this adds (and preserves)

`custody::{CustodyContext, CustodyMaterialDescriptor, CustodyProfile}` adds an
explicit authenticated execution boundary around the existing wrapping vocabulary.
`material.rs` and `wrapping.rs` remain unchanged. The existing V1 context is nested
byte-for-byte, including its own domain/version. The new **custody-contract frame
version 1** is not `WrappingContextVersion::V1` or an implicitly upgraded V1
envelope. A provider must authenticate the **entire new frame**, including profile,
under a separately qualified construction. Using just the nested V1 bytes loses
the profile binding and is not conformant.

The transport descriptor contains the complete context, an opaque envelope
reference, and SHA-256 of the exact stored envelope bytes. It is not another
`KeyMaterial` storage variant, has no operable child handle, and has no automatic
conversion to the existing descriptor/journal. The envelope hash stays outside
the wrapping context to avoid a circular dependency on the resulting ciphertext.
References are identifiers, not URLs or instructions to fetch caller-chosen paths.

Execution boundaries are distinct: provider session object, provider journaled
temporary object, and trusted-host worker memory. The last one is **not** either
`WrappedKeyLifecycle` variant. Boundary tags are placement declarations, not an
assurance ordering. A profile name must identify an immutable, versioned profile;
changing its construction or rules requires a new name. `require_profile` performs
an exact match against a trusted allowlist; an empty list denies. Parsing an opaque
profile name never qualifies it. No provider advertises a new capability here.

Export eligibility, exposure history and independent backup history are **not**
profile names or assurance flags. They remain separately enforced policy/lifecycle
facts: changing an eligibility flag cannot undo an earlier export or recover the
managed erasure guarantee. This frame makes no erasure/HYOK claim by itself. In
particular, the software-worker boundary does not make a plaintext-working-set
child independently HYOK, nor does it tolerate host-root compromise.

## Authority, leases and observations

`RequestBinding` includes operation UUID, attempt UUID, fresh executor incarnation,
full custody-context digest and exact request-transcript digest. The transcript
hash is a binding slot, **not an unspecified serializer to improvise**: the worker
must propose the operation-specific transcript covering input, data AAD and any
options before production use. Existing harness input hashes/JSON are not adopted.
Incarnations must be freshly generated in the executor trust boundary on restart;
nonzero validation is not an entropy or replay-resistance test.

`AuthorityIdentity` names issuer, exact scope and nonzero generation. Scopes are
either a full-context digest or an exact provider/security-domain pair, permitting
domain-wide revocation without per-key fanout. `AuthorityGrant` adds request,
principal, operation, sequence, its validity interval and an independently derived
ancestor-authority ceiling. Supported operations in this version are wrapped-only
generation, encrypt and decrypt. Rewrap, signing and MAC request semantics are not
smuggled into these tags; they require explicit contract evolution. Encrypt/decrypt
is structurally denied for a wrapping-only context even with a matching grant.

Time intervals are half-open `[not_before, not_after)`. A clock is explicitly Unix
milliseconds or milliseconds in one executor incarnation's monotonic domain. No
automatic conversion, implicit UTC assumption, default five-second lease or
maximum-authority duration exists here. Trusted deployment policy must select the
clock and maximum horizons, bound uncertainty/rollback, and establish any authority
to monotonic-clock mapping. Matching numeric timestamps alone is insufficient.

`LeaseIdentity` is an executor incarnation plus a nonzero counter, never a portable
key handle. `LeaseRecord` describes one residency interval, context and originating
authority identity; it grants no crypto authority. Residency can outlive authority,
but use cannot. A cache hit renews neither ancestor nor grant authority. Per-lease
usage/nonce limits, renewal and reinstatement are consuming-profile responsibilities,
not inherited from the provisional worker's counters or terminal-fence behavior.

These result families are separate Rust types and have different wire tags:

| Family | Binding and meaning | Does not mean |
|---|---|---|
| `CreationResult` | Exact request, storage attempt owner, material-descriptor digest, and provider-session closure / temporary-object destruction / native wrapped-only generation provenance | Residency cleanup, current permission, or verified storage closure merely because it parses |
| `LeaseCleanupResult` | One exact lease record and local cleanup reason | Creation-object destruction, all cached copies removed, or an applied authority fence |
| `RevocationResult` | Exact command digest/fence ID, issuer/scope/generation, executor incarnation, in-flight disposition, and bounded diagnostic lease list | Global/all-holder completion or permanent erasure |

`CreationResult::check_attempt` compares with trusted reservation state;
`check_material` verifies context/descriptor digests and outcome/boundary compatibility.
Native wrapped-only generation is not a fabricated session-close receipt. Its
producer must demonstrate that generation actually stayed wrapped-only and bind
the full attempt and owner. A fixture that generates before obtaining authority
does not establish authorized production creation. These types have no conversion
to `VerifiedA2Closure`; the storage owner must review that integration separately.

`RevocationCommand` carries a new authority generation, exact executor and scope,
fence UUID and validity. Applying it requires an independently authenticated issuer
authorized for that scope, currentness checks and serialization with admission and
output release. The result can report drained in-flight work or suppressed outputs;
it cannot report success while allowing a new usable-output commit under fenced
authority after the applied fence. Earlier irrevocable commits are not recalled. Suppression
does not itself establish erasure of still-running secret copies. `check_command`
checks bindings, not these execution facts. Observed leases must be sorted, unique,
local and at most 128 entries; this diagnostic list is deliberately **not** an
exhaustive holder census. The applied fence must cover its whole scope, including
leases absent from the list. Permanent erasure must also initiate revocation; a
local acknowledgement is not proof that that broader workflow finished.

### In-flight disposition and mid-delivery fences (v1 ruling)

**Keep the two existing tags: `Drained = 1`, `OutputsSuppressed = 2`.** There is
no third successful "partially delivered" or "unknown but fenced" disposition.
The classification is local to the exact command's entire authority scope and
executor incarnation, not to the bounded diagnostic lease list.

Let **F** be the linearization point at which authenticated fence application has
established the applicable admission/use fence and the selected disposition's
postcondition, serialized with irrevocable usable-output release. It is not
command arrival, acknowledgement delivery or recipient read time. A qualified
profile must identify and test that release point; a final userspace check
followed by an uncoordinated write is not
sufficient. Both dispositions require that no new usable-output commit under the
fenced authority can occur after F.

- **Drained:** all fenced work and output-release obligations finished or
  terminated at or before F; nothing remains pending. Previously committed output
  can still sit in a pipe or be retained/read by its recipient. This is not a claim
  that the recipient consumed or erased it. Finishing crypto while leaving an
  unguarded output queue is not draining.
- **OutputsSuppressed:** every response unreleased at F permanently loses its
  ability to commit usable output under the fenced authority. This includes
  queued/staged responses and late results of still-running computation. It
  does not claim that earlier commits were suppressed, nor that every secret
  copy was erased. Ciphertext staging/status records can continue only if they
  cannot make the suppressed response usable.

For the current experimental worker's encrypted staging and atomic one-use
key-capsule release (see its [transport description](../crates/keyrack-crypto-worker/OUTPUT_RELEASE.md)):

| State at F | Disposition for the local scope |
| --- | --- |
| Ciphertext partly/fully staged, capsule not committed, remaining release capabilities cancelled | `OutputsSuppressed` |
| Capsule commit returns EAGAIN/interruption without writing, then fence cancels retry | `OutputsSuppressed` |
| Capsule committed before F and no other work/release obligation remains | `Drained`; do not relabel the prior commit as suppressed |
| Some prior commits plus other responses cancelled at F | `OutputsSuppressed` for the unreleased set; prior commits are not recalled |
| Usable bytes partly released and continuation/scope coverage unresolved | Neither; do not emit a successful `RevocationResult` |

The last row is an unqualified/incomplete execution state, not a new successful
wire outcome. A future raw-stream profile must establish its own complete release
and fence semantics before producing either result. A profile that cannot prevent
post-F usable release cannot fix that by choosing a more permissive enum tag.
Expiry is a separate clock contract: a release-admission deadline is not a hard
kernel-enqueue or receiver-delivery deadline.

This ruling does **not** make the experimental worker's private fence notice a
canonical receipt. The worker owner must authenticate/apply the exact canonical
`RevocationCommand`, preserve its digest/UUID/scope/incarnation, observe the above
postcondition under the delivery gate, and authenticate any returned evidence
under a trusted executor identity. No lossy conversion from a private fence or
invented command digest is permitted. Tests must exercise pre-capsule and
post-capsule races, mixed prior/pending results, invalid fences and exact command
binding. Encoding/signature tests here establish representation integrity, not
those runtime facts; `check_command` alone does not establish fence completion.

## Signed evidence is not permission

`Evidence<T>` is untrusted, including after decoding. Version 1 defines a single
Ed25519 evidence profile, using the existing library's strict verification. There
is no custom crypto primitive, algorithm negotiation or message-supplied public
key. Other evidence/transport profiles need a reviewed extension, not a fallback.

`authenticate(EvidenceKey)` binds issuer and key ID to a separately trusted key and
returns `AuthenticatedEvidence<T>` with private fields and read-only accessors.
The signed transcript includes signer metadata and the full typed claim. Grants
and commands also require their authority issuer to equal the evidence signer.
Observation receipts are signed by an independently trusted executor/provenance
signer, not necessarily by the authority issuer they reference. Trusted configuration
must bind such a signer to the claimed executor, provider/domain and profile; matching
a signature alone does not establish that relationship or that the observation is true.

Required consuming checks, not implemented authority infrastructure:

1. Resolve exact key/material/profile and principal independently; reject unknown
   profiles and untrusted endpoints/parent mappings. Compare full envelope digest
   before using it and authenticate the entire custody context in the backend.
2. Authenticate issuer/key and enforce issuer-to-scope/executor policy. Never
   populate `EvidenceKey` or expected bindings from coordinator-supplied claims.
3. Check operation/purpose, attempt/input/context, clock, validity and ancestor
   ceilings. `AuthorityGrant::check_request` provides only these structural/time
   checks; it deliberately cannot decide that a generation is current.
4. Consult trusted current generation/revocation state for **every applicable
   scope**, including broader domain/ancestor fences, and atomically consume replay
   state. Sequence policy is not implicitly the harness's global high-water mark.
5. Repeat authority checks at admission/materialization, cache use and output
   release; serialize fences with those operations. A valid signature does not
   renew a grant or prevent its replay. Restart cannot bootstrap from saved grants.
6. Enforce local secret lifetime, nonce/use bounds and zeroization; authenticate
   receipts and reconcile attempts/holders without treating one receipt family as
   another. Integrators retain authority distribution and all-holder coordination.

This module does not close the credential/host-isolation deployment gate, implement
an integrator's revocation platform, prove malicious-coordinator secrecy, or qualify
Vault/PKCS#11/KMIP. Provider integration remains fail closed. In particular, a backend
that refuses or fails to authenticate the required context cannot be used by treating
the context as optional. No Tamarin, Kani or live-provider claim is added by these
serialization and signature tests.

## Normative encoding

All integers are unsigned big-endian; no padding or optional trailing fields.
Every canonical message starts with ASCII `KeyRack:CustodyContract`, NUL, `u16(1)`,
then a one-byte message kind. Names are `u16(byte_length) || printable-ASCII bytes`,
1–256 bytes, case-sensitive, no whitespace/normalization. `ProviderRef` is subject
to the same bound. UUIDs are 16 raw bytes (non-nil); digests/incarnations are 32 raw
bytes (incarnations nonzero). Counters/generations are nonzero u64. Nested messages
are `u32(byte_length) || full canonical message`, including domain/version/kind.
Whole and nested messages are bounded to 65,536 bytes before allocation.

| Kind | Type | Body fields in order |
|---|---|---|
| 1 | CustodyProfile | boundary u8; profile name |
| 2 | CustodyContext | length-prefixed complete legacy V1 wrapping bytes; nested profile |
| 3 | CustodyMaterialDescriptor | nested context; envelope reference; envelope digest |
| 4 | RequestBinding | operation UUID; attempt UUID; executor; context digest; request digest |
| 5 | AuthorityIdentity | issuer; scope; generation |
| 6 | AuthorityGrant | nested authority; nested request; principal; operation u8; sequence; validity; ancestor-not-after u64 |
| 7 | LeaseIdentity | executor; counter |
| 8 | LeaseRecord | nested lease; context digest; nested authority; residency validity |
| 9 | CreationResult | nested request; owner instance UUID; owner generation; material digest; outcome |
| 10 | LeaseCleanupResult | nested lease record; reason u8 |
| 11 | RevocationCommand | fence UUID; executor; nested authority; validity |
| 12 | RevocationResult | fence UUID; executor; nested authority; command digest; in-flight u8; lease-count u16; nested lease identities |
| 13 | Evidence<T> | algorithm u8; issuer; key ID; nested typed claim; 64 signature bytes |

Tags and compound fields:

- Boundary: 1 provider session, 2 provider journaled temporary object, 3 trusted-host
  worker memory. No other boundary is defined, including hardware-worker execution.
- Scope: 1 followed by context digest; 2 followed by provider and security-domain
  names. Asterisks are ordinary name bytes, never wildcard scopes.
- Operation: 1 GenerateWrapped, 2 Encrypt, 3 Decrypt.
- Validity: clock tag (1 Unix milliseconds, 2 executor-monotonic milliseconds plus
  32-byte incarnation), then not-before u64 and not-after u64. A monotonic clock's
  incarnation must equal that of its request, lease or command.
- Creation outcome: 1 followed by session name, 2 followed by temporary-object
  name, 3 native wrapped-only generation with no appended field.
- Cleanup reason: 1 released, 2 residency expired, 3 authority fenced.
- In-flight: 1 drained, 2 outputs suppressed. Algorithm: 1 Ed25519 only.
- The legacy wrapping byte grammar and its numeric tags remain those in
  `WrappingContext::canonical_bytes`; decoding re-encodes with that unchanged
  implementation and requires exact equality.

The Ed25519 signature transcript is ASCII `KeyRack:CustodyEvidenceSignature`, NUL,
`u16(1)`, algorithm `u8(1)`, issuer name, key-ID name, then the length-prefixed full
typed canonical claim. It excludes the signature itself and signs these bytes
directly (not a caller-selected prehash). Message kind is therefore authenticated.
SHA-256 fields naming a context, descriptor or command hash its **entire canonical
message**; envelope digest hashes the raw envelope, not a display/JSON encoding.

Unknown versions, numeric tags, wrong nested kinds, malformed lengths, conflicting
fields and trailing bytes are errors. Decoders re-encode and compare every accepted
message, rejecting noncanonical alternatives. Structurally valid opaque profile
names still require exact trusted qualification; they are not an extensibility
mechanism that permits permissive execution.

## Conformance and consumer handoff

Run `cargo test --locked -p keyrack-core --test custody_contract` and
`cargo test --locked -p keyrack-core --doc`. The existing workspace Test job includes
these tests; no new maintained CI stack is introduced. Do not confuse a workflow
run with a required branch-protection context; see [Vault CI status](VAULT_PROVIDER_TESTS.md).

`crates/keyrack-core/tests/vectors/custody-contract-v1.json` is the shared cross-language
fixture. `scripts/custody-contract-vectors.mjs` independently encodes it using only
Node built-ins, not the Rust encoder. All signing material in this fixture is public
test material and must never be used outside tests. Regenerate to stdout with
`node scripts/custody-contract-vectors.mjs`; use `--check` to compare without writing.

Tests compare typed Rust fixtures to independently generated bytes/hashes/signatures,
exercise alternate tags, reject truncated/extended frames and cross-family receipts,
mutate signed bytes, check exact binding/time/clock/lease constraints, and use
proptest for malformed and structured inputs. Compile-fail doctests prevent result
family substitution. These checks reduce the implementation/model gap; they are
not a proof of the authority platform, execution profile or provider construction.

Worker adoption requires concrete diffs: replace provisional JSON/V1-only hashing
with this frame; propose request transcripts and approved profile identifiers;
bind native generation to full request/attempt/owner and independently authenticated
authority; produce authenticated observations without overstating them. Production
persistence/creation verification and qualified provider cleanup remain subsequent
owner-reviewed integrations. Do not rewrite existing V1 records or silently grant
capabilities while making the worker compile against these types.
