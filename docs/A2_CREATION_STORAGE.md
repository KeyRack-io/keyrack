# A2 creation storage

This is transactional persistence groundwork, **not an enabled hierarchical KMS
operation or a qualified custody profile**. The provider capability gate and
ordinary wrapped-operation refusals remain in place. No worker/A3 format,
canonical V1 context bytes, or external authority protocol is changed.

## Implemented slice

`keyrack-core::creation` and the SQLite/PostgreSQL storage implementations support:

`Reserved → Staged → Resolved → Committed`

- Reserve an immutable operation/attempt, owner incarnation/generation, exact
  child version, parent snapshot, envelope reference and recovery correlation
  before provider effects. Identical retries return recorded progress; conflicting
  intents, child versions and envelope references fail.
- Claim dispatch once, durably, before Generate. Only the transaction that
  first commits `dispatch_started = true` returns `CreationDispatch::Started`.
  Identical retries return `Existing`, including after a lost commit response.
  This marker does not advance the four publication revisions. Claiming also
  rechecks the child and exact parent snapshot; it is not provider authorization.
- Stage an immutable envelope of 1–65,536 bytes. The complete proposed record
  stays in the journal, outside normal key reads. Neither staging nor resolution
  exposes the envelope through the committed-envelope read method. Staging
  requires the dispatch marker. The internal owner-fenced `creation_snapshot`
  returns journal and exact staged bytes from a single validated row read.
- Resolve a creation object only using `VerifiedA2Closure`, obtained through a
  trusted `A2ClosureVerifier`. The evidence binds the complete intent, including
  operation, attempt, owner, exact material/context, and BLAKE3 digest of the
  staged envelope. There is no production
  verifier or provider ceremony in this slice. Tests explicitly use a test-only
  verifier and non-cryptographic fixture bytes.
- Publish the key/version, committed dependency state and terminal journal/result
  in one database transaction. Recheck child OCC and exact parent eligibility.
  A lost-response retry returns the original result without overwriting later
  metadata, even when the parent has since changed state.

The initial storage profile is AES-128/AES-256 encryption leaves beneath an
explicitly provider-bound resident AES parent. It supports initial creation and
new-version publication preserving prior history. This validates structural
bindings and database state; it does not verify provider-enforced wrapping usage,
context authentication, security-domain identity, or authority freshness.

The journal row contains envelope bytes and indexed exact parent/child identities.
Its phase, JSON, index bindings and bytes are checked on reads. Envelope digests
and intent fingerprints detect storage inconsistencies and support idempotency;
they are **not** signatures, MACs, trusted currentness evidence, or a new wrapping
construction. SQLite uses an immediate writer transaction. PostgreSQL serializes
key/journal writes with a transaction-scoped advisory lock and also serializes
schema initialization, including first concurrent startup on an empty database.

Ordinary key writes observe reservations. Tracked child history/primary selection
cannot be replaced through ordinary CRUD; referenced parent versions/material
cannot be removed or replaced. Metadata and Disable updates remain possible and
invalidate a pending publication through its snapshot checks. Destruction of
referenced material is conservatively refused; authorized subtree destruction and
dependency retirement are later operations, not an implicit cascade here.

## Recovery and trust limits

- Recovery uses bounded keyset pages (1–100 operations) over a partial index of
  nonterminal operations. No timeout or owner expiry releases a reservation or
  proves an object gone. Unknown outcomes remain non-usable and inspectable.
- Re-reading a reservation is not renewed authorization, nor evidence generation
  never happened. Lost provider responses require correlation-based reconciliation,
  not another Generate call. The provider must prove its native correlation
  encoding/recovery works in its exact security domain.
- Automatic owner takeover, abort/cleanup completion, and reservation retirement
  are not implemented. A restarted database connection can resume the same
  recorded attempt; a new owner cannot simply claim it.
- A creation-object closure is not a working-lease closure or an authority-fencing
  receipt. Only the first is accepted by this storage protocol; the separately
  defined shared custody results are not implicitly converted into it. The verifier is a trusted
  integration extension point, not a defense against arbitrary code execution in
  that integration or a proof against a malicious coordinator.
- All writers must use the new transaction protocol once journaled creation is
  used. Older binaries/direct SQL writers can bypass its guards. Quiesce
  incompatible writers before use; installing additive tables alone does not
  make a mixed-version rollout safe. Database administrators and restored/tampered
  database snapshots are not turned into trusted security authorities.
- PostgreSQL's global metadata-write lock is an explicit first-slice correctness
  tradeoff, not a scalability result. Finer-grained locking and throughput evidence
  remain work; ordinary reads and provider calls do not hold that lock.

## Deliberately not activated

The SQL schema is additive and legacy **key-record** codecs remain compatible.
The experimental creation-journal codec is deliberately stricter: old journals
without `dispatch_started`, and old closure claims without `envelope_digest`,
are rejected. There is no automatic backfill or migration asserting that an old
Reserved attempt had no provider effects. Existing experimental journals require
explicit inventory and qualified reconciliation before upgrade/use; do not
delete unresolved rows or silently default their marker to false. Normal key
records with no creation journal are unaffected. All writers must be quiesced
for any such reconciliation; mixed-version creation is unsupported.

Existing
material-only `ParentWrapped` descriptors are not retroactively qualified or given
committed creation records. Storage backends/wrappers without transaction support
fail closed through default methods; in particular the service caching wrapper is
not wired to these methods yet. No REST/gRPC creation/rotation path invokes them.

Remaining activation work includes a qualified provider adapter and creation
verifier implementing the [unregistered lifecycle driver](A2_CREATION_LIFECYCLE.md),
provider-side preflight/cleanup recovery, complete per-version lifecycle,
recursive dependency resolution, owned operation leases, authority validation,
cache integration, service orchestration and destructive-operation coordination.
Ordinary service/provider side effects are not made atomic by these database
methods. No parent-loss/erasure or operational A2/A3 claim follows from storage
tests alone.

## Tests

```bash
cargo test -p keyrack-sqlite -p keyrack-test-support --locked
DATABASE_URL=postgres://... cargo test -p keyrack-postgres --features live-tests --locked
```

Both backends run the same creation conformance suite: early-use denial,
idempotency, collisions, owner/revision fencing, immutable material, parent-state
and child-OCC preemption, rotation history, and bounded recovery. Backend-specific
tests cover reconnects at each durable phase, competing database connections,
and an injected SQL failure after the key write but before journal publication.
SQLite additionally tests half-staging rollback and corrupted persisted bindings.
Dispatch tests cover competing connections, owner fencing, parent preemption,
rollback of the marker write, and owner-bound exact snapshots; SQLite also rejects
pre-marker journal JSON. The driver's SQLite fault tests exercise uncertain
responses, caller cancellation and repeated cleanup without another Generate.
Property tests exercise context perturbations and atomic rejection of arbitrary
journal transition sequences. These do not simulate an actual HSM process crash
or establish provider custody. The four real-Vault export tests have their own
[existing-fixture CI lane](VAULT_PROVIDER_TESTS.md), not an A2 qualification lane.
