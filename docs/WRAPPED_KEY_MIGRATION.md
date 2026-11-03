# Wrapped-key migration

**Evidence baseline:** `558bd6a6561e1f9e77cf506ad7f3fdc02ed764ec`.
Use the [contract at that exact source revision](https://github.com/KeyRack-io/keyrack/blob/558bd6a6561e1f9e77cf506ad7f3fdc02ed764ec/docs/WRAPPED_KEY_MIGRATION.md)
and the [pinned CI and conformance evidence](#pinned-revision-and-ci-results)
for this handoff. A later branch head does not inherit these results.

`RewrapKey` moves every retained version of one logical wrapped key. Omitting a
new parent rewraps under the existing parent's current version; naming a new
parent reparents the key. The target version is pinned at reservation. Child
LID, version numbers, key specification and key material stay unchanged, so old
data ciphertext continues to decrypt. `parent_lid` changes only through this
operation. Attribute-based hierarchy rules are not rewritten; stored ancestry
changes at commit. See [key resolution](KEY_RESOLUTION.md#hierarchy-parent_lid).

## API and immutable intent

The gRPC method is `KeyService.RewrapKey`. Its REST equivalent is
`POST /v1/keys/{key_id}/rewrap`:

```json
{
  "operation_id": "8d98d268-7f1d-42db-9847-13b6ffbd3b60",
  "old_parent_key_id": "<current-parent-lid>",
  "new_parent_key_id": "<destination-parent-lid>",
  "expected_child_revision": 4,
  "expected_old_parent_revision": 8,
  "expected_new_parent_revision": 2,
  "covered_versions": [1, 2, 3]
}
```

`operation_id` is required and must be a non-nil UUID. The gRPC request also
contains `key_id`; REST obtains it from the path. Every other field shown is
optional. Parent IDs are logical IDs, never aliases. Empty parent strings mean
omission. Empty or omitted `covered_versions` means all retained versions;
a supplied nonempty set must equal the entire retained set. Order is
canonicalized; duplicates, zero, omitted retained versions and invented versions
are refused. The service never interprets a subset as permission to move only
some versions.

The three optional revisions are **key OCC revisions**, not cryptographic key
version numbers. Supplied values must match the corresponding stored snapshots.
The journal binds the child, both parent identities, their observed revisions,
the target parent version, every retained child version, and all caller
assertions. Presence is significant: omitting a revision and explicitly supplying
its observed value are different intents, as are implicit and explicit parent
selection or version coverage. Reusing an ID with identical intent resumes the
operation or returns its original result. A changed intent returns gRPC
`FAILED_PRECONDITION` / HTTP 409. Invalid syntax or duplicate version entries
returns `INVALID_ARGUMENT` / HTTP 400. A concurrent OCC/fence conflict is
retryable; retry the original operation ID, never invent another ID to bypass it.

`kms:RewrapKey` permission is required independently on the child, old parent and
new parent, including two parent grants when both roles name the same LID.
Authorization reads current uncached metadata, uses distinct correlated PDP
request IDs, and fails closed. Recovery and committed-result retries authorize
again. Attempt and outcome audit events carry the operation ID.

## Committed result schema

Both surfaces return `operation_id`, `metadata` (the original committed child
snapshot), and `result`. The typed gRPC result and REST JSON result have the same
fields:

| Field | Meaning |
| --- | --- |
| `operation_id` | Original operation UUID. |
| `child` | Unchanged logical child ID. |
| `old_parent` | Source logical parent ID. |
| `old_parent_versions` | Sorted unique source parent versions used by the retained child versions. |
| `new_parent` | Destination logical parent ID. |
| `new_parent_version` | Destination version pinned at reservation. |
| `digest_algorithm` | `blake3`. |
| `versions[]` | Exactly one entry for every retained child version. |

Each `versions[]` entry contains:

| Field | Meaning |
| --- | --- |
| `version` | Unchanged child version number. |
| `old_parent_version`, `new_parent_version` | Exact source and destination parent versions. |
| `old_envelope_digest`, `new_envelope_digest` | Lowercase 64-character hexadecimal BLAKE3 digests of the exact encrypted envelope bytes. |
| `old_reference`, `new_reference` | Original retired reference and resulting live reference, such as `creation:<uuid>` and `migration:<uuid>:<version>`. |

The old hashes are computed from durable source envelopes inside the commit
transaction, before erasure. New hashes are checked against the staged bytes and
exact version set. The result, child switch and erasure commit atomically. A
Reserved or Staged journal has no terminal result. Only a committed terminal
result releases this migration's old-parent dependency; other children or
journals can still block that parent. The result is immutable and a retry returns
the same result even after metadata changes or another migration. It is a durable
binding receipt, not a signature or a proof of token custody.

## Supported combinations

| Combination | Support |
| --- | --- |
| Same explicit provider and security domain, software AES-256 parent and AES-256 child | Implemented with `software:aes-256-gcm:v1`. |
| Native PKCS#11 profile through Worker | Pending Worker's integration and profile qualification; not enabled by this PR. Child unwrap and rewrap must remain inside the token. |
| Cross-provider or cross-security-domain | Explicitly refused; no transport or software fallback. |
| Wrapped child as destination parent, or a cycle | Refused; only a resident wrapping parent is eligible. |
| Scheduled, destroyed, compromised or otherwise ineligible parent | Refused. This slice conservatively requires both parents and the child to be enabled, uncompromised and non-exportable. |

Software wrapping is not hardware custody. Its resident keys live in process
memory; persistent journal recovery assumes the provider's resident parent
material remains available.

The provider primitive is:

```rust
async fn rewrap_wrapped_key(
    &self,
    old_context: &WrappingContext,
    old_parent: &KeyHandle,
    envelope: &[u8],
    new_context: &WrappingContext,
    new_parent: &KeyHandle,
) -> Result<Vec<u8>>;
```

Both exact capability tuples require `WrappingOperation::Rewrap`. Only parent
identity/version and parent spec may change. Child identity/version, purpose,
format, provider, security domain and mechanism remain bound. A successful
provider return means intermediate objects have been cleaned up. Only encrypted
envelopes cross this interface. `rewrap_is_retry_safe()` defaults to false;
software explicitly returns true because repeating its local zeroized
transformation has no durable child effect and consumes neither parent nor input.
A token capability declaration alone never authorizes blind repetition.

## Recovery, ownership and cancellation

1. **Reserve:** recheck child and both parent snapshots under the storage writer
   fence, fix the complete version set and pin the target version. Readers keep
   using the current envelopes. All three identities remain reserved.
2. **Claim ownership:** compare the current journal epoch and atomically advance
   it for an owner UUID. Every dispatch, stage and commit must supply that owner
   and epoch. Takeover advances the epoch; an old worker cannot stage or commit,
   even if it later receives a successful provider reply.
3. **Record dispatch before effects:** a durable marker records the dispatch
   epoch and whether the provider explicitly permits repetition. A crash or lost
   response after this marker is conservatively an unknown outcome, including
   a crash just before the actual provider call. Partial output never changes
   the live child or releases a parent.
4. **Stage:** publish all replacement envelopes with exact version/digest
   bindings under the current ownership epoch. Readers still use the original
   committed material. Staged recovery takes ownership and commits without
   invoking the provider again.
5. **Commit and erase:** recheck ownership, snapshots and staged bytes, produce
   the terminal receipt, replace every descriptor and `parent_lid`, and erase
   old envelopes and active dependencies in one transaction. There is no
   separate post-commit erasure phase. A crash during that transaction leaves
   either the original key plus staged journal, or the complete new key plus
   terminal receipt with old envelopes retired. A lost commit reply is recovered
   by retrying the same operation ID.

For explicitly repeatable providers, Reserved recovery may reproduce the whole
batch. For a nonrepeatable native effect with an unknown outcome, the reservation
and source-parent destruction block remain until correlated reconciliation.
Takeover does not clear that marker. The service does not retry that native effect,
accept stale output, or provide an administrative flag that declares it safe.
Worker/native integration must supply qualified outcome/cleanup reconciliation
before that profile is enabled. A nonrepeatable batch that successfully reaches
Staged is recoverable without repeating its effects.

**There is no operation-cancel API after reservation.** Cancelling an HTTP/gRPC
request cancels the caller's wait, not the migration. Admitted tasks retain
execution and audit-outcome ownership after disconnect; at most 64 run per
process. A process crash can leave an audit attempt without an outcome. The
reservation has no timeout release; retry/reconcile the same operation ID. An
error or a client disconnect is not evidence that a native effect did not occur.

## Readers and ordinary updates

Readers obtain the current child descriptor, envelope and parent in one storage
snapshot. A reader holding pre-migration metadata still resolves the retained
version using its current binding. If the old parent disappears between that
snapshot and provider open, the reader refreshes a changed parent binding before
running its data operation. The data decrypt/encrypt itself is never retried.
Thus reservation, staging, the atomic switch and erasure introduce no failure
window for retained-version reads. Existing crypto leases are not drained by the
migration fence.

| Operation while Reserved or Staged | Behavior |
| --- | --- |
| Child/old-parent/new-parent metadata changes, enable/disable, schedule/cancel deletion | Fenced; refused as retryable. The transaction repeats the check after service preflight. |
| Child rotation, either parent rotation, new child creation under either parent | Fenced; a competing committed change instead makes reservation fail OCC. Wrapped-child rotation remains unsupported outside migration. |
| Another migration involving any reserved identity | Fenced. |
| Destruction claim for child or either parent | Refused while the journal is nonterminal. |
| Alias create, delete or retarget | Safely permitted. Migration intent is addressed by LID, so changing an alias cannot retarget it. |
| Decrypt a retained version | Permitted under ordinary key/PDP policy, through the consistent snapshot path. |

## Rotation integration protocol

The protocol agreed for [wrapped-child rotation, #68](https://github.com/KeyRack-io/keyrack/pull/68)
is **first reservation admitted under the shared storage writer fence wins**.
The rotation implementation reviewed for this agreement is
`f6e8797d67a88e39cf47cad0152d47fad35a4c87`; it is separate from the pinned #66
evidence below. Wrapped-child rotation is not enabled by the #66 baseline alone.

1. If migration is Reserved or Staged first, rotation is refused retryably
   (`UNAVAILABLE` / HTTP 503) before provider dispatch. Creation reservation and
   publication retain their migration guards on both storage backends.
2. If rotation's creation journal is reserved first, migration is refused
   retryably by its pending-creation check. After rotation publishes, a freshly
   prepared migration covers every version, including the new one. This is a
   refusal, not a queued wait. A refusal before migration reservation leaves no
   migration journal, so unchanged caller parameters may retry with the same
   operation ID and fresh snapshots.
3. If migration commits between rotation's read and reservation, OCC rejects
   the stale rotation before dispatch. Rotation re-reads the child and its new
   parent and wraps under that parent's current version; exhaustion of its
   bounded retries returns `ABORTED` / HTTP 409.

Caller-supplied expected revisions and `covered_versions` are never silently
advanced. If rotation makes an assertion stale, the caller must deliberately
refresh it. Once a migration journal exists, its snapshots and optional
assertions are immutable; a changed intent under its operation ID conflicts.

`withdraw_creation` may release only a Reserved entry with no dispatch marker,
or a Resolved entry with verified provider closure, under the writer fence.
Dispatch claimed/unknown and unclosed staged effects continue to block migration
and destruction until reconciled. Committed entries retain their retirement
rules. Safe withdrawal relinquishes the reservation's priority. Migration
ownership epochs, pinned target version, full-version commit and terminal-result
requirements remain in force.

## Database restore and destroyed parents

Restoring a database backup from before migration also restores the old
references and envelopes; it cannot restore a parent key that was subsequently
destroyed in the provider. Use of that restored child fails explicitly with
`wrapping parent destroyed` (gRPC `FAILED_PRECONDITION`, HTTP 409). It does not
silently select a newer parent, generate a key, substitute another envelope or
fall back to resident material. Recovery requires a coordinated recoverable
provider/database backup or a database snapshot whose envelopes reference a
surviving parent. The harness models an independently persistent provider by
restoring a pre-migration SQLite copy while keeping the same provider instance
with the old parent destroyed; it does not claim software resident keys survive
process exit.

When the parent binding changes, a new envelope rejects the old context. If the
binding was already current, the old and new contexts are identical. Erasing
service-owned old bytes cannot revoke a separately retained old envelope while
its old parent survives, and does not erase database logs or backups.

## Acceptance evidence

### Pinned revision and CI results

Results produced on 2026-11-02 are pinned to source commit
[`558bd6a6561e1f9e77cf506ad7f3fdc02ed764ec`](https://github.com/KeyRack-io/keyrack/commit/558bd6a6561e1f9e77cf506ad7f3fdc02ed764ec).
The three runs below report that exact `head_sha` and `success`; verified again
on 2026-11-04. Their checkout logs identify GitHub's PR merge commit
`ed4dccb0c92ff952bd2cc84da85e05ca311f27fb`, merging the source into
`8f45f83f212fb21ec3db9b0fe086499248636ea9`. Both source and tested merge have
Git tree `2ebfb752f7a53cb4e63c1fbc63ee200b164705db`: the tested contents are identical.

| CI run for this source SHA | Evidence |
| --- | --- |
| [CI — 41475420166](https://github.com/KeyRack-io/keyrack/actions/runs/41475420166) | Test, Clippy and Format passed. Test includes 14 service migration tests, 10 API authorization/intent/receipt tests and 51 SQLite library tests. |
| [REST/gRPC surface parity — 41475419914](https://github.com/KeyRack-io/keyrack/actions/runs/41475419914) | Explicit API surface and generated claim passed. |
| [Wrapped-key migration — 41475419960](https://github.com/KeyRack-io/keyrack/actions/runs/41475419960) | 10 live PostgreSQL migration tests and 16 deliberate fence reversions passed; restored baseline passed. |

The migration run's [migration-fence-controls artifact](https://github.com/KeyRack-io/keyrack/actions/runs/41475419960/artifacts/13157377884)
contains the complete logs and `results.json`. Its downloaded archive SHA-256 is
`1f8954814f7c817093dc18aa747eea7969f9e986a57fbd840dc5e3d316a3c5d0`.
The [archived conformance receipt](evidence/wrapped-key-migration-558bd6a.json)
preserves that result, all 16 control names, source-file hashes, source/checkout
SHAs, tree identity and run links independently of CI artifact retention. Every
receipt source-file hash was checked against the pinned commit. The 35-test
full PostgreSQL conformance result reported on #66 was a separate local run;
the linked migration CI job ran the 10-test migration subset.

**0.5.0 release re-pin is pending:** `v0.5.0` did not exist on 2026-11-04.
When cut, pin the contract to that tag, record its peeled commit SHA, and attach
successful CI/conformance runs for that release commit. Preserve this record
as historical evidence; do not relabel these pre-release runs as tag results.
The required handoff is in [Releasing KeyRack](RELEASING.md#050-migration-evidence-handoff).

### Acceptance coverage

The CI **Test** job (`.github/workflows/ci.yml`) runs the service and core tests.
The **Explicit API surface and generated claim** job checks REST/gRPC parity.
The **Migration PostgreSQL parity and reverted fences** job
(`.github/workflows/wrapped-migration.yml`) runs the shared tests on live
PostgreSQL, reconnect/rollback checks, and deliberate fence reversions. SQLite
storage tests also run in **Test**. Software service tests use real AES wrapping;
shared storage envelope fixtures and native-like fault injection are synthetic,
not native PKCS#11 qualification.

| Acceptance point | Executable tests |
| --- | --- |
| Every intent field, optional OCC and version set | `every_caller_intent_field_is_bound_on_both_surfaces`, `initial_occ_and_covered_version_assertions_refuse_without_reservation`, `migration_intent_binds_every_condition` |
| Continuity of every version at every phase | `retained_versions_decrypt_continuously_in_reserve_stage_commit_and_after_erasure`, `reader_paused_before_open_survives_commit_and_parent_destruction_on_both_paths`, `migration_concurrent_reader_snapshots` |
| Unchanged identity/material and old ciphertext | `every_version_survives_rewrap_and_reparent_and_old_parent_is_destroyable`; software wrapping tests |
| Rotation, creation and ordinary updates | `cancellation_retains_the_fence_and_retry_finishes_the_migration`, `migration_all_writer_fences`, `migration_creation_and_occ_preempt`, `metadata_and_lifecycle_updates_are_fenced_but_aliases_are_safe_during_migration`, `migration_ordinary_updates_and_aliases`, `lifecycle_updates_are_retryable_fenced_on_both_surfaces_before_state_validation` |
| Lost replies, retries and restarts | `terminal_receipt_binds_envelopes_and_survives_lost_reply_and_later_changes`, `recovery_resumes_each_phase_and_committed_replay_is_idempotent`, `migration_reopens_at_every_durable_phase`, `migration_reconnects_at_each_phase_and_rolls_back_failed_commit`, `simultaneous_same_operation_retries_share_the_committed_result`, `independently_prepared_same_operation_keeps_the_first_reserved_intent` |
| Partial/unknown provider outcomes | `partial_repeatable_provider_failure_preserves_every_reader_until_recovery`, `unknown_nonrepeatable_provider_outcome_retains_reservation_without_redispatch`, `migration_ownership_epoch_and_unknown_outcome` |
| Stale worker rejected after takeover | `migration_ownership_epoch_and_unknown_outcome`; ownership stage/commit reversion controls |
| Terminal result, original parent block and erasure | `migration_terminal_result_and_reader_snapshots`, `migration_atomic_publication_and_retirement`, `migration_commit_rollback_restores_old_envelopes_and_fence`, `migration_blocks_due_unreferenced_target_destruction` |
| Restore with destroyed source parent | `restoring_pre_migration_database_after_parent_destruction_fails_explicitly` |
| PDP on child and both parents | `both_surfaces_deny_missing_permission_on_either_parent_before_reservation`, `same_parent_still_has_two_parent_grants_and_replayed_permit_is_refused`, `committed_replay_authorizes_fresh_parent_metadata_beyond_cache_ttl` |

`scripts/test-migration-controls.py` requires each reverted fence to cause its
named test assertion to fail, rejects compilation/zero-test failures as evidence,
and reruns the restored suite. It writes `target/proofs/migration/results.json`
and logs, uploaded by the migration CI job.
