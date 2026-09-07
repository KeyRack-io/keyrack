# Delivery facts for revocation disposition arbitration

This is an enumeration of the current private worker transport, supplied before
canonical receipt implementation. It proposes no wire encoding. `Drained` and
`OutputsSuppressed` below name the existing custody variants; their aggregate
scope remains A2's decision.

The code supports **two normal per-response output outcomes, but does not retain
enough history to attest which happened**. A complete release capsule committed
before the fence makes output readable; destruction of its uncommitted transport
key suppresses output. A partially staged ciphertext is not partially released
plaintext. A mixed collection of responses is reachable. A transport fault with
uncertain disclosure is not either successful disposition.

## Observation boundary and population

The boundary is successful fence validation/application inside `Delivery::fence`
while holding the same mutex as final capsule admission and write. It is not the
arrival of an unverified command, acknowledgement enqueue, or receiver read.
The executable processes provider operations, preparation/enqueue, and fence
commands sequentially; a fence cannot interrupt that thread midway through a
provider call. The writer runs concurrently. Concurrent preparation/enqueue
interleavings are supported by the private Delivery API and tested, but are not
currently an executable command-processing interleaving.

Each accepted delivery has its own ID and one-use transport key. A successful
capsule write is one nonblocking FIFO write of at most 512 bytes. The writer has
already written every ciphertext record for that ID before attempting its
capsule. At the fence barrier that syscall cannot be halfway through: the fence
must wait for its mutex. Ciphertext staging is outside the mutex and can finish
a record after fence acceptance; the key cannot subsequently commit.

Sources: [delivery admission and writer](src/delivery.rs),
[runtime transition kernel](src/release_state.rs),
[executable command loop](src/main.rs), and the existing
[release point and OS-preemption limits](OUTPUT_RELEASE.md).

## Per-response enumeration

`S` means an output-suppression fact; `D` means a completed transport-commit fact.
These are proposed inputs to a receipt, not dispositions currently emitted.
“Readable” means that the receiver has enough bytes to recover the response;
the worker cannot observe whether it has actually read or used them.

| Condition at the fence boundary | Precisely what happened to output | Truthful disposition fact / limit |
|---|---|---|
| No accepted operation, or authorization/primitive failure before a result exists | Nothing was staged; no successful response exists. Redacted control errors are separate. | No response to classify. An empty affected set may be vacuously `Drained`; rejection is not proof of fence-caused suppression. |
| A result exists, but preparation or enqueue rejects it (size, capacity, identifier exhaustion, time or incarnation/generation) | Nothing was staged for that delivery; no capsule was committed. Any prepared transport key is dropped on rejection. No admitted delivery ID records this failure. | Suppression/non-release is a local fact if a result existed; not completed delivery. Include it only if the receipt's defined population includes such pre-enqueue results. |
| Prepared value held by another Delivery caller when fence is accepted | Nothing was staged; the later enqueue is refused and drops its key. Fence does not reach into the caller's still-held Prepared value. | Admission is fenced. Not a statement that all caller-owned buffers were already erased at the barrier. This overlap is absent from the current executable's single command thread. |
| Enqueued, no writer step yet | Nothing was staged. Fence drops the pending transport key. | `OutputsSuppressed`; not `Drained`. |
| Some complete ciphertext records staged | A ciphertext prefix remains, but no transport key was committed. Fence drops that key. | `OutputsSuppressed`; ciphertext prefix is not partial usable-output delivery. |
| A ciphertext staging syscall is currently in progress | That record may finish after fence acceptance. Its release key is dropped under the fence lock. | `OutputsSuppressed` for usable output; not “no bytes after fence.” |
| All ciphertext staged, capsule not attempted | Entire ciphertext remains unreadable without the withheld key. Fence drops the key. | `OutputsSuppressed`. |
| Capsule attempted and returned `EAGAIN` or `Interrupted` | Under the verified atomic FIFO assumption, zero capsule bytes committed. Permit remains pending until fence drops its key. | `OutputsSuppressed`, including a blocked writer. |
| Capsule write holds the mutex when a fence arrives | Fence has not yet been accepted. Full success resolves to the committed row below; retry resolves to the preceding row; hard failure resolves to a fault row. | No additional “half committed at an accepted fence” state under the pipe assumption. |
| Deadline elapsed, but the permit has not yet been swept | No capsule committed; the fence drops the still-present key. | Suppression is true. Do not claim the fence was the only cause: release was already ineligible. |
| Prior expiry/admission recheck removed the permit; ciphertext or a cancellation notification is still queued/writer-held | Nothing, some ciphertext, or all ciphertext was staged; no key committed. Cancellation happened before this fence. | `OutputsSuppressed` if this unresolved response belongs to the chosen cohort. Never infer `Drained` just from permit absence. |
| Suppression notification already committed and its job removed | No usable response was released; the receiver can learn it was cancelled. Current transport state forgets the response. | Historical suppression, not historical delivery. Outside a cohort of currently outstanding responses; relevant to an incarnation-wide history. |
| Complete capsule committed, including the interval before Writer clears its current job | All ciphertext and its complete key capsule precede fence acceptance. Output remains readable indefinitely. | `Drained` at the accepted transport-commit meaning; never `OutputsSuppressed` for this response. Receiver consumption cannot be claimed. |
| Capsule committed after release admission but after its clock deadline because of OS preemption | Same complete readable response as above; it still committed before an accepted fence because the mutex was held. | `Drained` as a delivery fact; **not** evidence of a hard physical deadline. The existing deadline limitation remains. |
| Normal shutdown/EOF already dropped pending keys and queues | Uncommitted outputs are suppressed; earlier committed outputs remain readable. A fence acknowledgement is not assured. | Not a successful new fence receipt. The command may not be processed, and a stopped transport rejects acknowledgement enqueue. |

These rows are exhaustive with respect to result existence/admission, staging
progress (none/prefix/all), and capsule outcome (not attempted/retry/committed),
plus eligibility loss and shutdown. Unverified/invalid fences change none of the
release policy and yield no applied-fence receipt; outputs may continue according
to their existing grants.

## Fault conditions and “partially committed”

The real sink verifies stdout is a FIFO and uses one nonblocking syscall per
bounded record. Within that contract, a partial capsule write is excluded. The
following cases describe explicit fault injection or broken transport assumptions,
not an additional normal state hidden by queue ordering.

| Fault | Output fact | Receipt consequence |
|---|---|---|
| Capsule construction/serialization fails before the syscall | No capsule written. The permit remains until fence, expiry or writer shutdown drops it. | Non-release can be established, but the writer is aborting; do not promise a delivered acknowledgement. |
| Hard error while staging, or capsule error known to have written zero bytes | No key release for the affected response. Writer stops and drops remaining keys. Earlier releases remain. | Failed/aborted transport, not a new successful completion receipt. |
| Short ciphertext-record write | Incomplete ciphertext, no capsule yet; writer aborts. | No usable response, but the atomic-record contract failed. No successful fence receipt on that transport. |
| **Short capsule write** | A prefix may contain **the entire key**, even if the syscall omits the final JSON delimiter or newline. Output may already be readable. | Neither `Drained` nor `OutputsSuppressed` is justified from that return value. Treat disclosure as indeterminate and fail the receipt path. |
| Sink writes some/all bytes and then reports an error | Return status cannot establish how much key material escaped. | Same indeterminate result; no successful receipt. |
| Mutex poisoning, panic, process death or lost connection | Applied-fence state and/or acknowledgement delivery may be unavailable. Prior commits cannot be retracted. | Absence/failure of evidence, not either success disposition. |

The runtime kernel sets its private `Phase::Suppressed` on every callback error,
and Delivery removes the permit. **That internal value is not non-disclosure
evidence for a short write.** The new injected test returns `len - 1`, omitting
only the capsule newline, and independently decrypts the response from the bytes
already captured. It also shows that `fence()` itself can return before the
writer's subsequent `stop()` call; no transport-fault flag currently survives in
the fence's observation. Canonical receipt implementation must reject that fault
interval rather than translating the private phase to a success disposition.

## What the current fence can actually distinguish

Under its lock, the fence can see current policy, still-live permits and queued
jobs, and whether its core-validation callback succeeded. It currently returns
only that callback's local observation after clearing permits. A queued data job
has not yet been staged; a live permit absent from the queue belongs to the
writer. The writer's progress within that response is not shared.

It cannot recover the following from that state:

- Whether a removed permit committed, expired, was suppressed, or hit an I/O error.
- How many ciphertext records the writer has staged. `Writer::current` is outside
  shared state; an empty queue is not an empty writer.
- Which completed cancellation notifications correspond to historical responses;
  those jobs are removed. A notification still in flight uses an untyped control
  job after its original job ID is cleared.
- Whether the receiver consumed a committed capsule, or whether a queued fence
  acknowledgement will ever be delivered. Acknowledgement enqueue itself can fail.

This is an observable information loss, not merely a missing enum constructor.
A deterministic test constructs **identical shared state, policy, clock and empty
writer** after two different histories: complete capsule commit versus full
ciphertext staging followed by expiry suppression. Applying a fence produces the
same shared state in both. An implementation which guesses `Drained` from an empty
permit map would lie in one history **if the disposition covers that historical
response**. For an outstanding-only cohort, both completed histories can instead
leave a vacuously drained empty set. A separate test leaves an expired response
still held by the writer with an empty queue and permit map: its cancellation
notification remains unresolved, so even identifying the outstanding set needs
more than those two empty collections.

## Aggregate mapping and the actual contract choice

A deterministic mixed-history test commits response 1, partly stages response 2,
and fences before response 2's capsule. Response 1 stays released; response 2 gets
a cancellation notification. This is reachable in the real writer architecture.

| Defined receipt population | Existing variants sufficient? |
|---|---|
| One normal response | Yes: committed -> `Drained`; uncommitted key discarded -> `OutputsSuppressed`. |
| Outstanding, unresolved responses at the accepted fence barrier, with earlier completed releases excluded | Yes, if that scope is explicit. Actual cancellation of this set -> `OutputsSuppressed`; a confirmed empty set can be vacuously `Drained`. Prior committed bytes remain readable. Previously suppressed but unresolved notifications must not masquerade as delivered work. |
| An entire batch/history containing both committed and suppressed responses | **No**, if each variant describes the whole population. `Drained` misreports the cancelled responses; `OutputsSuppressed` misreports the committed ones. A third **mixed outcome** (or per-response outcomes) is required for that interpretation. It is not a “partially committed capsule” variant. |
| Transport failure with indeterminate disclosure | Neither success variant suffices. Fail or withhold the receipt. If the protocol requires encoding failures as results, it needs an explicit failure representation, not a successful completion disposition. |

**Worker recommendation:** retain the two values for an explicitly defined
outstanding-response cohort and refuse successful receipts on uncertain transport
faults. No third value is required just because readers retain committed bytes.
If A2 requires a whole-history summary instead, the mixed test is the concrete
counterexample requiring a third outcome. Neither choice repairs the missing
bookkeeping: canonical receipt implementation must retain terminal reasons and
fault state under the release lock, including writer-held responses, until the
chosen receipt population is resolved. Shared contract files remain untouched.

## Reproducible evidence

Existing tests cover authorization/enqueue, staged writes racing with fences,
full staging plus blocked capsule retry, invalid fences, expiry behind blocked
control output, irreversible prior commit, and release-admission preemption.
The real-process test `process_fence_cancels_staged_output_before_key_release`
exercises the concurrent writer case.

The following deterministic tests add the classification evidence:

- `fence_cancels_every_precommit_staging_position`: zero through every ciphertext
  record boundary, inclusive of full staging; cancellation and no capsule in each.
- `identical_empty_fence_state_can_follow_commit_or_expiry_suppression`: identical
  observable transport states after different actual output outcomes.
- `empty_queue_and_permits_can_hide_writer_held_cancellation`: both shared
  collections are empty while an unresolved suppressed response remains in the writer.
- `mixed_committed_and_cancelled_response_history_is_reachable`: one irrevocable
  prior response and one suppressed pending response in the same worker history.
- `injected_short_capsule_write_is_not_non_disclosure_evidence`: an out-of-contract
  short return leaks enough capsule bytes to decrypt, despite a removed permit.

Run with `cargo test -p keyrack-crypto-worker delivery::tests`. These tests establish
classification facts and counterexamples; they emit no canonical receipt and do
not approve any interpretation of the shared enum.
