# Private worker output release and cancellation

This is the unpublished harness transport, not a shared IPC revision or a
canonical `RevocationResult`. The worker does not emit `OutputsSuppressed`.

## Release point and exact claim

An operation response has two terminal outcomes: its one-use transport key is
committed to the verified pipe, or that key is discarded and the response is
suppressed. Ciphertext staging is not release of usable output.

**Release admission** is the final monotonic deadline/incarnation/generation check
while holding the release/fence mutex. **The irrevocable release point** is a
successful single nonblocking write of the complete key capsule into the pipe.
The mutex is held across that syscall. `EAGAIN` or interruption commits nothing;
a later attempt revalidates authority. A successful commit is never subsequently
reported as suppressed, even if the clock has advanced when the syscall returns.

**Fence observation in this claim means successful validation and application
under that same mutex**, including core purge and disposal of pending transport
keys. It does not mean the arrival of an unverified input line. No new key capsule
can commit after that accepted fence. Every admitted response either committed
before that fence, or loses its key and is suppressed. Invalid fences change
neither state nor pending releases. The fence acknowledgement is written by the
same writer after cancellation of preceding data jobs.

A receiver can read or use previously committed output after a fence; it can
retain bytes indefinitely. Pipe ordering cannot revoke those bytes. An already
committed capsule precedes the fence acknowledgement in the stream. A racing
ciphertext staging record may finish after internal fence acceptance, but no
corresponding capsule can follow it.

**Deadline limit:** this is a release-admission cutoff, not a hard kernel-delivery
deadline. OS preemption between the final clock check and the syscall can cause
kernel enqueue after that deadline. Such a successful write remains committed;
we do not falsely label it suppressed. Receiver read time is also outside this
claim. A deterministic test explicitly exercises this case. Any stronger physical
delivery deadline requires additional OS/transport support and a separately
reviewed contract; these local outcomes must not be promoted to canonical
`OutputsSuppressed` or platform-wide completion.

## Mechanism and bounds

`execute_for_delivery` returns the independently verified grant fingerprint,
worker incarnation, authority generation and sequence, not-before time and the
minimum of grant/ancestor/residency/resident deadlines alongside the result.
Native creation uses the authenticated canonical grant and its ancestor ceiling.
Queue admission and final release both validate that state. Pending delivery does
not renew authority, a lease or secret residency.

Each result is serialized inside the worker, encrypted with AES-256-GCM under a
fresh random 256-bit one-use transport key, then staged in bounded records. The
nonce is zero because each independent key encrypts exactly one transport message.
This protects pending application output only; it does not change Vault wrapping,
material envelopes, custody context, authority signing or any shared contract.
The gate owns all pending transport keys. The writer owns ciphertext only.
Release serialization borrows a zeroizing base64 key string and uses a zeroizing
byte buffer; it does not create an ordinary owned JSON key string.

The writer requires Unix stdout to be a pipe/FIFO, sets `O_NONBLOCK`, and writes
one complete newline record of at most 512 bytes per syscall. There is no buffered
`flush`, `write_all`, regular-file fallback or blocking release write. This uses
the [POSIX atomic pipe-write rule](https://pubs.opengroup.org/onlinepubs/9699919799/functions/write.html).
Other platforms and stdout types fail closed. All output comes from this single
writer. The trusted launcher must not replace or change its descriptors.

At most four jobs queue and three result permits exist, including a writer-held
result. Plain serialized results are bounded at 65,536 bytes; staging chunks hold
256 base64 characters. Existing application/input limits remain. Queue overflow rejects the new response; previously admitted responses remain
authorized unless even the redacted error cannot queue. I/O failure, failure to
queue that error and process shutdown discard pending keys and close the stream; EOF
is terminal cancellation for any result without a capsule. A partial record write
is a violation of the verified pipe assumption and terminates the process.

The writer checks expiry independently of the current job, including while a
control response is blocked. Expired keys are discarded without waiting for pipe
space. Cancelled jobs emit a bounded terminal control response when the reader
resumes, correlated by delivery ID. Fence validation, core purge and pending-key
cancellation do not wait for a blocked pipe. Draining means discarding unreleased
result jobs/keys and emitting cancellation/status records; it does not retract
already committed output or require a malicious reader to consume anything.

The writer polls with a 1 ms pause between nonblocking steps. That is scheduling
behavior, not a wall-clock guarantee. Crypto/provider calls remain serialized in
the core; a fence waiting in input does not interrupt an active provider call.
Previously staged output can be cancelled as soon as the fence is validated.

## Private records and tests

- `control`: base64 JSON chunks with part/last markers, for public ready metadata,
  redacted errors, correlated `output suppressed` results and local fence notices.
- `staged`: delivery ID, part/last markers and base64 ciphertext chunks.
- `release`: delivery ID, worker incarnation, generation, sequence, grant digest
  and one-use key. Only this capsule makes the staged response usable.

The test decoder reconstructs a response only after its capsule, or returns a
terminal cancellation. It is a private fixture adapter, not an A3 client library.
No managed child key appears in these records; a transport key is a distinct
one-use key. Owned-buffer zeroization does not prove erasure of every compiler,
allocator, GCM-derived or OS copy.

Deterministic tests cover fences between authorization/enqueue, during a suspended
staging write, after enqueue/full staging and an `EAGAIN` capsule attempt; deadline
expiry on retry; wrong incarnation/generation; invalid fence preservation;
committed output followed by a fence; and queued-key expiry behind blocked control
output with a terminal cancellation. Another test demonstrates the admitted
release/OS-preemption deadline limitation explicitly.

Real-process tests fence a maximum-size response after its first staging record,
verify cancellation with no capsule and deny subsequent use. A Linux test shrinks
the real pipe to 4 KiB, leaves a maximum response undrained beyond its signed
deadline, then requires terminal cancellation without a release key. The existing
flood/backpressure termination and four live Vault assertions remain in place.
