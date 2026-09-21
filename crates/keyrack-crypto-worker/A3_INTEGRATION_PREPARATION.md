# A3 service integration: independent runtime preparation

Status: work in progress, **not an enabled service provider**. The existing
provisional executable remains a fixture. No service code depends on its private
IPC, and no wrapping capability or production profile is advertised here.

Worker-owned prerequisites are implemented without changing the shared
provider/journal contract:

* The output writer owns a validated write-only FIFO descriptor. Its private
  `spawn_on_pipe` seam preserves the existing encrypted staging and atomic capsule
  release gate. The harness delegates using a close-on-exec duplicate of stdout.
  Files, stream sockets, read ends and read/write FIFOs are refused; the sink
  enforces nonblocking mode and records of at most 512 bytes. This is not worker
  authentication or descriptor provisioning by a production supervisor.
* `Worker::new_scoped` takes the exact provider/domain from trusted runtime
  configuration before admission. Use and canonical revocation compare against
  the same immutable scope. The old constructor retains the fixture default.
  Creation remains fixture-allowlisted and also rejects a reservation outside
  the configured scope. No scope is adopted from a caller's signed request.
* `Worker::new_with_trust` takes an authority verification key, issuer/key identity,
  initial generation and observer labels from trusted startup configuration.
  Canonical creation and revocation authenticate against that same key identity;
  both observation families use the configured labels and a fresh worker-owned
  signing key. This configuration is not deserialized from coordinator IPC.
  The private use-grant adapter verifies the same public key and pinned generation;
  it still has no canonical issuer/key fields and is not a production transcript.
* Cache residency stores an executor-incarnation/counter `LeaseIdentity`. Private
  closure checks that exact identity and the original wrapping-context binding
  before zeroizing the entry. Stale, duplicate, wrong-context and old-incarnation
  closes cannot remove a reopened entry. Canonical revocation diagnostics copy
  these actual identities rather than reconstructing them from counters.

Startup generation is immutable admission policy. The provisional launcher uses
generation 1; it no longer adopts the first signed use request's generation.
A configured runtime must provision its baseline before creation or use. Zero is
unrepresentable, and `u64::MAX` is refused so a strictly newer terminal fence remains
possible. A valid fence advances the generation and ends the incarnation; rotation
or reinstatement needs a new incarnation and trusted configuration. This does not
implement persistent generation storage or authority issuance.

The internal close operation grants no crypto permission, emits no canonical
`LeaseCleanupResult`, and does not cancel staged output or apply a domain fence.
The existing private cleanup observation is unchanged. Its V1 wrapping digest is
not the full custody-context/material digest required for canonical lease evidence.
The future adapter must retain complete admission provenance and enforce its
approved cleanup authorization before exposing a close path to the service.
Counters never wrap; only restart resets them, together with a fresh incarnation.
Warm hits preserve the existing lease identity, residence deadline and use budget.

The tests exercise actual kernel-pipe backpressure and cancellation before capsule
commit, descriptor refusal, owned-descriptor closure, and configured-scope use and
fencing across multiple cached contexts. Correct signatures for another scope
must neither admit material nor purge the legitimate cache. Existing subprocess
and release-race tests still exercise the harness through the refactored sink.
Additional tests cover configured creation/use/fencing identities, wrong signer
labels and keys, pinned and exhausted startup generations, exact lease closure,
reopening and restart counter reuse. They exercise private runtime prerequisites,
not an enabled service provider or canonical lease authorization protocol.

The next integration consumes the shared `generate_wrapped_key`,
`open_wrapped_key`, `close_wrapped_key` and creation-journal work from its owner.
It needs an opaque worker lease, independently signed per-operation authority,
complete material/profile binding, caller data AAD, trusted supervisor registration,
and accepted worker-memory capability/creation semantics. These are not supplied
by treating a legacy provider handle as a bearer permission or by claiming an A2
object lifecycle for worker memory.

Secret keys and the bounded residency cache remain worker-local. No PKCS#11
parent, coordinator key cache, plaintext key export, automatic local fallback for
production, new canonical encoding or fabricated closure evidence is added.
Production Vault profile approval, protected endpoint/parent configuration,
persisted-material reopening and the new service-connected real-user acceptance
remain integration work; the existing fixture's acceptance is not their substitute.
