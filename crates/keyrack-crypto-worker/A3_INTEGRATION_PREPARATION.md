# A3 service integration: independent runtime preparation

Status: work in progress, **not an enabled service provider**. The existing
provisional executable remains a fixture. No service code depends on its private
IPC, and no wrapping capability or production profile is advertised here.

Two worker-owned prerequisites are implemented without changing the shared
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

The tests exercise actual kernel-pipe backpressure and cancellation before capsule
commit, descriptor refusal, owned-descriptor closure, and configured-scope use and
fencing across multiple cached contexts. Correct signatures for another scope
must neither admit material nor purge the legitimate cache. Existing subprocess
and release-race tests still exercise the harness through the refactored sink.

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
