# A2 creation lifecycle driver

`keyrack_core::creation_driver` implements unregistered orchestration for the
[A2 storage protocol](A2_CREATION_STORAGE.md). It does **not** qualify a provider,
enable hierarchy creation in REST/gRPC, or implement cross-provider transport.
No runtime implementation of `A2CreationProvider` is installed. Its SQLite tests
use a scripted, non-cryptographic provider; they test orchestration only.

## Implemented sequence

1. Validate and reserve the complete immutable intent.
2. Check the trusted adapter's read-only preflight, then commit a one-shot
   dispatch marker. Only the fresh committed decision may invoke Generate.
3. Invoke one provider-native create-and-wrap attempt and stage its exact bytes.
4. Attempt cleanup even if generation returns an error, the envelope is invalid,
   or staging fails. An error does not establish absence of provider effects.
5. Verify exact-intent, exact-envelope closure provenance; resolve the journal.
6. Recheck preflight and atomically publish against the current parent/child
   snapshots. Permission denial does not cancel the preceding cleanup obligation.

Dropping a caller detaches the owned Tokio operation so cleanup can continue.
Runtime shutdown or panic can still interrupt it. There is no asynchronous Drop
receipt, background supervisor, production admission quota or shutdown-drain
contract in this slice.

## Retry and uncertainty

| Durable state | Runner action |
|---|---|
| Reserved, dispatch not claimed | Recheck preflight and try the single dispatch transaction |
| Reserved, dispatch claimed | Return pending; never Generate again or infer executor quiescence |
| Staged | Read owner-fenced exact bytes, repeat verified original-object cleanup, resolve and publish |
| Resolved | Reverify the recorded claim against exact bytes, recheck preflight and publish |
| Committed | Return the original result, without renewed authority or another provider effect |

Generation failure, failed staging, cleanup uncertainty, rejected evidence, failed
resolution and refused/uncertain publication remain distinguishable pending
results. No pending result is a cleanup, revocation or erasure receipt. A lost
dispatch response can strand an attempt even if Generate was never reached:
this deliberately sacrifices availability rather than risking duplicate keys.
Qualified reconciliation of such Reserved attempts, owner takeover, terminal
abort and reservation retirement are still unimplemented. An old owner must be
proven quiescent before recovery can treat an apparent absence as conclusive.

Retries arriving after staging may call cleanup while the original runner is
still active. The adapter must serialize effects on that exact attempt and make
cleanup/its evidence repeatable. A fresh-session empty label lookup, a successful
generic Destroy call, an expired lease or Drop is not that contract.

## Trusted adapter requirements and limits

`A2CreationProvider` extends `A2ClosureVerifier`. Installing it is a trusted
integration decision, not a user-configurable declaration of qualification. A real
adapter must qualify the exact provider/domain, parent and child specification,
wrapping mechanism, authenticated context, native attributes/trusted-wrap policy,
nonce/use limits and authority checks inside its claimed trust boundary. It must
correlate the attempt before effects, never blindly retry ambiguous Generate,
return neither plaintext material nor an independently operable child handle,
and prove closure of the original object/session. Cleanup cannot Generate,
unwrap or rewrap to recover missing bytes. Denied authority cannot excuse owed
cleanup. None of those provider claims follows from the scripted tests.

The driver uses the existing V1 creation journal and its BLAKE3 retry/digest
bindings. It does not invent another external encoding, migrate to the
[shared custody contract](CUSTODY_CONTRACT.md), reinterpret worker secret memory
as a provider session object, or turn a worker observation into `VerifiedA2Closure`.
An explicit reviewed adapter is needed for any future shared-contract binding.
The accepted shared custody codecs and frozen material/wrapping types are unchanged.

The storage/integration are trusted here. The dispatch bit, owner identity and
unkeyed digest are not authorization, cryptographic evidence or protection against
a malicious coordinator/database administrator. The preflight-to-publish sequence
is not an atomic distributed revocation barrier. Full authority/lease/result-release
and fencing semantics remain activation requirements.

Service activation also requires dependency-aware fencing **before destructive
provider effects**, complete per-version lifecycle, recursive resolution and
cache invalidation. Current ordinary deletion workers can call provider Destroy
before guarded metadata updates; the storage guard alone cannot protect a parent
already destroyed that way. The service caching wrapper does not support these
creation transactions. The PostgreSQL global write lock is a correctness-first
choice, not cloud-scale performance evidence. See storage documentation for the
intentional experimental-journal upgrade incompatibility.

## Executable checks

```sh
cargo test --locked -p keyrack-sqlite --test creation_driver
cargo test --locked -p keyrack-sqlite --lib
cargo test --locked -p keyrack-test-support
```

The driver tests use real SQLite transactions and scripted independent attempt
records for provenance. They cover lost dispatch/generation/staging/resolution/
publication responses, wrong intent/envelope/object claims, invalid envelope
length, denied preflight, changed parent, corrupt recovery snapshots, repeated
cleanup, concurrent retries during Generate and during cleanup, caller cancellation
and provider panic. The backend suite adds competing connections and reconnects.
These tests do not simulate a real HSM process crash or establish native wrapping,
HSM closure, operational HYOK or cross-provider custody preservation.
