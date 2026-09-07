# Worker verification scope

The worker uses three complementary checks. Ordinary property tests run in the
Test job; the Worker bounded verification job runs Kani and an IPC fuzz smoke
campaign. These checks do not activate a production execution profile.

## Release transition proofs

`src/release_state.rs` is the actual allocation-free transition kernel called by
`delivery.rs` under the release/fence mutex. The standalone Kani invocation
avoids compiling unrelated HTTP and cryptographic dependencies. It does not use
a substitute transition model, mocked policy, or conditional runtime implementation.
The [Kani standalone interface](https://model-checking.github.io/kani/usage.html)
checks the following registered harnesses:

```sh
kani crates/keyrack-crypto-worker/src/release_state.rs --harness worker_fence_release_interleavings
kani crates/keyrack-crypto-worker/src/release_state.rs --harness worker_release_checks_every_retry
kani crates/keyrack-crypto-worker/src/release_state.rs --harness worker_invalid_fence_preserves_admission
```

The first explores eight arbitrary serialized transitions and symbolic write
success/retry outcomes: accepted fence/stop prevents later commits, each permit
commits at most once, and committed output never becomes suppressed. The second
checks retry admission with arbitrary 64-bit generation/deadline values and
incarnation match results. The third checks that rejected fencing preserves state.
The runner executes every entry of `verification/kani-harnesses.json`; the ordinary
`documented_kani_harnesses_exist` test checks the registry against proof annotations
and these documented commands. The existing core `documented_kani_harnesses_exist` control also validates this
worker registry, proof annotations and documented invocations.

The proofs assume the caller computes incarnation equality correctly, verifies
fence authenticity correctly, holds the mutex across the callback, and uses the
stated atomic pipe-write contract. They do not model OS scheduling, actual reader
consumption, crypto correctness or memory zeroization. Eight transitions are a
bounded result, not a proof of all infinite executions. Runtime deterministic and
subprocess race tests cover the integration with locks and pipes. The documented
release-admission/OS-preemption limitation in OUTPUT_RELEASE.md still applies.

## Generated cache sequences

The property test executes the real Worker against an independent residency model
for 192 generated sequences of up to 95 actions, with 1–3 cache slots and five
contexts. It checks cache capacity, exact lease/deadline/use-count state, provider
call counts, warm-cache non-renewal, source failure, replay, valid/invalid fences,
and rejection of old-incarnation grants after restart. Idle sweeps are generated
immediately before, at and after deadlines and must report each removed lease once.
This verifies the sweep operation; it is not a hard wall-clock scheduling proof.

```sh
cargo test -p keyrack-crypto-worker core::tests::properties
```

## IPC fuzzing

The fuzz target includes the same `src/ipc.rs` used by the executable. It exercises
bounded framing and strict request deserialization, compares fragmented and
contiguous readers, and checks the frame-size limit. Seeds cover each command,
duplicate fields, truncation, nested JSON and the frame limit. It does not execute
untrusted operations against Vault or claim proof of authorization correctness.

```sh
cd crates/keyrack-crypto-worker
cargo +nightly fuzz run ipc_decoder -- -max_total_time=60 -max_len=70000 -timeout=5
```

The CI script uses a temporary writable corpus, retains crash artifacts, and treats
build errors, crashes and timeouts as failures. A bounded smoke run is evidence for
that run, not exhaustive decoder correctness. Longer campaigns can use the same
[target and cargo-fuzz interface](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html).
