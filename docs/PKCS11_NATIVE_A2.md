# Native PKCS#11 A2 candidate

Status: **unqualified, conformance-only internals**, not an enabled service
provider. The `native-a2-conformance` feature compiles native Generate/Wrap,
Unwrap/use and original-session Close in `keyrack-pkcs11`. Default builds omit
this developer entry point. `wrapping_capabilities()` remains empty, including
when the feature is enabled. The shared wrapping-trait/creation-journal adapter
is not implemented by this slice; its incoming signatures must be consumed, not
replaced by these synchronous internal methods.

## What the engine establishes

- A native attempt is consumed before provider reads/effects. Generate and Unwrap
  never go through the ordinary provider's automatic recovery/retry wrapper.
- An owned session retains module admission even while idle; library recovery
  cannot finalize underneath it. Session close/destructor precedes admission
  release. An idle lease can delay recovery until closed; no TTL is invented here.
- Opened AES leaves must be session-only, sensitive, non-extractable,
  non-copyable, non-modifiable and restricted to their intended use. Readback
  mismatches refuse use without attribute repair. No operable child handle or
  raw key bytes are returned. Application plaintext is a separate operation result.
- Explicit Close is locally repeatable. A consumed close error stays unconfirmed;
  a destructor's possible cleanup is not evidence. This is not a creation closure,
  lease-cleanup attestation or revocation receipt.

The owner is synchronous, Send and not Sync. Async serialization, cancellation
ownership, opaque lease dispatch and durable restart reconciliation belong in the
pending shared adapter. A fresh owner is not permission to repeat an uncertain
journal attempt. The in-process `NativeEnvelope` is not a persisted wire format.

## Mechanism versus custody

`GcmCandidate` supplies the complete existing canonical context to native GCM.
`KwMechanicsOnly` exercises AES-KW without claiming external context authentication.
Selection is explicit, never a fallback after failure. Host-side intent comparisons
are not cryptographic binding against a malicious coordinator.

SoftHSM's positive KW lifecycle therefore cannot satisfy the current hierarchy
gate. Its native GCM Wrap refusal must be `MechanismInvalid` at `WrapKey`, not a
generic device error treated as success. No result from this profile may fabricate
`VerifiedA2Closure` or publish an A2 creation through a permissive verifier.

SoftHSM 2.7.0 also reports zero `CKA_VALUE_LEN` after native unwrap: its source
sets the secret value without updating that size attribute. The **KW mechanics
profile only** permits expected length or exactly zero after checking the original
generated length and exact KW ciphertext length. Missing, duplicate or other
lengths refuse; all remaining attributes stay strict. Zero is not independent
size evidence. GCM candidate, parent and generation readback retain exact size
requirements. [SoftHSM 2.7.0 unwrap implementation](https://github.com/softhsm/SoftHSMv2/blob/2.7.0/src/lib/SoftHSM.cpp#L7073-L7102)

The strict template puts `CKA_MODIFIABLE=false` last. SoftHSM 2.6.1 processes
attributes in caller order and rejects further unwrap attributes once this flag
has been applied; 2.7.0 exempts unwrap from that check. Ordering changes expression,
not policy: the same flags are supplied in one native call, every flag is checked
afterward, and there is no retry or post-creation attribute repair.
[2.6.1 attribute processing](https://github.com/softhsm/SoftHSMv2/blob/2.6.1/src/lib/P11Objects.cpp#L218-L240),
[2.6.1 immutability check](https://github.com/softhsm/SoftHSMv2/blob/2.6.1/src/lib/P11Attributes.cpp#L413-L417),
[2.7.0 unwrap exemption](https://github.com/softhsm/SoftHSMv2/blob/2.7.0/src/lib/P11Attributes.cpp#L413-L417)

Trusted wrapping/unwrap-template policy, exact trusted parent/provider/domain
resolution, native nonce accounting, authority/freshness and per-token qualification
remain gates. In particular, cryptoki's GCM wrap performs two native calls and a
random IV alone is not a qualified nonce policy. Neither candidate claims custody.

## Reproducible live evidence

```sh
RUSTUP_TOOLCHAIN=1.98.0 bash scripts/test-pkcs11-wrapping.sh
```

The existing runner creates a fresh disposable SoftHSM token, retains the original
primitive probe, and runs the provider-owned lifecycle test in a separate process.
It first verifies that the named new test exists and is not ignored. The native
test verifies SoftHSM module/token identity and unique slot selection before login
or creation. The existing Docker fixture builds both paths; no second stack exists.

Assertions include exact GCM refusal/no retry, KW generation/open/use/close,
caller-AAD rejection, changed intent/wrong parent/corrupt envelope/wrong mechanism,
no use after close, destructor cleanup without claiming evidence, and idle-session
admission blocking quiescence. Cold parent loss prevents opening; an already-open
child remains usable until closed. This warm-copy limit is intentional evidence,
not a revocation or erasure success. Successful completion checks an empty token.
