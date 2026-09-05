# Provider-native wrapping: experimental mechanism probe

This is the first executable mechanism experiment for a provider-wrapped key
hierarchy. **It does not enable hierarchical keys in the service or establish a
conforming authenticated wrapping profile.** Existing key records and API behavior
remain unchanged; no production wrapping capability is advertised.

The probe uses a dedicated disposable SoftHSM token and standard PKCS#11 calls.
It generates a wrapping-only parent and a sensitive session child, wraps the child,
destroys the creation object, and unwraps only into a sensitive, non-extractable
session object. Application encryption/decryption uses that object's handle;
the test never needs the child's plaintext key value.

The probe asserts native object attributes, unusable tampered/wrong-
parent envelopes, explicit object/session cleanup, no persistent child objects,
and the distinction between cold parent loss and an already-open warm child.
They are provider-mechanism evidence, not complete service lifecycle or revocation
evidence. A live opened child is not automatically destroyed with its parent.

## Run in an isolated container

```sh
DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile.wrapping-probe -t keyrack-wrapping-probe:local .
docker run --rm --network none keyrack-wrapping-probe:local
```

BuildKit is required so the Dockerfile-specific context allowlist is honored.
The image contains tools and test binaries, not initialized tokens. The runner
creates and removes a fresh temporary token store. It does not mount existing
tokens, read deployment PINs, or modify a running service. The test PINs are
disposable fixtures.

On an isolated Linux development/CI machine with SoftHSM2 installed:

```sh
bash scripts/test-pkcs11-wrapping.sh
```

`KMS_PKCS11_LIB` can select the installed SoftHSM module. The runner deliberately
chooses its own token label and test PIN. Do not use this probe against production
tokens or treat its token initialization as a deployment persistence recipe.

## Remaining profile gate: authenticated context

AES-KW protects wrapped key bytes, but does not bind external child identity,
parent version, security domain or other metadata. General AES-GCM encryption
support also does not establish AES-GCM `C_WrapKey` support. The probe checks the
actual wrapping mechanism behavior rather than inferring it from data encryption.
The distinction is also visible in the upstream
[SoftHSM 2.6.1 wrapping dispatch](https://github.com/softhsm/SoftHSMv2/blob/2.6.1/src/lib/SoftHSM.cpp#L5978-L6004):
AES-GCM is not among the accepted wrapping mechanisms.

A full hierarchy profile still requires a reviewed construction authenticating
the complete canonical wrapping context, plus independently trusted currentness
evidence. Canonical context bytes alone supply neither authentication nor rollback
protection. No ad-hoc MAC, truncated context IV, weaker cipher or plaintext-key
fallback is introduced to make this probe look like a completed feature.

Persisted version representation, shared REST/gRPC integration, authorization and
purpose enforcement, bounded leases, rotation/rewrap, recovery and all hierarchy
release tests remain separate work. SoftHSM results do not certify hardware or a
malicious-coordinator deployment boundary.
