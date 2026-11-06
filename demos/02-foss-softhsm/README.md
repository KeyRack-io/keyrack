# Demo 2 — KeyRack FOSS + SoftHSM2 (PKCS#11)

This demo runs KeyRack with ordinary AES keys through the PKCS#11 interface,
using [SoftHSM2](https://www.opendnssec.org/softhsm/) as the provider.

SoftHSM2 is a software token loaded into the KeyRack service process. It does
not provide hardware custody or keep key material outside that process's memory.
The demo uses independent tenant and data keys: `parent_key_id` requests wrapped
key material, and this ordinary provider configuration has no wrapping opt-in.

## What it demonstrates

| Step | Operation | Detail |
|------|-----------|--------|
| 1 | Create tenant key | Nonempty key ID and `pkcs11` provider asserted |
| 2 | Create independent data key | Distinct nonempty ID, `pkcs11` provider and initial version 1 asserted |
| 3 | Encrypt | AES-256-GCM through SoftHSM2; nonempty ciphertext asserted |
| 4 | Decrypt | Round-trip verified |
| 5 | Rotate key | Version 2 asserted after generating new material in SoftHSM2 |
| 6 | Decrypt (old) | Old ciphertexts still work after rotation |
| 7 | Encrypt and decrypt (new) | Post-rotation payload round-trip verified |
| 8 | Describe key | PKCS#11 provider class and version 2 asserted |

## Run

```bash
docker compose up --build
```

The demo container runs automatically once KeyRack is healthy, fails on HTTP
errors or failed assertions, and prints `ALL CHECKS PASSED` on success.

## Architecture

```
┌────────────────────────────────────┐
│         KeyRack Service            │
│  (REST :8080 / gRPC :50051)       │
│                                    │
│  ┌──────────────────────────────┐  │
│  │   PKCS#11 CryptoProvider     │  │
│  │   (keyrack-pkcs11 crate)     │  │
│  └────────────┬─────────────────┘  │
│               │ PKCS#11 C_*() calls│
│  ┌────────────▼─────────────────┐  │
│  │   SoftHSM2                   │  │
│  │   /usr/lib/softhsm/          │  │
│  │   Token: keyrack-demo        │  │
│  └──────────────────────────────┘  │
└────────────────────────────────────┘
```

## Scope and deployment

The image uses the distribution's SoftHSM2 package and initializes a disposable
demo token with public credentials. Its configuration disables authentication and
authorization for demonstration. Do not deploy it unchanged.

This demo does not qualify the experimental context-derived native wrapping
profile. That profile requires a dedicated provider, explicit opt-in and its own
[qualification checks](../../docs/OPERATOR.md#experimental-context-derived-wrapping-profile). Hardware tokens need
separate provider qualification; success with SoftHSM2 does not qualify them.
