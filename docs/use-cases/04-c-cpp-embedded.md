# Use Case: C/C++ and Embedded Systems

## Who

C/C++ developers building systems that need key management — embedded
devices, IoT gateways, game engines, native applications, legacy
systems with C interfaces.

**Examples:** IoT device fleet management, industrial control systems,
native desktop applications, C libraries that need encryption.

## The problem

C/C++ projects need key management but:

- Most KMS solutions are SaaS-only (AWS KMS, GCP KMS) — no local option
- PKCS#11 is the standard HSM interface but provides no key lifecycle
  management, rotation, audit, or hierarchy
- Building key management in C is dangerous and error-prone
- Modern C projects often link to Rust for security-critical code

## How KeyRack could serve C

### Path 1: C API via `cbindgen` (new work)

KeyRack is written in Rust. Exposing a C-compatible API is natural:

```c
#include "keyrack.h"

keyrack_provider_t *provider = keyrack_provider_new_software();
keyrack_key_t *key = keyrack_generate_key(provider, KEYRACK_AES_256);

keyrack_ciphertext_t *ct = keyrack_encrypt(provider, key, data, len, NULL, 0);
keyrack_plaintext_t *pt = keyrack_decrypt(provider, key, ct, NULL, 0);

keyrack_free_plaintext(pt);
keyrack_free_ciphertext(ct);
keyrack_free_key(key);
keyrack_free_provider(provider);
```

This would be a thin FFI layer over `keyrack-core`, exposing:
- Key generation, encrypt, decrypt, sign, verify
- Provider selection (software, PKCS#11)
- Memory management via explicit free functions

### Path 2: REST API (available today)

Any C program with `libcurl` can talk to KeyRack's REST API:

```c
// Already works — curl http://localhost:8080/v1/keys -X POST ...
```

### Path 3: gRPC via `grpc-c` (possible but heavy)

gRPC has C bindings, but they're rarely used in pure C projects. Better
for C++ projects that already use gRPC.

## Fit rating

**Medium for local embedding via C API. Good for networked via REST.**

The REST path works today for any C program that can make HTTP calls.
The C API path requires new work (FFI layer, memory management, build
system integration) but is technically straightforward.

## What would be needed

| Item | Effort | Impact |
|---|---|---|
| `keyrack-ffi` crate (C API) | 1-2 weeks | High — unique differentiator |
| `keyrack.h` header generation | 1 day | Included with above |
| CMake/pkg-config integration | 2-3 days | High — C build system compatibility |
| C example project | 1-2 days | Medium |
| Static and shared library builds | 1-2 days | High |

## Strategic note

Few KMS solutions offer a C API. This would be a genuine differentiator,
especially for:

- **IoT** — devices that need key rotation and crypto agility
- **Legacy systems** — C codebases that can't adopt Go/Rust but need
  modern key management
- **System libraries** — projects like OpenSSL providers, PAM modules,
  or database encryption plugins

However, the C audience is small relative to Go/Python/JS. Prioritize
this only if there's a specific customer pull or if the IoT/embedded
angle aligns with the product strategy.
