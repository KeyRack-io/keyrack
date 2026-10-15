# KeyRack Use Cases

This folder maps out who needs KeyRack and how well we serve them today.

## Overview

| # | Use Case | Fit Today | Primary Path |
|---|---|---|---|
| 01 | [Greenfield Rust Backend](01-greenfield-rust-backend.md) | Excellent | Native gRPC/REST or library embed |
| 02 | [TypeScript / Browser](02-typescript-frontend.md) | Poor | WASM (no npm package yet) |
| 03 | [Go Services](03-go-services.md) | Good | Native gRPC or REST |
| 04 | [C/C++ / Embedded](04-c-cpp-embedded.md) | Medium | REST (C API not yet built) |
| 05 | [Python Services](05-python-services.md) | Good | Native REST or gRPC |
| 06 | [Brownfield Migration](06-brownfield-migration.md) | Requires application integration | Native gRPC/REST; AWS KMS and Barbican shims are commercial components outside this repo |
| 07 | [Crypto Agility / PQC](07-crypto-agility.md) | Good (framework) | Provider abstraction + rotation protocol |

The AWS KMS and OpenStack Barbican compatibility shims are commercial
components and are not part of this repository. Using Core directly requires
integration with its native API.

## "Migration" means four different things here

KeyRack uses the word *migration* for four distinct axes — don't conflate them:

| Axis | What moves | Where it's documented | Runnable reference |
|---|---|---|---|
| **Onboarding** from a cloud KMS | your *callers* (adapt to the native API, or use a separate commercial shim) | [06-brownfield-migration](06-brownfield-migration.md) | AWS KMS and Barbican shims are commercial components, not included in this repo |
| **Backend / provider** (BYOK ↔ HYOK, HSM-to-HSM) | where a key's *material* lives | [OPERATOR.md → Multiple providers and routing](../OPERATOR.md), [06-brownfield-migration](06-brownfield-migration.md#backend--provider-migration-byok--hyok) | [`demos/06-provider-routing`](../../demos/06-provider-routing/) |
| **Algorithm / crypto agility** (incl. PQC) | the *algorithm* a key uses | [07-crypto-agility](07-crypto-agility.md) | — (PQC algorithms pending) |
| **Identity** (rule / canonicalization changes) | a key's *parent / LID* | [MIGRATION.md](../../MIGRATION.md) | — (design + `keyrack migrate` CLI) |

## Key takeaways

1. **Brownfield integration uses the native API.** Applications moving to
   Core use gRPC or REST. AWS KMS and Barbican compatibility shims are
   commercial components outside this repository; an endpoint-only switch
   to Core is not supported here.

2. **Best-served: Rust greenfield.** This is the primary use case and
   where documentation, tooling, and examples are focused.

3. **Biggest gap: TypeScript/Browser.** The WASM target exists but has
   no developer experience. Fixing this requires a published npm package
   and higher-level API wrapper.

4. **Highest-value new work: Go SDK + Python SDK.** These two languages
   cover the majority of backend services. A thin SDK wrapper over
   gRPC (with connection pooling, retry, and error handling) would
   make KeyRack immediately usable for these ecosystems.

5. **Unique differentiator opportunity: C API.** No other KMS offers
   a C library. This opens IoT, embedded, and legacy system markets.

6. **Crypto agility is a positioning play.** The architecture supports
   it; the PQC algorithms aren't ready yet. Worth marketing now,
   delivering when the ecosystem catches up.
