# KeyRack Language Support

## Coverage today

| Language | Native library | Service access | Status |
|----------|---------------|----------------|--------|
| **Rust** | `keyrack-core` (embed), `keyrack` (client facade) | gRPC, REST | **Shipped** (library is production-grade; facade is API-shaped stub) |
| **TypeScript/JS** | `keyrack-wasm` (WASM + TS types) | REST, gRPC-Web | **Scaffolding** (build scripts and types exist; no functional WASM module) |
| **Go** | — | gRPC (protoc-gen-go), REST, AWS KMS shim | **No SDK.** gRPC works via generated stubs. |
| **Python** | — | REST, gRPC (grpcio), AWS KMS shim (boto3) | **No SDK.** REST is usable but not idiomatic. |
| **Java/Kotlin** | — | gRPC (protoc-gen-java), REST, AWS KMS shim | **No SDK.** |
| **C#/.NET** | — | gRPC (Grpc.Tools), REST, AWS KMS shim | **No SDK.** |
| **C/C++** | — | REST (libcurl) | **No SDK.** C FFI from Rust is natural but not built. |
| **Ruby** | — | REST, AWS KMS shim | **No SDK.** |
| **PHP** | — | REST, AWS KMS shim | **No SDK.** |
| **Swift** | — | REST, gRPC (grpc-swift) | **No SDK.** |

## Which languages matter most

### Tier 1 — build native SDKs

| Language | Why | Effort | Form |
|----------|-----|--------|------|
| **Go** | Dominant cloud-native language. a partner uses Go. K8s ecosystem. | 3-5 days | gRPC client wrapper with retry, pooling, typed errors |
| **Python** | Largest web backend community. Django/FastAPI/Flask. | 2-3 days | REST wrapper (`pip install keyrack`) |
| **TypeScript** | Browser + Node.js. Growing backend share (Deno, Bun). | 1-2 weeks | WASM module + REST client + npm package |

### Tier 2 — serve via existing infrastructure

| Language | Access path | Why not a native SDK yet |
|----------|-------------|------------------------|
| **Java/Kotlin** | gRPC generated stubs, AWS KMS shim | Enterprise adoption usually comes through compatibility (AWS shim), not a new SDK |
| **C#/.NET** | gRPC generated stubs, AWS KMS shim | Same reasoning as Java |
| **Ruby** | REST API, AWS KMS shim | Smaller addressable market |
| **PHP** | REST API, AWS KMS shim | Smaller addressable market |

### Tier 3 — unique differentiator

| Language | Access path | Why it matters |
|----------|-------------|---------------|
| **C/C++** | `keyrack-ffi` crate via `cbindgen` | No other KMS offers a C library. Opens IoT, embedded, legacy. |
| **Swift** | C FFI (via the C library above) or REST | iOS/macOS device-side key management |

## The key insight

Languages in Tier 2 don't need a native KeyRack SDK because the **AWS KMS shim is their SDK.** A Java service using `aws-sdk-java` pointed at the KeyRack AWS shim gets full KeyRack lifecycle management without any new dependency. Same for C#, Ruby, PHP — anything with an AWS SDK.

The languages that need native SDKs are those where:
1. The developer is building **greenfield** (no existing AWS SDK usage) — Go, Python
2. The environment is **browser/edge** (no server to proxy through) — TypeScript/WASM
3. The environment has **no network** (embedded/IoT) — C/C++

## Before/after examples

See [`docs/sdk-examples/`](sdk-examples/) for detailed before/after code in each language, showing how a typical key management task looks today vs. with KeyRack.
