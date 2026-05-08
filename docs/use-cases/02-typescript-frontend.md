# Use Case: TypeScript / Browser Applications

## Who

Frontend engineers building browser or Node.js applications that need
client-side encryption, data signing, or end-to-end encrypted features.

**Examples:** E2EE messaging, secure document editors, client-side
encrypted storage, browser-based credential managers.

## The problem

Browser crypto is hard:
- WebCrypto API is low-level and footgun-prone
- Key management (generation, storage, rotation) must be handled manually
- No standard way to interoperate with a server-side KMS
- Each framework has its own patterns (or none at all)

## How KeyRack could help

KeyRack has a `keyrack-wasm` crate that compiles to WebAssembly, exposing
the same `CryptoProvider` interface that the Rust backend uses.

### Current state (v0.1)

```typescript
// You would need to write this wrapper yourself today
import init, { WasmProvider } from 'keyrack-wasm';
await init();

const provider = new WasmProvider();
const key = provider.generateKey('AES_256');
const ct = provider.encrypt(key, plaintext);
const pt = provider.decrypt(key, ct);
```

### What's actually shipped

The WASM crate exists and compiles, but:

- No published npm package
- No TypeScript type definitions
- No ergonomic JS/TS wrapper (raw `wasm-bindgen` exports only)
- No integration with the KeyRack service (pure local crypto)
- No key persistence or synchronization
- No examples beyond the crate's own tests

## Fit rating

**Poor today. Medium-term potential.**

The building blocks exist (WASM compilation, WebCrypto provider), but
there is no usable developer experience. A frontend engineer would need
to write their own wrapper, handle key serialization, and build the
service integration layer.

## What would make this viable

1. **npm package** — published `@keyrack/wasm` with TypeScript types
2. **High-level API** — `KeyRack.encrypt(data)` instead of raw provider calls
3. **Service bridge** — optional REST client that syncs with a KeyRack server
4. **Key storage** — IndexedDB or localStorage adapter for persisting handles
5. **Framework adapters** — React hooks, Vue composables, etc.
6. **Documentation** — end-to-end browser example with a real use case

## Effort estimate

| Item | Effort |
|---|---|
| npm package + TS types | 2-3 days |
| High-level JS API wrapper | 3-5 days |
| REST client bridge | 2-3 days |
| IndexedDB adapter | 1-2 days |
| React hooks | 2-3 days |
| Documentation + examples | 2-3 days |
| **Total** | **~2-3 weeks** |

## Strategic note

This use case is important for adoption but should not be prioritized
over the core backend story. A minimal viable offering would be an npm
package with TypeScript types and a basic example — that alone would
differentiate KeyRack from every other KMS.
