# KeyRack: Target API Usage Samples

> **These files predate the implementation.** They are design-time API sketches
> written during the integration cycle to validate developer experience. They
> reference crate names and types (`keyrack`, `@keyrack/client`) that don't
> exist yet — the actual library is `keyrack-core` and will evolve to match
> (or diverge from) these sketches as the implementation proceeds.
>
> They are **not runnable code** and are not compiled as part of the workspace.

## What these samples demonstrate

1. **Encrypting new data** — resolve a key by attributes, store the version number alongside ciphertext
2. **Decrypting existing data** — pass the same attributes + stored version to retrieve the exact key
3. **Crypto agility** — the developer never specifies algorithms; routing rules determine key specs. Updating rules upgrades new keys without breaking existing data or changing app code
4. **Data re-encryption** — when a DEK is rotated, the app re-encrypts its data (the app's actual job; KEK rotation is handled by the KeyRack service)

## Key design decisions visible in these samples

| Concern | How it works |
|---------|-------------|
| **Key identity** | Keys are identified by attributes — your own domain concepts (tenant, user, document ID, etc.). The LID is computed deterministically from these and never needs to be stored by the application. |
| **Version storage** | `resolve()` returns a version number (a `u32`). The app stores this single integer alongside each encrypted payload. That's the only KeyRack metadata in your data model. |
| **Versioned decryption** | `resolve_at_version(attributes, version)` reconstructs the same attributes the app already knows, plus the stored version, to retrieve the exact key material. |
| **Lazy decryption** | Apps that don't store the version can use `resolve_versions_desc(attributes)` to try from latest version downward. Viable when rotation is infrequent. |
| **Crypto agility** | Routing rules define key specs. New rules → new keys use new algorithms. Old keys unchanged. The app's encrypt/decrypt code is identical before and after an algorithm upgrade. |
| **DEK re-encryption** | When KeyRack rotates a DEK, it notifies the app. The app decrypts with the old version, re-encrypts with the new one, and updates its stored version. KEK rotation (re-wrapping child keys) is internal to the KeyRack service. |
| **Backend abstraction** | `ResolvedKey` exposes `material()` for Transit backends (bytes returned directly) and `operations()` for KMIP backends (ops to execute against HSM). The Rust example shows both paths; the TypeScript example focuses on Transit. |

## Files

- `app_example.rs` — Rust consuming application
- `app_example.ts` — TypeScript consuming application (library delivered as wasm-bindgen bindings)
