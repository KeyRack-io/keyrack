# @keyrack/keyrack-wasm

KeyRack cryptographic operations in the browser and Node.js via WebAssembly.

## Installation

```bash
npm install @keyrack/keyrack-wasm
```

## Usage

```typescript
import init, { WasmKeyRack } from "@keyrack/keyrack-wasm";

// Initialize the WASM module
await init();

const kr = new WasmKeyRack();

// Generate a key and encrypt data
const keyId = await kr.generateKey("AES_256");
const plaintext = new TextEncoder().encode("sensitive data");
const aad = new Uint8Array();

const ciphertext = await kr.encrypt(keyId, plaintext, aad);
const decrypted = await kr.decrypt(keyId, ciphertext, aad);

console.log(new TextDecoder().decode(decrypted)); // "sensitive data"
```

### Signing and verification

```typescript
// Ed25519
const sigKey = await kr.generateKey("ED25519");
const message = new TextEncoder().encode("sign me");
const signature = await kr.signEd25519(sigKey, message);
const valid = await kr.verifyEd25519(sigKey, message, signature);

// ECDSA P-256
const ecKey = await kr.generateKey("ECDSA_P256");
const ecSig = await kr.signEcdsaP256(ecKey, message);
const ecValid = await kr.verifyEcdsaP256(ecKey, message, ecSig);
```

### Logical ID computation

```typescript
const lid = kr.computeLid('{"kind":"dek","tenant":"acme"}');
```

## Supported algorithms

| Spec | Algorithm | Usage |
|------|-----------|-------|
| `AES_256` | AES-256-GCM | Encrypt / Decrypt |
| `ED25519` | Ed25519 | Sign / Verify |
| `ECDSA_P256` | ECDSA P-256 SHA-256 | Sign / Verify |
| `RSA_2048` | RSA PKCS#1 v1.5 SHA-256 | Sign / Verify |
| `RSA_3072` | RSA PKCS#1 v1.5 SHA-256 | Sign / Verify |
| `RSA_4096` | RSA PKCS#1 v1.5 SHA-256 | Sign / Verify |

## Building from source

```bash
# Install wasm-pack
cargo install wasm-pack

# Build
cd crates/keyrack-wasm
./build.sh
```

## License

AGPL-3.0-or-later (commercial licensing available)
