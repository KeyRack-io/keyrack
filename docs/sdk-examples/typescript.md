# TypeScript — Before and After

## Scenario A: Node.js API encrypting user secrets

A Node.js backend stores API keys for third-party integrations.
Each user's keys must be encrypted at rest and rotatable.

## Scenario B: Browser app with end-to-end encryption

A document editor where documents are encrypted client-side before
upload. The server never sees plaintext.

---

## Scenario A — Node.js API

### Before: `crypto` module + env var

```typescript
import crypto from "node:crypto";

const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY!, "hex");
const ALGORITHM = "aes-256-gcm";

function encrypt(plaintext: string): { iv: string; ciphertext: string; tag: string } {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    iv: iv.toString("hex"),
    ciphertext: encrypted.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
  };
}

function decrypt(data: { iv: string; ciphertext: string; tag: string }): string {
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    ENCRYPTION_KEY,
    Buffer.from(data.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(data.tag, "hex"));
  return decipher.update(data.ciphertext, "hex", "utf8") + decipher.final("utf8");
}

// Store a user's third-party API key
async function storeApiKey(db: Database, userId: string, apiKey: string) {
  const encrypted = encrypt(apiKey);
  await db.query(
    "INSERT INTO api_keys (user_id, iv, ciphertext, tag) VALUES ($1, $2, $3, $4)",
    [userId, encrypted.iv, encrypted.ciphertext, encrypted.tag]
  );
  // No audit. No rotation. No per-user isolation.
  // One env var key for all users.
}
```

### After: `@keyrack/client`

```typescript
import { KeyRack } from "@keyrack/client";

const kr = new KeyRack({
  serviceUrl: "http://localhost:8080",
  auth: { token: process.env.KEYRACK_TOKEN },
});

async function storeApiKey(db: Database, userId: string, apiKey: string) {
  // Per-user DEK, managed by KeyRack
  const key = await kr.createKey("AES_256", {
    parent: `user-kek-${userId}`,
    description: "third-party-api-key-dek",
    tags: { user: userId, purpose: "api_keys" },
  });

  // Encrypt with context binding
  const ciphertext = await kr.encrypt(key.id, Buffer.from(apiKey), {
    encryptionContext: { user: userId, purpose: "api_key" },
  });

  // Single blob — key ID, version, context hash all embedded in header
  await db.query(
    "INSERT INTO api_keys (user_id, ciphertext) VALUES ($1, $2)",
    [userId, ciphertext]
  );
}

async function readApiKey(db: Database, userId: string): Promise<string> {
  const row = await db.queryOne("SELECT ciphertext FROM api_keys WHERE user_id = $1", [userId]);

  // KeyRack reads key ID from header, decrypts with correct version
  const plaintext = await kr.decrypt(row.ciphertext, {
    encryptionContext: { user: userId, purpose: "api_key" },
  });

  return plaintext.toString();
}

// Rotation: kr.rotateKey("user-kek-alice")
// All of Alice's DEKs get rotation jobs. Background worker re-encrypts.
```

---

## Scenario B — Browser E2EE

### Before: raw WebCrypto

```typescript
// Every developer writes this differently. Most get it wrong.

async function encryptDocument(doc: ArrayBuffer): Promise<ArrayBuffer> {
  // Where does the key come from? How is it stored? How is it rotated?
  // WebCrypto doesn't help with any of this.
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    doc
  );

  // Now what? How do you:
  // - Store the key securely in the browser?
  // - Sync the key with the server (for other devices)?
  // - Rotate the key?
  // - Know which key encrypted which document?
  // Answer: you build all of this yourself, and probably get it wrong.

  // Manually prepend IV to ciphertext
  const result = new Uint8Array(iv.length + new Uint8Array(ciphertext).length);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), iv.length);
  return result.buffer;
}
```

### After: `@keyrack/wasm`

```typescript
import { KeyRack } from "@keyrack/wasm";

// Initialize WASM module (one-time, ~500ms)
const kr = await KeyRack.init({
  serviceUrl: "https://api.example.com/keyrack",
  auth: { bearer: userJwt },
});

async function encryptDocument(docId: string, content: ArrayBuffer): Promise<Uint8Array> {
  // KeyRack resolves or creates the user's document DEK.
  // Key hierarchy: User KEK → Document DEK
  // Key never leaves the browser in plaintext — WASM does crypto locally.
  return kr.encrypt("doc-dek-" + docId, new Uint8Array(content), {
    encryptionContext: { doc: docId, user: currentUser.id },
  });
  // Returns ciphertext with self-describing header.
  // Upload to server. Server sees only ciphertext.
}

async function decryptDocument(ciphertext: Uint8Array): Promise<ArrayBuffer> {
  // KeyRack reads key ID from header, fetches wrapped DEK from server,
  // unwraps locally, decrypts locally. Server never sees plaintext.
  const plaintext = kr.decrypt(ciphertext, {
    encryptionContext: { doc: docId, user: currentUser.id },
  });
  return plaintext.buffer;
}
```

### What changed

| Concern | Before (Node) | Before (Browser) | After |
|---------|---------------|-------------------|-------|
| Key management | Env var | Manual WebCrypto | KeyRack manages lifecycle |
| Key storage | Process memory | ???  | HSM (server), IndexedDB (browser) |
| Rotation | Redeploy | Not addressed | `rotateKey()` + cooperative re-wrap |
| Audit | None | None | Server-side audit log |
| Multi-device sync | N/A | Build it yourself | KeyRack syncs wrapped DEKs |
| Encryption context | None | None | AAD-bound |
