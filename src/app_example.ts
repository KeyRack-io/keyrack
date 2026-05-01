/**
 * KeyRack: TypeScript consuming application example
 *
 * This file demonstrates the target API for an application using the KeyRack
 * TypeScript client (delivered as wasm-bindgen bindings over the Rust core).
 *
 * It is syntactically valid TypeScript but references `@keyrack/client` which
 * does not exist yet — this is the API we intend to build.
 */

import {
  KeyRack,
  ResolvedKey,
  ReencryptionJob,
  type Attributes,
} from "@keyrack/client";

// ---------------------------------------------------------------------------
// Your application's data model (NOT part of KeyRack)
// ---------------------------------------------------------------------------

interface EncryptedDocument {
  id: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  /**
   * The key version used at encryption time. This is the ONLY piece of
   * KeyRack metadata you need to persist. The attributes that identify
   * the key (tenant, user, doc ID) are your own domain data — you already
   * know them when it's time to decrypt.
   */
  keyVersion: number;
}

// Stubs for your own infrastructure
declare const db: {
  store(doc: EncryptedDocument): Promise<void>;
  load(id: string): Promise<EncryptedDocument>;
  findByKeyVersion(attrs: Attributes, version: number): Promise<EncryptedDocument[]>;
  update(id: string, ct: Uint8Array, nonce: Uint8Array, keyVersion: number): Promise<void>;
};

declare const appCrypto: {
  aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  aesGcmDecrypt(key: Uint8Array, ciphertext: Uint8Array, nonce: Uint8Array): Promise<Uint8Array>;
};

// ===========================================================================
//  MAIN
// ===========================================================================

async function main(): Promise<void> {
  // -------------------------------------------------------------------------
  // 1. CONNECT TO KEYRACK
  // -------------------------------------------------------------------------

  const kr = await KeyRack.connect("https://keyrack.internal:8443");

  // -------------------------------------------------------------------------
  // 2. REGISTER NAMESPACE (once per application, typically at deploy time)
  // -------------------------------------------------------------------------
  //
  // Routing rules define key hierarchy AND cryptographic parameters.
  // Crypto agility lives here: update rules to upgrade algorithms for newly
  // created keys, without changing any application encrypt/decrypt code.

  await kr.registerNamespace({
    name: "docs-app",
    attachment: { tenant: "acme" },
    rules: [
      // Document DEK -> wrapped by user KEK
      {
        match: { kind: "dek", tenant: "$T", user: "$U", doc: "$D" },
        parent: { kind: "user-kek", tenant: "$T", user: "$U" },
      },
      // User KEK -> wrapped by app root
      {
        match: { kind: "user-kek", tenant: "$T", user: "$U" },
        parent: { kind: "app-root", tenant: "$T" },
      },
      // App root -> attached to infrastructure hierarchy
      {
        match: { kind: "app-root", tenant: "$T" },
        parent: null, // resolved via attachment
      },
    ],
  });

  // -------------------------------------------------------------------------
  // 3. ENCRYPT NEW DATA
  // -------------------------------------------------------------------------

  // Describe what this key is *for* using attributes. These are your own
  // domain concepts — KeyRack resolves them to the correct key, provisioning
  // the entire chain lazily if needed.
  const resolved: ResolvedKey = await kr.resolve({
    kind: "dek",
    tenant: "acme",
    user: "user-123",
    doc: "invoice-42",
  });

  // resolved.version is the ONLY thing from KeyRack you need to persist.
  // The attributes (tenant, user, doc) are your own data — you already
  // know them when it's time to decrypt.
  const version: number = resolved.version;
  console.log(`Resolved key version: ${version}`);

  // For the TypeScript client the backend is typically Transit, so key
  // material is returned directly. (KMIP apps are more likely Rust-native.)
  const dek: Uint8Array = resolved.material();

  const plaintext = new TextEncoder().encode("sensitive invoice data");
  const { ciphertext, nonce } = await appCrypto.aesGcmEncrypt(dek, plaintext);

  // Persist: ciphertext + nonce + version number
  await db.store({
    id: "invoice-42",
    ciphertext,
    nonce,
    keyVersion: version,
  });

  // -------------------------------------------------------------------------
  // 4. DECRYPT EXISTING DATA
  // -------------------------------------------------------------------------

  const doc = await db.load("invoice-42");

  // Reconstruct the same attributes (they're your domain data) and pass
  // the stored version to get the EXACT key material used at encryption.
  const decryptKey: ResolvedKey = await kr.resolveAtVersion(
    {
      kind: "dek",
      tenant: "acme",
      user: "user-123",
      doc: "invoice-42",
    },
    doc.keyVersion,
  );

  const decryptDek: Uint8Array = decryptKey.material();
  const decrypted = await appCrypto.aesGcmDecrypt(decryptDek, doc.ciphertext, doc.nonce);

  console.log("Decrypted:", new TextDecoder().decode(decrypted));

  // For applications that don't store the version at all ("lazy mode"),
  // KeyRack can return versions from latest downward. The app tries each
  // until decryption succeeds. Viable when rotation is infrequent:
  //
  //   for await (const candidate of kr.resolveVersionsDesc({ kind: "dek", ... })) {
  //     try {
  //       const result = await appCrypto.aesGcmDecrypt(candidate.material(), ct, nonce);
  //       return result; // success
  //     } catch {
  //       continue; // wrong version, try next
  //     }
  //   }

  // -------------------------------------------------------------------------
  // 5. CRYPTO AGILITY
  // -------------------------------------------------------------------------
  //
  // Suppose the operator updates routing rules to use stronger algorithms
  // (e.g. AES-128-GCM -> AES-256-GCM, or to a post-quantum cipher).
  //
  // No application code changes:
  //   - Existing keys: still decryptable via stored version
  //   - New keys: automatically use the updated spec
  //
  // You can inspect what spec was used:

  const newResolved = await kr.resolve({
    kind: "dek",
    tenant: "acme",
    user: "user-456",
    doc: "invoice-99",
  });

  const spec = newResolved.keySpec;
  console.log(`invoice-99 uses algorithm=${spec.algorithm}, size=${spec.size}`);

  // Both invoice-42 (old spec) and invoice-99 (new spec) decrypt correctly.
  // The stored version number is enough — KeyRack knows which algorithm and
  // parameters were used for each version.

  // -------------------------------------------------------------------------
  // 6. DATA RE-ENCRYPTION (the app's job during DEK rotation)
  // -------------------------------------------------------------------------
  //
  // KEK rotation (re-wrapping child keys) is handled entirely by the
  // KeyRack service — the app is not involved.
  //
  // DEK rotation is the app's responsibility: when KeyRack creates a new
  // version of a DEK, the app must re-encrypt its data with the new version.
  // This is typically run in a background worker, not the request path.

  const events: ReencryptionJob[] = await kr.pollDataReencryptionJobs("docs-app");

  for (const event of events) {
    // event.attributes: which key was rotated
    // event.oldVersion: the version being retired
    // event.newVersion: the new current version
    await kr.acknowledgeReencryptionJob(event.id);

    // Find all your data encrypted with the old DEK version.
    // This query is YOUR responsibility — only you know your data model.
    const affected = await db.findByKeyVersion(event.attributes, event.oldVersion);

    for (const affectedDoc of affected) {
      // Decrypt with old version
      const oldKey = await kr.resolveAtVersion(event.attributes, affectedDoc.keyVersion);
      const oldDek = oldKey.material();
      const oldPlaintext = await appCrypto.aesGcmDecrypt(
        oldDek,
        affectedDoc.ciphertext,
        affectedDoc.nonce,
      );

      // Re-encrypt with new version
      const newKey = await kr.resolve(event.attributes);
      const newDek = newKey.material();
      const reEncrypted = await appCrypto.aesGcmEncrypt(newDek, oldPlaintext);

      // Update stored data with new ciphertext and new version
      await db.update(
        affectedDoc.id,
        reEncrypted.ciphertext,
        reEncrypted.nonce,
        newKey.version,
      );
    }

    await kr.completeReencryptionJob(event.id);
  }

  console.log(`Processed ${events.length} re-encryption jobs`);
}

main().catch(console.error);
