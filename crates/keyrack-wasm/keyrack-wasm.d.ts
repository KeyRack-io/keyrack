/**
 * TypeScript type definitions for @keyrack/keyrack-wasm.
 *
 * These types supplement the wasm-bindgen auto-generated definitions
 * with higher-level documentation and stricter typing.
 */

/** Supported key specification strings. */
export type KeySpec =
  | "AES_256"
  | "ED25519"
  | "RSA_2048"
  | "RSA_3072"
  | "RSA_4096"
  | "ECDSA_P256";

/**
 * KeyRack client for WASM environments.
 *
 * Uses the pure-Rust SoftwareProvider under the hood. All key material
 * lives in WASM linear memory and is dropped when the instance is
 * garbage-collected.
 *
 * @example
 * ```typescript
 * import init, { WasmKeyRack } from "@keyrack/keyrack-wasm";
 *
 * await init();
 * const kr = new WasmKeyRack();
 *
 * // Encrypt / decrypt
 * const keyId = await kr.generateKey("AES_256");
 * const ciphertext = await kr.encrypt(keyId, plaintext, aad);
 * const decrypted = await kr.decrypt(keyId, ciphertext, aad);
 *
 * // Sign / verify (Ed25519)
 * const sigKeyId = await kr.generateKey("ED25519");
 * const signature = await kr.signEd25519(sigKeyId, message);
 * const valid = await kr.verifyEd25519(sigKeyId, message, signature);
 *
 * // Compute a Logical ID (LID) from attributes
 * const lid = kr.computeLid('{"kind":"dek","tenant":"acme"}');
 * ```
 */
export class WasmKeyRack {
  constructor();

  /**
   * Generate a key and return its ID.
   * @param spec - Key algorithm specification
   * @returns Key ID string handle
   */
  generateKey(spec: KeySpec): Promise<string>;

  /**
   * Encrypt plaintext using AES-256-GCM.
   * @param keyId - Key ID from generateKey
   * @param plaintext - Data to encrypt
   * @param aad - Additional authenticated data (pass empty Uint8Array for none)
   * @returns Ciphertext bytes
   */
  encrypt(keyId: string, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;

  /**
   * Decrypt ciphertext produced by encrypt().
   * @param keyId - Key ID used for encryption
   * @param ciphertext - Data to decrypt
   * @param aad - Same AAD used during encryption
   * @returns Plaintext bytes
   */
  decrypt(keyId: string, ciphertext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;

  /** Sign a message using Ed25519. */
  signEd25519(keyId: string, message: Uint8Array): Promise<Uint8Array>;

  /** Verify an Ed25519 signature. */
  verifyEd25519(keyId: string, message: Uint8Array, signature: Uint8Array): Promise<boolean>;

  /** Sign a message using ECDSA P-256 SHA-256. */
  signEcdsaP256(keyId: string, message: Uint8Array): Promise<Uint8Array>;

  /** Verify an ECDSA P-256 SHA-256 signature. */
  verifyEcdsaP256(keyId: string, message: Uint8Array, signature: Uint8Array): Promise<boolean>;

  /**
   * Generate cryptographically secure random bytes.
   * @param length - Number of bytes to generate
   */
  generateRandom(length: number): Promise<Uint8Array>;

  /**
   * Destroy key material. The key ID becomes invalid after this call.
   * @param keyId - Key ID to destroy
   */
  destroyKey(keyId: string): Promise<void>;

  /**
   * Compute a Logical ID (LID) from a JSON attribute object.
   *
   * Useful for client-side LID pre-computation without a server round-trip.
   * The JSON must be an object with string values: `{"key": "value", ...}`.
   *
   * @param attrsJson - JSON string of attributes
   * @returns LID string
   */
  computeLid(attrsJson: string): string;
}

/** Initialize the WASM module. Must be called before constructing WasmKeyRack. */
export default function init(): Promise<void>;
