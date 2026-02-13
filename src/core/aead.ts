/**
 * Authenticated Encryption with Associated Data (AEAD)
 *
 * Default: XChaCha20-Poly1305 (192-bit nonce, safe for random generation)
 *
 * Security properties:
 * - Confidentiality: Ciphertext reveals no information about plaintext
 * - Authenticity: Detects tampering via authentication tag
 * - Nonce misuse resistance: XChaCha20 has 192-bit nonce (vs ChaCha20's 96-bit)
 *
 * @module core/aead
 */

import sodium from 'sodium-native';
import type { AEADOptions, EncryptedData } from '../types/index.js';

// Constants from sodium-native
const NONCE_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
const KEY_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;   // 32
const TAG_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;     // 16

/**
 * Encrypt plaintext using XChaCha20-Poly1305 AEAD
 *
 * Nonce is automatically generated using CSPRNG.
 * XChaCha20's 192-bit nonce makes random generation safe (no birthday bound concerns).
 *
 * @param plaintext - Data to encrypt (string or Uint8Array)
 * @param key - 32-byte encryption key
 * @param options - Optional algorithm selection and associated data
 * @returns Encrypted data with nonce, ciphertext, and authentication tag
 *
 * @example
 * ```typescript
 * const key = generateKey();
 * const encrypted = encrypt('secret message', key);
 * const decrypted = decrypt(encrypted, key);
 * ```
 */
export function encrypt(
  plaintext: Uint8Array | string,
  key: Uint8Array,
  options: AEADOptions = {}
): EncryptedData {
  // Convert string to buffer
  const plaintextBuf = typeof plaintext === 'string'
    ? Buffer.from(plaintext, 'utf-8')
    : Buffer.from(plaintext);

  // Validate key length
  if (key.length !== KEY_BYTES) {
    throw new Error(`Key must be ${KEY_BYTES} bytes, got ${key.length}`);
  }

  // Generate random nonce (safe for XChaCha20 with 192-bit nonce)
  const nonce = Buffer.alloc(NONCE_BYTES);
  sodium.randombytes_buf(nonce);

  // Allocate buffer for ciphertext + tag
  const ciphertext = Buffer.alloc(plaintextBuf.length + TAG_BYTES);

  // Handle optional associated data
  const ad = options.associatedData
    ? Buffer.from(options.associatedData)
    : null;

  // Encrypt using XChaCha20-Poly1305
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    ciphertext,
    plaintextBuf,
    ad,
    null,  // nsec (unused)
    nonce,
    Buffer.from(key)
  );

  // Split ciphertext and tag
  return {
    ciphertext: new Uint8Array(ciphertext.slice(0, -TAG_BYTES)),
    nonce: new Uint8Array(nonce),
    tag: new Uint8Array(ciphertext.slice(-TAG_BYTES)),
    algorithm: 'xchacha20-poly1305',
  };
}

/**
 * Decrypt ciphertext using XChaCha20-Poly1305 AEAD
 *
 * Verifies authentication tag before returning plaintext.
 * Throws on tag mismatch (tampering detected).
 *
 * @param encrypted - Encrypted data from encrypt()
 * @param key - 32-byte encryption key (same as used for encryption)
 * @param options - Optional associated data (must match encryption)
 * @returns Decrypted plaintext
 * @throws Error if authentication tag verification fails
 *
 * @example
 * ```typescript
 * const decrypted = decrypt(encrypted, key);
 * console.log(Buffer.from(decrypted).toString('utf-8'));
 * ```
 */
export function decrypt(
  encrypted: EncryptedData,
  key: Uint8Array,
  options: AEADOptions = {}
): Uint8Array {
  // Validate key length
  if (key.length !== KEY_BYTES) {
    throw new Error(`Key must be ${KEY_BYTES} bytes, got ${key.length}`);
  }

  // Validate nonce length
  if (encrypted.nonce.length !== NONCE_BYTES) {
    throw new Error(`Nonce must be ${NONCE_BYTES} bytes, got ${encrypted.nonce.length}`);
  }

  // Validate tag length
  if (encrypted.tag.length !== TAG_BYTES) {
    throw new Error(`Tag must be ${TAG_BYTES} bytes, got ${encrypted.tag.length}`);
  }

  // Recombine ciphertext and tag
  const combined = Buffer.concat([
    Buffer.from(encrypted.ciphertext),
    Buffer.from(encrypted.tag),
  ]);

  // Allocate buffer for plaintext
  const plaintext = Buffer.alloc(combined.length - TAG_BYTES);

  // Handle optional associated data
  const ad = options.associatedData
    ? Buffer.from(options.associatedData)
    : null;

  // Decrypt and verify tag
  try {
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext,
      null,  // nsec (unused)
      combined,
      ad,
      Buffer.from(encrypted.nonce),
      Buffer.from(key)
    );
  } catch {
    throw new Error('Decryption failed: authentication tag mismatch (data may be tampered)');
  }

  return new Uint8Array(plaintext);
}

/**
 * Encrypt plaintext to a single combined buffer (nonce || ciphertext || tag)
 *
 * Convenience wrapper that produces a single Uint8Array for storage/transmission.
 * Format: [nonce (24 bytes)] [ciphertext (variable)] [tag (16 bytes)]
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte encryption key
 * @param options - Optional algorithm and associated data
 * @returns Combined buffer ready for storage
 *
 * @example
 * ```typescript
 * const key = generateKey();
 * const combined = encryptCombined('secret', key);
 * // Store combined to file or database
 * fs.writeFileSync('encrypted.bin', combined);
 * ```
 */
export function encryptCombined(
  plaintext: Uint8Array | string,
  key: Uint8Array,
  options?: AEADOptions
): Uint8Array {
  const encrypted = encrypt(plaintext, key, options);

  return new Uint8Array(Buffer.concat([
    Buffer.from(encrypted.nonce),
    Buffer.from(encrypted.ciphertext),
    Buffer.from(encrypted.tag),
  ]));
}

/**
 * Decrypt a combined buffer (nonce || ciphertext || tag)
 *
 * Inverse of encryptCombined(). Parses the combined format.
 *
 * @param combined - Combined buffer from encryptCombined()
 * @param key - 32-byte encryption key
 * @param options - Optional associated data
 * @returns Decrypted plaintext
 *
 * @example
 * ```typescript
 * const combined = fs.readFileSync('encrypted.bin');
 * const plaintext = decryptCombined(combined, key);
 * ```
 */
export function decryptCombined(
  combined: Uint8Array,
  key: Uint8Array,
  options?: AEADOptions
): Uint8Array {
  const combinedBuf = Buffer.from(combined);

  // Validate minimum length
  if (combinedBuf.length < NONCE_BYTES + TAG_BYTES) {
    throw new Error(`Combined buffer too short: ${combinedBuf.length} bytes`);
  }

  // Parse components
  const nonce = combinedBuf.slice(0, NONCE_BYTES);
  const ciphertext = combinedBuf.slice(NONCE_BYTES, -TAG_BYTES);
  const tag = combinedBuf.slice(-TAG_BYTES);

  return decrypt(
    {
      nonce: new Uint8Array(nonce),
      ciphertext: new Uint8Array(ciphertext),
      tag: new Uint8Array(tag),
      algorithm: 'xchacha20-poly1305',
    },
    key,
    options
  );
}

/**
 * Generate a random 32-byte key for AEAD encryption
 *
 * Uses libsodium's CSPRNG for cryptographically secure randomness.
 *
 * @returns 32-byte key suitable for XChaCha20-Poly1305
 *
 * @example
 * ```typescript
 * const key = generateKey();
 * // Store key securely (KMS, hardware token, etc.)
 * ```
 */
export function generateKey(): Uint8Array {
  const key = Buffer.alloc(KEY_BYTES);
  sodium.randombytes_buf(key);
  return new Uint8Array(key);
}

/**
 * Get the required key size for AEAD encryption
 *
 * @returns Key size in bytes (32 for XChaCha20-Poly1305)
 */
export function getKeySize(): number {
  return KEY_BYTES;
}

/**
 * Get the nonce size for AEAD encryption
 *
 * @returns Nonce size in bytes (24 for XChaCha20-Poly1305)
 */
export function getNonceSize(): number {
  return NONCE_BYTES;
}

/**
 * Get the authentication tag size for AEAD encryption
 *
 * @returns Tag size in bytes (16 for Poly1305)
 */
export function getTagSize(): number {
  return TAG_BYTES;
}
