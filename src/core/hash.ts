/**
 * Cryptographic Hash Functions
 *
 * Provides SHA-256, SHA-512, and BLAKE2b hashing.
 * All functions produce fixed-size digests and are collision-resistant.
 *
 * @module core/hash
 */

import { createHash, createHmac } from 'crypto';
import sodium from 'sodium-native';

/**
 * Compute SHA-256 hash
 *
 * SHA-256 produces a 256-bit (32-byte) digest.
 * Widely supported and standardized (NIST FIPS 180-4).
 *
 * @param data - Data to hash
 * @returns 32-byte hash
 *
 * @example
 * ```typescript
 * const hash = sha256('hello world');
 * const fileHash = sha256(fs.readFileSync('file.txt'));
 * ```
 */
export function sha256(data: Uint8Array | string): Uint8Array {
  const input = typeof data === 'string'
    ? Buffer.from(data, 'utf-8')
    : Buffer.from(data);

  const hash = createHash('sha256')
    .update(input)
    .digest();

  return new Uint8Array(hash);
}

/**
 * Compute SHA-512 hash
 *
 * SHA-512 produces a 512-bit (64-byte) digest.
 * More secure than SHA-256 but slower and larger output.
 *
 * @param data - Data to hash
 * @returns 64-byte hash
 *
 * @example
 * ```typescript
 * const hash = sha512('hello world');
 * ```
 */
export function sha512(data: Uint8Array | string): Uint8Array {
  const input = typeof data === 'string'
    ? Buffer.from(data, 'utf-8')
    : Buffer.from(data);

  const hash = createHash('sha512')
    .update(input)
    .digest();

  return new Uint8Array(hash);
}

/**
 * Compute BLAKE2b hash (variable output length)
 *
 * BLAKE2b is faster than SHA-2 and more secure than MD5/SHA-1.
 * Recommended for general-purpose hashing.
 *
 * Default output: 32 bytes (256 bits)
 * Max output: 64 bytes (512 bits)
 *
 * @param data - Data to hash
 * @param outputLength - Desired hash length in bytes (default: 32, max: 64)
 * @param key - Optional key for keyed hashing (HMAC-like)
 * @returns Hash of specified length
 *
 * @example
 * ```typescript
 * const hash = blake2b('data');
 * const shortHash = blake2b('data', 16); // 128-bit hash
 * const keyedHash = blake2b('data', 32, key); // Keyed hash
 * ```
 */
export function blake2b(
  data: Uint8Array | string,
  outputLength: number = 32,
  key?: Uint8Array
): Uint8Array {
  const input = typeof data === 'string'
    ? Buffer.from(data, 'utf-8')
    : Buffer.from(data);

  if (outputLength < 1 || outputLength > 64) {
    throw new Error('Output length must be between 1 and 64 bytes');
  }

  const hash = Buffer.alloc(outputLength);

  if (key) {
    sodium.crypto_generichash(hash, input, Buffer.from(key));
  } else {
    sodium.crypto_generichash(hash, input);
  }

  return new Uint8Array(hash);
}

/**
 * Compute HMAC using SHA-256
 *
 * HMAC provides message authentication using a secret key.
 * Resistant to length extension attacks (unlike raw SHA-256).
 *
 * @param key - Secret key
 * @param data - Data to authenticate
 * @returns 32-byte HMAC
 *
 * @example
 * ```typescript
 * const key = randomBytes(32);
 * const mac = hmacSHA256(key, 'message');
 * // Verify: timingSafeEqual(mac, receivedMAC)
 * ```
 */
export function hmacSHA256(key: Uint8Array, data: Uint8Array | string): Uint8Array {
  const input = typeof data === 'string'
    ? Buffer.from(data, 'utf-8')
    : Buffer.from(data);

  const hmac = createHmac('sha256', Buffer.from(key))
    .update(input)
    .digest();

  return new Uint8Array(hmac);
}

/**
 * Compute HMAC using BLAKE2b
 *
 * Faster than HMAC-SHA256 with equivalent security.
 * Uses BLAKE2b's built-in keying mode.
 *
 * @param key - Secret key (max 64 bytes)
 * @param data - Data to authenticate
 * @param outputLength - HMAC length (default: 32)
 * @returns HMAC
 *
 * @example
 * ```typescript
 * const key = randomBytes(32);
 * const mac = hmacBLAKE2b(key, 'message');
 * ```
 */
export function hmacBLAKE2b(
  key: Uint8Array,
  data: Uint8Array | string,
  outputLength: number = 32
): Uint8Array {
  return blake2b(data, outputLength, key);
}

/**
 * Compute short hash (SipHash-2-4)
 *
 * Produces 64-bit (8-byte) hash optimized for hash tables.
 * Provides protection against hash-flooding DoS attacks.
 *
 * NOT suitable for cryptographic purposes (only 64 bits).
 * Use for hash tables, Bloom filters, etc.
 *
 * @param data - Data to hash
 * @param key - 16-byte key
 * @returns 8-byte hash
 *
 * @example
 * ```typescript
 * const key = randomBytes(16);
 * const hashValue = shortHash('username@example.com', key);
 * // Use as hash table index
 * ```
 */
export function shortHash(data: Uint8Array | string, key: Uint8Array): Uint8Array {
  const input = typeof data === 'string'
    ? Buffer.from(data, 'utf-8')
    : Buffer.from(data);

  if (key.length !== 16) {
    throw new Error('Key must be 16 bytes for SipHash');
  }

  const hash = Buffer.alloc(8);

  sodium.crypto_shorthash(hash, input, Buffer.from(key));

  return new Uint8Array(hash);
}

/**
 * Hash to hex string
 *
 * Convenience function to hash and encode as hex.
 *
 * @param data - Data to hash
 * @param algorithm - Hash algorithm (default: 'sha256')
 * @returns Hex-encoded hash
 *
 * @example
 * ```typescript
 * const hash = hashToHex('data'); // '3a6e...'
 * const blake2 = hashToHex('data', 'blake2b');
 * ```
 */
export function hashToHex(
  data: Uint8Array | string,
  algorithm: 'sha256' | 'sha512' | 'blake2b' = 'sha256'
): string {
  let hash: Uint8Array;

  switch (algorithm) {
    case 'sha256':
      hash = sha256(data);
      break;
    case 'sha512':
      hash = sha512(data);
      break;
    case 'blake2b':
      hash = blake2b(data);
      break;
    default:
      throw new Error(`Unknown algorithm: ${algorithm}`);
  }

  return Buffer.from(hash).toString('hex');
}

/**
 * Hash to base64
 *
 * Convenience function to hash and encode as base64.
 *
 * @param data - Data to hash
 * @param algorithm - Hash algorithm (default: 'sha256')
 * @returns Base64-encoded hash
 *
 * @example
 * ```typescript
 * const hash = hashToBase64('data');
 * ```
 */
export function hashToBase64(
  data: Uint8Array | string,
  algorithm: 'sha256' | 'sha512' | 'blake2b' = 'sha256'
): string {
  let hash: Uint8Array;

  switch (algorithm) {
    case 'sha256':
      hash = sha256(data);
      break;
    case 'sha512':
      hash = sha512(data);
      break;
    case 'blake2b':
      hash = blake2b(data);
      break;
    default:
      throw new Error(`Unknown algorithm: ${algorithm}`);
  }

  return Buffer.from(hash).toString('base64');
}
