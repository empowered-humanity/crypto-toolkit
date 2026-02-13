/**
 * Password Hashing using Argon2id
 *
 * Argon2id is the recommended password hashing algorithm (winner of Password Hashing Competition).
 * Provides resistance to:
 * - GPU cracking attacks (memory-hard)
 * - Side-channel attacks (data-independent memory access)
 * - Tradeoff attacks (hybrid of Argon2i and Argon2d)
 *
 * @module core/password
 */

import sodium from 'sodium-native';
import type { PasswordHashOptions, HashedPassword } from '../types/index.js';

// Libsodium defaults (OWASP-compliant for interactive use)
const OPSLIMIT_INTERACTIVE = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE; // 2 iterations
const MEMLIMIT_INTERACTIVE = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE; // 64 MiB

// Moderate security (recommended for most applications)
const OPSLIMIT_MODERATE = sodium.crypto_pwhash_OPSLIMIT_MODERATE; // 3 iterations
const MEMLIMIT_MODERATE = sodium.crypto_pwhash_MEMLIMIT_MODERATE;  // 256 MiB

// Sensitive data (high security, slower)
const OPSLIMIT_SENSITIVE = sodium.crypto_pwhash_OPSLIMIT_SENSITIVE; // 4 iterations
const MEMLIMIT_SENSITIVE = sodium.crypto_pwhash_MEMLIMIT_SENSITIVE;  // 1 GiB

/**
 * Hash a password using Argon2id
 *
 * Returns PHC string format: $argon2id$v=19$m=65536,t=2,p=1$...
 * This format includes algorithm, version, parameters, salt, and hash.
 *
 * OWASP recommendations (2023):
 * - Memory: 64 MiB minimum (interactive), 256 MiB recommended
 * - Iterations: 2-3 minimum, adjust based on response time budget
 * - Parallelism: Number of CPU cores
 *
 * @param password - Password to hash
 * @param options - Hashing parameters (defaults to MODERATE security)
 * @returns Hashed password with embedded parameters
 *
 * @example
 * ```typescript
 * const hashed = await hashPassword('my-secure-password');
 * // Store hashed.hash in database
 * // {
 * //   hash: '$argon2id$v=19$m=262144,t=3,p=1$...',
 * //   algorithm: 'argon2id',
 * //   parameters: { memoryCost: 262144, timeCost: 3 }
 * // }
 * ```
 */
export async function hashPassword(
  password: string,
  options: PasswordHashOptions = {}
): Promise<HashedPassword> {
  if (!password || password.length === 0) {
    throw new Error('Password cannot be empty');
  }

  // Allocate buffer for PHC string (fixed size in libsodium)
  const hash = Buffer.alloc(sodium.crypto_pwhash_STRBYTES);

  // Use provided options or defaults (MODERATE)
  const opslimit = options.timeCost || OPSLIMIT_MODERATE;
  const memlimit = options.memoryCost || MEMLIMIT_MODERATE;

  // Hash password (synchronous in libsodium, but we return Promise for API consistency)
  try {
    sodium.crypto_pwhash_str(
      hash,
      Buffer.from(password, 'utf-8'),
      opslimit,
      memlimit
    );
  } catch (error) {
    throw new Error(`Password hashing failed: ${(error as Error).message}`);
  }

  // Trim null bytes from fixed-size buffer
  const hashStr = hash.toString('utf-8').replace(/\0+$/, '');

  return {
    hash: hashStr,
    algorithm: 'argon2id',
    parameters: {
      memoryCost: memlimit,
      timeCost: opslimit,
    },
  };
}

/**
 * Verify a password against a stored hash
 *
 * Uses timing-safe comparison to prevent timing attacks.
 * Parameters (memory cost, iterations) are extracted from the PHC string.
 *
 * @param password - Password to verify
 * @param hashedPassword - Hashed password from hashPassword() or PHC string
 * @returns True if password matches
 *
 * @example
 * ```typescript
 * const isValid = await verifyPassword('user-input', storedHash);
 * if (isValid) {
 *   // Proceed with authentication
 * }
 * ```
 */
export async function verifyPassword(
  password: string,
  hashedPassword: HashedPassword | string
): Promise<boolean> {
  if (!password || password.length === 0) {
    throw new Error('Password cannot be empty');
  }

  // Extract hash string
  const hash = typeof hashedPassword === 'string'
    ? hashedPassword
    : hashedPassword.hash;

  if (!hash || hash.length === 0) {
    return false;
  }

  // Verify using libsodium (timing-safe)
  // Hash buffer must be exactly crypto_pwhash_STRBYTES, null-padded
  try {
    const hashBuf = Buffer.alloc(sodium.crypto_pwhash_STRBYTES);
    Buffer.from(hash, 'utf-8').copy(hashBuf);
    return sodium.crypto_pwhash_str_verify(
      hashBuf,
      Buffer.from(password, 'utf-8')
    );
  } catch (error) {
    // Invalid hash format or verification error
    return false;
  }
}

/**
 * Check if a stored hash needs rehashing (parameters changed)
 *
 * Returns true if the hash was created with different parameters than current defaults.
 * Useful for upgrading security over time.
 *
 * @param hashedPassword - Hashed password to check
 * @param options - New target parameters (defaults to MODERATE)
 * @returns True if rehashing is recommended
 *
 * @example
 * ```typescript
 * if (await needsRehash(storedHash)) {
 *   const newHash = await hashPassword(password);
 *   // Update database with newHash
 * }
 * ```
 */
export async function needsRehash(
  hashedPassword: HashedPassword | string,
  options: PasswordHashOptions = {}
): Promise<boolean> {
  const hash = typeof hashedPassword === 'string'
    ? hashedPassword
    : hashedPassword.hash;

  const targetOpslimit = options.timeCost || OPSLIMIT_MODERATE;
  const targetMemlimit = options.memoryCost || MEMLIMIT_MODERATE;

  // Hash buffer must be exactly crypto_pwhash_STRBYTES, null-padded
  try {
    const hashBuf = Buffer.alloc(sodium.crypto_pwhash_STRBYTES);
    Buffer.from(hash, 'utf-8').copy(hashBuf);
    return sodium.crypto_pwhash_str_needs_rehash(
      hashBuf,
      targetOpslimit,
      targetMemlimit
    );
  } catch (error) {
    // Invalid hash format
    return true; // Recommend rehashing
  }
}

/**
 * Derive a key from a password using Argon2id
 *
 * Unlike hashPassword(), this produces a raw key (not a PHC string).
 * Useful for key derivation from passwords (e.g., encryption keys).
 *
 * WARNING: For password storage, use hashPassword() instead.
 * This function is for deriving encryption keys.
 *
 * @param password - Password to derive from
 * @param salt - 16-byte salt (must be stored with ciphertext)
 * @param keyLength - Desired key length in bytes (default: 32)
 * @param options - Hashing parameters
 * @returns Derived key
 *
 * @example
 * ```typescript
 * const salt = randomBytes(16);
 * const key = await deriveKey('user-password', salt, 32);
 * // Use key for encryption, store salt alongside ciphertext
 * ```
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  keyLength: number = 32,
  options: PasswordHashOptions = {}
): Promise<Uint8Array> {
  if (!password || password.length === 0) {
    throw new Error('Password cannot be empty');
  }

  if (salt.length !== 16) {
    throw new Error('Salt must be 16 bytes');
  }

  const opslimit = options.timeCost || OPSLIMIT_MODERATE;
  const memlimit = options.memoryCost || MEMLIMIT_MODERATE;

  const key = Buffer.alloc(keyLength);

  try {
    sodium.crypto_pwhash(
      key,
      Buffer.from(password, 'utf-8'),
      Buffer.from(salt),
      opslimit,
      memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
  } catch (error) {
    throw new Error(`Key derivation failed: ${(error as Error).message}`);
  }

  return new Uint8Array(key);
}

/**
 * Get preset security levels for password hashing
 *
 * @returns Security level presets
 */
export function getSecurityLevels() {
  return {
    interactive: {
      memoryCost: MEMLIMIT_INTERACTIVE,
      timeCost: OPSLIMIT_INTERACTIVE,
      description: 'Fast, suitable for login forms (64 MiB RAM)',
    },
    moderate: {
      memoryCost: MEMLIMIT_MODERATE,
      timeCost: OPSLIMIT_MODERATE,
      description: 'Recommended for most applications (256 MiB RAM)',
    },
    sensitive: {
      memoryCost: MEMLIMIT_SENSITIVE,
      timeCost: OPSLIMIT_SENSITIVE,
      description: 'High security for sensitive data (1 GiB RAM)',
    },
  } as const;
}
