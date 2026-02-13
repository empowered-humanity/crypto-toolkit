/**
 * Cryptographically Secure Random Number Generation
 *
 * All random generation uses libsodium's CSPRNG, which uses:
 * - /dev/urandom on Unix
 * - BCryptGenRandom on Windows
 * - getentropy() where available
 *
 * @module core/random
 */

import sodium from 'sodium-native';

/**
 * Generate cryptographically secure random bytes
 *
 * @param length - Number of bytes to generate
 * @returns Random bytes
 *
 * @example
 * ```typescript
 * const key = randomBytes(32);
 * const nonce = randomBytes(24);
 * ```
 */
export function randomBytes(length: number): Uint8Array {
  if (length < 0 || !Number.isInteger(length)) {
    throw new Error('Length must be a positive integer');
  }

  if (length === 0) {
    return new Uint8Array(0);
  }

  const buffer = Buffer.alloc(length);
  sodium.randombytes_buf(buffer);
  return new Uint8Array(buffer);
}

/**
 * Generate a random integer in range [0, upperBound)
 *
 * Uses rejection sampling to ensure uniform distribution.
 * Much more secure than `Math.random() * n`.
 *
 * @param upperBound - Exclusive upper bound (must be positive)
 * @returns Random integer in [0, upperBound)
 *
 * @example
 * ```typescript
 * const diceRoll = randomInt(6) + 1; // 1-6
 * const randomIndex = randomInt(array.length);
 * ```
 */
export function randomInt(upperBound: number): number {
  if (upperBound <= 0 || !Number.isInteger(upperBound)) {
    throw new Error('Upper bound must be a positive integer');
  }

  return sodium.randombytes_uniform(upperBound);
}

/**
 * Generate a random integer in range [min, max]
 *
 * @param min - Inclusive minimum
 * @param max - Inclusive maximum
 * @returns Random integer in [min, max]
 *
 * @example
 * ```typescript
 * const percentage = randomIntInRange(0, 100);
 * const year = randomIntInRange(1900, 2024);
 * ```
 */
export function randomIntInRange(min: number, max: number): number {
  if (!Number.isInteger(min) || !Number.isInteger(max)) {
    throw new Error('Min and max must be integers');
  }

  if (min > max) {
    throw new Error('Min must be less than or equal to max');
  }

  if (min === max) {
    return min;
  }

  const range = max - min + 1;
  return min + randomInt(range);
}

/**
 * Generate a random string with specified charset
 *
 * @param length - Length of string to generate
 * @param charset - Character set ('base64url', 'hex', 'alphanumeric', 'numeric')
 * @returns Random string
 *
 * @example
 * ```typescript
 * const token = randomString(32, 'base64url');
 * const code = randomString(6, 'numeric'); // OTP
 * ```
 */
export function randomString(
  length: number,
  charset: 'base64url' | 'hex' | 'alphanumeric' | 'numeric' = 'base64url'
): string {
  if (length <= 0 || !Number.isInteger(length)) {
    throw new Error('Length must be a positive integer');
  }

  const bytes = randomBytes(Math.ceil(length * 1.5)); // Extra bytes for encoding overhead

  switch (charset) {
    case 'hex':
      return Buffer.from(bytes).toString('hex').slice(0, length);

    case 'base64url':
      return Buffer.from(bytes).toString('base64url').slice(0, length);

    case 'alphanumeric': {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      const result: string[] = [];
      for (let i = 0; i < length; i++) {
        result.push(chars.charAt(randomInt(chars.length)));
      }
      return result.join('');
    }

    case 'numeric': {
      const chars = '0123456789';
      const result: string[] = [];
      for (let i = 0; i < length; i++) {
        result.push(chars.charAt(randomInt(chars.length)));
      }
      return result.join('');
    }

    default:
      throw new Error(`Unknown charset: ${charset}`);
  }
}

/**
 * Shuffle an array in-place using Fisher-Yates algorithm with CSPRNG
 *
 * @param array - Array to shuffle (modified in-place)
 * @returns The shuffled array (same reference)
 *
 * @example
 * ```typescript
 * const deck = [...Array(52).keys()];
 * shuffle(deck); // Cryptographically secure shuffle
 * ```
 */
export function shuffle<T>(array: T[]): T[] {
  for (let i = array.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [array[i], array[j]] = [array[j]!, array[i]!];
  }
  return array;
}

/**
 * Pick a random element from an array
 *
 * @param array - Array to pick from
 * @returns Random element
 *
 * @example
 * ```typescript
 * const colors = ['red', 'green', 'blue'];
 * const randomColor = randomChoice(colors);
 * ```
 */
export function randomChoice<T>(array: T[]): T {
  if (array.length === 0) {
    throw new Error('Array cannot be empty');
  }

  const index = randomInt(array.length);
  return array[index]!;
}

/**
 * Generate a cryptographically secure UUID v4
 *
 * @returns UUID string
 *
 * @example
 * ```typescript
 * const id = randomUUID();
 * // '550e8400-e29b-41d4-a716-446655440000'
 * ```
 */
export function randomUUID(): string {
  const bytes = randomBytes(16);

  // Set version (4) and variant (RFC 4122)
  bytes[6] = (bytes[6]! & 0x0f) | 0x40; // Version 4
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // Variant 10

  const hex = Buffer.from(bytes).toString('hex');

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

/**
 * Generate a random base64-encoded token
 *
 * Useful for session tokens, CSRF tokens, etc.
 *
 * @param byteLength - Length in bytes (default: 32)
 * @returns Base64url-encoded token
 *
 * @example
 * ```typescript
 * const sessionToken = randomToken(32);
 * const csrfToken = randomToken(16);
 * ```
 */
export function randomToken(byteLength: number = 32): string {
  const bytes = randomBytes(byteLength);
  return Buffer.from(bytes).toString('base64url');
}
