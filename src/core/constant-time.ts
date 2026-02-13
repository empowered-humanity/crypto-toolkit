/**
 * Constant-Time Operations
 *
 * Timing-safe comparison functions to prevent timing attacks.
 * All comparisons take constant time regardless of where differences occur.
 *
 * @module core/constant-time
 */

import { timingSafeEqual as nodeTimingSafeEqual } from 'crypto';
import { createHmac } from 'crypto';

/**
 * Timing-safe equality comparison for buffers
 *
 * Compares two buffers in constant time to prevent timing attacks.
 * Returns false if lengths differ.
 *
 * @param a - First buffer
 * @param b - Second buffer
 * @returns True if buffers are equal
 *
 * @example
 * ```typescript
 * const storedHash = Buffer.from('...');
 * const computedHash = sha256('data');
 * if (timingSafeEqual(storedHash, computedHash)) {
 *   // Hashes match
 * }
 * ```
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Fast path: different lengths
  if (a.length !== b.length) {
    return false;
  }

  try {
    return nodeTimingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

/**
 * Timing-safe string comparison
 *
 * Compares two strings in constant time.
 * Converts to buffers using UTF-8 encoding.
 *
 * @param a - First string
 * @param b - Second string
 * @returns True if strings are equal
 *
 * @example
 * ```typescript
 * const storedToken = 'abc123...';
 * const providedToken = request.headers['x-api-token'];
 * if (timingSafeCompare(storedToken, providedToken)) {
 *   // Tokens match
 * }
 * ```
 */
export function timingSafeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');

  if (bufA.length !== bufB.length) {
    return false;
  }

  try {
    return nodeTimingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Double HMAC comparison (browser-safe timing attack mitigation)
 *
 * Compares two values by computing HMACs and comparing those.
 * Provides additional protection in environments where timing-safe
 * comparison might not be available or reliable.
 *
 * @param a - First value
 * @param b - Second value
 * @param key - HMAC key (optional, generates random if not provided)
 * @returns True if values are equal
 *
 * @example
 * ```typescript
 * const key = randomBytes(32);
 * if (doubleHMACCompare(valueA, valueB, key)) {
 *   // Values match
 * }
 * ```
 */
export function doubleHMACCompare(
  a: Uint8Array,
  b: Uint8Array,
  key?: Uint8Array
): boolean {
  // Use provided key or generate ephemeral key
  const hmacKey = key || Buffer.from(require('crypto').randomBytes(32));

  // Compute HMACs
  const hmacA = createHmac('sha256', Buffer.from(hmacKey))
    .update(Buffer.from(a))
    .digest();

  const hmacB = createHmac('sha256', Buffer.from(hmacKey))
    .update(Buffer.from(b))
    .digest();

  // Compare HMACs in constant time
  return timingSafeEqual(new Uint8Array(hmacA), new Uint8Array(hmacB));
}

/**
 * Constant-time conditional select
 *
 * Returns `a` if condition is true, `b` otherwise.
 * Selection happens in constant time.
 *
 * Note: This is a best-effort implementation in JavaScript.
 * True constant-time behavior requires compiler support.
 *
 * @param condition - Boolean condition
 * @param a - Value if true
 * @param b - Value if false
 * @returns Selected value
 *
 * @example
 * ```typescript
 * const result = constantTimeSelect(isValid, secretA, secretB);
 * ```
 */
export function constantTimeSelect<T>(
  condition: boolean,
  a: T,
  b: T
): T {
  // In JavaScript, we can't guarantee true constant-time behavior
  // This is a best-effort implementation
  const mask = condition ? -1 : 0;

  // For primitive types, use bitwise operations
  if (typeof a === 'number' && typeof b === 'number') {
    return ((a & mask) | (b & ~mask)) as T;
  }

  // For objects/arrays, fall back to ternary
  // (compiler may optimize this, but we can't control it)
  return condition ? a : b;
}

/**
 * Constant-time buffer copy based on condition
 *
 * Copies `source` to `dest` if condition is true, otherwise fills `dest` with zeros.
 * Operates in constant time.
 *
 * @param dest - Destination buffer
 * @param source - Source buffer
 * @param condition - Whether to copy
 *
 * @example
 * ```typescript
 * const result = Buffer.alloc(32);
 * constantTimeCopy(result, secretKey, isAuthorized);
 * ```
 */
export function constantTimeCopy(
  dest: Uint8Array,
  source: Uint8Array,
  condition: boolean
): void {
  if (dest.length !== source.length) {
    throw new Error('Buffers must be same length');
  }

  const mask = condition ? 0xff : 0x00;

  for (let i = 0; i < dest.length; i++) {
    dest[i] = source[i]! & mask;
  }
}

/**
 * Constant-time check if buffer is all zeros
 *
 * Returns true if all bytes are zero.
 * Operates in constant time (always scans entire buffer).
 *
 * @param buffer - Buffer to check
 * @returns True if all zeros
 *
 * @example
 * ```typescript
 * if (isZero(buffer)) {
 *   throw new Error('Key is all zeros');
 * }
 * ```
 */
export function isZero(buffer: Uint8Array): boolean {
  let result = 0;

  for (let i = 0; i < buffer.length; i++) {
    result |= buffer[i]!;
  }

  return result === 0;
}
