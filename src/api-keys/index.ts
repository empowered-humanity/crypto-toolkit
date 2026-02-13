/**
 * API Key Management
 *
 * Secure generation, hashing, and validation of API keys.
 * Keys follow the format: prefix_randomdata (e.g., te_abc123...)
 *
 * Storage pattern:
 * - Store SHA-256 hash of key in database (never store raw key)
 * - Return raw key to user exactly once during creation
 * - Validate by hashing provided key and comparing to stored hash
 *
 * @module api-keys
 */

import { sha256 } from '../core/hash.js';
import { randomString } from '../core/random.js';
import { timingSafeCompare } from '../core/constant-time.js';
import type { APIKeyConfig, GeneratedAPIKey } from '../types/index.js';

const DEFAULT_KEY_LENGTH = 32;
const DEFAULT_CHARSET = 'base64url' as const;

/**
 * Generate a new API key with prefix
 *
 * The returned key should be shown to the user exactly once.
 * Store only the hash in your database.
 *
 * @param config - Key configuration (prefix, length, charset)
 * @returns Generated key with hash for storage
 *
 * @example
 * ```typescript
 * const apiKey = generateAPIKey({ prefix: 'te' });
 * // Show apiKey.key to user once: "te_a1b2c3d4..."
 * // Store apiKey.hash in database
 * // Store apiKey.keyId for identification
 * ```
 */
export function generateAPIKey(config: APIKeyConfig): GeneratedAPIKey {
  const length = config.length ?? DEFAULT_KEY_LENGTH;
  const charset = config.charset ?? DEFAULT_CHARSET;

  const randomPart = randomString(length, charset);
  const key = `${config.prefix}_${randomPart}`;

  const hash = hashAPIKey(key);
  const keyId = extractKeyId(key);

  return {
    key,
    keyId,
    hash,
    createdAt: new Date(),
  };
}

/**
 * Hash an API key for storage
 *
 * Uses SHA-256 to create a one-way hash. The hash can be stored
 * safely in the database.
 *
 * @param key - Raw API key string
 * @returns Hex-encoded SHA-256 hash
 *
 * @example
 * ```typescript
 * const hash = hashAPIKey('te_a1b2c3d4...');
 * // Store hash in database
 * ```
 */
export function hashAPIKey(key: string): string {
  return Buffer.from(sha256(key)).toString('hex');
}

/**
 * Validate an API key against a stored hash
 *
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param providedKey - Key provided by the user
 * @param storedHash - Hash stored in database
 * @returns True if key matches
 *
 * @example
 * ```typescript
 * const isValid = validateAPIKey(request.headers['x-api-key'], storedHash);
 * if (!isValid) {
 *   return res.status(401).json({ error: 'Invalid API key' });
 * }
 * ```
 */
export function validateAPIKey(providedKey: string, storedHash: string): boolean {
  if (!providedKey || !storedHash) {
    return false;
  }

  const computedHash = hashAPIKey(providedKey);
  return timingSafeCompare(computedHash, storedHash);
}

/**
 * Extract key ID from an API key
 *
 * Returns prefix + first 8 characters of the random part.
 * Useful for logging and identification without exposing the full key.
 *
 * @param key - Raw API key string
 * @returns Key identifier (e.g., "te_a1b2c3d4")
 *
 * @example
 * ```typescript
 * const keyId = extractKeyId('te_a1b2c3d4e5f6g7h8...');
 * // Returns: "te_a1b2c3d4"
 * ```
 */
export function extractKeyId(key: string): string {
  const underscoreIndex = key.indexOf('_');
  if (underscoreIndex === -1) {
    return key.slice(0, 8);
  }

  const prefix = key.slice(0, underscoreIndex);
  const randomPart = key.slice(underscoreIndex + 1);
  return `${prefix}_${randomPart.slice(0, 8)}`;
}

/**
 * Parse an API key into its components
 *
 * @param key - Raw API key string
 * @returns Parsed components or null if invalid format
 */
export function parseAPIKey(key: string): { prefix: string; secret: string } | null {
  const underscoreIndex = key.indexOf('_');
  if (underscoreIndex <= 0 || underscoreIndex === key.length - 1) {
    return null;
  }

  return {
    prefix: key.slice(0, underscoreIndex),
    secret: key.slice(underscoreIndex + 1),
  };
}
