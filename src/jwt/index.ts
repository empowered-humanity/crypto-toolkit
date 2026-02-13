/**
 * JWT Security Module
 *
 * Secure JWT signing and verification with:
 * - Algorithm lock (prevents algorithm confusion attacks)
 * - Asymmetric-only algorithms (RS256, ES256, EdDSA)
 * - Refresh token family tracking (detects token theft)
 * - Token blacklisting
 *
 * @module jwt
 */

import * as jose from 'jose';
import type { JWTSignOptions, JWTVerifyOptions, RefreshTokenFamily } from '../types/index.js';
import { randomToken, randomUUID } from '../core/random.js';
import { sha256 } from '../core/hash.js';

// ============================================================================
// JWT Signing & Verification
// ============================================================================

/**
 * Sign a JWT using asymmetric algorithms only
 *
 * Supports RS256, ES256, and EdDSA. Symmetric algorithms (HS256)
 * are deliberately excluded to prevent algorithm confusion attacks.
 *
 * @param payload - Claims to include in the JWT
 * @param privateKey - PEM-encoded private key or CryptoKey
 * @param options - Signing options (algorithm, expiry, issuer)
 * @returns Signed JWT string
 *
 * @example
 * ```typescript
 * const token = await signJWT(
 *   { sub: 'user123', role: 'admin' },
 *   privateKey,
 *   { algorithm: 'EdDSA', expiresIn: '1h', issuer: 'te-security' }
 * );
 * ```
 */
export async function signJWT(
  payload: Record<string, unknown>,
  privateKey: jose.KeyLike | Uint8Array,
  options: JWTSignOptions
): Promise<string> {
  let builder = new jose.SignJWT(payload as jose.JWTPayload)
    .setProtectedHeader({ alg: options.algorithm })
    .setIssuedAt();

  if (typeof options.expiresIn === 'string') {
    builder = builder.setExpirationTime(options.expiresIn);
  } else {
    builder = builder.setExpirationTime(Math.floor(Date.now() / 1000) + options.expiresIn);
  }

  if (options.issuer) {
    builder = builder.setIssuer(options.issuer);
  }

  if (options.audience) {
    builder = builder.setAudience(options.audience);
  }

  if (options.jwtId) {
    builder = builder.setJti(options.jwtId);
  } else {
    builder = builder.setJti(randomUUID());
  }

  return builder.sign(privateKey);
}

/**
 * Verify a JWT with algorithm lock
 *
 * Rejects tokens signed with unexpected algorithms.
 * This prevents algorithm confusion attacks where an attacker
 * signs with HS256 using the public key as the HMAC secret.
 *
 * @param token - JWT string to verify
 * @param publicKey - PEM-encoded public key or CryptoKey
 * @param options - Verification options (allowed algorithms, issuer)
 * @returns Decoded payload if valid
 * @throws Error if verification fails
 *
 * @example
 * ```typescript
 * const payload = await verifyJWT(token, publicKey, {
 *   algorithms: ['EdDSA'],
 *   issuer: 'te-security',
 * });
 * ```
 */
export async function verifyJWT(
  token: string,
  publicKey: jose.KeyLike | Uint8Array,
  options: JWTVerifyOptions
): Promise<jose.JWTPayload> {
  const verifyOptions: jose.JWTVerifyOptions = {
    algorithms: options.algorithms,
    clockTolerance: options.clockTolerance ?? 5,
  };

  if (options.issuer) {
    verifyOptions.issuer = options.issuer;
  }

  if (options.audience) {
    verifyOptions.audience = options.audience;
  }

  const result = await jose.jwtVerify(token, publicKey, verifyOptions);

  return result.payload;
}

/**
 * Decode a JWT without verification (for inspection only)
 *
 * WARNING: Do NOT use the decoded payload for authorization.
 * Always verify first with verifyJWT().
 *
 * @param token - JWT string
 * @returns Decoded header and payload
 */
export function decodeJWT(token: string): {
  header: jose.JWTHeaderParameters;
  payload: jose.JWTPayload;
} {
  const header = jose.decodeProtectedHeader(token) as jose.JWTHeaderParameters;
  const payload = jose.decodeJwt(token);
  return { header, payload };
}

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Generate a key pair for JWT signing
 *
 * @param algorithm - Algorithm to generate keys for
 * @returns Key pair with public and private keys
 */
export async function generateJWTKeyPair(
  algorithm: 'RS256' | 'ES256' | 'EdDSA'
): Promise<jose.GenerateKeyPairResult<jose.KeyLike>> {
  return jose.generateKeyPair(algorithm);
}

/**
 * Export a key to JWK format
 */
export async function exportJWK(key: jose.KeyLike | Uint8Array): Promise<jose.JWK> {
  return jose.exportJWK(key);
}

/**
 * Import a key from JWK format
 */
export async function importJWK(
  jwk: jose.JWK,
  algorithm: string
): Promise<jose.KeyLike | Uint8Array> {
  return jose.importJWK(jwk, algorithm);
}

// ============================================================================
// Refresh Token Families
// ============================================================================

/**
 * Create a new refresh token family
 *
 * A "family" tracks all refresh tokens derived from one login session.
 * When a token is reused (theft detected), the entire family is revoked.
 *
 * @param userId - User ID this token family belongs to
 * @returns New refresh token family with initial token
 */
export function createRefreshTokenFamily(userId: string): {
  family: RefreshTokenFamily;
  refreshToken: string;
} {
  const familyId = randomUUID();
  const tokenId = randomUUID();
  const refreshToken = randomToken(48);

  return {
    family: {
      familyId,
      currentTokenId: tokenId,
      userId,
      createdAt: new Date(),
      rotationCount: 0,
    },
    refreshToken: `${tokenId}:${refreshToken}`,
  };
}

/**
 * Rotate a refresh token (issue new token, invalidate old)
 *
 * Call this every time a refresh token is used. If the provided
 * tokenId doesn't match the family's current token, it means
 * a previously-rotated token was reused (potential theft).
 *
 * @param family - Current token family state
 * @param providedTokenId - Token ID from the refresh request
 * @returns New token and updated family, or null if reuse detected
 */
export function rotateRefreshToken(
  family: RefreshTokenFamily,
  providedTokenId: string
): { family: RefreshTokenFamily; refreshToken: string } | null {
  // Token reuse detection: if the provided token isn't the current one,
  // a previous token was reused → possible theft
  if (providedTokenId !== family.currentTokenId) {
    return null; // Caller should revoke the entire family
  }

  const newTokenId = randomUUID();
  const newRefreshToken = randomToken(48);

  return {
    family: {
      ...family,
      currentTokenId: newTokenId,
      rotationCount: family.rotationCount + 1,
    },
    refreshToken: `${newTokenId}:${newRefreshToken}`,
  };
}

/**
 * Parse a refresh token into its components
 *
 * @param refreshToken - Full refresh token string
 * @returns Token ID and secret, or null if invalid
 */
export function parseRefreshToken(refreshToken: string): { tokenId: string; secret: string } | null {
  const colonIndex = refreshToken.indexOf(':');
  if (colonIndex <= 0 || colonIndex === refreshToken.length - 1) {
    return null;
  }

  return {
    tokenId: refreshToken.slice(0, colonIndex),
    secret: refreshToken.slice(colonIndex + 1),
  };
}

// ============================================================================
// Token Blacklisting (in-memory, for single-instance)
// ============================================================================

const blacklist = new Set<string>();

/**
 * Add a token's JTI to the blacklist
 *
 * For production, use Redis or a database instead of in-memory.
 *
 * @param jti - JWT ID to blacklist
 */
export function blacklistToken(jti: string): void {
  const hash = Buffer.from(sha256(jti)).toString('hex');
  blacklist.add(hash);
}

/**
 * Check if a token's JTI is blacklisted
 *
 * @param jti - JWT ID to check
 * @returns True if blacklisted
 */
export function isTokenBlacklisted(jti: string): boolean {
  const hash = Buffer.from(sha256(jti)).toString('hex');
  return blacklist.has(hash);
}

/**
 * Clear the blacklist (for testing)
 */
export function clearBlacklist(): void {
  blacklist.clear();
}
