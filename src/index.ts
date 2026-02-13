/**
 * @te-security/crypto-toolkit
 *
 * Comprehensive cryptographic utilities library providing secure-by-default primitives.
 *
 * @module crypto-toolkit
 */

// Core primitives
export * from './core/aead.js';
export * from './core/password.js';
export * from './core/random.js';
export * from './core/hash.js';
export * from './core/constant-time.js';

// Asymmetric cryptography - Ed25519 signatures
export {
  generateKeyPair,
  extractPublicKey,
  sign,
  verify,
  signCombined,
  verifyCombined,
  createSignature,
  getPublicKeySize as getEd25519PublicKeySize,
  getSecretKeySize as getEd25519SecretKeySize,
  getSignatureSize,
} from './asymmetric/ed25519.js';

// Asymmetric cryptography - X25519 key exchange
export {
  generateX25519KeyPair,
  computeSharedSecret,
  box,
  openBox,
  sealedBox,
  openSealedBox,
  convertEd25519ToX25519,
  getPublicKeySize as getX25519PublicKeySize,
  getSecretKeySize as getX25519SecretKeySize,
  getSharedSecretSize,
} from './asymmetric/x25519.js';

// API Key management
export * from './api-keys/index.js';

// JWT security
export {
  signJWT,
  verifyJWT,
  decodeJWT,
  generateJWTKeyPair,
  exportJWK,
  importJWK,
  createRefreshTokenFamily,
  rotateRefreshToken,
  parseRefreshToken,
  blacklistToken,
  isTokenBlacklisted,
  clearBlacklist,
} from './jwt/index.js';

// Types
export * from './types/index.js';
