/**
 * Type definitions for crypto-toolkit
 */

// ============================================================================
// AEAD (Authenticated Encryption with Associated Data)
// ============================================================================

export type AEADAlgorithm = 'xchacha20-poly1305' | 'aes-256-gcm' | 'chacha20-poly1305';

export interface AEADOptions {
  algorithm?: AEADAlgorithm;
  associatedData?: Uint8Array;
}

export interface EncryptedData {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  tag: Uint8Array;
  algorithm: AEADAlgorithm;
}

// ============================================================================
// Password Hashing
// ============================================================================

export type PasswordHashAlgorithm = 'argon2id' | 'scrypt' | 'pbkdf2';

export interface PasswordHashOptions {
  algorithm?: PasswordHashAlgorithm;
  memoryCost?: number;
  timeCost?: number;
  parallelism?: number;
  hashLength?: number;
}

export interface HashedPassword {
  hash: string;
  algorithm: PasswordHashAlgorithm;
  parameters: {
    memoryCost: number;
    timeCost: number;
  };
}

// ============================================================================
// Asymmetric Cryptography
// ============================================================================

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface Signature {
  signature: Uint8Array;
  publicKey: Uint8Array;
}

export interface X25519KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

// ============================================================================
// Streaming Encryption
// ============================================================================

export interface StreamEncryptOptions {
  chunkSize?: number;
  algorithm?: 'secretstream' | 'chunked-gcm';
}

export interface EncryptedFileMetadata {
  header: Uint8Array;
  originalSize: number;
  chunkSize: number;
  algorithm: string;
}

// ============================================================================
// Shamir Secret Sharing
// ============================================================================

export interface ShareOptions {
  totalShares: number;
  threshold: number;
}

export interface SecretShare {
  index: number;
  data: Uint8Array;
}

// ============================================================================
// Blind Indexing
// ============================================================================

export interface BlindIndexConfig {
  key: Uint8Array;
  algorithm?: 'hmac-sha256' | 'siphash';
  outputLength?: number;
}

export interface EncryptedFieldWithIndex {
  ciphertext: Uint8Array;
  blindIndex: string;
}

// ============================================================================
// JWT
// ============================================================================

export type JWTAlgorithm = 'RS256' | 'ES256' | 'EdDSA';

export interface JWTSignOptions {
  algorithm: JWTAlgorithm;
  expiresIn: string | number;
  issuer?: string;
  audience?: string;
  jwtId?: string;
}

export interface JWTVerifyOptions {
  algorithms: JWTAlgorithm[];
  issuer?: string;
  audience?: string;
  clockTolerance?: number;
}

export interface RefreshTokenFamily {
  familyId: string;
  currentTokenId: string;
  userId: string;
  createdAt: Date;
  rotationCount: number;
}

// ============================================================================
// API Keys
// ============================================================================

export interface APIKeyConfig {
  prefix: string;
  length?: number;
  charset?: 'base64url' | 'hex' | 'alphanumeric';
}

export interface GeneratedAPIKey {
  key: string;
  keyId: string;
  hash: string;
  createdAt: Date;
}

// ============================================================================
// Certificate Validation
// ============================================================================

export interface CertificateValidationResult {
  valid: boolean;
  chain: unknown[];
  errors: string[];
  ocspStatus?: 'good' | 'revoked' | 'unknown';
  expiresAt: Date;
  issuer: string;
  subject: string;
}

export interface OCSPCheckResult {
  status: 'good' | 'revoked' | 'unknown';
  thisUpdate: Date;
  nextUpdate?: Date;
  revocationTime?: Date;
  revocationReason?: string;
}
