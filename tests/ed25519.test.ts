/**
 * Tests for Ed25519 digital signatures
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  extractPublicKey,
  sign,
  verify,
  signCombined,
  verifyCombined,
  createSignature,
  getPublicKeySize,
  getSecretKeySize,
  getSignatureSize,
} from '../src/asymmetric/ed25519.js';
import { randomBytes } from '../src/core/random.js';

describe('Ed25519 Digital Signatures', () => {
  describe('Key generation', () => {
    it('should generate valid key pairs', () => {
      const keyPair = generateKeyPair();

      expect(keyPair.publicKey.length).toBe(32);
      expect(keyPair.secretKey.length).toBe(64);
    });

    it('should generate different key pairs', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();

      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.secretKey).not.toEqual(keyPair2.secretKey);
    });

    it('should generate deterministic key pair from seed', () => {
      const seed = randomBytes(32);

      const keyPair1 = generateKeyPair(seed);
      const keyPair2 = generateKeyPair(seed);

      expect(keyPair1.publicKey).toEqual(keyPair2.publicKey);
      expect(keyPair1.secretKey).toEqual(keyPair2.secretKey);
    });

    it('should reject invalid seed length', () => {
      const badSeed = randomBytes(16); // Should be 32

      expect(() => generateKeyPair(badSeed)).toThrow('Seed must be 32 bytes');
    });

    it('should report correct sizes', () => {
      expect(getPublicKeySize()).toBe(32);
      expect(getSecretKeySize()).toBe(64);
      expect(getSignatureSize()).toBe(64);
    });
  });

  describe('Public key extraction', () => {
    it('should extract public key from secret key', () => {
      const keyPair = generateKeyPair();
      const extracted = extractPublicKey(keyPair.secretKey);

      expect(extracted).toEqual(keyPair.publicKey);
    });

    it('should reject invalid secret key length', () => {
      const badKey = randomBytes(32); // Should be 64

      expect(() => extractPublicKey(badKey)).toThrow('Secret key must be 64 bytes');
    });
  });

  describe('Signing and verification', () => {
    it('should sign and verify strings', () => {
      const keyPair = generateKeyPair();
      const message = 'Hello, World!';

      const signature = sign(message, keyPair.secretKey);
      const isValid = verify(message, signature, keyPair.publicKey);

      expect(signature.length).toBe(64);
      expect(isValid).toBe(true);
    });

    it('should sign and verify binary data', () => {
      const keyPair = generateKeyPair();
      const message = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      const signature = sign(message, keyPair.secretKey);
      const isValid = verify(message, signature, keyPair.publicKey);

      expect(isValid).toBe(true);
    });

    it('should produce deterministic signatures (same message + key = same signature)', () => {
      const keyPair = generateKeyPair();
      const message = 'Same message';

      const signature1 = sign(message, keyPair.secretKey);
      const signature2 = sign(message, keyPair.secretKey);

      expect(signature1).toEqual(signature2);
    });

    it('should reject signatures signed with different key', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      const message = 'Message';

      const signature = sign(message, keyPair1.secretKey);
      const isValid = verify(message, signature, keyPair2.publicKey);

      expect(isValid).toBe(false);
    });

    it('should reject modified messages', () => {
      const keyPair = generateKeyPair();
      const originalMessage = 'Original message';
      const modifiedMessage = 'Modified message';

      const signature = sign(originalMessage, keyPair.secretKey);
      const isValid = verify(modifiedMessage, signature, keyPair.publicKey);

      expect(isValid).toBe(false);
    });

    it('should reject tampered signatures', () => {
      const keyPair = generateKeyPair();
      const message = 'Message';

      const signature = sign(message, keyPair.secretKey);

      // Tamper with signature
      signature[0] ^= 1;

      const isValid = verify(message, signature, keyPair.publicKey);
      expect(isValid).toBe(false);
    });

    it('should handle empty messages', () => {
      const keyPair = generateKeyPair();
      const message = '';

      const signature = sign(message, keyPair.secretKey);
      const isValid = verify(message, signature, keyPair.publicKey);

      expect(isValid).toBe(true);
    });

    it('should handle large messages', () => {
      const keyPair = generateKeyPair();
      const message = new Uint8Array(1024 * 1024); // 1 MB
      message.fill(42);

      const signature = sign(message, keyPair.secretKey);
      const isValid = verify(message, signature, keyPair.publicKey);

      expect(isValid).toBe(true);
    });

    it('should reject invalid signature length', () => {
      const keyPair = generateKeyPair();
      const message = 'Test';
      const badSignature = randomBytes(32); // Should be 64

      const isValid = verify(message, badSignature, keyPair.publicKey);
      expect(isValid).toBe(false);
    });

    it('should reject invalid public key length', () => {
      const keyPair = generateKeyPair();
      const message = 'Test';
      const signature = sign(message, keyPair.secretKey);
      const badPublicKey = randomBytes(16); // Should be 32

      const isValid = verify(message, signature, badPublicKey);
      expect(isValid).toBe(false);
    });

    it('should reject invalid secret key length during signing', () => {
      const message = 'Test';
      const badSecretKey = randomBytes(32); // Should be 64

      expect(() => sign(message, badSecretKey)).toThrow('Secret key must be 64 bytes');
    });
  });

  describe('Combined format', () => {
    it('should sign and verify in combined format', () => {
      const keyPair = generateKeyPair();
      const message = 'Test message';

      const signed = signCombined(message, keyPair.secretKey);
      const verified = verifyCombined(signed, keyPair.publicKey);

      expect(verified).not.toBeNull();
      expect(Buffer.from(verified!).toString('utf-8')).toBe(message);
    });

    it('should return null for invalid combined signature', () => {
      const keyPair = generateKeyPair();
      const message = 'Test message';

      const signed = signCombined(message, keyPair.secretKey);

      // Tamper with signed message
      signed[0] ^= 1;

      const verified = verifyCombined(signed, keyPair.publicKey);
      expect(verified).toBeNull();
    });

    it('should return null for too-short combined message', () => {
      const keyPair = generateKeyPair();
      const tooShort = new Uint8Array(32); // Needs at least 64 bytes for signature

      const verified = verifyCombined(tooShort, keyPair.publicKey);
      expect(verified).toBeNull();
    });

    it('should return null for invalid public key in combined verification', () => {
      const keyPair = generateKeyPair();
      const message = 'Test';
      const signed = signCombined(message, keyPair.secretKey);
      const badPublicKey = randomBytes(16); // Should be 32

      const verified = verifyCombined(signed, badPublicKey);
      expect(verified).toBeNull();
    });
  });

  describe('Signature object creation', () => {
    it('should create signature objects', () => {
      const keyPair = generateKeyPair();
      const message = 'Test';

      const sig = createSignature(message, keyPair.secretKey);

      expect(sig.signature.length).toBe(64);
      expect(sig.publicKey).toEqual(keyPair.publicKey);

      const isValid = verify(message, sig.signature, sig.publicKey);
      expect(isValid).toBe(true);
    });
  });

  describe('Edge cases', () => {
    it('should handle unicode messages', () => {
      const keyPair = generateKeyPair();
      const message = '测试消息 🔒 テスト';

      const signature = sign(message, keyPair.secretKey);
      const isValid = verify(message, signature, keyPair.publicKey);

      expect(isValid).toBe(true);
    });

    it('should handle messages with null bytes', () => {
      const keyPair = generateKeyPair();
      const message = new Uint8Array([1, 0, 2, 0, 3]);

      const signature = sign(message, keyPair.secretKey);
      const isValid = verify(message, signature, keyPair.publicKey);

      expect(isValid).toBe(true);
    });
  });

  describe('RFC 8032 Test Vectors', () => {
    // Test vectors from RFC 8032, Section 7.1
    // Note: RFC 8032 provides 32-byte seeds, not 64-byte expanded secret keys.
    // We must expand via generateKeyPair(seed) first.
    it('should match RFC 8032 test vector 1', () => {
      const seedHex =
        '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
      const publicKeyHex =
        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
      const messageHex = '';
      const signatureHex =
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
        '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

      const seed = Buffer.from(seedHex, 'hex');
      const keyPair = generateKeyPair(seed);
      const publicKey = Buffer.from(publicKeyHex, 'hex');
      const message = Buffer.from(messageHex, 'hex');
      const expectedSignature = Buffer.from(signatureHex, 'hex');

      // Verify generated public key matches expected
      expect(Buffer.from(keyPair.publicKey).toString('hex')).toBe(publicKeyHex);

      const signature = sign(message, keyPair.secretKey);

      expect(Buffer.from(signature).toString('hex')).toBe(signatureHex);
      expect(verify(message, expectedSignature, publicKey)).toBe(true);
    });

    it('should match RFC 8032 test vector 2', () => {
      const seedHex =
        '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
      const publicKeyHex =
        '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
      const messageHex = '72';
      const signatureHex =
        '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' +
        '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00';

      const seed = Buffer.from(seedHex, 'hex');
      const keyPair = generateKeyPair(seed);
      const publicKey = Buffer.from(publicKeyHex, 'hex');
      const message = Buffer.from(messageHex, 'hex');
      const expectedSignature = Buffer.from(signatureHex, 'hex');

      // Verify generated public key matches expected
      expect(Buffer.from(keyPair.publicKey).toString('hex')).toBe(publicKeyHex);

      const signature = sign(message, keyPair.secretKey);

      expect(Buffer.from(signature).toString('hex')).toBe(signatureHex);
      expect(verify(message, expectedSignature, publicKey)).toBe(true);
    });
  });
});
