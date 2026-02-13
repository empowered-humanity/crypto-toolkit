/**
 * Tests for X25519 key exchange and box encryption
 */

import { describe, it, expect } from 'vitest';
import {
  generateX25519KeyPair,
  computeSharedSecret,
  box,
  openBox,
  sealedBox,
  openSealedBox,
  convertEd25519ToX25519,
  getPublicKeySize,
  getSecretKeySize,
  getSharedSecretSize,
} from '../src/asymmetric/x25519.js';
import { generateKeyPair as generateEd25519KeyPair } from '../src/asymmetric/ed25519.js';
import { randomBytes } from '../src/core/random.js';

describe('X25519 Key Exchange', () => {
  describe('Key generation', () => {
    it('should generate valid key pairs', () => {
      const kp = generateX25519KeyPair();
      expect(kp.publicKey.length).toBe(32);
      expect(kp.secretKey.length).toBe(32);
    });

    it('should generate different key pairs', () => {
      const kp1 = generateX25519KeyPair();
      const kp2 = generateX25519KeyPair();
      expect(kp1.publicKey).not.toEqual(kp2.publicKey);
      expect(kp1.secretKey).not.toEqual(kp2.secretKey);
    });

    it('should generate deterministic key pair from seed', () => {
      const seed = randomBytes(32);
      const kp1 = generateX25519KeyPair(seed);
      const kp2 = generateX25519KeyPair(seed);
      expect(kp1.publicKey).toEqual(kp2.publicKey);
      expect(kp1.secretKey).toEqual(kp2.secretKey);
    });

    it('should reject invalid seed length', () => {
      expect(() => generateX25519KeyPair(randomBytes(16))).toThrow('32 bytes');
    });

    it('should report correct sizes', () => {
      expect(getPublicKeySize()).toBe(32);
      expect(getSecretKeySize()).toBe(32);
      expect(getSharedSecretSize()).toBe(32);
    });
  });

  describe('Shared secret (ECDH)', () => {
    it('should produce same shared secret for both parties', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      const aliceShared = computeSharedSecret(alice.secretKey, bob.publicKey);
      const bobShared = computeSharedSecret(bob.secretKey, alice.publicKey);

      expect(aliceShared).toEqual(bobShared);
    });

    it('should produce 32-byte shared secret', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      expect(computeSharedSecret(alice.secretKey, bob.publicKey).length).toBe(32);
    });

    it('should produce different secrets for different key pairs', () => {
      const alice = generateX25519KeyPair();
      const bob1 = generateX25519KeyPair();
      const bob2 = generateX25519KeyPair();

      const shared1 = computeSharedSecret(alice.secretKey, bob1.publicKey);
      const shared2 = computeSharedSecret(alice.secretKey, bob2.publicKey);

      expect(shared1).not.toEqual(shared2);
    });

    it('should reject invalid key lengths', () => {
      const kp = generateX25519KeyPair();
      expect(() => computeSharedSecret(randomBytes(16), kp.publicKey)).toThrow('32 bytes');
      expect(() => computeSharedSecret(kp.secretKey, randomBytes(16))).toThrow('32 bytes');
    });
  });

  describe('Authenticated box', () => {
    it('should encrypt and decrypt messages', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      const message = 'Hello Bob!';
      const encrypted = box(message, bob.publicKey, alice.secretKey);
      const decrypted = openBox(encrypted, alice.publicKey, bob.secretKey);

      expect(decrypted).not.toBeNull();
      expect(Buffer.from(decrypted!).toString('utf-8')).toBe(message);
    });

    it('should encrypt and decrypt binary data', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const encrypted = box(data, bob.publicKey, alice.secretKey);
      const decrypted = openBox(encrypted, alice.publicKey, bob.secretKey);

      expect(decrypted).toEqual(data);
    });

    it('should fail with wrong recipient key', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();
      const eve = generateX25519KeyPair();

      const encrypted = box('secret', bob.publicKey, alice.secretKey);
      const decrypted = openBox(encrypted, alice.publicKey, eve.secretKey);

      expect(decrypted).toBeNull();
    });

    it('should fail with wrong sender key', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();
      const eve = generateX25519KeyPair();

      const encrypted = box('secret', bob.publicKey, alice.secretKey);
      const decrypted = openBox(encrypted, eve.publicKey, bob.secretKey);

      expect(decrypted).toBeNull();
    });

    it('should detect tampering', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      const encrypted = box('secret', bob.publicKey, alice.secretKey);
      // Tamper with ciphertext
      encrypted[30] ^= 1;

      const decrypted = openBox(encrypted, alice.publicKey, bob.secretKey);
      expect(decrypted).toBeNull();
    });

    it('should return null for too-short ciphertext', () => {
      const kp = generateX25519KeyPair();
      expect(openBox(new Uint8Array(10), kp.publicKey, kp.secretKey)).toBeNull();
    });

    it('should reject invalid key lengths', () => {
      const kp = generateX25519KeyPair();
      expect(() => box('msg', randomBytes(16), kp.secretKey)).toThrow('32 bytes');
      expect(() => box('msg', kp.publicKey, randomBytes(16))).toThrow('32 bytes');
    });
  });

  describe('Sealed box (anonymous encryption)', () => {
    it('should encrypt and decrypt messages', () => {
      const bob = generateX25519KeyPair();

      const message = 'Anonymous message';
      const sealed = sealedBox(message, bob.publicKey);
      const decrypted = openSealedBox(sealed, bob.secretKey, bob.publicKey);

      expect(decrypted).not.toBeNull();
      expect(Buffer.from(decrypted!).toString('utf-8')).toBe(message);
    });

    it('should produce different ciphertexts for same message (ephemeral key)', () => {
      const bob = generateX25519KeyPair();

      const sealed1 = sealedBox('same message', bob.publicKey);
      const sealed2 = sealedBox('same message', bob.publicKey);

      expect(sealed1).not.toEqual(sealed2);
    });

    it('should fail with wrong key', () => {
      const bob = generateX25519KeyPair();
      const eve = generateX25519KeyPair();

      const sealed = sealedBox('secret', bob.publicKey);
      const decrypted = openSealedBox(sealed, eve.secretKey, eve.publicKey);

      expect(decrypted).toBeNull();
    });

    it('should detect tampering', () => {
      const bob = generateX25519KeyPair();

      const sealed = sealedBox('secret', bob.publicKey);
      sealed[20] ^= 1;

      expect(openSealedBox(sealed, bob.secretKey, bob.publicKey)).toBeNull();
    });

    it('should return null for too-short ciphertext', () => {
      const kp = generateX25519KeyPair();
      expect(openSealedBox(new Uint8Array(10), kp.secretKey, kp.publicKey)).toBeNull();
    });

    it('should reject invalid key length', () => {
      expect(() => sealedBox('msg', randomBytes(16))).toThrow('32 bytes');
    });
  });

  describe('Ed25519 to X25519 conversion', () => {
    it('should convert Ed25519 public key to X25519', () => {
      const edKey = generateEd25519KeyPair();
      const x25519Pub = convertEd25519ToX25519(edKey.publicKey, 'public');
      expect(x25519Pub.length).toBe(32);
    });

    it('should convert Ed25519 secret key to X25519', () => {
      const edKey = generateEd25519KeyPair();
      const x25519Sec = convertEd25519ToX25519(edKey.secretKey, 'secret');
      expect(x25519Sec.length).toBe(32);
    });

    it('should produce working encryption keys from signing keys', () => {
      const alice = generateEd25519KeyPair();
      const bob = generateEd25519KeyPair();

      const aliceX = {
        publicKey: convertEd25519ToX25519(alice.publicKey, 'public'),
        secretKey: convertEd25519ToX25519(alice.secretKey, 'secret'),
      };

      const bobX = {
        publicKey: convertEd25519ToX25519(bob.publicKey, 'public'),
        secretKey: convertEd25519ToX25519(bob.secretKey, 'secret'),
      };

      const encrypted = box('test', bobX.publicKey, aliceX.secretKey);
      const decrypted = openBox(encrypted, aliceX.publicKey, bobX.secretKey);

      expect(decrypted).not.toBeNull();
      expect(Buffer.from(decrypted!).toString('utf-8')).toBe('test');
    });

    it('should reject invalid key lengths', () => {
      expect(() => convertEd25519ToX25519(randomBytes(16), 'public')).toThrow('32 bytes');
      expect(() => convertEd25519ToX25519(randomBytes(32), 'secret')).toThrow('64 bytes');
    });
  });
});
