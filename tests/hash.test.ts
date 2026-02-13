/**
 * Tests for hash functions (SHA-256, SHA-512, BLAKE2b)
 */

import { describe, it, expect } from 'vitest';
import {
  sha256,
  sha512,
  blake2b,
  hmacSHA256,
  hmacBLAKE2b,
  shortHash,
  hashToHex,
  hashToBase64,
} from '../src/core/hash.js';
import { randomBytes } from '../src/core/random.js';

describe('Hash Functions', () => {
  describe('SHA-256', () => {
    it('should produce 32-byte hash', () => {
      expect(sha256('hello').length).toBe(32);
    });

    it('should match known test vector', () => {
      // SHA-256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const hash = sha256('');
      expect(Buffer.from(hash).toString('hex')).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      );
    });

    it('should produce deterministic output', () => {
      expect(sha256('test')).toEqual(sha256('test'));
    });

    it('should produce different hashes for different inputs', () => {
      expect(sha256('abc')).not.toEqual(sha256('def'));
    });

    it('should accept Uint8Array input', () => {
      const data = new Uint8Array([1, 2, 3]);
      expect(sha256(data).length).toBe(32);
    });
  });

  describe('SHA-512', () => {
    it('should produce 64-byte hash', () => {
      expect(sha512('hello').length).toBe(64);
    });

    it('should match known test vector', () => {
      // SHA-512('') known hash
      const hash = sha512('');
      expect(Buffer.from(hash).toString('hex')).toBe(
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' +
        '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
      );
    });

    it('should produce deterministic output', () => {
      expect(sha512('test')).toEqual(sha512('test'));
    });
  });

  describe('BLAKE2b', () => {
    it('should default to 32-byte output', () => {
      expect(blake2b('hello').length).toBe(32);
    });

    it('should support variable output length', () => {
      expect(blake2b('hello', 16).length).toBe(16);
      expect(blake2b('hello', 64).length).toBe(64);
    });

    it('should produce deterministic output', () => {
      expect(blake2b('test')).toEqual(blake2b('test'));
    });

    it('should produce different hashes for different inputs', () => {
      expect(blake2b('abc')).not.toEqual(blake2b('def'));
    });

    it('should support keyed hashing', () => {
      const key = randomBytes(32);
      const keyed = blake2b('data', 32, key);
      const unkeyed = blake2b('data', 32);
      expect(keyed).not.toEqual(unkeyed);
    });

    it('should produce same keyed hash with same key', () => {
      const key = randomBytes(32);
      expect(blake2b('data', 32, key)).toEqual(blake2b('data', 32, key));
    });

    it('should reject invalid output length', () => {
      expect(() => blake2b('data', 0)).toThrow('between 1 and 64');
      expect(() => blake2b('data', 65)).toThrow('between 1 and 64');
    });
  });

  describe('HMAC-SHA256', () => {
    it('should produce 32-byte HMAC', () => {
      const key = randomBytes(32);
      expect(hmacSHA256(key, 'message').length).toBe(32);
    });

    it('should be deterministic with same key and data', () => {
      const key = randomBytes(32);
      expect(hmacSHA256(key, 'msg')).toEqual(hmacSHA256(key, 'msg'));
    });

    it('should produce different HMACs with different keys', () => {
      const key1 = randomBytes(32);
      const key2 = randomBytes(32);
      expect(hmacSHA256(key1, 'msg')).not.toEqual(hmacSHA256(key2, 'msg'));
    });

    it('should produce different HMACs for different messages', () => {
      const key = randomBytes(32);
      expect(hmacSHA256(key, 'a')).not.toEqual(hmacSHA256(key, 'b'));
    });

    it('should differ from plain SHA-256', () => {
      const key = randomBytes(32);
      const hmac = hmacSHA256(key, 'data');
      const hash = sha256('data');
      expect(hmac).not.toEqual(hash);
    });
  });

  describe('HMAC-BLAKE2b', () => {
    it('should produce 32-byte HMAC by default', () => {
      const key = randomBytes(32);
      expect(hmacBLAKE2b(key, 'message').length).toBe(32);
    });

    it('should be deterministic', () => {
      const key = randomBytes(32);
      expect(hmacBLAKE2b(key, 'msg')).toEqual(hmacBLAKE2b(key, 'msg'));
    });

    it('should support variable output length', () => {
      const key = randomBytes(32);
      expect(hmacBLAKE2b(key, 'msg', 16).length).toBe(16);
    });
  });

  describe('Short Hash (SipHash)', () => {
    it('should produce 8-byte hash', () => {
      const key = randomBytes(16);
      expect(shortHash('data', key).length).toBe(8);
    });

    it('should be deterministic', () => {
      const key = randomBytes(16);
      expect(shortHash('data', key)).toEqual(shortHash('data', key));
    });

    it('should produce different hashes for different inputs', () => {
      const key = randomBytes(16);
      expect(shortHash('abc', key)).not.toEqual(shortHash('def', key));
    });

    it('should require 16-byte key', () => {
      const badKey = randomBytes(32);
      expect(() => shortHash('data', badKey)).toThrow('16 bytes');
    });
  });

  describe('Hash encoding helpers', () => {
    it('should produce hex string for SHA-256', () => {
      const hex = hashToHex('hello', 'sha256');
      expect(hex).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should produce hex string for SHA-512', () => {
      const hex = hashToHex('hello', 'sha512');
      expect(hex).toMatch(/^[0-9a-f]{128}$/);
    });

    it('should produce hex string for BLAKE2b', () => {
      const hex = hashToHex('hello', 'blake2b');
      expect(hex).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should default to SHA-256', () => {
      const hex = hashToHex('hello');
      expect(hex.length).toBe(64);
    });

    it('should produce base64 encoding', () => {
      const b64 = hashToBase64('hello');
      expect(b64).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });

    it('should produce base64 for SHA-512', () => {
      const b64 = hashToBase64('hello', 'sha512');
      expect(b64.length).toBeGreaterThan(hashToBase64('hello', 'sha256').length);
    });
  });
});
