/**
 * Tests for API key management
 */

import { describe, it, expect } from 'vitest';
import {
  generateAPIKey,
  hashAPIKey,
  validateAPIKey,
  extractKeyId,
  parseAPIKey,
} from '../src/api-keys/index.js';

describe('API Key Management', () => {
  describe('generateAPIKey', () => {
    it('should generate key with prefix', () => {
      const result = generateAPIKey({ prefix: 'te' });

      expect(result.key).toMatch(/^te_/);
      expect(result.keyId).toMatch(/^te_/);
      expect(result.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.createdAt).toBeInstanceOf(Date);
    });

    it('should generate keys of specified length', () => {
      const result = generateAPIKey({ prefix: 'sk', length: 48 });
      const randomPart = result.key.slice(3); // Remove "sk_"
      expect(randomPart.length).toBe(48);
    });

    it('should generate hex keys', () => {
      const result = generateAPIKey({ prefix: 'api', charset: 'hex' });
      const randomPart = result.key.slice(4); // Remove "api_"
      expect(randomPart).toMatch(/^[0-9a-f]+$/);
    });

    it('should generate unique keys', () => {
      const keys = new Set<string>();
      for (let i = 0; i < 50; i++) {
        keys.add(generateAPIKey({ prefix: 'te' }).key);
      }
      expect(keys.size).toBe(50);
    });

    it('should generate unique hashes', () => {
      const hashes = new Set<string>();
      for (let i = 0; i < 50; i++) {
        hashes.add(generateAPIKey({ prefix: 'te' }).hash);
      }
      expect(hashes.size).toBe(50);
    });
  });

  describe('hashAPIKey', () => {
    it('should produce 64-char hex hash', () => {
      const hash = hashAPIKey('te_abc123');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should be deterministic', () => {
      expect(hashAPIKey('te_test')).toBe(hashAPIKey('te_test'));
    });

    it('should produce different hashes for different keys', () => {
      expect(hashAPIKey('te_key1')).not.toBe(hashAPIKey('te_key2'));
    });
  });

  describe('validateAPIKey', () => {
    it('should validate correct key against stored hash', () => {
      const generated = generateAPIKey({ prefix: 'te' });
      expect(validateAPIKey(generated.key, generated.hash)).toBe(true);
    });

    it('should reject wrong key', () => {
      const generated = generateAPIKey({ prefix: 'te' });
      expect(validateAPIKey('te_wrong_key', generated.hash)).toBe(false);
    });

    it('should reject empty key', () => {
      expect(validateAPIKey('', 'somehash')).toBe(false);
    });

    it('should reject empty hash', () => {
      expect(validateAPIKey('te_key', '')).toBe(false);
    });
  });

  describe('extractKeyId', () => {
    it('should extract prefix + first 8 chars', () => {
      const keyId = extractKeyId('te_abcdefghijklmnop');
      expect(keyId).toBe('te_abcdefgh');
    });

    it('should handle short random part', () => {
      const keyId = extractKeyId('te_abc');
      expect(keyId).toBe('te_abc');
    });

    it('should handle no prefix', () => {
      const keyId = extractKeyId('abcdefghijklmnop');
      expect(keyId).toBe('abcdefgh');
    });
  });

  describe('parseAPIKey', () => {
    it('should parse valid key', () => {
      const parsed = parseAPIKey('te_abc123');
      expect(parsed).toEqual({ prefix: 'te', secret: 'abc123' });
    });

    it('should return null for key without underscore', () => {
      expect(parseAPIKey('nounderscore')).toBeNull();
    });

    it('should return null for key starting with underscore', () => {
      expect(parseAPIKey('_noprefix')).toBeNull();
    });

    it('should return null for key ending with underscore', () => {
      expect(parseAPIKey('nodata_')).toBeNull();
    });
  });
});
