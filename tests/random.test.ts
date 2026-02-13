/**
 * Tests for cryptographically secure random generation
 */

import { describe, it, expect } from 'vitest';
import {
  randomBytes,
  randomInt,
  randomIntInRange,
  randomString,
  shuffle,
  randomChoice,
  randomUUID,
  randomToken,
} from '../src/core/random.js';

describe('Secure Random Generation', () => {
  describe('randomBytes', () => {
    it('should generate bytes of specified length', () => {
      expect(randomBytes(16).length).toBe(16);
      expect(randomBytes(32).length).toBe(32);
      expect(randomBytes(64).length).toBe(64);
    });

    it('should generate different bytes each call', () => {
      const a = randomBytes(32);
      const b = randomBytes(32);
      expect(a).not.toEqual(b);
    });

    it('should handle zero length', () => {
      const result = randomBytes(0);
      expect(result.length).toBe(0);
    });

    it('should reject negative length', () => {
      expect(() => randomBytes(-1)).toThrow('positive integer');
    });

    it('should reject non-integer length', () => {
      expect(() => randomBytes(3.5)).toThrow('positive integer');
    });
  });

  describe('randomInt', () => {
    it('should return values in range [0, upperBound)', () => {
      for (let i = 0; i < 100; i++) {
        const value = randomInt(10);
        expect(value).toBeGreaterThanOrEqual(0);
        expect(value).toBeLessThan(10);
      }
    });

    it('should return 0 for upper bound of 1', () => {
      for (let i = 0; i < 10; i++) {
        expect(randomInt(1)).toBe(0);
      }
    });

    it('should reject zero upper bound', () => {
      expect(() => randomInt(0)).toThrow('positive integer');
    });

    it('should reject negative upper bound', () => {
      expect(() => randomInt(-5)).toThrow('positive integer');
    });

    it('should reject non-integer', () => {
      expect(() => randomInt(2.5)).toThrow('positive integer');
    });
  });

  describe('randomIntInRange', () => {
    it('should return values in range [min, max]', () => {
      for (let i = 0; i < 100; i++) {
        const value = randomIntInRange(5, 15);
        expect(value).toBeGreaterThanOrEqual(5);
        expect(value).toBeLessThanOrEqual(15);
      }
    });

    it('should return exact value when min === max', () => {
      expect(randomIntInRange(7, 7)).toBe(7);
    });

    it('should reject min > max', () => {
      expect(() => randomIntInRange(10, 5)).toThrow('less than or equal');
    });

    it('should reject non-integers', () => {
      expect(() => randomIntInRange(1.5, 5)).toThrow('integers');
    });
  });

  describe('randomString', () => {
    it('should generate hex strings of correct length', () => {
      const str = randomString(16, 'hex');
      expect(str.length).toBe(16);
      expect(str).toMatch(/^[0-9a-f]+$/);
    });

    it('should generate base64url strings', () => {
      const str = randomString(20, 'base64url');
      expect(str.length).toBe(20);
      expect(str).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate alphanumeric strings', () => {
      const str = randomString(20, 'alphanumeric');
      expect(str.length).toBe(20);
      expect(str).toMatch(/^[A-Za-z0-9]+$/);
    });

    it('should generate numeric strings', () => {
      const str = randomString(6, 'numeric');
      expect(str.length).toBe(6);
      expect(str).toMatch(/^[0-9]+$/);
    });

    it('should default to base64url', () => {
      const str = randomString(16);
      expect(str.length).toBe(16);
      expect(str).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should reject non-positive length', () => {
      expect(() => randomString(0)).toThrow('positive integer');
      expect(() => randomString(-1)).toThrow('positive integer');
    });
  });

  describe('shuffle', () => {
    it('should shuffle array in-place', () => {
      const original = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      const copy = [...original];
      const result = shuffle(copy);

      // Same reference
      expect(result).toBe(copy);
      // Same elements
      expect(result.sort()).toEqual(original.sort());
    });

    it('should handle empty array', () => {
      const arr: number[] = [];
      expect(shuffle(arr)).toEqual([]);
    });

    it('should handle single element', () => {
      expect(shuffle([42])).toEqual([42]);
    });

    it('should produce different orderings over many runs', () => {
      const original = [1, 2, 3, 4, 5, 6, 7, 8];
      const results = new Set<string>();

      for (let i = 0; i < 50; i++) {
        const arr = [...original];
        shuffle(arr);
        results.add(JSON.stringify(arr));
      }

      // Should produce multiple distinct orderings
      expect(results.size).toBeGreaterThan(1);
    });
  });

  describe('randomChoice', () => {
    it('should pick from array', () => {
      const arr = ['a', 'b', 'c'];
      for (let i = 0; i < 20; i++) {
        expect(arr).toContain(randomChoice(arr));
      }
    });

    it('should return only element for single-element array', () => {
      expect(randomChoice([42])).toBe(42);
    });

    it('should reject empty array', () => {
      expect(() => randomChoice([])).toThrow('empty');
    });
  });

  describe('randomUUID', () => {
    it('should produce valid UUID v4 format', () => {
      const uuid = randomUUID();
      expect(uuid).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
      );
    });

    it('should produce unique UUIDs', () => {
      const uuids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        uuids.add(randomUUID());
      }
      expect(uuids.size).toBe(100);
    });
  });

  describe('randomToken', () => {
    it('should generate base64url-encoded token', () => {
      const token = randomToken(32);
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
      // 32 bytes -> ~43 base64url chars
      expect(token.length).toBeGreaterThanOrEqual(40);
    });

    it('should generate different tokens', () => {
      const a = randomToken();
      const b = randomToken();
      expect(a).not.toBe(b);
    });

    it('should respect byte length parameter', () => {
      const short = randomToken(8);
      const long = randomToken(64);
      expect(short.length).toBeLessThan(long.length);
    });
  });
});
