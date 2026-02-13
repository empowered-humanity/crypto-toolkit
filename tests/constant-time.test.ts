/**
 * Tests for constant-time operations
 */

import { describe, it, expect } from 'vitest';
import {
  timingSafeEqual,
  timingSafeCompare,
  doubleHMACCompare,
  constantTimeSelect,
  constantTimeCopy,
  isZero,
} from '../src/core/constant-time.js';
import { randomBytes } from '../src/core/random.js';

describe('Constant-Time Operations', () => {
  describe('timingSafeEqual (buffers)', () => {
    it('should return true for equal buffers', () => {
      const buf = randomBytes(32);
      expect(timingSafeEqual(buf, new Uint8Array(buf))).toBe(true);
    });

    it('should return false for different buffers', () => {
      const a = randomBytes(32);
      const b = randomBytes(32);
      expect(timingSafeEqual(a, b)).toBe(false);
    });

    it('should return false for different lengths', () => {
      const a = randomBytes(16);
      const b = randomBytes(32);
      expect(timingSafeEqual(a, b)).toBe(false);
    });

    it('should detect single-byte difference', () => {
      const a = randomBytes(32);
      const b = new Uint8Array(a);
      b[31] ^= 1;
      expect(timingSafeEqual(a, b)).toBe(false);
    });

    it('should handle empty buffers', () => {
      expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
    });
  });

  describe('timingSafeCompare (strings)', () => {
    it('should return true for equal strings', () => {
      expect(timingSafeCompare('hello', 'hello')).toBe(true);
    });

    it('should return false for different strings', () => {
      expect(timingSafeCompare('hello', 'world')).toBe(false);
    });

    it('should return false for different lengths', () => {
      expect(timingSafeCompare('short', 'much longer string')).toBe(false);
    });

    it('should handle empty strings', () => {
      expect(timingSafeCompare('', '')).toBe(true);
    });

    it('should handle unicode', () => {
      expect(timingSafeCompare('密码', '密码')).toBe(true);
      expect(timingSafeCompare('密码', '密碼')).toBe(false);
    });
  });

  describe('doubleHMACCompare', () => {
    it('should return true for equal buffers', () => {
      const buf = randomBytes(32);
      const key = randomBytes(32);
      expect(doubleHMACCompare(buf, new Uint8Array(buf), key)).toBe(true);
    });

    it('should return false for different buffers', () => {
      const a = randomBytes(32);
      const b = randomBytes(32);
      const key = randomBytes(32);
      expect(doubleHMACCompare(a, b, key)).toBe(false);
    });

    it('should work without explicit key (auto-generated)', () => {
      const buf = randomBytes(32);
      expect(doubleHMACCompare(buf, new Uint8Array(buf))).toBe(true);
    });
  });

  describe('constantTimeSelect', () => {
    it('should return first value when condition is true', () => {
      expect(constantTimeSelect(true, 'a', 'b')).toBe('a');
    });

    it('should return second value when condition is false', () => {
      expect(constantTimeSelect(false, 'a', 'b')).toBe('b');
    });

    it('should work with numbers', () => {
      expect(constantTimeSelect(true, 42, 0)).toBe(42);
      expect(constantTimeSelect(false, 42, 0)).toBe(0);
    });
  });

  describe('constantTimeCopy', () => {
    it('should copy when condition is true', () => {
      const dest = new Uint8Array(4);
      const source = new Uint8Array([1, 2, 3, 4]);

      constantTimeCopy(dest, source, true);
      expect(dest).toEqual(source);
    });

    it('should zero when condition is false', () => {
      const dest = new Uint8Array([9, 9, 9, 9]);
      const source = new Uint8Array([1, 2, 3, 4]);

      constantTimeCopy(dest, source, false);
      expect(dest).toEqual(new Uint8Array(4));
    });

    it('should reject different lengths', () => {
      const dest = new Uint8Array(4);
      const source = new Uint8Array(8);

      expect(() => constantTimeCopy(dest, source, true)).toThrow('same length');
    });
  });

  describe('isZero', () => {
    it('should return true for all-zero buffer', () => {
      expect(isZero(new Uint8Array(32))).toBe(true);
    });

    it('should return false for non-zero buffer', () => {
      const buf = new Uint8Array(32);
      buf[15] = 1;
      expect(isZero(buf)).toBe(false);
    });

    it('should detect last byte being non-zero', () => {
      const buf = new Uint8Array(32);
      buf[31] = 0xff;
      expect(isZero(buf)).toBe(false);
    });

    it('should handle empty buffer', () => {
      expect(isZero(new Uint8Array(0))).toBe(true);
    });

    it('should detect first byte being non-zero', () => {
      const buf = new Uint8Array(32);
      buf[0] = 1;
      expect(isZero(buf)).toBe(false);
    });
  });
});
