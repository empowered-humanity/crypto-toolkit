/**
 * Tests for JWT security module
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  signJWT,
  verifyJWT,
  decodeJWT,
  generateJWTKeyPair,
  createRefreshTokenFamily,
  rotateRefreshToken,
  parseRefreshToken,
  blacklistToken,
  isTokenBlacklisted,
  clearBlacklist,
} from '../src/jwt/index.js';

describe('JWT Security', () => {
  describe('EdDSA signing and verification', () => {
    it('should sign and verify with EdDSA', async () => {
      const { publicKey, privateKey } = await generateJWTKeyPair('EdDSA');

      const token = await signJWT(
        { sub: 'user123', role: 'admin' },
        privateKey,
        { algorithm: 'EdDSA', expiresIn: '1h' }
      );

      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);

      const payload = await verifyJWT(token, publicKey, {
        algorithms: ['EdDSA'],
      });

      expect(payload.sub).toBe('user123');
      expect(payload['role']).toBe('admin');
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
      expect(payload.jti).toBeDefined();
    });
  });

  describe('ES256 signing and verification', () => {
    it('should sign and verify with ES256', async () => {
      const { publicKey, privateKey } = await generateJWTKeyPair('ES256');

      const token = await signJWT(
        { sub: 'user456' },
        privateKey,
        { algorithm: 'ES256', expiresIn: '30m' }
      );

      const payload = await verifyJWT(token, publicKey, {
        algorithms: ['ES256'],
      });

      expect(payload.sub).toBe('user456');
    });
  });

  describe('Algorithm lock', () => {
    it('should reject token signed with wrong algorithm', async () => {
      const edKeys = await generateJWTKeyPair('EdDSA');
      const esKeys = await generateJWTKeyPair('ES256');

      const token = await signJWT(
        { sub: 'user' },
        edKeys.privateKey,
        { algorithm: 'EdDSA', expiresIn: '1h' }
      );

      // Try to verify EdDSA token with ES256 algorithm lock
      await expect(
        verifyJWT(token, esKeys.publicKey, { algorithms: ['ES256'] })
      ).rejects.toThrow();
    });
  });

  describe('JWT options', () => {
    it('should include issuer', async () => {
      const { publicKey, privateKey } = await generateJWTKeyPair('EdDSA');

      const token = await signJWT(
        { sub: 'user' },
        privateKey,
        { algorithm: 'EdDSA', expiresIn: '1h', issuer: 'te-security' }
      );

      const payload = await verifyJWT(token, publicKey, {
        algorithms: ['EdDSA'],
        issuer: 'te-security',
      });

      expect(payload.iss).toBe('te-security');
    });

    it('should reject wrong issuer', async () => {
      const { publicKey, privateKey } = await generateJWTKeyPair('EdDSA');

      const token = await signJWT(
        { sub: 'user' },
        privateKey,
        { algorithm: 'EdDSA', expiresIn: '1h', issuer: 'te-security' }
      );

      await expect(
        verifyJWT(token, publicKey, {
          algorithms: ['EdDSA'],
          issuer: 'wrong-issuer',
        })
      ).rejects.toThrow();
    });

    it('should support numeric expiresIn (seconds)', async () => {
      const { publicKey, privateKey } = await generateJWTKeyPair('EdDSA');

      const token = await signJWT(
        { sub: 'user' },
        privateKey,
        { algorithm: 'EdDSA', expiresIn: 3600 }
      );

      const payload = await verifyJWT(token, publicKey, {
        algorithms: ['EdDSA'],
      });

      expect(payload.exp).toBeDefined();
    });

    it('should include custom JTI', async () => {
      const { publicKey, privateKey } = await generateJWTKeyPair('EdDSA');

      const token = await signJWT(
        { sub: 'user' },
        privateKey,
        { algorithm: 'EdDSA', expiresIn: '1h', jwtId: 'custom-id-123' }
      );

      const payload = await verifyJWT(token, publicKey, {
        algorithms: ['EdDSA'],
      });

      expect(payload.jti).toBe('custom-id-123');
    });
  });

  describe('decodeJWT', () => {
    it('should decode without verification', async () => {
      const { privateKey } = await generateJWTKeyPair('EdDSA');

      const token = await signJWT(
        { sub: 'user123', data: 'test' },
        privateKey,
        { algorithm: 'EdDSA', expiresIn: '1h' }
      );

      const decoded = decodeJWT(token);

      expect(decoded.header.alg).toBe('EdDSA');
      expect(decoded.payload.sub).toBe('user123');
      expect(decoded.payload['data']).toBe('test');
    });
  });

  describe('Refresh token families', () => {
    it('should create a new family', () => {
      const { family, refreshToken } = createRefreshTokenFamily('user123');

      expect(family.userId).toBe('user123');
      expect(family.familyId).toBeDefined();
      expect(family.currentTokenId).toBeDefined();
      expect(family.rotationCount).toBe(0);
      expect(refreshToken).toContain(':');
    });

    it('should rotate token successfully', () => {
      const initial = createRefreshTokenFamily('user123');
      const parsed = parseRefreshToken(initial.refreshToken);

      expect(parsed).not.toBeNull();

      const rotated = rotateRefreshToken(initial.family, parsed!.tokenId);

      expect(rotated).not.toBeNull();
      expect(rotated!.family.rotationCount).toBe(1);
      expect(rotated!.family.currentTokenId).not.toBe(initial.family.currentTokenId);
      expect(rotated!.refreshToken).not.toBe(initial.refreshToken);
    });

    it('should detect token reuse (theft)', () => {
      const initial = createRefreshTokenFamily('user123');
      const parsed = parseRefreshToken(initial.refreshToken);

      // First rotation succeeds
      const rotated = rotateRefreshToken(initial.family, parsed!.tokenId);
      expect(rotated).not.toBeNull();

      // Attempting to use the OLD token ID with the NEW family state = reuse
      const reuse = rotateRefreshToken(rotated!.family, parsed!.tokenId);
      expect(reuse).toBeNull(); // Theft detected
    });

    it('should track rotation count', () => {
      let current = createRefreshTokenFamily('user123');

      for (let i = 0; i < 5; i++) {
        const parsed = parseRefreshToken(current.refreshToken);
        const rotated = rotateRefreshToken(current.family, parsed!.tokenId);
        expect(rotated).not.toBeNull();
        current = rotated!;
      }

      expect(current.family.rotationCount).toBe(5);
    });
  });

  describe('parseRefreshToken', () => {
    it('should parse valid token', () => {
      const parsed = parseRefreshToken('tokenId:secretPart');
      expect(parsed).toEqual({ tokenId: 'tokenId', secret: 'secretPart' });
    });

    it('should return null for invalid format', () => {
      expect(parseRefreshToken('no-colon')).toBeNull();
      expect(parseRefreshToken(':no-id')).toBeNull();
      expect(parseRefreshToken('no-secret:')).toBeNull();
    });
  });

  describe('Token blacklisting', () => {
    beforeEach(() => {
      clearBlacklist();
    });

    it('should blacklist a token', () => {
      blacklistToken('jti-123');
      expect(isTokenBlacklisted('jti-123')).toBe(true);
    });

    it('should not blacklist unrelated tokens', () => {
      blacklistToken('jti-123');
      expect(isTokenBlacklisted('jti-456')).toBe(false);
    });

    it('should clear blacklist', () => {
      blacklistToken('jti-123');
      clearBlacklist();
      expect(isTokenBlacklisted('jti-123')).toBe(false);
    });
  });
});
