# Security Policy

## Reporting a Vulnerability

We take security issues seriously. If you discover a security vulnerability in crypto-toolkit, please report it privately.

### Where to Report

**Email**: security@empoweredhumanity.ai

**Include in your report**:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Critical issues within 30 days, others within 90 days

### Disclosure Policy

- Please allow us reasonable time to fix the issue before public disclosure
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We will notify you when the fix is released

### Security Advisory Process

1. We validate the report
2. We develop and test a fix
3. We release a patched version
4. We publish a security advisory (GitHub Security Advisories)
5. We credit the reporter (if desired)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | Yes                |
| < 1.0   | No                 |

## Security Best Practices

When using crypto-toolkit in your projects:

1. **Keep Updated**: Use the latest version to get security fixes
2. **Key Storage**: Store keys securely (KMS, hardware tokens, encrypted key files)
3. **Key Rotation**: Implement regular key rotation policies
4. **Memory Safety**: Wipe sensitive data after use with `sodium.sodium_memzero()`
5. **Dependency Scanning**: Regularly update dependencies

## Cryptographic Guarantees

- **XChaCha20-Poly1305**: 192-bit nonces prevent birthday-bound collisions
- **Argon2id**: OWASP-compliant memory/time cost parameters
- **Ed25519**: Deterministic signatures, no weak nonces
- **Constant-time**: All comparisons use timing-safe functions
- **No weak algorithms**: HS256, CBC, MD5, and SHA-1 are not exposed

## Security Update Notifications

Subscribe to security updates:
- **GitHub**: Watch this repository for security advisories
- **npm**: `npm audit` will show vulnerabilities
- **Email**: security@empoweredhumanity.ai (for critical advisories)

## Bug Bounty

We currently do not offer a bug bounty program. However, we deeply appreciate security researchers who responsibly disclose vulnerabilities and will publicly acknowledge your contribution.

## Questions?

For non-security questions, please use GitHub Issues.
For security concerns, email security@empoweredhumanity.ai.
