# Security Policy

## Supported Versions

We actively maintain security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in MetaFuse, please report it responsibly:

### Preferred Method: Private Security Advisory

1. Navigate to the [Security Advisories](https://github.com/YOUR_ORG/MetaFuse/security/advisories) page
2. Click "Report a vulnerability"
3. Provide detailed information about the vulnerability

### Alternative: Direct Email

Send a detailed report to: **security@YOUR_DOMAIN.com**

### What to Include

Please include as much of the following information as possible:

- **Type of vulnerability** (e.g., SQL injection, authentication bypass, DoS)
- **Affected component(s)** (e.g., catalog-api, rate limiting, API key auth)
- **Affected version(s)** or commit hash
- **Step-by-step instructions to reproduce**
- **Proof-of-concept or exploit code** (if available)
- **Impact assessment** (who is affected, what can be exploited)
- **Suggested fix** (if you have one)

### What to Expect

- **Initial Response**: Within 48 hours of submission
- **Triage**: Within 5 business days, we'll confirm the vulnerability and severity
- **Fix Timeline**:
  - **Critical**: Patch within 7 days
  - **High**: Patch within 14 days
  - **Medium/Low**: Patch in next scheduled release
- **Disclosure**: We'll coordinate public disclosure with you after the fix is released
- **Credit**: You'll be credited in the security advisory (unless you prefer to remain anonymous)

## Security Features

MetaFuse includes security features that should be enabled in production:

### Rate Limiting (Feature: `rate-limiting`)

- Tiered limits: 5000/hour (with key), 100/hour (IP only)
- Configurable via `RATE_LIMIT_*` environment variables
- Trusted proxy support (X-Forwarded-For, X-Real-IP)
- Automatic cleanup of expired buckets

### API Key Authentication (Feature: `api-keys`)

- Cryptographically secure key generation (OsRng)
- bcrypt hashing (cost factor: 12)
- Automatic last-used-at tracking
- Soft deletion for audit trails
- Prefer `Authorization: Bearer` header over query parameters

### General Best Practices

- Run with least privilege (non-root user)
- Enable HTTPS/TLS for all API endpoints
- Configure trusted proxies carefully (see docs/SECURITY.md)
- Monitor rate limit and authentication metrics
- Rotate API keys regularly
- Review database permissions

## Known Security Considerations

### API Key Validation (O(n) Performance)

**Current behavior**: Each API key validation loads all non-revoked keys and bcrypt-verifies each one.

**Why**: bcrypt hashes are salted, preventing direct database lookups.

**Mitigation**:
- Aggressive caching (5-minute TTL by default)
- Revocation immediately clears cache
- Cache keys are hashed (not plaintext)

**Future optimization**: Consider adding a SHA-256 lookup column for O(1) candidate filtering before bcrypt verification.

**Impact**: Potential DoS if key count grows very large. Monitor key count and validation latency.

### Rate Limiting Memory Bounds

**Current behavior**: In-memory DashMap stores rate limit buckets per-key or per-IP.

**Mitigation**:
- Automatic bucket expiry (configurable TTL)
- Maximum bucket cap (10,000 by default)
- Periodic cleanup task

**Impact**: Memory usage scales with unique client count. Monitor memory consumption in high-traffic environments.

## Security Advisories

Security advisories for MetaFuse are published at:

https://github.com/YOUR_ORG/MetaFuse/security/advisories

Subscribe to notifications to stay informed about security updates.

## Security Contacts

- **Security Team**: security@YOUR_DOMAIN.com
- **Maintainer**: @ethanurbanski

---

For more detailed security guidance, see [docs/SECURITY.md](../docs/SECURITY.md).
