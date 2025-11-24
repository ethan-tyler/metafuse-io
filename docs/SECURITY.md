# MetaFuse Security Guide

**TL;DR**: Enable both `rate-limiting` and `api-keys` features in production. Use `Authorization: Bearer` headers (not query params). Configure trusted proxies correctly. Enable HTTPS. Monitor key usage and rotate regularly. Review the security checklist before deploying.

---

## Table of Contents

- [Security Features Overview](#security-features-overview)
- [Rate Limiting](#rate-limiting)
- [API Key Authentication](#api-key-authentication)
- [Deployment Security](#deployment-security)
- [Monitoring & Incident Response](#monitoring--incident-response)
- [Security Checklist](#security-checklist)

---

## Security Features Overview

MetaFuse provides two complementary security features:

| Feature | Purpose | Default Limits | Memory Overhead |
|---------|---------|----------------|-----------------|
| `rate-limiting` | Prevent abuse, DoS protection | 5000/hour (with key), 100/hour (IP) | ~10MB per 10K clients |
| `api-keys` | Authentication, access control | N/A | ~1KB per key + 5-min cache |

**Recommendation**: Enable both features in production for defense-in-depth.

---

## Rate Limiting

### How It Works

**Middleware Architecture (Identity-Aware)**:

```text
Request → Auth Middleware → Rate Limiter → Handler
          (validates key,    (reads identity
           attaches identity) for tier selection)
```

1. **Authentication First**: Auth middleware validates API keys and attaches `ApiKeyId` to request extensions
2. **Identity-Aware Limiting**: Rate limiter reads identity from extensions (NOT raw headers)
3. **Tiered Limits**:
   - Valid API key → Authenticated tier: 5000 requests/hour
   - No/invalid API key → Anonymous tier (IP-based): 100 requests/hour
4. **Trusted Proxies**: Extracts real client IP from `X-Forwarded-For` or `X-Real-IP` headers (for anonymous tier)

**Security Guarantee**: Invalid API keys do NOT get elevated rate limits because identity is only attached after successful validation.

### Configuration

```bash
# Enable rate limiting feature
cargo build --features rate-limiting

# Environment variables (all optional)
RATE_LIMIT_REQUESTS_PER_HOUR=5000       # Authenticated limit
RATE_LIMIT_IP_REQUESTS_PER_HOUR=100     # Unauthenticated limit
RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12  # Trusted proxy CIDRs
RATE_LIMIT_BUCKET_TTL_SECS=86400        # Bucket expiry (24 hours)
RATE_LIMIT_MAX_BUCKETS=10000            # Memory cap
```

### Default Limits and Tuning

**Default Rate Limits**:

- **Authenticated (with valid API key)**: 5000 requests/hour (~83 req/min, ~1.4 req/sec)
- **Anonymous (IP-based)**: 100 requests/hour (~1.7 req/min, ~0.03 req/sec)

**When Limits Apply**:

- Authenticated limit applies ONLY when a **valid** API key is provided
- Invalid API keys fall back to anonymous (IP-based) limits
- By default, all requests without trusted proxy configuration use direct connection IP

**Tuning Guidance**:

```bash
# High-traffic API (authenticated clients)
RATE_LIMIT_REQUESTS_PER_HOUR=50000       # 833 req/min

# Restrictive anonymous access
RATE_LIMIT_IP_REQUESTS_PER_HOUR=10       # Prevent abuse

# Lenient development environment
RATE_LIMIT_REQUESTS_PER_HOUR=100000
RATE_LIMIT_IP_REQUESTS_PER_HOUR=1000
```

**Important**: Proxy headers (`X-Forwarded-For`, `X-Real-IP`) are **ignored by default** unless `RATE_LIMIT_TRUSTED_PROXIES` is configured. This prevents IP spoofing attacks.

### Trusted Proxy Configuration

**CRITICAL**: Only configure proxies you control. Incorrect configuration allows IP spoofing.

#### AWS (Application Load Balancer)

```bash
# ALB uses private IPs (RFC 1918)
RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

#### GCP (Cloud Load Balancing)

```bash
# GCP uses specific IP ranges
RATE_LIMIT_TRUSTED_PROXIES=130.211.0.0/22,35.191.0.0/16
```

#### Cloudflare

```bash
# Cloudflare publishes IP ranges (example, check current list)
RATE_LIMIT_TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22
```

#### Testing/Development

```bash
# Trust localhost for testing ONLY
RATE_LIMIT_TRUSTED_PROXIES=127.0.0.1/32,::1/128
```

**Security Note**:
- Validate proxy IPs against **current** official ranges (they change)
- Never trust public/untrusted proxies
- Monitor for `X-Forwarded-For` chain length attacks
- Prefer `X-Real-IP` if your proxy sets it correctly

### IPv6 Support

Rate limiting fully supports IPv6:
- IPv6 addresses extracted from `X-Forwarded-For` and `X-Real-IP`
- Trusted proxy CIDRs support IPv6 notation (e.g., `::1/128`)
- Dual-stack environments work transparently

### Memory Management

**Automatic Cleanup**:
- Expired buckets removed on access
- Periodic cleanup task (every 60 seconds)
- Maximum bucket cap enforced (10,000 default)

**Memory Estimation**:
```
Buckets = min(unique_clients, MAX_BUCKETS)
Memory ≈ Buckets × 100 bytes ≈ 1MB per 10K clients
```

**High-Traffic Environments**:
- Monitor memory usage via system metrics
- Increase `RATE_LIMIT_MAX_BUCKETS` if needed (with caution)
- Consider shorter `RATE_LIMIT_BUCKET_TTL_SECS` to expire faster

### Testing Rate Limits

```bash
# Test unauthenticated limit (100/hour = ~1.67/min)
for i in {1..110}; do
  curl http://localhost:8080/v1/catalogs
  sleep 0.1
done
# Expect 429 after ~100 requests

# Test authenticated limit (5000/hour = ~83/min)
API_KEY=$(metafuse api-key create test | grep "API Key:" | awk '{print $3}')
for i in {1..5100}; do
  curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/v1/catalogs
  sleep 0.01
done
# Expect 429 after ~5000 requests
```

---

## API Key Authentication

### How It Works

1. **Key Generation**: 32-byte base64 key via `OsRng` (cryptographically secure)
2. **Hashing**: bcrypt with cost factor 12 (~300ms verification time)
3. **Validation**: Checks bcrypt hash against database (cached for 5 minutes)
4. **Tracking**: Updates `last_used_at` in background (batch flush every 30 seconds)
5. **Revocation**: Soft-delete with immediate cache eviction

### Creating Keys

```bash
# Via CLI
metafuse api-key create "production-api-key"
# Output:
# Created API key: production-api-key (ID: 1)
# API Key: mf_1a2b3c4d5e6f7g8h9i0j...
#
# IMPORTANT: Store this key securely. It cannot be retrieved later.

# List keys (shows metadata, not plaintext)
metafuse api-key list
# Output:
# ID | Name               | Created             | Last Used           | Revoked
# ---+--------------------+---------------------+---------------------+---------
# 1  | production-api-key | 2024-01-15 10:30:00 | 2024-01-15 14:22:05 | No

# Revoke a key
metafuse api-key revoke 1
# Output: Revoked API key ID 1
```

### Using Keys

**Preferred: Authorization Header**

```bash
curl -H "Authorization: Bearer mf_1a2b3c4d5e6f7g8h9i0j..." \
  http://localhost:8080/v1/catalogs
```

**Alternative: Query Parameter** (avoid in production)

```bash
curl "http://localhost:8080/v1/catalogs?api_key=mf_1a2b3c4d5e6f7g8h9i0j..."
```

**Why Avoid Query Parameters**:
- Logged by web servers, proxies, and CDNs
- Visible in browser history and referrer headers
- Included in error pages and stack traces
- Cached by intermediaries

**Use query params ONLY for**:
- Quick local testing
- Environments where headers are impractical (e.g., browser data sources)

### Security Model

#### Cache Security

- **Cache Keys**: Hashed via `DefaultHasher` (not plaintext)
- **Eviction**: Revocation immediately clears entire cache
- **TTL**: 5-minute default (configurable via `cache_ttl_secs`)
- **Pending Updates**: Keyed by bcrypt hash (not plaintext)

**Memory Safety**: No plaintext keys stored in memory maps.

#### Validation Performance

**Current**: O(n) over all non-revoked keys
- Each validation loads all hashes and bcrypt-verifies each
- **Why**: bcrypt salts prevent direct database lookups

**Mitigation**:
- Aggressive 5-minute caching
- Average validation: <10ms (cache hit)
- Cache miss: ~300ms × number of keys

**DoS Risk**: High key count (>100) degrades performance
- Monitor validation latency
- Limit key creation to trusted admins
- Consider key rotation/cleanup policies

**Future Optimization**: Add SHA-256 lookup column for O(1) candidate filtering:
```sql
ALTER TABLE api_keys ADD COLUMN key_sha256 TEXT;
CREATE INDEX idx_key_sha256 ON api_keys(key_sha256);
-- Then: WHERE key_sha256 = sha256(plaintext) LIMIT 1
```

#### Revocation Model

**Soft Deletion**:
- Sets `revoked_at` timestamp (preserves audit trail)
- Validation excludes `WHERE revoked_at IS NULL`
- `list_keys` shows revocation status

**Immediate Enforcement**:
- Cache cleared on revoke (prevents TOCTOU)
- Pending updates cleared (prevents stale flush)
- Next validation will fail (cache miss → DB check)

### Configuration

```rust
// In code (when instantiating ApiKeyManager)
let manager = ApiKeyManager::with_config(
    db_path,
    ApiKeyConfig {
        cache_ttl_secs: 300,      // 5 minutes
        flush_interval_secs: 30,  // 30 seconds
        bcrypt_cost: 12,          // ~300ms verification
    },
)?;
```

**Tuning**:
- **Higher `bcrypt_cost`** (13-14): More secure, slower validation (600ms-1200ms)
- **Lower `cache_ttl_secs`** (60-120): Faster revocation propagation, more DB load
- **Higher `flush_interval_secs`** (60-300): Less write load, longer delay in `last_used_at`

### Key Rotation Best Practices

1. **Create new key** before revoking old one
2. **Update clients** with new key
3. **Monitor `last_used_at`** to confirm migration
4. **Revoke old key** after 24-48 hours
5. **Verify no errors** from old key usage

```bash
# 1. Create new key
NEW_KEY=$(metafuse api-key create "production-v2" | grep "API Key:" | awk '{print $3}')

# 2. Update app config (gradual rollout)
# 3. Wait 24 hours, monitor logs
metafuse api-key list  # Check last_used_at for old key

# 4. Revoke old key
metafuse api-key revoke 1  # Old key ID
```

---

## Deployment Security

### Pre-Deployment Checklist

- [ ] Enable `rate-limiting` and `api-keys` features in production
- [ ] Configure `RATE_LIMIT_TRUSTED_PROXIES` for your infrastructure
- [ ] Generate production API keys (do NOT reuse dev keys)
- [ ] Enable HTTPS/TLS for all endpoints
- [ ] Run MetaFuse as non-root user (drop privileges)
- [ ] Restrict database file permissions (`chmod 600`)
- [ ] Configure firewall rules (allow only necessary ports)
- [ ] Set up monitoring and alerting (see below)
- [ ] Review and apply security updates regularly

### TLS/HTTPS Configuration

**Do NOT** terminate TLS at MetaFuse. Use a reverse proxy:

#### Nginx

```nginx
upstream metafuse {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/api.example.com.crt;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://metafuse;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Caddy (automatic HTTPS)

```
api.example.com {
    reverse_proxy localhost:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
    }
}
```

### Container Security

```dockerfile
# Use minimal base image
FROM debian:bookworm-slim

# Run as non-root user
RUN useradd -m -u 1001 metafuse
USER metafuse

# Copy binary (built in multi-stage)
COPY --from=builder /app/target/release/metafuse-api /usr/local/bin/

# Restrict file permissions
RUN chmod 600 /data/catalog.db

# Expose only necessary port
EXPOSE 8080

CMD ["metafuse-api"]
```

### Cloud Security

#### AWS

- Use **Security Groups** to restrict inbound traffic
- Store API keys in **AWS Secrets Manager** (not environment variables)
- Enable **CloudWatch Logs** for audit trails
- Use **ALB access logs** for request monitoring
- Configure **VPC** for network isolation

#### GCP

- Use **Firewall Rules** to restrict access
- Store keys in **Secret Manager**
- Enable **Cloud Logging** and **Cloud Monitoring**
- Use **Cloud Armor** for additional DDoS protection
- Configure **VPC Service Controls** for data isolation

---

## Monitoring & Incident Response

### Metrics to Monitor

| Metric | Alert Threshold | Action |
|--------|----------------|--------|
| `429` response rate | >5% | Check for attack or legitimate traffic spike |
| `401` response rate | >1% | Check for key compromise or misconfiguration |
| API key validation latency | >500ms | Investigate key count or DB performance |
| `last_used_at` staleness | >7 days | Rotate or revoke stale keys |
| Memory usage | >80% | Check bucket count or increase limits |
| Request rate | >1000 RPS | Scale horizontally or adjust rate limits |

### Logging Security Events

```rust
// Add logging to your application
use tracing::{info, warn};

// Log authentication failures
if !is_valid {
    warn!(api_key_prefix = &key[..8], "Invalid API key attempt");
}

// Log rate limit hits
info!(client_id, "Rate limit exceeded (429 response)");

// Log key usage for audit
info!(key_id, "API key used for request");
```

### Incident Response

#### Suspected Key Compromise

1. **Immediately revoke** the compromised key
2. **Check `last_used_at`** to determine exposure window
3. **Review logs** for unauthorized access patterns
4. **Rotate all keys** from the same source
5. **Notify affected parties** (if applicable)

```bash
# Emergency key revocation
metafuse api-key revoke <ID>

# Verify revocation
metafuse api-key list | grep "ID: <ID>"  # Should show "Revoked: Yes"

# Test revocation
curl -H "Authorization: Bearer <COMPROMISED_KEY>" http://localhost:8080/v1/catalogs
# Expect: 401 Unauthorized
```

#### DDoS/Rate Limit Attack

1. **Check current limits**: Review `RATE_LIMIT_*` environment variables
2. **Tighten limits temporarily**: Lower `RATE_LIMIT_IP_REQUESTS_PER_HOUR`
3. **Enable upstream protection**: CloudFlare, AWS Shield, GCP Cloud Armor
4. **Review logs**: Identify attack patterns (IPs, user agents, endpoints)
5. **Block at firewall**: Add firewall rules for malicious IPs

---

## Security Checklist

Use this checklist before deploying to production or after major changes:

### Features & Configuration

- [ ] Rate limiting enabled (`--features rate-limiting`)
- [ ] API key authentication enabled (`--features api-keys`)
- [ ] Trusted proxies configured correctly (`RATE_LIMIT_TRUSTED_PROXIES`)
- [ ] HTTPS/TLS enabled via reverse proxy
- [ ] Production API keys generated (not dev/test keys)
- [ ] Query parameter auth disabled or documented

### Infrastructure

- [ ] MetaFuse runs as non-root user
- [ ] Database file permissions restricted (`chmod 600`)
- [ ] Firewall rules configured (allow only 443/80)
- [ ] Secrets stored securely (not in environment variables or code)
- [ ] Reverse proxy configured (Nginx, Caddy, ALB, etc.)
- [ ] Container images scanned for vulnerabilities

### Monitoring & Operations

- [ ] Logging enabled (API requests, auth failures, rate limits)
- [ ] Metrics collection configured (Prometheus, CloudWatch, etc.)
- [ ] Alerts configured (429/401 rates, latency, memory)
- [ ] Backup strategy for database
- [ ] Key rotation policy documented
- [ ] Incident response plan defined

### Testing

- [ ] Rate limiting tested under load
- [ ] API key authentication tested (valid, invalid, revoked)
- [ ] Trusted proxy IP extraction tested
- [ ] Revocation enforcement tested (cache cleared)
- [ ] Security headers tested (CSP, HSTS, etc. via reverse proxy)

### Documentation

- [ ] Security policy published (`.github/SECURITY.md`)
- [ ] Deployment docs include security hardening
- [ ] Key rotation procedures documented
- [ ] Monitoring/alerting runbook created
- [ ] Incident response contacts identified

---

## Additional Resources

- **OWASP API Security Top 10**: https://owasp.org/www-project-api-security/
- **Bcrypt Best Practices**: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **Rate Limiting Patterns**: https://www.rfc-editor.org/rfc/rfc6585#section-4
- **Trusted Proxy Risks**: https://adam-p.ca/blog/2022/03/x-forwarded-for/

---

**For vulnerability reporting, see**: [.github/SECURITY.md](../.github/SECURITY.md)
