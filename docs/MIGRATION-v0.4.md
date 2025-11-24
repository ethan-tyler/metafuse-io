# Migration Guide: v0.3.0 → v0.4.3

This guide helps you upgrade from MetaFuse v0.3.0 (Cloud Backends) to v0.4.3 (Security & Authentication).

---

## TL;DR

**Good news**: v0.4.3 is **100% backward compatible**. All v0.3.0 code continues to work unchanged. Security features are opt-in via feature flags.

**Quick upgrade**:

```bash
# Update dependency
cargo update -p metafuse-catalog-api

# Build with default features (no changes)
cargo build

# Or enable security features (recommended for production)
cargo build --features "rate-limiting,api-keys"
```

---

## What's New in v0.4.x

### v0.4.0 - v0.4.3: Security & Authentication

MetaFuse v0.4.x introduces enterprise-grade security features:

- **Rate Limiting**: Protect your API from abuse and DoS attacks
- **API Key Authentication**: Secure access control with bcrypt-hashed keys
- **Identity-Aware Architecture**: Proper separation of concerns for security
- **Production-Ready**: Comprehensive documentation, testing, and deployment guides

All features are opt-in via feature flags, so you can adopt them incrementally.

---

## Breaking Changes

**None.** This is a non-breaking feature release.

- All v0.3.0 APIs remain unchanged
- Database schema is backward compatible
- No configuration changes required

---

## Step-by-Step Migration

### Step 1: Update Dependencies

Update your `Cargo.toml`:

```toml
[dependencies]
metafuse-catalog-api = "0.4.3"
metafuse-catalog-core = "0.4.3"
metafuse-catalog-storage = "0.4.3"
```

Then update:

```bash
cargo update
```

### Step 2: Test Without Security Features

First, ensure your existing code works unchanged:

```bash
cargo test
cargo run
```

If everything works, you're ready for Step 3.

### Step 3 (Optional): Enable Rate Limiting

Enable rate limiting to protect your API from abuse:

**Update Cargo.toml**:

```toml
[dependencies]
metafuse-catalog-api = { version = "0.4.3", features = ["rate-limiting"] }
```

**Build and run**:

```bash
cargo build --features rate-limiting
cargo run --features rate-limiting
```

**Configure via environment variables** (optional):

```bash
# Authenticated clients (with valid API key)
export RATE_LIMIT_REQUESTS_PER_HOUR=5000

# Anonymous clients (IP-based)
export RATE_LIMIT_IP_REQUESTS_PER_HOUR=100

# Trusted proxies (AWS ALB example)
export RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

**Test rate limiting**:

```bash
# Should allow first 100 requests, then return 429
for i in {1..110}; do
  curl http://localhost:8080/v1/catalogs
  sleep 0.1
done
```

### Step 4 (Optional): Enable API Key Authentication

Enable API keys for access control:

**Update Cargo.toml**:

```toml
[dependencies]
metafuse-catalog-api = { version = "0.4.3", features = ["api-keys"] }
metafuse-catalog-cli = { version = "0.4.3", features = ["api-keys"] }
```

**Build with API key support**:

```bash
cargo build --features api-keys
```

**Create your first API key**:

```bash
metafuse api-key create "production-api"
# Output:
# ✓ Created API key: production-api
#
# API Key (save this - it won't be shown again!):
#   mf_1a2b3c4d5e6f...
#
# Use this key in your requests:
#   Authorization: Bearer mf_1a2b3c4d5e6f...
```

**Test authentication**:

```bash
# With valid key (should succeed)
curl -H "Authorization: Bearer mf_1a2b3c4d5e6f..." \
  http://localhost:8080/v1/catalogs

# Without key (should return 401 if middleware is enabled)
curl http://localhost:8080/v1/catalogs
```

**List and manage keys**:

```bash
# List all keys
metafuse api-key list

# Revoke a key
metafuse api-key revoke <id>
```

### Step 5 (Recommended): Enable Both Features

For maximum security, enable both rate limiting and API keys:

**Update Cargo.toml**:

```toml
[dependencies]
metafuse-catalog-api = { version = "0.4.3", features = ["rate-limiting", "api-keys"] }
metafuse-catalog-cli = { version = "0.4.3", features = ["api-keys"] }
```

**Build with both features**:

```bash
cargo build --features "rate-limiting,api-keys"
```

**Configure environment**:

```bash
# Rate limits
export RATE_LIMIT_REQUESTS_PER_HOUR=5000
export RATE_LIMIT_IP_REQUESTS_PER_HOUR=100

# Trusted proxies (if behind load balancer)
export RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/8
```

**Identity-aware rate limiting**:

With both features enabled, the middleware architecture ensures:

- Valid API keys get **high-tier** limits (5000/hour)
- Invalid/missing API keys get **low-tier** limits (100/hour, IP-based)
- **Security guarantee**: Invalid keys do NOT receive elevated limits

```text
Request → Auth Middleware → Rate Limiter → Handler
          (validates key,    (reads identity
           attaches identity) for tier selection)
```

---

## Database Migration

### Schema Changes

The `api_keys` table is created automatically on first run:

```sql
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT,
  last_used_at TEXT
);
```

**Important**: This table is always created (even without the `api-keys` feature) for schema stability. It's harmless when unused and enables zero-downtime feature enablement.

### Upgrading Existing Databases

No manual migration required:

1. Existing databases from v0.3.0 are automatically upgraded
2. The `api_keys` table is created on first run
3. All existing data remains intact
4. Schema version is compatible with v0.4.0+

---

## Configuration Changes

### New Environment Variables

All variables are optional with sensible defaults:

#### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_REQUESTS_PER_HOUR` | 5000 | Authenticated limit |
| `RATE_LIMIT_IP_REQUESTS_PER_HOUR` | 100 | Anonymous limit |
| `RATE_LIMIT_TRUSTED_PROXIES` | None | Comma-separated proxy CIDRs |
| `RATE_LIMIT_BUCKET_TTL_SECS` | 86400 | Bucket expiry (24 hours) |
| `RATE_LIMIT_MAX_BUCKETS` | 10000 | Memory cap |

#### API Keys

Configuration is primarily via CLI commands, not environment variables. The manager uses in-code defaults:

- `cache_ttl_secs`: 300 (5 minutes)
- `flush_interval_secs`: 30 (30 seconds)
- `bcrypt_cost`: 12 (~300ms verification)

### Trusted Proxy Configuration

**CRITICAL**: Only configure proxies you control.

#### AWS (Application Load Balancer)

```bash
export RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

#### GCP (Cloud Load Balancing)

```bash
export RATE_LIMIT_TRUSTED_PROXIES=130.211.0.0/22,35.191.0.0/16
```

#### Development (localhost only)

```bash
export RATE_LIMIT_TRUSTED_PROXIES=127.0.0.1/32,::1/128
```

---

## Testing Your Upgrade

### 1. Unit Tests

```bash
# Test with default features
cargo test

# Test with security features
cargo test --features "rate-limiting,api-keys"
```

### 2. Integration Tests

```bash
# Test rate limiting
for i in {1..110}; do curl http://localhost:8080/v1/catalogs; done

# Test API key authentication
API_KEY=$(metafuse api-key create test | grep "API Key:" | awk '{print $3}')
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/v1/catalogs
```

### 3. Load Testing (Optional)

Use a tool like `wrk` or `ab` to verify rate limiting under load:

```bash
# Test authenticated throughput (should handle 5000/hour)
wrk -t2 -c10 -d60s \
  -H "Authorization: Bearer $API_KEY" \
  http://localhost:8080/v1/catalogs

# Test anonymous throughput (should rate limit at 100/hour)
wrk -t2 -c10 -d60s http://localhost:8080/v1/catalogs
```

---

## Rollback Plan

If you encounter issues, rollback is simple:

### Option 1: Disable Features

```bash
# Rebuild without security features
cargo build

# Or disable specific features
cargo build --features metrics  # metrics only, no security
```

### Option 2: Downgrade Version

```toml
[dependencies]
metafuse-catalog-api = "0.3.0"
metafuse-catalog-core = "0.3.0"
metafuse-catalog-storage = "0.3.0"
```

```bash
cargo update
cargo build
```

The database schema remains compatible, so no data migration is needed.

---

## Performance Impact

### With Features Disabled (Default)

- **Zero overhead**: No performance impact
- **Binary size**: No increase
- **Dependencies**: No additional dependencies

### With Rate Limiting Enabled

- **Latency**: <1ms overhead per request (in-memory DashMap)
- **Memory**: ~100 bytes per bucket (~1MB per 10K clients)
- **CPU**: Minimal (hash lookup and counter increment)

### With API Key Auth Enabled

- **Cache hit**: <10ms (hash lookup)
- **Cache miss**: ~300ms × key count (bcrypt verification)
- **Mitigation**: 5-minute cache TTL reduces database load by ~99%

---

## Common Issues

### Issue: Rate limiting not working

**Symptom**: All requests allowed regardless of count

**Solution**:

1. Verify feature is enabled: `cargo build --features rate-limiting`
2. Check middleware is installed (see API server code)
3. Test with lower limits for debugging:

```bash
export RATE_LIMIT_IP_REQUESTS_PER_HOUR=10
```

### Issue: API keys not validating

**Symptom**: 401 Unauthorized for valid keys

**Solution**:

1. Verify feature is enabled: `cargo build --features api-keys`
2. Check database path is correct
3. List keys to verify they exist:

```bash
metafuse api-key list
```

4. Try recreating the key:

```bash
metafuse api-key revoke <old-id>
metafuse api-key create "new-key"
```

### Issue: Trusted proxy not working

**Symptom**: Rate limiting uses proxy IP instead of client IP

**Solution**:

1. Verify proxy IP is in trusted list
2. Check header format: `X-Forwarded-For: client-ip, proxy-ip`
3. Use exact IP (not CIDR) for testing:

```bash
export RATE_LIMIT_TRUSTED_PROXIES=10.0.0.1
```

4. Check logs for warnings about untrusted proxies

---

## Security Checklist

Before deploying v0.4.3 to production, review:

- [ ] Rate limiting enabled (`--features rate-limiting`)
- [ ] API key auth enabled (`--features api-keys`)
- [ ] Trusted proxies configured correctly (match your infrastructure)
- [ ] Production API keys created (not dev/test keys)
- [ ] HTTPS/TLS enabled via reverse proxy
- [ ] Database file permissions restricted (`chmod 600`)
- [ ] Monitoring and alerting configured
- [ ] Key rotation policy documented

See [docs/security-checklist.md](security-checklist.md) for the full checklist.

---

## Next Steps

1. **Read Security Documentation**: [docs/SECURITY.md](SECURITY.md)
2. **Review Deployment Guides**:
   - AWS: [docs/deployment-aws.md](deployment-aws.md)
   - GCP: [docs/deployment-gcp.md](deployment-gcp.md)
3. **Set Up Monitoring**: [docs/METRICS.md](METRICS.md)
4. **Join the Community**: GitHub Discussions, Discord

---

## Support

- **Issues**: [GitHub Issues](https://github.com/YOUR_ORG/MetaFuse/issues)
- **Security**: [.github/SECURITY.md](../.github/SECURITY.md)
- **Documentation**: [docs/](.)

---

**Congratulations!** You've successfully upgraded to MetaFuse v0.4.3 with enterprise-grade security features. 🎉
