# Troubleshooting Guide

This guide covers common issues and solutions for MetaFuse deployment and operation.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Catalog Initialization](#catalog-initialization)
- [Validation Errors](#validation-errors)
- [API Server Issues](#api-server-issues)
- [Search Problems](#search-problems)
- [Performance Issues](#performance-issues)
- [Error Correlation](#error-correlation)

---

## Installation Issues

### Binary not found after installation

**Symptom**: `metafuse: command not found` after running install script

**Solution**:
```bash
# Check if binary exists
ls -la ~/.metafuse/bin/metafuse

# Add to PATH (add to ~/.bashrc or ~/.zshrc)
export PATH="$PATH:$HOME/.metafuse/bin"

# Reload shell
source ~/.bashrc  # or source ~/.zshrc
```

### Permission denied when running binary

**Symptom**: `Permission denied` error

**Solution**:
```bash
chmod +x ~/.metafuse/bin/metafuse
chmod +x ~/.metafuse/bin/metafuse-api
```

### Platform-specific issues

**Linux (glibc version)**:
```bash
# Check glibc version
ldd --version

# MetaFuse requires glibc 2.31+ (Ubuntu 20.04+, Debian 11+)
```

**macOS (M1/M2)**:
```bash
# Ensure you downloaded the aarch64-apple-darwin binary
file ~/.metafuse/bin/metafuse
# Should show: Mach-O 64-bit executable arm64
```

---

## Catalog Initialization

### Catalog already exists error

**Symptom**: `Catalog already exists at 'metafuse_catalog.db'`

**Solution**:
```bash
# Force reinitialize (WARNING: destroys existing catalog)
metafuse init --force

# Or use a different path
metafuse init --catalog my_new_catalog.db
```

### SQLite errors during init

**Symptom**: `Failed to initialize catalog: SQLite error`

**Solution**:
```bash
# Check disk space
df -h

# Check write permissions
touch metafuse_catalog.db && rm metafuse_catalog.db

# Check for corrupted database
rm metafuse_catalog.db*
metafuse init
```

---

## Validation Errors

### Invalid dataset name

**Symptom**: `Validation error: Dataset name contains invalid characters`

**Allowed characters**: Alphanumeric, underscore (`_`), hyphen (`-`), dot (`.`)
**Max length**: 255 characters
**Cannot start/end with**: Hyphen

**Examples**:
```rust
// Valid
"my_dataset"
"dataset-v2"
"analytics.users"

// Invalid
"my dataset"    // Space
"my@dataset"    // Special char
"-dataset"      // Starts with hyphen
```

### Invalid field name

**Symptom**: `Validation error: Field name contains invalid characters`

**Allowed characters**: Alphanumeric, underscore (`_`)
**Max length**: 255 characters

**Examples**:
```rust
// Valid
"user_id"
"totalAmount"
"field123"

// Invalid
"user-id"      // Hyphen
"user id"      // Space
"user.id"      // Dot
```

### Invalid tenant/domain

**Symptom**: `Validation error: tenant contains invalid characters`

**Allowed characters**: Alphanumeric, underscore (`_`), hyphen (`-`)
**Max length**: 100 characters

**Examples**:
```rust
// Valid
"prod"
"team-analytics"
"tenant_123"

// Invalid
"my:tenant"    // Colon
"tenant 1"     // Space
```

### Invalid tag

**Symptom**: `Validation error: Tag contains invalid characters`

**Allowed characters**: Alphanumeric, underscore (`_`), hyphen (`-`), colon (`:`)
**Max length**: 100 characters

**Note**: Colons are allowed for namespacing (e.g., `env:prod`, `team:analytics`)

---

## API Server Issues

### Port already in use

**Symptom**: `Address already in use (os error 48)`

**Solution**:
```bash
# Check what's using port 8080
lsof -i :8080
netstat -an | grep 8080

# Use a different port
export METAFUSE_PORT=8081
metafuse-api

# Or kill the process
kill <PID>
```

### Catalog file not found

**Symptom**: API returns 500 errors, logs show `No such file or directory`

**Solution**:
```bash
# Initialize catalog first
metafuse init

# Or specify path
export METAFUSE_CATALOG_PATH=/path/to/catalog.db
metafuse-api
```

### Internal server error with request ID

**Symptom**: API returns `{"error": "Internal server error. Please contact support with the request ID.", "request_id": "abc-123"}`

**Solution**:
```bash
# Enable debug logging
export RUST_LOG=debug
metafuse-api

# Search logs for request ID
grep "abc-123" api.log

# Common causes:
# - Database locked (concurrent writes)
# - Corrupted catalog file
# - Schema mismatch (try recreating catalog)
```

### CORS errors in browser

**Symptom**: Browser console shows CORS policy errors

**Note**: MetaFuse API uses `CorsLayer::permissive()` by default. If you still see CORS errors:

**Solution**:
```bash
# Check if API is actually running
curl http://localhost:8080/health

# Check browser is using correct URL
# Should be: http://localhost:8080/api/v1/datasets
# Not: https://localhost:8080/...  (note http vs https)
```

---

## Search Problems

### Search returns no results

**Symptom**: `/api/v1/search?q=analytics` returns empty array

**Possible causes**:

1. **FTS index not populated**:
```bash
# Check if dataset_search table is empty
sqlite3 metafuse_catalog.db "SELECT COUNT(*) FROM dataset_search;"
```

2. **Query syntax error**:
```bash
# Try simple search first
curl "http://localhost:8080/api/v1/search?q=test"

# FTS5 operators require proper syntax
curl "http://localhost:8080/api/v1/search?q=analytics+AND+finance"
# (Note: + for space in URLs)
```

3. **Case sensitivity**:
```bash
# FTS5 is case-insensitive by default, but verify:
curl "http://localhost:8080/api/v1/search?q=ANALYTICS"
```

### Query too long error

**Symptom**: `Validation error: Search query too long: 512 > 500 characters`

**Solution**: Shorten your query to 500 characters or less

---

## Performance Issues

### Slow dataset listing

**Symptom**: `/api/v1/datasets` takes >1s to respond

**Solution**:
```bash
# Check catalog size
ls -lh metafuse_catalog.db

# Analyze indexes
sqlite3 metafuse_catalog.db "ANALYZE;"

# Vacuum to reclaim space
sqlite3 metafuse_catalog.db "VACUUM;"

# Enable WAL mode for better concurrency
sqlite3 metafuse_catalog.db "PRAGMA journal_mode=WAL;"
```

### Slow search queries

**Symptom**: Search takes multiple seconds

**Solution**:
```bash
# Check FTS index
sqlite3 metafuse_catalog.db "SELECT COUNT(*) FROM dataset_search;"

# Rebuild FTS index
sqlite3 metafuse_catalog.db "INSERT INTO dataset_search(dataset_search) VALUES('rebuild');"

# Optimize FTS
sqlite3 metafuse_catalog.db "INSERT INTO dataset_search(dataset_search) VALUES('optimize');"
```

### High memory usage

**Symptom**: API process using >1GB RAM

**Common causes**:
- Large result sets (use filters: `?tenant=...`)
- Frequent full scans
- No connection pooling (SQLite opens fresh connections)

**Solution**:
```bash
# Filter queries
curl "http://localhost:8080/api/v1/datasets?domain=analytics"

# Monitor memory
ps aux | grep metafuse-api
```

---

## Error Correlation

### Finding request in logs

**Symptom**: Got request ID from error response, need to find logs

**Solution**:
```bash
# Set structured logging format
export RUST_LOG=info
metafuse-api | tee api.log

# Search for request ID
grep "abc-123" api.log

# Example log entry:
# 2025-01-21T10:30:45 INFO request{request_id=abc-123 method=GET uri=/api/v1/datasets}: Request started
```

### Request ID in response headers

**All API responses include X-Request-ID header**:

```bash
curl -v http://localhost:8080/api/v1/datasets
# ...
# < X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
```

### Correlating errors across systems

If you're calling MetaFuse API from another service:

1. **Extract request ID from response**
2. **Include in your application logs**
3. **Search MetaFuse API logs for same ID**

Example:
```python
import requests

response = requests.get("http://localhost:8080/api/v1/datasets/my_dataset")
request_id = response.headers.get("X-Request-ID")

if not response.ok:
    logger.error(
        f"MetaFuse API error: {response.json()}",
        extra={"metafuse_request_id": request_id}
    )
```

---

## Docker Deployment Issues

### Container fails to start

**Symptom**: `docker run` exits immediately

**Solution**:
```bash
# Check logs
docker logs <container_id>

# Common issues:
# 1. Catalog file permissions
docker run -v $(pwd)/data:/data metafuse-api

# 2. Port mapping
docker run -p 8080:8080 metafuse-api

# 3. Health check failures (wait for startup)
docker run --health-cmd=none metafuse-api
```

### Catalog not persisting

**Symptom**: Data lost after container restart

**Solution**:
```bash
# Mount volume for persistence
docker run -v metafuse-data:/data metafuse-api

# Or bind mount
docker run -v $(pwd)/catalog-data:/data metafuse-api
```

---

## Getting Help

If you're still stuck:

1. **Check GitHub Issues**: https://github.com/ethan-tyler/MetaFuse/issues
2. **Enable debug logging**: `export RUST_LOG=debug`
3. **Gather diagnostics**:
```bash
# System info
uname -a
metafuse --version

# Catalog info
metafuse stats --catalog metafuse_catalog.db

# SQLite info
sqlite3 metafuse_catalog.db "SELECT sqlite_version();"
sqlite3 metafuse_catalog.db "PRAGMA integrity_check;"
```

4. **Create issue with**:
   - MetaFuse version
   - Operating system
   - Error message
   - Request ID (if applicable)
   - Steps to reproduce
