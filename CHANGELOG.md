# Changelog

All notable changes to MetaFuse will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [0.4.3] - 2025-01-24

### Week 3: Security Features (Rate Limiting & API Key Authentication) - Production Ready

**Major security enhancements with production-ready rate limiting and API key authentication, including critical architecture fix for identity-aware rate limiting.**

#### 🔒 Security - Critical Architecture Fix

- **Fixed Identity-Aware Rate Limiting Vulnerability**
  - **Previous behavior**: Rate limiter checked for Bearer token presence (not validity) to assign tier
  - **Security flaw**: Invalid API keys received elevated rate limits until auth middleware rejected them
  - **Fix**: Proper middleware ordering with identity-aware architecture:

    ```text
    Request → Auth Middleware → Rate Limiter → Handler
              (validates key,    (reads identity
               attaches identity) for tier selection)
    ```

  - Auth middleware now validates keys and attaches `ApiKeyId` to request extensions
  - Rate limiter reads identity from extensions (NOT raw headers)
  - **Security guarantee**: Invalid API keys NO LONGER get elevated rate limits
  - Added `test_invalid_key_does_not_get_identity()` security test
  - Added `test_error_response_format()` for error consistency

#### ✨ Enhanced - Production-Ready Improvements

- **Consistent Error Responses**
  - All error responses now include `request_id` for traceability
  - 401 Unauthorized: `{error, message, request_id}`
  - 429 Too Many Requests: `{error, message, request_id, retry_after}`
  - 500 Internal Server Error: `{error, message, request_id}`
  - Improves observability and incident response

- **Default Limits and Tuning Documentation**
  - Documented default rate limits (5000/hour auth, 100/hour anon)
  - Added tuning guidance for high-traffic APIs
  - Clarified when limits apply (only valid keys get elevated limits)
  - **Security note**: Proxy headers ignored by default (prevents IP spoofing)

- **Schema Stability Design**
  - `api_keys` table always created (feature-independent)
  - Enables zero-downtime feature enablement
  - Prevents migration issues when enabling/disabling features
  - Documented design rationale in schema comments

- **Module Exports**
  - Added `pub mod rate_limiting` to `catalog-api/lib.rs`
  - Enables proper cross-module usage with feature flags

#### Added - Security Features

- **Rate Limiting (Optional, Feature-Gated)**
  - Opt-in `rate-limiting` feature flag for DDoS protection
  - Tiered limits: 5000/hour (authenticated), 100/hour (unauthenticated)
  - Custom key extractor (API key → IP fallback)
  - Trusted proxy support (X-Forwarded-For, X-Real-IP)
  - IPv4/IPv6 validation for trusted proxy CIDRs
  - Automatic bucket lifecycle/TTL (configurable)
  - Memory bounds (max 10,000 buckets by default)
  - Configurable via environment variables:
    - `RATE_LIMIT_REQUESTS_PER_HOUR`
    - `RATE_LIMIT_IP_REQUESTS_PER_HOUR`
    - `RATE_LIMIT_TRUSTED_PROXIES`
    - `RATE_LIMIT_BUCKET_TTL_SECS`
    - `RATE_LIMIT_MAX_BUCKETS`
  - Returns 429 Too Many Requests with Retry-After header

- **API Key Authentication (Optional, Feature-Gated)**
  - Opt-in `api-keys` feature flag for authentication
  - Cryptographically secure key generation (OsRng, 32-byte base64)
  - bcrypt hashing with configurable cost factor (default: 12)
  - In-memory cache (5-minute TTL, hashed keys)
  - Background `last_used_at` flushing (30-second interval)
  - Soft deletion with audit trail (`revoked_at` timestamp)
  - Immediate cache eviction on revocation
  - CLI commands:
    - `metafuse api-key create <name>` - Create new key
    - `metafuse api-key list` - List all keys
    - `metafuse api-key revoke <id>` - Revoke key
  - Authorization methods:
    - `Authorization: Bearer <key>` header (preferred)
    - `?api_key=<key>` query parameter (testing only)
  - Schema: `api_keys` table with `id`, `name`, `key_hash`, `created_at`, `revoked_at`, `last_used_at`

#### Added - Documentation

- **Security Documentation**
  - `.github/SECURITY.md` - Vulnerability disclosure policy
  - `docs/SECURITY.md` - Comprehensive security guide (600+ lines)
    - TL;DR for quick reference
    - Rate limiting configuration and best practices
    - API key authentication usage and security model
    - Trusted proxy configuration for AWS/GCP/Cloudflare
    - Memory management and performance tuning
    - Key rotation procedures
    - Incident response procedures
  - `docs/security-checklist.md` - Pre-deployment checklist
    - Features & build checklist
    - Configuration checklist
    - Infrastructure security
    - Operational security
    - Testing requirements
    - Cloud-specific checklists (AWS/GCP)
    - Container security checklist

- **Deployment Documentation Updates**
  - `docs/deployment-aws.md` - Enhanced security section
    - Rate limiting & API key configuration for ALB
    - AWS Secrets Manager integration
    - Security Group configuration
    - HTTPS/TLS setup with ALB
    - IAM policy for least privilege
    - CloudWatch security monitoring
    - AWS WAF integration
  - `docs/deployment-gcp.md` - Enhanced security section
    - Rate limiting & API key configuration for Cloud Load Balancing
    - Secret Manager integration
    - Cloud Run and GKE deployment examples
    - IAM policy for least privilege
    - Cloud Monitoring security alerts
    - Cloud Armor DDoS protection
    - Managed TLS certificates

#### Added - Tests

- **Rate Limiting Tests** (11 tests)
  - `test_rate_limiter_allows_under_limit` - Basic functionality
  - `test_rate_limiter_key_with_api_key` - API key extraction
  - `test_rate_limiter_key_fallback_to_ip` - IP fallback
  - `test_trusted_proxy_validation` - Security validation
  - `test_untrusted_proxy_ignores_x_real_ip` - Security enforcement
  - `test_trusted_proxy_ipv6` - IPv6 support
  - `test_bucket_ttl_prevents_eviction_of_active` - TTL behavior
  - `test_bucket_cleanup` - Lifecycle management
  - `test_bucket_cap_enforcement` - Memory bounds
  - `test_config_defaults` - Configuration
  - `test_rate_limit_response_includes_request_id` - Error formatting

- **API Key Tests** (8 tests)
  - `test_create_and_validate_key` - Basic flow
  - `test_cache_hit` - Cache performance
  - `test_revoke_key` - Revocation
  - `test_revoke_clears_cache` - **SECURITY: Immediate eviction**
  - `test_list_keys` - CLI functionality
  - `test_flush_pending_updates` - Background flushing
  - `test_invalid_key_does_not_get_identity` - **SECURITY: Invalid keys don't get elevated limits**
  - `test_error_response_format` - **PRODUCTION: Consistent error format**

#### Changed - CI/CD

- **GitHub Actions**
  - Added `security-features` job with feature matrix:
    - `rate-limiting` only
    - `api-keys` only
    - `rate-limiting,api-keys` combined
    - `rate-limiting,api-keys,metrics` all features
  - Each matrix entry: build, test, and release build
  - Release workflow already includes `--all-features`

#### Security Fixes

- **Critical Security Vulnerabilities Fixed (Post-Implementation Review)**
  - Fixed plaintext API key storage in cache (now uses hashed keys)
  - Fixed cache not clearing on revocation (now immediate eviction)
  - Fixed pending updates using plaintext (now uses bcrypt hash)
  - Documented O(n) validation performance trade-off
  - Added comprehensive module-level security documentation

#### Performance Considerations

- **Rate Limiting**
  - Memory: ~100 bytes per bucket (~1MB per 10K clients)
  - Latency: <1ms overhead per request (in-memory DashMap)
  - Cleanup: Periodic (every 60 seconds) + on-access

- **API Key Validation**
  - Cache hit: <10ms (hash lookup)
  - Cache miss: ~300ms × key count (bcrypt verification)
  - Mitigation: 5-minute cache TTL (configurable)
  - **Known limitation**: O(n) validation due to bcrypt salting

#### Migration Notes

No migration required - this is a **non-breaking feature release**. All v0.4.1 code continues to work unchanged.

**To enable security features**:

```bash
# Rate limiting only
cargo build --features rate-limiting

# API keys only
cargo build --features api-keys

# Both (recommended for production)
cargo build --features "rate-limiting,api-keys"

# All features
cargo build --all-features
```

**Database schema changes** (backward compatible):

- New `api_keys` table created automatically on first run
- Existing databases upgraded seamlessly
- Schema version compatible with v0.4.0+

## [0.4.2] - 2025-01-23

**Observability, Testing, and Documentation Release** - Patch release adding optional Prometheus metrics, code coverage, benchmark checks, and comprehensive testing documentation.

### Added

- **Prometheus Metrics (Optional, Feature-Gated)**
  - Opt-in `metrics` feature flag for Prometheus monitoring
  - `/metrics` endpoint for Prometheus scraping (only when feature enabled)
  - HTTP request metrics: `http_requests_total`, `http_request_duration_seconds`
  - Catalog operation metrics: `catalog_operations_total`, `catalog_datasets_total`
  - Feature disabled by default - no impact on default builds
  - Run with: `cargo run --features metrics -p metafuse-catalog-api`

- **Enhanced Structured Logging**
  - Added structured fields to all API handlers (tenant, domain, query params)
  - Result counts logged for list/search operations
  - Detailed context for dataset retrieval (field_count, tag_count, lineage counts)
  - All logs include request_id for correlation

- **Code Coverage Integration**
  - New `.github/workflows/coverage.yml` workflow using cargo-tarpaulin
  - Codecov integration for coverage tracking and reporting
  - Coverage badge in README.md
  - Informational-only (doesn't block PRs)
  - Separate coverage runs for default and metrics features

- **Benchmark Compile Checks**
  - New benchmark compile check in CI workflow
  - Prevents benchmark bit-rot without running expensive performance tests
  - Scheduled weekly benchmark runs (`.github/workflows/benchmarks.yml`)
  - Benchmark results archived for 90 days
  - Performance regression alerts (50% threshold)

- **Monitoring Documentation**
  - Comprehensive `docs/METRICS.md` guide (300+ lines)
  - Prometheus configuration examples
  - Grafana dashboard JSON template (`docs/grafana-dashboard.json`)
  - Security best practices for `/metrics` endpoint
  - Docker Compose example with Prometheus + Grafana
  - Sample PromQL queries for common monitoring scenarios

- **Cloud Emulator Testing Documentation**
  - Comprehensive `docs/cloud-emulator-tests.md` guide (600+ lines)
  - Covers GCS (fake-gcs-server) and S3 (MinIO) emulator testing
  - Best practices, common patterns, and troubleshooting
  - Architecture diagrams and test case examples
  - Security considerations and CI/CD integration
  - Updated `docs/for-developers.md` with cloud emulator section
  - Updated `CONTRIBUTING.md` with emulator testing guidelines
  - Updated README.md with improved emulator test section

- **Examples**
  - `examples/metrics_demo.rs` - Quick start guide for metrics feature

### Changed

- **Dependencies**
  - Added `prometheus = "0.13"` (optional)
  - Added `lazy_static = "1.4"` (optional)
  - No new required dependencies

- **CI/CD**
  - Added coverage workflow (Linux-only, informational)
  - Added benchmark compile check to main CI workflow
  - Added scheduled weekly benchmarks workflow

### Migration Notes

No migration required - this is a **non-breaking patch release**. All v0.4.1 code continues to work unchanged.

**For production deployments:** Metrics feature is opt-in. Enable by building with `--features metrics`. See `docs/METRICS.md` for security considerations when exposing `/metrics` in production.

**For contributors:** Cloud emulator tests require Docker and `RUN_CLOUD_TESTS=1` environment variable. See `docs/cloud-emulator-tests.md` for comprehensive testing guide.

---

## [0.4.1] - 2025-01-22

**Quality & Compliance Release** - Patch release with lint enforcement and benchmark fixes.

### Added

- **Async Safety Lints**
  - `clippy::await_holding_lock = "warn"` - Prevents holding locks across await points
  - `unsafe_code = "forbid"` - Enforces memory safety guarantees
  - Completes async safety enforcement from v0.4.0 plan

### Fixed

- **Benchmark Suite**
  - Converted all benchmarks to async/await pattern
  - Benchmarks now compile and run with v0.4.0 async API
  - Use `criterion::to_async()` with tokio runtime
  - 5 benchmarks updated: emit_dataset (minimal/full/lineage), fts_search (simple/filtered)

- **Documentation**
  - Fixed migration guide to show manual `Pin<Box<dyn Future>>` pattern
  - Removed all `async_trait` references (not used in implementation)
  - Updated legacy adapter docs to reference v0.4.0 instead of v0.3.2
  - Improved inline examples with correct async patterns

### Migration Notes

No migration required - this is a **non-breaking patch release**. All v0.4.0 code continues to work unchanged.

**For benchmark users:** Update benchmarks to use async pattern (see migration guide).

---

## [0.4.0] - 2025-01-22

**Async/Await Migration Release** - Breaking release introducing async APIs throughout the codebase.

### Breaking Changes

- **`CatalogBackend` Trait is Now Async**
  - All methods (`initialize`, `download`, `upload`, `get_connection`, `exists`) now return futures
  - All backend implementations updated: `LocalSqliteBackend`, `GcsBackend`, `S3Backend`
  - **Migration:** Add `.await` to all backend method calls and use `#[tokio::main]`
- **`Emitter::emit_dataset` is Now Async**
  - Main metadata emission method returns a future
  - **Migration:** Add `.await` to `emit_dataset()` calls
- **Removed `tokio_runtime()` Helper**
  - No longer needed with native async APIs
  - **Migration:** Use `#[tokio::main]` or create runtime explicitly

### Added

- **Native Async Support**
  - `async fn` throughout the codebase (no `tokio::block_on` internally)
  - SQLite operations use `tokio::task::spawn_blocking` to avoid blocking executor
  - Cloud backends (GCS, S3) use native async HTTP clients
- **Migration Guide** (`MIGRATION_v0.4.0.md`)
  - Step-by-step migration instructions from v0.3.x to v0.4.0
  - Complete before/after code examples
  - Troubleshooting section for common errors
- **Improved Performance**
  - Non-blocking I/O for all cloud storage operations
  - Better concurrency support with async executor
  - Automatic thread pool management for SQLite via `spawn_blocking`

### Changed

- **Backend Implementations**
  - `LocalSqliteBackend`: Wraps blocking SQLite calls in `spawn_blocking`
  - `GcsBackend`: Converted to native async (removed `block_on`)
  - `S3Backend`: Converted to native async (removed `block_on`)
  - All backends return `Pin<Box<dyn Future<...> + Send + '_>>`
- **Emitter Internal Architecture**
  - `write_dataset_tx` extracted as standalone function (no longer method)
  - All SQLite operations in `write_dataset` wrapped in `spawn_blocking`
  - Replaced `std::thread::sleep` with `tokio::time::sleep` for async backoff
- **Test Suite**
  - All integration tests converted to `#[tokio::test]`
  - All emulator tests (GCS, S3) converted to async
  - Helper functions updated to async where needed
- **CLI (Internal Only)**
  - CLI already used async internally (Tokio runtime)
  - No user-facing changes for CLI commands
- **API Server (No Changes)**
  - API server already async (Axum-based)
  - All handlers already used `async fn`

### Dependencies

- **Tokio Features Expanded**
  - Added `tokio::time` feature for async sleep
  - Added `tokio::sync` feature for async primitives
  - CLI and storage crates now require `tokio` with `macros`, `rt-multi-thread`

### Migration Notes

**This is a breaking release.** All users must update their code:

1. **Update `Cargo.toml`:**

   ```toml
   metafuse-catalog-emitter = "0.4"
   metafuse-catalog-storage = "0.4"
   tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros"] }
   ```

2. **Make `main` async:**

   ```rust
   #[tokio::main]
   async fn main() -> Result<()> {
       // Your code
   }
   ```

3. **Add `.await` to all backend and emitter calls:**

   ```rust
   backend.initialize().await?;
   emitter.emit_dataset(/* ... */).await?;
   ```

4. **Update tests to `#[tokio::test]`:**

   ```rust
   #[tokio::test]
   async fn test_name() {
       // Your test code with .await
   }
   ```

See `MIGRATION_v0.4.0.md` for detailed migration instructions.

### Deprecation

- **`SyncBackendAdapter`** (if present) will be removed in v0.5.0
  - Migrate to async APIs before upgrading to v0.5.0

### Performance Impact

- **SQLite Operations:** Minimal overhead from `spawn_blocking` (~microseconds)
- **Cloud Operations:** Improved throughput due to native async HTTP
- **Concurrent Workloads:** Better scalability with async executor

### Testing

- All 41+ tests passing (unit + integration)
- Emulator tests passing (when run with `RUN_CLOUD_TESTS=1`)
- Examples updated and tested (simple_pipeline, lineage_tracking)

---

## [0.3.1] - 2025-01-21

**Quality & Testing Release** - Non-breaking enhancements to cloud backend testing and cache behavior.

### Added

- **Emulator-Based Integration Tests**
  - Comprehensive GCS backend tests using `fake-gcs-server` Docker emulator (9 tests)
  - Comprehensive S3 backend tests using MinIO Docker emulator (10 tests)
  - `testcontainers-rs` integration for automatic container lifecycle management
  - Emulator readiness retry helper with 30-second timeout
  - Tests cover: initialization, existence checks, upload/download, concurrent writes, retry logic, cache behavior, metadata preservation
- **Optional Cache Revalidation** (`METAFUSE_CACHE_REVALIDATE`)
  - HEAD request validation before returning cached entries
  - Ensures cached version matches remote version
  - Adds ~50-200ms latency per cache hit when enabled
  - Default: `false` (backwards compatible, no performance impact)
  - Set `METAFUSE_CACHE_REVALIDATE=true` to enable
- **HeadCheckBackend Trait**
  - Abstraction for backends to perform lightweight version checks
  - Implemented for `GcsBackend` (using generation numbers)
  - Implemented for `S3Backend` (using ETags)
  - Graceful fallback: logs warning and uses cached copy on HEAD failures

### Changed

- **Cache Revalidation Logic**
  - `CatalogCache::get()` now accepts optional backend reference
  - Revalidation compares cached version with remote HEAD response
  - Returns `None` (cache miss) if versions differ
  - Falls back to cached copy if HEAD request fails (prevents cascading failures)
- **ObjectVersion Comparison**
  - Added `PartialEq` and `Eq` derives to `ObjectVersion`
  - Enables version comparison for cache revalidation

### Testing

- **Emulator Test Coverage** (19 new tests)
  - GCS tests: initialize, exists, roundtrip, not found, connection, concurrent writes, cache disabled, retry, metadata, region config
  - S3 tests: same as GCS plus region configuration test
  - All tests use emulators (no cloud credentials required)
  - Tests are gated by feature flags (`gcs`, `s3`)
- **Cache Revalidation Tests** (3 new tests)
  - Default disabled behavior (backwards compatibility)
  - Explicit enable/disable via environment variable
  - All 8 cache tests passing

### Configuration

- **New Environment Variables**
  - `METAFUSE_CACHE_REVALIDATE`: Enable HEAD revalidation on cache hits (default: `false`)
  - Existing variables unchanged (`METAFUSE_CACHE_TTL_SECS` still controls TTL)

### Migration Notes

- **Breaking Changes**: None - all changes are fully backward compatible
- **Existing Deployments**: No action required
  - Cache behavior unchanged by default (no revalidation)
  - Performance characteristics remain the same
- **Enable Revalidation**: Set `METAFUSE_CACHE_REVALIDATE=true` for stronger consistency
  - Trade-off: Adds ~50-200ms per cache hit for HEAD request
  - Benefit: Detects stale cache immediately instead of waiting for TTL expiration

### Known Limitations

- **Emulator Tests Not in CI**: Emulator tests require Docker and are not yet integrated into CI
  - Run locally: `cargo test --features gcs --test gcs_emulator_tests`
  - Run locally: `cargo test --features s3 --test s3_emulator_tests`
  - Future release will add optional CI job (non-blocking)
- **Revalidation Overhead**: Enabling revalidation adds latency to every cache hit
  - Recommended for scenarios where cache freshness is critical
  - Keep disabled for read-heavy workloads prioritizing performance

### Dependencies

- Added `testcontainers` 0.15.0 (dev-dependency for emulator tests)

---

## [0.3.0] - 2025-01-21

**Cloud-Ready Release** - Multi-cloud backend support with optimistic concurrency and caching.

### Added

- **Google Cloud Storage Backend** (`GcsBackend`)
  - Catalog storage on GCS with `gs://bucket/path/catalog.db` URIs
  - Generation-based optimistic concurrency control
  - Application Default Credentials (ADC) authentication chain
  - Automatic retry with exponential backoff (3 attempts, 100-400ms delays)
  - Service account support via `GOOGLE_APPLICATION_CREDENTIALS`
  - Download-modify-upload pattern for SQLite-on-object-storage
- **Amazon S3 Backend** (`S3Backend`)
  - Catalog storage on S3 with `s3://bucket/key?region=us-east-1` URIs
  - ETag-based optimistic concurrency control
  - AWS credential chain authentication (env vars, IAM roles, EC2 instance profiles)
  - Automatic retry with exponential backoff
  - Region configuration via query parameters
  - Download-modify-upload pattern with precondition checks
- **XDG-Compliant Caching Layer** (`CatalogCache`)
  - Local file system caching for cloud-downloaded catalogs
  - Cache location: `$XDG_CACHE_HOME/metafuse` or `~/.cache/metafuse`
  - TTL-based expiration (default: 60 seconds, configurable via `METAFUSE_CACHE_TTL_SECS`)
  - Cache invalidation on write conflicts to prevent stale reads
  - Set `METAFUSE_CACHE_TTL_SECS=0` to disable caching
- **Feature Flags for Modular Compilation**
  - `local` (default): Local SQLite backend only
  - `gcs`: Enable Google Cloud Storage backend
  - `s3`: Enable Amazon S3 backend
  - `cloud`: Meta-feature enabling both `gcs` and `s3`
  - Build cloud-only binary: `cargo build --release --no-default-features --features cloud`

### Changed

- **Backend Trait Extension**: Added `download()` and `upload()` methods to `CatalogBackend`
  - `download()`: Fetch catalog from storage with version metadata
  - `upload()`: Upload catalog with optimistic concurrency checks
  - Existing `get_dataset()`, `emit_dataset()`, etc. remain unchanged
- **Shared Tokio Runtime**: Single `OnceLock<Runtime>` prevents nested runtime panics
  - Blocks async operations from sync trait methods
  - Improves performance by reusing runtime across calls
  - Avoids runtime creation overhead on every cloud operation
- **Error-Returning Constructors**: `GcsBackend::new()` and `S3Backend::new()` return `Result<Self>`
  - Previously panicked on authentication failures
  - Now returns descriptive error messages for easier debugging
  - Example: "Failed to create GCS client. Check GOOGLE_APPLICATION_CREDENTIALS: ..."

### Performance

- **Retry Logic**: Exponential backoff for conflict resolution (100ms → 200ms → 400ms)
- **Cache Hit Rate**: Typical workloads see 80%+ cache hits with 60s TTL
- **Reduced Cloud API Calls**: Caching reduces GCS/S3 API calls by ~90% for read-heavy workloads

### Documentation

- **Backend Options Table**: Comparison of Local, GCS, and S3 backends
- **Environment Variables**: Documented `METAFUSE_CATALOG_URI`, `METAFUSE_CACHE_TTL_SECS`, cloud credentials
- **Initialization Examples**: Code snippets for all three backend types
- **Build Instructions**: Updated with feature flag usage

### Testing

- **Unit Tests**: 14 unit tests + 3 doc tests (all passing)
  - Cache TTL behavior (enabled/disabled)
  - Cache miss scenarios
  - Hash URI consistency
  - Cache invalidation
- **Test Isolation**: Mutex-based serialization for environment variable tests
  - Prevents test pollution in parallel test runs
- **Cloud Tests**: Prepared for emulator integration tests (gated by `RUN_CLOUD_TESTS`)

### Migration Notes

- **Breaking Changes**: None - all changes are backward compatible
- **Local Catalogs**: Existing `file://` catalogs work without modification
- **Cloud Migration**: Set `METAFUSE_CATALOG_URI=gs://bucket/path.db` or `s3://bucket/key` to migrate
- **Feature Flags**: Local-only builds remain the default
  - Install cloud support: `cargo install metafuse --features cloud`
- **Authentication Setup**:
  - **GCS**: Set `GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json`
  - **S3**: Configure AWS credentials via environment variables or IAM roles
  - See authentication guides (upcoming) for detailed setup

### Known Limitations

- **Synchronous API**: Cloud operations block on shared Tokio runtime
  - Future versions may introduce async trait methods
- **Single-Writer Assumption**: Optimistic concurrency supports multiple readers, single writer
  - Heavy concurrent writes may experience retries
- **Cache Consistency**: TTL-based expiration may serve stale data within TTL window
  - Disable caching for strong consistency: `METAFUSE_CACHE_TTL_SECS=0`

### Dependencies

- `object_store` 0.12.4 (Apache Arrow's unified cloud storage interface)
- `tokio` 1.x (async runtime for cloud operations)
- `dirs` 5.0 (XDG directory specification)
- `serde` / `serde_json` (cache metadata serialization)

---

## [0.2.0] - 2025-01-21

**Production Hardening Release** - Security, validation, and observability improvements for production deployments.

### Security

- **Input Validation Module** (`catalog-core/validation.rs`)
  - Comprehensive validation for dataset names, field names, tags, and identifiers
  - Strict character set enforcement (alphanumeric, `_`, `-`, `.` for names)
  - Maximum length constraints (255 chars for names, 100 for identifiers/tags)
  - Prevents invalid characters and malformed identifiers from entering the system
- **Path Traversal Protection**
  - File URI validation blocks `..` patterns and null bytes in `file://` URIs
  - Applied consistently in emitter, API, and CLI via `backend_from_uri`
  - Raw paths remain unvalidated for development flexibility
  - Added comprehensive tests for valid/invalid file paths
- **API Input Validation**
  - Path parameters (`:name`) validated before database queries
  - Query parameters (`tenant`, `domain`) validated in list endpoint
  - Returns 400 Bad Request with clear error messages for invalid inputs
- **Error Message Sanitization**
  - Internal errors log detailed messages but return generic responses
  - Prevents leaking database schema, SQL queries, or implementation details
  - Validation errors remain user-facing for better developer experience
- **FTS Query Validation**
  - Search queries validated for length (max 500 characters)
  - FTS5 operators (AND, OR, NOT, `*`, quotes, NEAR) intentionally allowed
  - Parameterized queries prevent SQL injection regardless of operators
  - Documented security model in validation module

### Observability

- **Request ID Tracking**
  - UUID-based request IDs generated for every API request
  - Included in all error responses as `request_id` field
  - Propagated to response headers as `X-Request-ID` for client correlation
  - Enables end-to-end request tracing through logs and responses
- **Structured Logging with Tracing Spans**
  - All requests wrapped in tracing spans with `request_id`, `method`, `uri`
  - Handler logs automatically correlated via span context
  - Request start/completion logged with status codes
  - Enables log aggregation and distributed tracing in production

### Bug Fixes

- **CLI Search JOIN Bug**: Fixed FTS search to use `dataset_name` instead of `rowid` for JOIN
- **API Response Field Order**: Fixed `DatasetResponse` field assignments to match SQL column order
- **Partition Keys Serialization**: Corrected JSON array handling for partition key storage

### Changed

- **FTS Function Renamed**: `sanitize_fts_query` → `validate_fts_query`
  - More accurately reflects that FTS operators are validated, not sanitized
  - Updated documentation to explain that operators are intentionally allowed
  - Clarified security model: parameterized queries prevent SQL injection
- **Error Enum Cleanup**: Removed unused `CatalogError::DatabaseError` variant
  - Simplified error handling by relying on `From<rusqlite::Error>` trait
  - Updated architecture documentation to match actual implementations

### Testing

- **Expanded Test Coverage**: 38 → 41 tests passing
  - Added file URI validation tests (valid paths, traversal attacks, null bytes)
  - Added validation test suite for all input types (names, tags, identifiers)
  - All integration tests pass with new validation layer
- **Validation Test Coverage**
  - Dataset name validation (character sets, length, hyphen rules)
  - Field name validation (alphanumeric + underscore only)
  - Tag validation (supports namespacing with `:`)
  - Identifier validation (tenant/domain)
  - FTS query validation (length limits, operator allowance)
  - File URI validation (traversal protection, null byte detection)

### Documentation

- **Validation Rules**: Documented character sets and length limits for all input types
- **Security Model**: Explained FTS operator allowance and parameterized query safety
- **Error Handling**: Documented generic vs. specific error message strategy
- **Architecture**: Updated docs to show actual implementations (removed outdated examples)

### Migration Notes

- **Breaking Changes**: None - all changes are backward compatible
- **Validation**: Existing catalogs with invalid names/tags will fail validation on future writes
  - Use cargo test to verify your metadata adheres to validation rules
- **Error Responses**: Internal errors now return generic messages
  - Use `request_id` from response to correlate with server logs for details

---

## [0.1.0] - 2025-01-20

**Phase 1 MVP** - Core catalog functionality with local SQLite backend.

### Added

- **Core SQLite Schema**
  - Tables: `datasets`, `fields`, `lineage`, `tags`, `glossary_terms`, `term_links`
  - Full-text search with SQLite FTS5 and BM25 ranking
  - Automatic trigger maintenance to keep `dataset_search` in sync
  - Optimistic concurrency with version tracking via `catalog_meta` table
- **DataFusion Emitter API**
  - Automatic metadata capture from DataFusion pipelines
  - Schema extraction from Arrow DataTypes
  - Lineage tracking between upstream/downstream datasets
  - Operational metadata: row counts, sizes, partition keys
  - Tags for categorization and discovery
- **CLI Tool** (`metafuse`)
  - `init` - Initialize a new catalog
  - `list` - List datasets with tenant/domain filtering
  - `show` - Display dataset details with lineage
  - `search` - Full-text search across datasets
  - `stats` - Catalog statistics and top formats/domains
- **REST API** (`metafuse-api`)
  - `GET /api/v1/datasets` - List datasets with filters
  - `GET /api/v1/datasets/:name` - Get dataset details with fields, tags, lineage
  - `GET /api/v1/search?q=` - Full-text search with BM25 ranking
  - `GET /health` - Health check endpoint
- **Backend Abstraction**
  - URI-based backend selection (`file://`, `gs://`, `s3://`)
  - `LocalSqliteBackend` fully implemented
  - GCS and S3 backends are feature-gated stubs (Phase 2)
- **Multi-Tenant Support**
  - Tenant and domain fields for organizational isolation
  - Filtering by tenant/domain in list/search operations

### Documentation

- **Getting Started Guide**: 10-minute tutorial for first-time users
- **Architecture Documentation**: SQLite-on-object-storage pattern explained
- **API Reference**: REST endpoints with curl examples
- **Roadmap**: Phase 2 plans (cloud backends, authentication)

### Examples

- `simple_pipeline`: Basic metadata emission from DataFusion
- `lineage_tracking`: 3-stage ETL with dependency tracking

### Notes

- Cloud backends (GCS/S3) are not yet implemented; use local SQLite backend
- Authentication/authorization deferred to Phase 3
- Benchmarking framework added (run with `cargo bench --features bench`)

---

[Unreleased]: https://github.com/ethan-tyler/MetaFuse/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/ethan-tyler/MetaFuse/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ethan-tyler/MetaFuse/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/ethan-tyler/MetaFuse/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ethan-tyler/MetaFuse/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ethan-tyler/MetaFuse/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ethan-tyler/MetaFuse/releases/tag/v0.1.0
