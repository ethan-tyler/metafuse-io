# Changelog

All notable changes to MetaFuse will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ethan-tyler/MetaFuse/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ethan-tyler/MetaFuse/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ethan-tyler/MetaFuse/releases/tag/v0.1.0
