# MetaFuse Roadmap

This document outlines the planned development phases for MetaFuse.

## Current Status: Phase 2.5 (v0.4.2) Complete ✓

MetaFuse v0.4.2 is production-ready with enterprise-grade security features including rate limiting and API key authentication.

**Latest Release**: v0.4.2 - Security & Authentication Release (January 2025)

---

## Phase 1: MVP ✓ [Complete] (Q4 2024 - Q1 2025)

**Released**: v0.1.0 (January 2025)

**Goal:** Build a working proof-of-concept with core features.

### Completed

- [done] **Core Data Model**
  - `DatasetMeta` and `FieldMeta` types
  - Comprehensive SQLite schema (datasets, fields, lineage, tags, glossary)
  - FTS5 full-text search integration
  - Version-based optimistic concurrency control

- [done] **Storage Backend**
  - `CatalogBackend` trait abstraction
  - `LocalSqliteBackend` implementation
  - Connection management and initialization
  - Error handling

- [done] **DataFusion Integration**
  - `Emitter` API for metadata capture
  - Automatic schema extraction from Arrow `SchemaRef`
  - Lineage tracking support
  - Tag and multi-tenant metadata

- [done] **REST API**
  - Axum-based HTTP server
  - List datasets endpoint (`/api/v1/datasets`)
  - Get dataset details endpoint (`/api/v1/datasets/:name`)
  - Search endpoint (`/api/v1/search`)
  - CORS support for web UIs

- [done] **CLI Tool**
  - `init` command (initialize catalog)
  - `list` command (list datasets with filters)
  - `show` command (dataset details + lineage)
  - `search` command (full-text search)
  - `stats` command (catalog statistics)
  - Formatted output with table display

- [done] **Documentation**
  - Comprehensive README
  - Apache 2.0 license
  - Basic project structure

### Completed

- [done] **Examples and Testing**
  - Working examples (simple pipeline, lineage tracking)
  - Integration tests (41 tests passing)
  - Performance benchmarks

- [done] **Repository Infrastructure**
  - GitHub workflows (CI, lint, audit)
  - Issue and PR templates
  - Community policies (CoC, security, contributing)
  - Detailed documentation (architecture, getting started, API reference)

---

## Phase 1.5: Production Hardening ✓ [Complete] (January 2025)

**Released**: v0.2.0 (January 2025)

**Goal:** Harden MetaFuse for production deployments with security, validation, and observability.

### Completed

- [done] **Input Validation**
  - Comprehensive validation module for all user inputs
  - Dataset names, field names, tags, identifiers
  - Character set enforcement and length limits
  - Path traversal protection for file:// URIs

- [done] **API Security**
  - Request ID tracking (UUID-based)
  - Error message sanitization (prevent info leaks)
  - Path and query parameter validation
  - FTS query validation with documented operator support

- [done] **Observability**
  - Structured logging with tracing spans
  - Request correlation (request_id in logs and headers)
  - X-Request-ID header propagation
  - Comprehensive error correlation

- [done] **Release Infrastructure**
  - GitHub Actions release workflow
  - Multi-platform binary builds (x86_64, ARM64, Linux, macOS)
  - Automated checksum generation
  - Dockerfile for containerized deployments
  - Installation script for easy setup

- [done] **Documentation**
  - Comprehensive CHANGELOG with migration notes
  - Troubleshooting guide with common issues
  - Updated architecture docs
  - Validation rules documentation

- [done] **Quality Improvements**
  - Removed unused error variants
  - Fixed CLI search JOIN bug
  - Corrected API response field ordering
  - Expanded test coverage (38 → 41 tests)

---

## Phase 2: Cloud Backends ✓ [Complete] (January 2025)

**Released**: v0.3.0 (January 2025)

**Goal:** Enable multi-cloud catalog storage with production-ready cloud backends.

### Completed

- [done] **Google Cloud Storage Backend** (`GCSBackend`)
  - Generation-based optimistic concurrency control
  - Application Default Credentials (ADC) authentication
  - Download/upload with XDG-compliant local caching
  - Automatic retry with exponential backoff (3 attempts)
  - Service account and Workload Identity support
- [done] **Amazon S3 Backend** (`S3Backend`)
  - ETag-based optimistic concurrency control
  - AWS credential chain authentication (IAM roles, env vars, profiles)
  - Download/upload with caching
  - Region configuration via query parameters
  - Automatic retry with exponential backoff
- [done] **XDG-Compliant Caching Layer**
  - TTL-based expiration (default 60s, configurable)
  - Cache invalidation on write conflicts
  - Reduces cloud API calls by ~90% for read-heavy workloads
  - Documented cache staleness trade-offs
- [done] **Feature Flags for Modular Compilation**
  - `local` (default), `gcs`, `s3`, `cloud` features
  - Zero-dependency local builds
  - Pay-for-what-you-use compilation
- [done] **Deployment Documentation**
  - Comprehensive GCP deployment guide (Cloud Run, GKE)
  - Comprehensive AWS deployment guide (ECS, EKS, Lambda)
  - Cost estimation and best practices
  - Monitoring and troubleshooting guides
- [done] **Production-Ready Error Handling**
  - Error-returning constructors (no panics)
  - Descriptive error messages with context
  - Shared Tokio runtime (prevents nested runtime panics)
- [done] **Testing & Quality**
  - 45 tests passing (14 unit tests + 3 doc tests + 28 integration tests)
  - Test isolation with shared environment locks
  - Release builds successful for all packages
  - Zero breaking changes from v0.2.0

---

## Phase 2.5: Security & Authentication ✓ [Complete] (January 2025)

**Released**: v0.4.0 - v0.4.2 (January 2025)

**Goal:** Add production-grade security features for API protection and access control.

### Completed

- [done] **Rate Limiting**
  - Identity-aware tiered rate limits (5000/hour authenticated, 100/hour anonymous)
  - Trusted proxy support (X-Forwarded-For, X-Real-IP with validation)
  - IPv4/IPv6 support with CIDR-based proxy configuration
  - Memory-bounded with automatic bucket cleanup (TTL-based eviction)
  - In-memory DashMap for high-performance concurrent access
  - Configurable via environment variables

- [done] **API Key Authentication**
  - Cryptographically secure key generation (OsRng, 32-byte keys)
  - bcrypt password hashing (cost factor: 12)
  - In-memory caching (5-minute TTL) for performance
  - Background flush for last-used-at tracking
  - Soft deletion with audit trail preservation
  - CLI commands for key management (`create`, `list`, `revoke`)

- [done] **Identity-Aware Middleware Architecture**
  - Auth middleware validates keys and attaches identity to request extensions
  - Rate limiter reads identity from extensions (NOT raw headers)
  - Invalid API keys fall back to anonymous (IP-based) rate limits
  - Security guarantee: Invalid keys do NOT get elevated rate limits

- [done] **Production-Ready Error Responses**
  - Consistent JSON error format with request_id for traceability
  - 401 Unauthorized (invalid/missing API key)
  - 429 Too Many Requests (rate limit exceeded with retry_after)
  - 500 Internal Server Error (validation failures)

- [done] **Comprehensive Security Documentation**
  - SECURITY.md with deployment best practices
  - security-checklist.md for pre-production verification
  - Trusted proxy configuration guides (AWS, GCP, Cloudflare)
  - Rate limit tuning guidance with examples
  - Key rotation procedures and incident response

- [done] **Feature Flags for Modular Compilation**
  - `api-keys` feature for authentication
  - `rate-limiting` feature for rate limiting
  - `metrics` feature for observability
  - Zero-dependency builds when features disabled

- [done] **Security Testing & Validation**
  - 19 tests for API keys (validation, caching, revocation)
  - 11 tests for rate limiting (tiering, proxy validation, cleanup)
  - Security test verifying invalid keys don't get elevated limits
  - CI matrix testing all feature combinations

- [done] **Schema Stability**
  - `api_keys` table always created (feature-independent)
  - Enables zero-downtime feature enablement
  - Documented design rationale for schema decisions

### Security Guarantee

**Critical Fix**: Invalid API keys do NOT receive elevated rate limits because the architecture enforces proper separation of concerns:

```text
Request → Auth Middleware → Rate Limiter → Handler
          (validates key,    (reads identity
           attaches identity) for tier selection)
```

Only validated API keys get identity attached, ensuring attackers cannot bypass rate limits with invalid credentials.

---

## Phase 2.1: Cloud Backend Enhancements (v0.5.0 - Q2 2025)

**Goal:** Improve cloud backend performance, testing, and developer experience.

### Planned Features

- **Async Backend Refactoring**
  - Convert `CatalogBackend` trait methods to async
  - Eliminate blocking calls on shared Tokio runtime
  - Improve throughput for high-concurrency workloads
  - Cleaner integration with async API/CLI codebases

- **Emulator Integration Tests**
  - Add `fake-gcs-server` tests for GCS backend
  - Add `localstack` tests for S3 backend
  - Gate tests behind `RUN_CLOUD_TESTS=1` environment variable
  - Test optimistic locking conflict scenarios
  - Test retry logic and exponential backoff
  - Verify cache invalidation behavior

- **Optional Cache Revalidation**
  - Add `METAFUSE_CACHE_REVALIDATE=true` flag
  - Perform HEAD request on cache hits to check staleness
  - Trade extra cloud call for stronger consistency
  - Document when to enable (critical reads) vs. disable (cost optimization)

- **Performance Optimizations**
  - Benchmark upload/download throughput
  - Profile cache hit rates in production workloads
  - Optimize temp file handling (reduce copies)
  - Add connection pooling for concurrent operations

---

## Phase 3: Web UI & Community Launch (Q2-Q3 2025)

**Goal:** Prepare for public launch with web UI and community infrastructure.

### Planned Features

- **Web UI (Initial)**
  - Basic dataset browser
  - Interactive lineage visualization (DAG graph)
  - Search interface
  - Schema explorer
  - Tech stack: React/Vue + D3.js/Cytoscape.js for lineage graphs

- **Comprehensive Documentation**
  - Video tutorials (YouTube)
  - Migration guides (dbt, Airflow, Great Expectations)
  - Best practices for lakehouse architectures

- **Community Infrastructure**
  - GitHub Discussions enabled
  - Discord or Slack community
  - Contributing guidelines with good-first-issue labels
  - Release process and versioning strategy

- **Testing and Quality**
  - Load testing (10,000+ datasets)
  - Performance benchmarks published
  - Example projects (dbt integration, Airflow DAG, serverless pipeline)

---

## Phase 4: Enhanced Features (Q3-Q4 2025)

**Goal:** Add advanced features requested by the community.

### Planned Features

- **Usage Analytics**
  - Track dataset access patterns
  - Identify popular datasets
  - Detect stale/unused datasets
  - Freshness monitoring (last updated time)
  - Dashboard for catalog health

- **Advanced Search**
  - Fuzzy matching (typo tolerance)
  - Column-level search (find datasets with specific field names)
  - Faceted search (filter by domain, owner, tags, format)
  - Search suggestions and autocomplete

- **Column-Level Lineage**
  - Track field-level dependencies (e.g., `output.revenue` depends on `input.sales * input.quantity`)
  - Visualize column-level transformations
  - Impact analysis at the field level

- **Scale Testing**
  - Validate performance with 10,000+ datasets
  - Optimize for 100,000+ fields
  - Test catalog file sizes >100MB
  - Identify bottlenecks and optimize

- **Ecosystem Integrations**
  - **dbt Integration**
    - Automatically ingest dbt models as datasets
    - Map dbt lineage to MetaFuse lineage
    - Sync dbt descriptions and tags
  - **Great Expectations Integration**
    - Attach data quality expectations to datasets
    - Track validation results over time
  - **Airflow Integration**
    - Emit metadata from Airflow DAGs
    - Visualize pipeline orchestration alongside lineage
  - **Apache Iceberg Integration**
    - Catalog Iceberg tables
    - Track Iceberg snapshot lineage

---

## Phase 5: Enterprise Features (2026+)

**Goal:** Provide enterprise-ready features for larger organizations.

### Completed Early

- [done] **API Key Authentication** (completed in v0.4.2)
  - Cryptographically secure key generation and bcrypt hashing
  - In-memory caching with TTL-based expiration
  - CLI management commands and soft deletion
  - See Phase 2.5 for full details

### Planned Features

- **Multi-Tenant Hosted Service**
  - SaaS offering with managed hosting
  - Tenant isolation and resource quotas
  - Subscription tiers (free, team, enterprise)

- **Advanced Authentication and Authorization**
  - OAuth2/OIDC SSO (Google, Okta, Azure AD)
  - Role-based access control (RBAC)
    - Reader, Writer, Admin roles
    - Dataset-level and domain-level permissions
  - Fine-grained access policies

- **Audit Logging**
  - Track all metadata changes (who, what, when)
  - Compliance reporting (GDPR, SOC2)
  - Retention policies for audit logs

- **Advanced Backend Options**
  - **PostgreSQL Backend**
    - For high write-throughput scenarios
    - Full ACID transactions
    - Horizontal scaling with read replicas
  - **DuckDB Backend**
    - For larger catalogs (>100MB)
    - Better OLAP query performance
    - Parquet-based storage

- **Professional Support**
  - SLA-backed support plans
  - Onboarding and training
  - Custom integrations and consulting

---

## Community Wishlist 

Features suggested by the community (not yet prioritized):

- **Data Contracts**
  - Define expected schemas for datasets
  - Validate incoming data against contracts
  - Alert on schema drift

- **Cost Tracking**
  - Attach cost metadata to datasets (storage cost, compute cost)
  - Identify expensive datasets
  - Budget alerts

- **Data Retention Policies**
  - Define TTLs for datasets
  - Automated archival or deletion
  - Compliance with retention regulations

- **Notifications and Alerts**
  - Slack/email notifications for schema changes
  - Alerts for stale datasets
  - Lineage impact notifications

- **Semantic Layer Integration**
  - Integrate with Cube.js, Looker, Tableau
  - Map semantic models to physical datasets

- **Query-Level Metadata**
  - Capture SQL queries that generated datasets
  - Link query execution logs to datasets
  - Enable query-level lineage

- **Schema Evolution Tracking**
  - Track schema changes over time
  - Diff schemas between versions
  - Alert on breaking changes

- **Data Profiling**
  - Capture min/max/avg/null-count statistics
  - Histograms and distribution data
  - Data quality scores

---

## Release Schedule

| Version | Release Date | Status       | Focus                                  |
|---------|--------------|--------------|----------------------------------------|
| 0.1.0   | Jan 2025     | ✓ Released   | MVP - Core functionality               |
| 0.2.0   | Jan 2025     | ✓ Released   | Production hardening                   |
| 0.3.0   | Jan 2025     | ✓ Released   | Cloud backends (GCS/S3)                |
| 0.4.0   | Jan 2025     | ✓ Released   | Security features (rate limiting)      |
| 0.4.1   | Jan 2025     | ✓ Released   | Async emitter benchmarks               |
| 0.4.2   | Jan 2025     | ✓ Released   | API key authentication                 |
| 0.5.0   | Q2 2025      | Planned      | Async backends + emulator tests        |
| 0.6.0   | Q2-Q3 2025   | Planned      | Web UI + community launch              |
| 1.0.0   | Q1 2026      | Planned      | Stable release + enterprise features   |

---

## How to Influence the Roadmap

We welcome community input! Here's how you can help shape MetaFuse:

1. **Vote on Issues**:  the GitHub issues that matter most to you
2. **Submit RFCs**: Use the [RFC template](.github/ISSUE_TEMPLATE/rfc.yml) for significant proposals
3. **Join Discussions**: Participate in [GitHub Discussions](https://github.com/ethan-tyler/MetaFuse/discussions)
4. **Contribute Code**: See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to contribute

---

## Versioning and Stability

- **v0.x**: Experimental. APIs may change without notice.
- **v1.0+**: Stable. Breaking changes will follow semantic versioning.
- **LTS versions** (future): Long-term support for enterprise users.

---

## Success Metrics

We'll track these metrics to measure progress:

- **Adoption**: GitHub stars, downloads, active users
- **Performance**: API latency, catalog size limits, query speed
- **Community**: Contributors, issues resolved, discussions activity
- **Quality**: Test coverage, CI pass rate, bug reports

---

## Questions?

- Open a [discussion](https://github.com/ethan-tyler/MetaFuse/discussions) to ask about the roadmap
- Submit a [feature request](https://github.com/ethan-tyler/MetaFuse/issues/new?template=feature_request.yml) for new ideas

---

**Last Updated:** 2025-01-21
