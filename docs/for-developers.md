# For Developers

This guide is for developers working on MetaFuse itself. If you're looking to use MetaFuse in your project, see the [Getting Started Guide](getting-started.md).

## Table of Contents

- [Development Setup](#development-setup)
- [Project Architecture](#project-architecture)
- [Running Tests](#running-tests)
- [Backend URI System](#backend-uri-system)
- [Adding New Features](#adding-new-features)
- [Debugging](#debugging)
- [Performance Profiling](#performance-profiling)
- [Release Process](#release-process)

---

## Development Setup

### Prerequisites

- **Rust 1.70+** ([install](https://rustup.rs/))
- **Git**
- Optional: **SQLite CLI** for database inspection
- Optional: **Docker** for cloud backend testing (future)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/ethan-tyler/MetaFuse.git
cd MetaFuse

# Build all crates
cargo build --workspace

# Run tests to verify
cargo test --workspace

# Format code
cargo fmt --all

# Run linter
cargo clippy --workspace --all-features -- -D warnings
```

### Development Tools

```bash
# Watch mode for continuous compilation
cargo install cargo-watch
cargo watch -x "check --workspace"

# Better test output
cargo install cargo-nextest
cargo nextest run --workspace

# Code coverage
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --out Html
```

---

## Project Architecture

### Crate Organization

```
MetaFuse/
├── crates/
│   ├── catalog-core/      # Core types, schema, errors
│   ├── catalog-storage/   # Storage backend abstraction
│   ├── catalog-emitter/   # DataFusion integration
│   ├── catalog-api/       # REST API server
│   └── catalog-cli/       # CLI tool
├── examples/              # Example pipelines
├── tests/                 # Integration tests
├── docs/                  # Documentation
└── benches/               # Performance benchmarks (gated)
```

### Dependency Graph

```
catalog-cli ──┬──> catalog-storage ──> catalog-core
              └──> catalog-api

catalog-api ──> catalog-storage ──> catalog-core

catalog-emitter ──┬──> catalog-storage ──> catalog-core
                  └──> datafusion
```

### Key Design Patterns

1. **Download-Modify-Upload Pattern** (catalog-emitter):
   - Download catalog with version metadata
   - Modify in a transaction
   - Upload with optimistic locking (version preconditions)

2. **Backend Abstraction** (catalog-storage):
   - `CatalogBackend` trait abstracts storage
   - Implementations: Local, GCS (future), S3 (future)
   - Enables testing without cloud dependencies

3. **Optimistic Concurrency**:
   - `catalog_meta.version` (local SQLite version)
   - `ObjectVersion` (generation/ETag for cloud)
   - Retry with exponential backoff on conflicts

---

## Running Tests

### Quick Test Commands

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p metafuse-catalog-core

# Specific test
cargo test test_fts_search

# With output
cargo test -- --nocapture

# Documentation tests
cargo test --doc
```

### Integration Tests

Integration tests are in `tests/integration_test.rs`:

```bash
# Run all integration tests
cargo test --test integration_test

# Run specific integration test
cargo test --test integration_test test_partition_keys
```

### Test Coverage

Current test coverage:

```bash
cargo tarpaulin --workspace --out Html --output-dir coverage/
open coverage/index.html
```

**Coverage targets:**
- Core: >90%
- Storage: >85%
- Emitter: >80%
- API: >75%
- CLI: >70%

### Cloud Emulator Tests

MetaFuse includes comprehensive integration tests for GCS and S3 backends using Docker-based emulators. These tests validate cloud-specific behavior (versioning, concurrency, retries) without requiring cloud credentials.

**Requirements:**

- Docker installed and running
- `RUN_CLOUD_TESTS=1` environment variable to enable tests

**Quick Start:**

```bash
# Run GCS emulator tests
RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests

# Run S3 emulator tests
RUN_CLOUD_TESTS=1 cargo test --features s3 --test s3_emulator_tests

# Run with verbose output
RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests -- --nocapture
```

**What's Tested:**

- Catalog initialization and existence checks
- Upload/download roundtrips with versioning (GCS generations, S3 ETags)
- Concurrent write detection and conflict handling
- Retry logic with exponential backoff
- Cache behavior (enabled/disabled)
- Metadata preservation

**Emulators Used:**

- **GCS**: `fsouza/fake-gcs-server` - HTTP-compatible GCS API emulator
- **S3**: `minio/minio` - Full S3-compatible object storage

**When to Run:**

- Before submitting PRs that touch cloud backend code
- After modifying versioning/concurrency logic
- When adding new cloud-specific features

For comprehensive documentation, see [Cloud Emulator Testing Guide](cloud-emulator-tests.md).

---

## Backend URI System

MetaFuse uses a URI-based system for specifying catalog storage:

### URI Formats

```rust
// Local filesystem
"catalog.db"
"file:///path/to/catalog.db"

// Google Cloud Storage (future)
"gs://bucket-name/path/to/catalog.db"

// AWS S3 (future)
"s3://bucket-name/path/to/catalog.db"
"s3://bucket-name/path/to/catalog.db?region=us-east-1"
```

### Using Backends in Code

```rust
use metafuse_catalog_storage::backend_from_uri;

// Local
let backend = backend_from_uri("catalog.db")?;

// Cloud (when implemented)
let backend = backend_from_uri("gs://my-bucket/catalog.db")?;
let backend = backend_from_uri("s3://my-bucket/catalog.db?region=us-west-2")?;
```

### Adding a New Backend

1. **Implement the trait** in `catalog-storage/src/lib.rs`:
   ```rust
   pub struct MyBackend {
       // Fields...
   }

   impl CatalogBackend for MyBackend {
       fn download(&self) -> Result<CatalogDownload> {
           // Download logic...
       }

       fn upload(&self, download: &CatalogDownload) -> Result<()> {
           // Upload with preconditions...
       }

       // Other methods...
   }
   ```

2. **Update URI parser** in `parse_catalog_uri()`:
   ```rust
   if let Some(rest) = uri.strip_prefix("myscheme://") {
       // Parse and return CatalogLocation::MyBackend
   }
   ```

3. **Add tests** in `catalog-storage/tests/`

4. **Update documentation**

---

## Adding New Features

### Step-by-Step Guide

1. **Create an issue** describing the feature
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Write failing tests** first (TDD)
4. **Implement the feature**
5. **Update documentation**
6. **Run quality checks**:
   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-features -- -D warnings
   cargo test --workspace
   ```
7. **Create a Pull Request**

### Example: Adding Partition Key Support

```rust
// 1. Add field to DatasetMeta (catalog-core/src/lib.rs)
pub struct DatasetMeta {
    // ... existing fields
    pub partition_keys: Vec<String>,
}

// 2. Update SQL schema (catalog-core/src/lib.rs)
const DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS datasets (
        -- ... existing columns
        partition_keys TEXT  -- JSON array
    );
"#;

// 3. Update emitter (catalog-emitter/src/lib.rs)
pub fn emit_dataset(
    // ... existing params
    partition_keys: Vec<String>,
) -> Result<()> {
    // Store as JSON
    let partition_keys_json = serde_json::to_string(&partition_keys)?;
    // Insert into database...
}

// 4. Add tests (tests/integration_test.rs)
#[test]
fn test_partition_keys() {
    // Test implementation...
}
```

---

## Debugging

### Enable Logging

```bash
# Set log level
export RUST_LOG=metafuse=debug,datafusion=info

# Run with logging
cargo run --example simple_pipeline
```

### Inspect SQLite Catalog

```bash
# Open catalog database
sqlite3 metafuse_catalog.db

# Show schema
.schema

# Query datasets
SELECT * FROM datasets;

# Query FTS index
SELECT * FROM dataset_search WHERE dataset_search MATCH 'transactions';

# Check version
SELECT * FROM catalog_meta;
```

### Debugging Tests

```rust
#[test]
fn test_something() {
    env_logger::init();  // Enable logging in tests
    // Test code...
}
```

```bash
# Run test with logging
RUST_LOG=debug cargo test test_something -- --nocapture
```

---

## Performance Profiling

### Benchmarking

Benchmarks are gated behind a `bench` feature:

```bash
# Run benchmarks
cargo bench --features bench

# Benchmark specific function
cargo bench --features bench emit_dataset
```

### Adding a Benchmark

Create `benches/emit_benchmark.rs`:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use metafuse_catalog_emitter::Emitter;
use metafuse_catalog_storage::LocalSqliteBackend;

fn bench_emit_dataset(c: &mut Criterion) {
    let backend = LocalSqliteBackend::new("bench_catalog.db");
    let emitter = Emitter::new(backend);

    c.bench_function("emit_dataset", |b| {
        b.iter(|| {
            emitter.emit_dataset(
                black_box("test"),
                // ... parameters
            )
        });
    });
}

criterion_group!(benches, bench_emit_dataset);
criterion_main!(benches);
```

### Profiling with Flamegraph

```bash
cargo install flamegraph

# Profile a test
cargo flamegraph --test integration_test -- test_fts_search

# Open flamegraph.svg in browser
```

---

## Release Process

### Version Bumping

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.2.0): New features, backward compatible
- **PATCH** (0.1.1): Bug fixes, backward compatible

```bash
# Update version in all Cargo.toml files
# Update CHANGELOG.md with changes
# Commit changes
git commit -m "chore: bump version to 0.2.0"

# Tag release
git tag -a v0.2.0 -m "Release v0.2.0"

# Push tag
git push origin v0.2.0
```

### Publishing to crates.io

```bash
# Dry run
cargo publish --dry-run -p metafuse-catalog-core

# Publish (order matters due to dependencies)
cargo publish -p metafuse-catalog-core
cargo publish -p metafuse-catalog-storage
cargo publish -p metafuse-catalog-emitter
cargo publish -p metafuse-catalog-api
cargo publish -p metafuse-catalog-cli
```

---

## Common Development Tasks

### Adding a New Error Type

```rust
// In catalog-core/src/lib.rs
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    // ... existing variants

    #[error("My new error: {0}")]
    MyNewError(String),
}
```

### Adding a New SQL Table

1. Update DDL in `catalog-core/src/lib.rs`
2. Add migration logic (or version check)
3. Update tests
4. Update API endpoints if needed

### Adding a New API Endpoint

```rust
// In catalog-api/src/main.rs
async fn my_handler(
    State(backend): State<Arc<LocalSqliteBackend>>,
    Json(req): Json<MyRequest>,
) -> Result<Json<MyResponse>, StatusCode> {
    // Implementation...
}

// Add route
let app = Router::new()
    .route("/api/v1/my-endpoint", post(my_handler))
    // ... other routes
```

---

## Troubleshooting

### "Database is locked" Error

```bash
# Check for open connections
lsof | grep catalog.db

# Kill hanging processes
killall -9 metafuse-api
```

### Clippy Warnings Differ Between Local and CI

Ensure you're using the same flags:

```bash
cargo clippy --workspace --all-features -- -D warnings
```

### Tests Fail Intermittently

- Use `TempDir` for isolated test storage
- Avoid shared state between tests
- Check for race conditions

---

## Additional Resources

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [DataFusion Documentation](https://arrow.apache.org/datafusion/)
- [SQLite FTS5](https://www.sqlite.org/fts5.html)
- [Axum Web Framework](https://docs.rs/axum/)

---

## Getting Help

- **GitHub Issues**: [https://github.com/ethan-tyler/MetaFuse/issues](https://github.com/ethan-tyler/MetaFuse/issues)
- **GitHub Discussions**: [https://github.com/ethan-tyler/MetaFuse/discussions](https://github.com/ethan-tyler/MetaFuse/discussions)
- **Documentation**: [docs/](.)

---

**Happy coding!** 🚀
