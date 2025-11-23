# MetaFuse

> **Lightweight, serverless data catalog for DataFusion and modern lakehouse pipelines**

[![CI](https://github.com/ethan-tyler/MetaFuse/workflows/CI/badge.svg)](https://github.com/ethan-tyler/MetaFuse/actions)
[![codecov](https://codecov.io/gh/ethan-tyler/MetaFuse/branch/main/graph/badge.svg)](https://codecov.io/gh/ethan-tyler/MetaFuse)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

MetaFuse captures dataset schemas, lineage, and operational metadata automatically from your data pipelines without requiring Kafka, MySQL, or Elasticsearch. Just a SQLite file on object storage.

**Status:** v0.3.0 Cloud-Ready — Production-hardened with GCS and S3 backends. Supports local SQLite, Google Cloud Storage, and AWS S3 with optimistic concurrency and caching.

## Why MetaFuse?

- **Native DataFusion integration** - Emit metadata directly from pipelines
- **Serverless-friendly** - $0-$5/month on object storage (GCS/S3 supported)
- **Zero infrastructure** - No databases, no clusters to maintain
- **Multi-cloud** - Works on local filesystem, Google Cloud Storage, and AWS S3
- **Automatic lineage capture** - Track data flow through transformations
- **Full-text search with FTS5** - Fast search with automatic trigger maintenance
- **Optimistic concurrency** - Safe concurrent writes with version-based locking
- **Tags and glossary** - Organize with business context
- **Operational metadata** - Track row counts, sizes, partition keys

MetaFuse fills the gap between expensive, complex enterprise catalogs (DataHub, Collibra) and the needs of small-to-medium data teams.

## Quick Start

### Install

#### Option 1: Install Script (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/ethan-tyler/MetaFuse/main/install.sh | bash
```

This downloads pre-built binaries for your platform (Linux/macOS, x86_64/ARM64).

#### Option 2: Build from Source

```bash
git clone https://github.com/ethan-tyler/MetaFuse.git
cd MetaFuse

# Local-only (default)
cargo build --release

# With GCS support
cargo build --release --features gcs

# With S3 support
cargo build --release --features s3

# With all cloud backends
cargo build --release --features cloud
```

#### Option 3: Docker

```bash
docker pull ghcr.io/ethan-tyler/metafuse-api:latest
docker run -p 8080:8080 -v $(pwd)/data:/data ghcr.io/ethan-tyler/metafuse-api
```

### Backend Options

MetaFuse supports multiple storage backends:

| Backend | URI Format | Authentication | Features Required |
|---------|-----------|----------------|-------------------|
| **Local SQLite** | `file://catalog.db` or `catalog.db` | None | `local` (default) |
| **Google Cloud Storage** | `gs://bucket/path/catalog.db` | ADC, GOOGLE_APPLICATION_CREDENTIALS | `gcs` |
| **Amazon S3** | `s3://bucket/key?region=us-east-1` | AWS credential chain | `s3` |

#### Environment Variables

- **`METAFUSE_CATALOG_URI`**: Override default catalog location
- **`METAFUSE_CACHE_TTL_SECS`**: Cache TTL for cloud backends (default: 60, 0 to disable)
- **`GOOGLE_APPLICATION_CREDENTIALS`**: Path to GCS service account JSON (GCS only)
- **`AWS_ACCESS_KEY_ID`**, **`AWS_SECRET_ACCESS_KEY`**: AWS credentials (S3 only)

#### Examples

```bash
# Local
export METAFUSE_CATALOG_URI="file://my_catalog.db"
metafuse init

# Google Cloud Storage
export METAFUSE_CATALOG_URI="gs://my-bucket/catalogs/prod.db"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
metafuse init

# Amazon S3
export METAFUSE_CATALOG_URI="s3://my-bucket/catalogs/prod.db?region=us-west-2"
metafuse init
```

### Initialize Catalog

```bash
./target/release/metafuse init
```

### Emit Metadata from DataFusion

```rust
use datafusion::prelude::*;
use metafuse_catalog_core::OperationalMeta;
use metafuse_catalog_emitter::Emitter;
use metafuse_catalog_storage::LocalSqliteBackend;

#[tokio::main]
async fn main() -> datafusion::error::Result<()> {
    let ctx = SessionContext::new();
    let df = ctx.read_parquet("input.parquet", Default::default()).await?;
    let result = df.filter(col("status").eq(lit("active")))?.select_columns(&["id", "name"])?;

    // Get schema and row count before writing
    let schema = result.schema().inner().clone();
    let batches = result.collect().await?;
    let row_count: usize = batches.iter().map(|b| b.num_rows()).sum();

    // Write output
    ctx.register_batches("active_records", batches.clone())?;
    ctx.sql("SELECT * FROM active_records")
        .await?
        .write_parquet("output.parquet", Default::default())
        .await?;

    // Emit metadata to catalog
    let backend = LocalSqliteBackend::new("metafuse_catalog.db");
    let emitter = Emitter::new(backend);
    emitter.emit_dataset(
        "active_records",
        "output.parquet",
        "parquet",
        Some("Filtered active records"),  // Description
        Some("prod"),                       // Tenant
        Some("analytics"),                  // Domain
        Some("team@example.com"),          // Owner
        schema,                            // Arrow schema
        Some(OperationalMeta {
            row_count: Some(row_count as i64),
            size_bytes: None,
            partition_keys: vec![],
        }),
        vec!["raw_records".to_string()],   // Upstream lineage
        vec!["active".to_string()],        // Tags
    )?;

    Ok(())
}
```

### Query the Catalog

```bash
# List datasets
metafuse list

# Show details with lineage
metafuse show active_records --lineage

# Search
metafuse search "analytics"

# Statistics
metafuse stats
```

### Run the REST API

```bash
cargo run --bin metafuse-api

# Query endpoints
curl http://localhost:8080/api/v1/datasets
curl http://localhost:8080/api/v1/datasets/active_records
curl "http://localhost:8080/api/v1/search?q=analytics"
```

### Try the Examples

```bash
# Simple pipeline - basic metadata emission
cargo run --example simple_pipeline

# Lineage tracking - 3-stage ETL with dependencies
cargo run --example lineage_tracking
```

See [examples/README.md](examples/README.md) for detailed walkthrough and expected output.

### Cloud Emulator Tests (Optional)

MetaFuse includes comprehensive integration tests for GCS and S3 backends using Docker-based emulators. These tests validate cloud-specific behavior without requiring cloud credentials.

```bash
# Run GCS emulator tests (requires Docker)
RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests

# Run S3 emulator tests (requires Docker)
RUN_CLOUD_TESTS=1 cargo test --features s3 --test s3_emulator_tests
```

**What's tested:** Versioning (generations/ETags), concurrent writes, retry logic, cache behavior, metadata preservation.

For comprehensive documentation, see [Cloud Emulator Testing Guide](docs/cloud-emulator-tests.md).

## Testing

### Running Tests

```bash
# Run all local tests (no cloud dependencies)
cargo test

# Run cache tests with GCS/S3 features
cargo test -p metafuse-catalog-storage --features gcs,s3
```

### Emulator-Based Integration Tests

MetaFuse includes comprehensive integration tests for GCS and S3 backends using Docker emulators. These tests validate cloud backend behavior without requiring actual cloud credentials.

**Requirements:**

- Docker installed and running
- `testcontainers-rs` dependency (included in dev-dependencies)

**Running GCS Emulator Tests:**

```bash
# Requires Docker
cargo test --features gcs --test gcs_emulator_tests
```

Uses `fake-gcs-server` Docker image. Tests cover:

- Catalog initialization and existence checks
- Upload/download roundtrips with generation-based versioning
- Concurrent write detection and conflict handling
- Retry logic with exponential backoff
- Cache behavior (enabled/disabled)
- Metadata preservation across uploads

**Running S3 Emulator Tests:**

```bash
# Requires Docker
cargo test --features s3 --test s3_emulator_tests
```

Uses MinIO Docker image. Tests cover:

- Catalog initialization and existence checks
- Upload/download roundtrips with ETag-based versioning
- Concurrent write detection and conflict handling
- Retry logic with exponential backoff
- Cache behavior (enabled/disabled)
- Metadata preservation and region configuration

**Note:** Emulator tests automatically:

- Start Docker containers via `testcontainers-rs`
- Wait for container readiness (30-second timeout)
- Clean up containers after test completion
- Run in isolated environments (no credential leakage)

## Documentation

- **[Getting Started](docs/getting-started.md)** - 10-minute tutorial
- **[Architecture](docs/architecture.md)** - How MetaFuse works
- **[API Reference](docs/api-reference.md)** - REST API endpoints
- **[Deployment (GCP)](docs/deployment-gcp.md)** - Cloud Run/GKE setup, auth, cost notes
- **[Deployment (AWS)](docs/deployment-aws.md)** - ECS/EKS/Lambda setup, auth, cost notes
- **[Authentication](docs/auth-gcp.md)** / **[auth-aws.md](docs/auth-aws.md)** - Credential patterns and best practices
- **[Migration: Local → Cloud](docs/migration-local-to-cloud.md)** - Step-by-step move to object storage
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and fixes
- **[Roadmap](docs/roadmap.md)** - What's coming next

## Project Structure

```
MetaFuse/
|-- crates/
|   |-- catalog-core/       # Core types and SQLite schema
|   |-- catalog-storage/    # Local + cloud catalog backends
|   |-- catalog-emitter/    # DataFusion integration
|   |-- catalog-api/        # REST API (Axum)
|   `-- catalog-cli/        # CLI for catalog operations
|-- docs/                   # Documentation
|-- examples/               # Usage examples
`-- tests/                  # Integration tests
```

## Use Cases

- **Data Discovery**: Find datasets with full-text search
- **Data Lineage**: Track dependencies and impact analysis
- **Data Governance**: Know what exists, where it lives, and who owns it
- **Team Collaboration**: Share knowledge with tags and glossary terms

## Comparison

| Feature | MetaFuse | DataHub | AWS Glue |
|---------|----------|---------|----------|
| **Cost** | $0-$5/mo | High (self-hosted) | Pay-per-use |
| **Setup** | < 30 min | Days | Hours |
| **Infrastructure** | None | Kafka, MySQL, ES | AWS only |
| **DataFusion Integration** | Native | Via connector | No |
| **Local Development** | Yes | No | No |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Community

- **Issues**: [Report bugs or request features](https://github.com/ethan-tyler/MetaFuse/issues)
- **Discussions**: [Ask questions](https://github.com/ethan-tyler/MetaFuse/discussions)

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Built with [Apache Arrow](https://arrow.apache.org/), [DataFusion](https://datafusion.apache.org/), [SQLite](https://www.sqlite.org/), and [Rust](https://www.rust-lang.org/).

---

**Built for data teams who want catalogs, not complexity.**
