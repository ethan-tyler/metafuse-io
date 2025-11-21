# MetaFuse

> **Lightweight, serverless data catalog for DataFusion and modern lakehouse pipelines**

[![CI](https://github.com/ethan-tyler/MetaFuse/workflows/CI/badge.svg)](https://github.com/ethan-tyler/MetaFuse/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

MetaFuse captures dataset schemas, lineage, and operational metadata automatically from your data pipelines without requiring Kafka, MySQL, or Elasticsearch. Just a SQLite file on object storage.

**Status:** Phase 1 MVP Complete (Q4 2025) - Core foundation stable. Cloud backends (GCS/S3) coming in Phase 2.

## Why MetaFuse?

- **Native DataFusion integration** - Emit metadata directly from pipelines
- **Serverless-friendly** - $0-$5/month on object storage (GCS/S3 coming soon)
- **Zero infrastructure** - No databases, no clusters to maintain
- **Automatic lineage capture** - Track data flow through transformations
- **Full-text search with FTS5** - Fast search with automatic trigger maintenance
- **Optimistic concurrency** - Safe concurrent writes with version-based locking
- **Tags and glossary** - Organize with business context
- **Operational metadata** - Track row counts, sizes, partition keys

MetaFuse fills the gap between expensive, complex enterprise catalogs (DataHub, Collibra) and the needs of small-to-medium data teams.

## Quick Start

### Install

```bash
git clone https://github.com/ethan-tyler/MetaFuse.git
cd MetaFuse
cargo build --release
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

## Documentation

- **[Getting Started](docs/getting-started.md)** - 10-minute tutorial
- **[Architecture](docs/architecture.md)** - How MetaFuse works
- **[API Reference](docs/api-reference.md)** - REST API endpoints
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
