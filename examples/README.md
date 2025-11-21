# MetaFuse Examples

This directory contains runnable examples demonstrating how to use MetaFuse with DataFusion pipelines.

## Available Examples

### 1. Simple Pipeline (`simple_pipeline.rs`)

A basic example showing how to:
- Create in-memory data with Apache Arrow
- Run a simple DataFusion query
- Emit metadata to the MetaFuse catalog

**Run:**
```bash
cargo run --example simple_pipeline
```

**What it does:**
1. Creates sample data (5 rows, 3 columns)
2. Runs a filter query (`value > 150.0`)
3. Emits metadata to `metafuse_catalog.db`
4. Creates a dataset named `sample_dataset`

**After running:**
```bash
metafuse show sample_dataset
metafuse list
```

---

### 2. Lineage Tracking (`lineage_tracking.rs`)

A multi-stage ETL pipeline demonstrating lineage tracking:
- Stage 1: Load raw transaction data
- Stage 2: Clean and validate data
- Stage 3: Aggregate daily summaries

**Run:**
```bash
cargo run --example lineage_tracking
```

**What it does:**
1. Creates 3 datasets with upstream dependencies:
   - `raw_transactions` (no upstream)
   - `cleaned_transactions` (upstream: `raw_transactions`)
   - `daily_summary` (upstream: `cleaned_transactions`)
2. Tracks lineage relationships automatically
3. Demonstrates filtering, validation, and aggregation

**After running:**
```bash
# View full lineage chain
metafuse show daily_summary --lineage

# View cleaned data lineage
metafuse show cleaned_transactions --lineage

# List all sales datasets
metafuse list --domain sales
```

**Expected lineage output:**
```
daily_summary
  -> cleaned_transactions
      -> raw_transactions
```

---

## Running All Examples

Use the convenience script to run all examples:

```bash
./run_examples.sh
```

Or run them individually:

```bash
cargo run --example simple_pipeline
cargo run --example lineage_tracking
```

---

## Prerequisites

No setup required! Examples automatically create their own catalog databases:

- `simple_pipeline` → `metafuse_catalog.db`
- `lineage_tracking` → `lineage_catalog.db`

Just run the examples and they'll handle initialization automatically.

---

## Verifying Example Results

### Using the CLI

```bash
# List all datasets
metafuse list

# Show specific dataset
metafuse show sample_dataset

# Show dataset with lineage
metafuse show daily_summary --lineage

# Search for datasets
metafuse search "transactions"

# View catalog statistics
metafuse stats
```

### Using the REST API

Start the API server:
```bash
cargo run --bin metafuse-api
```

Query endpoints:
```bash
# List datasets
curl http://localhost:8080/api/v1/datasets

# Get dataset details
curl http://localhost:8080/api/v1/datasets/sample_dataset

# Search
curl "http://localhost:8080/api/v1/search?q=transactions"
```

---

## Understanding the Output

### Simple Pipeline Output

```
=== MetaFuse Simple Pipeline Example ===

1. Creating sample data...
   Created 5 rows with 3 columns

2. Running DataFusion query...
   Query returned 4 rows (filtered value > 150.0)

3. Emitting metadata to catalog...
   Metadata emitted: sample_dataset

4. Verifying catalog entry...
   Run: metafuse show sample_dataset
   Or:  metafuse list
```

### Lineage Tracking Output

```
=== MetaFuse Lineage Tracking Example ===

Stage 1: Loading raw transaction data...
  Done Loaded 8 raw transactions
  Done Metadata emitted: raw_transactions

Stage 2: Cleaning data (filter invalid records)...
  Cleaned 6 transactions (removed 2 invalid)
  Metadata emitted: cleaned_transactions
  Lineage: raw_transactions -> cleaned_transactions

Stage 3: Aggregating daily summary...
  Aggregated 3 customer summaries
  Metadata emitted: daily_summary
  Lineage: cleaned_transactions -> daily_summary

=== Pipeline Complete ===

Full lineage chain:
  raw_transactions (8 rows)
    -> cleaned_transactions (6 rows)
        -> daily_summary (3 rows)
```

---

## Extending the Examples

### Add Your Own Example

1. Create a new file in `examples/`:
   ```rust
   // examples/my_example.rs
   use datafusion::prelude::*;
   use metafuse_catalog_emitter::Emitter;
   use metafuse_catalog_storage::LocalSqliteBackend;

   #[tokio::main]
   async fn main() -> Result<()> {
       // Your pipeline code here
       Ok(())
   }
   ```

2. Run it:
   ```bash
   cargo run --example my_example
   ```

### Common Patterns

**Emitting metadata:**
```rust
let backend = LocalSqliteBackend::new("metafuse_catalog.db");
let emitter = Emitter::new(backend);

emitter.emit_dataset(
    "dataset_name",
    "/path/to/data.parquet",
    "parquet",
    Some("Description"),
    Some("tenant"),
    Some("domain"),
    Some("owner@example.com"),
    schema,  // Arrow SchemaRef
    Some(OperationalMeta {
        row_count: Some(row_count),
        size_bytes: None,
        partition_keys: vec![],
    }),
    vec!["upstream_dataset".to_string()],  // Lineage
    vec!["tag1".to_string(), "tag2".to_string()],  // Tags
)?;
```

**Tracking lineage:**
```rust
// Parent dataset (no upstream)
emitter.emit_dataset("parent", ..., vec![], ...)?;

// Child dataset (depends on parent)
emitter.emit_dataset("child", ..., vec!["parent".to_string()], ...)?;

// Grandchild dataset (depends on child)
emitter.emit_dataset("grandchild", ..., vec!["child".to_string()], ...)?;
```

---

## Troubleshooting

### "Catalog not found" error

If you see errors about the catalog not existing:
```bash
metafuse init --force
```

### Permission denied on catalog.db

Ensure the catalog file has write permissions:
```bash
chmod 600 metafuse_catalog.db
```

### DataFusion version mismatch

If you encounter compatibility issues, ensure you're using DataFusion v42 (or the version specified in `Cargo.toml`).

---

## Next Steps

- **Read the docs:** [Getting Started Guide](../docs/getting-started.md)
- **Explore the API:** [API Reference](../docs/api-reference.md)
- **Learn the architecture:** [Architecture](../docs/architecture.md)
- **Build your own pipeline:** Integrate MetaFuse into your DataFusion project

---

## Questions?

- [GitHub Issues](https://github.com/ethan-tyler/MetaFuse/issues)
- [GitHub Discussions](https://github.com/ethan-tyler/MetaFuse/discussions)
