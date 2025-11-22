// Simple DataFusion pipeline example demonstrating MetaFuse integration
//
// This example shows:
// 1. Creating in-memory data with Arrow
// 2. Running a simple DataFusion query
// 3. Emitting metadata to the MetaFuse catalog
//
// Run with: cargo run --example simple_pipeline

use datafusion::arrow::array::{Float64Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::error::Result;
use datafusion::prelude::*;
use metafuse_catalog_core::OperationalMeta;
use metafuse_catalog_emitter::Emitter;
use metafuse_catalog_storage::LocalSqliteBackend;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== MetaFuse Simple Pipeline Example ===\n");

    // Step 1: Create sample in-memory data
    println!("1. Creating sample data...");
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("value", DataType::Float64, true),
    ]));

    let id_array = Int64Array::from(vec![1, 2, 3, 4, 5]);
    let name_array = StringArray::from(vec![
        Some("Alice"),
        Some("Bob"),
        Some("Charlie"),
        None,
        Some("Eve"),
    ]);
    let value_array = Float64Array::from(vec![
        Some(100.5),
        Some(200.3),
        Some(150.7),
        Some(300.2),
        Some(250.0),
    ]);

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id_array),
            Arc::new(name_array),
            Arc::new(value_array),
        ],
    )?;

    println!(
        "   Created {} rows with {} columns",
        batch.num_rows(),
        batch.num_columns()
    );

    // Step 2: Create DataFusion context and register data
    println!("\n2. Running DataFusion query...");
    let ctx = SessionContext::new();
    ctx.register_batch("source_data", batch)?;

    // Run a simple query
    let df = ctx
        .sql("SELECT id, name, value FROM source_data WHERE value > 150.0")
        .await?;

    // Get the schema before consuming the DataFrame
    let result_schema = df.schema().inner().clone();

    let result = df.collect().await?;
    let row_count: usize = result.iter().map(|batch| batch.num_rows()).sum();
    println!(
        "   Query returned {} rows (filtered value > 150.0)",
        row_count
    );

    // Step 3: Emit metadata to catalog
    println!("\n3. Emitting metadata to catalog...");
    let backend = LocalSqliteBackend::new("metafuse_catalog.db");
    let emitter = Emitter::new(backend);

    emitter
        .emit_dataset(
            "sample_dataset",
            "/tmp/sample_data.parquet",
            "parquet",
            Some("Sample dataset for getting started with MetaFuse"),
            Some("dev"),
            Some("analytics"),
            Some("example@metafuse.dev"),
            result_schema,
            Some(OperationalMeta {
                row_count: Some(row_count as i64),
                size_bytes: None,
                partition_keys: vec![],
            }),
            vec![], // No upstream dependencies
            vec!["example".to_string(), "tutorial".to_string()],
        )
        .await?;

    println!("   Metadata emitted: sample_dataset");

    // Step 4: Verify emission (optional - query the catalog)
    println!("\n4. Verifying catalog entry...");
    println!("   Run: metafuse show sample_dataset");
    println!("   Or:  metafuse list");

    println!("\n=== Example Complete ===");
    println!("\nNext steps:");
    println!("  - View the dataset: metafuse show sample_dataset");
    println!("  - List all datasets: metafuse list");
    println!("  - Search: metafuse search analytics");
    println!("  - View stats: metafuse stats");

    Ok(())
}
