// Multi-stage pipeline example demonstrating lineage tracking
//
// This example shows:
// 1. A multi-stage ETL pipeline (raw -> cleaned -> aggregated)
// 2. Tracking lineage relationships between datasets
// 3. Querying lineage via CLI
//
// Run with: cargo run --example lineage_tracking

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
    println!("=== MetaFuse Lineage Tracking Example ===\n");
    println!("This example demonstrates a 3-stage ETL pipeline:\n");
    println!("  raw_transactions -> cleaned_transactions -> daily_summary\n");

    let backend = LocalSqliteBackend::new("metafuse_catalog.db");
    let emitter = Emitter::new(backend);
    let ctx = SessionContext::new();

    // ========== STAGE 1: Raw Data ==========
    println!("Stage 1: Loading raw transaction data...");

    let raw_schema = Arc::new(Schema::new(vec![
        Field::new("transaction_id", DataType::Int64, false),
        Field::new("customer_id", DataType::Int64, true),
        Field::new("amount", DataType::Float64, true),
        Field::new("status", DataType::Utf8, true),
    ]));

    let raw_batch = RecordBatch::try_new(
        raw_schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5, 6, 7, 8])),
            Arc::new(Int64Array::from(vec![
                Some(101),
                Some(102),
                None,
                Some(103),
                Some(101),
                Some(104),
                Some(102),
                Some(103),
            ])),
            Arc::new(Float64Array::from(vec![
                Some(50.0),
                Some(75.5),
                Some(-10.0),
                Some(120.0),
                Some(200.0),
                Some(0.0),
                Some(150.0),
                Some(90.0),
            ])),
            Arc::new(StringArray::from(vec![
                Some("completed"),
                Some("completed"),
                Some("failed"),
                Some("completed"),
                Some("completed"),
                Some("pending"),
                Some("completed"),
                Some("completed"),
            ])),
        ],
    )?;

    ctx.register_batch("raw_transactions", raw_batch.clone())?;
    println!("  Loaded {} raw transactions", raw_batch.num_rows());

    // Emit metadata for raw data
    emitter
        .emit_dataset(
            "raw_transactions",
            "/data/raw/transactions.parquet",
            "parquet",
            Some("Raw transaction data from payment gateway"),
            Some("prod"),
            Some("sales"),
            Some("data-ingestion@example.com"),
            raw_schema,
            Some(OperationalMeta {
                row_count: Some(raw_batch.num_rows() as i64),
                size_bytes: None,
                partition_keys: vec![],
            }),
            vec![], // No upstream dependencies
            vec!["raw".to_string(), "transactions".to_string()],
        )
        .await?;
    println!("  Metadata emitted: raw_transactions\n");

    // ========== STAGE 2: Data Cleaning ==========
    println!("Stage 2: Cleaning data (filter invalid records)...");

    let cleaned_df = ctx
        .sql(
            "SELECT transaction_id, customer_id, amount, status
             FROM raw_transactions
             WHERE status = 'completed'
               AND customer_id IS NOT NULL
               AND amount > 0",
        )
        .await?;

    // Get the schema before consuming the DataFrame
    let cleaned_schema = cleaned_df.schema().inner().clone();

    let cleaned_result = cleaned_df.collect().await?;
    let cleaned_count: usize = cleaned_result.iter().map(|b| b.num_rows()).sum();

    println!(
        "  Cleaned {} transactions (removed {} invalid)",
        cleaned_count,
        raw_batch.num_rows() - cleaned_count
    );

    // Emit metadata for cleaned data with lineage to raw data
    emitter
        .emit_dataset(
            "cleaned_transactions",
            "/data/cleaned/transactions.parquet",
            "parquet",
            Some("Cleaned and validated transaction data"),
            Some("prod"),
            Some("sales"),
            Some("data-pipeline@example.com"),
            cleaned_schema,
            Some(OperationalMeta {
                row_count: Some(cleaned_count as i64),
                size_bytes: None,
                partition_keys: vec![],
            }),
            vec!["raw_transactions".to_string()], // Upstream dependency
            vec!["cleaned".to_string(), "validated".to_string()],
        )
        .await?;
    println!("  Metadata emitted: cleaned_transactions");
    println!("  Lineage: raw_transactions -> cleaned_transactions\n");

    // Register cleaned data for next stage
    ctx.deregister_table("cleaned_transactions")?;
    let cleaned_batch = RecordBatch::try_new(
        cleaned_result[0].schema(),
        cleaned_result[0].columns().to_vec(),
    )?;
    ctx.register_batch("cleaned_transactions", cleaned_batch)?;

    // ========== STAGE 3: Aggregation ==========
    println!("Stage 3: Aggregating daily summary...");

    let summary_df = ctx
        .sql(
            "SELECT
                 customer_id,
                 COUNT(*) as transaction_count,
                 SUM(amount) as total_amount,
                 AVG(amount) as avg_amount
             FROM cleaned_transactions
             GROUP BY customer_id
             ORDER BY total_amount DESC",
        )
        .await?;

    // Get the schema before consuming the DataFrame
    let summary_schema = summary_df.schema().inner().clone();

    let summary_result = summary_df.collect().await?;
    let summary_count: usize = summary_result.iter().map(|b| b.num_rows()).sum();

    println!("  Aggregated {} customer summaries", summary_count);

    // Emit metadata for aggregated data with lineage to cleaned data
    emitter
        .emit_dataset(
            "daily_summary",
            "/data/aggregates/daily_summary.parquet",
            "parquet",
            Some("Daily customer transaction summary"),
            Some("prod"),
            Some("sales"),
            Some("analytics@example.com"),
            summary_schema,
            Some(OperationalMeta {
                row_count: Some(summary_count as i64),
                size_bytes: None,
                partition_keys: vec![],
            }),
            vec!["cleaned_transactions".to_string()], // Upstream dependency
            vec![
                "aggregated".to_string(),
                "summary".to_string(),
                "daily".to_string(),
            ],
        )
        .await?;
    println!("  Metadata emitted: daily_summary");
    println!("  Lineage: cleaned_transactions -> daily_summary\n");

    // ========== Summary ==========
    println!("=== Pipeline Complete ===\n");
    println!("Full lineage chain:");
    println!("  raw_transactions (8 rows)");
    println!("    -> cleaned_transactions ({} rows)", cleaned_count);
    println!("        -> daily_summary ({} rows)\n", summary_count);

    println!("View lineage with CLI:");
    println!("  metafuse show daily_summary --lineage");
    println!("  metafuse show cleaned_transactions --lineage");
    println!("  metafuse list --domain sales\n");

    println!("Query via API:");
    println!("  curl http://localhost:8080/api/v1/datasets/daily_summary");
    println!("  curl http://localhost:8080/api/v1/datasets/cleaned_transactions\n");

    Ok(())
}
