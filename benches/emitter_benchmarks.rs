//! Benchmarks for MetaFuse catalog emitter operations
//!
//! Run with: cargo bench --features bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use metafuse_catalog_core::OperationalMeta;
use metafuse_catalog_emitter::Emitter;
use metafuse_catalog_storage::{CatalogBackend, LocalSqliteBackend};
use std::sync::Arc;
use tempfile::TempDir;

/// Helper to create a test backend with isolated storage
fn create_bench_backend() -> (TempDir, LocalSqliteBackend) {
    let temp_dir = TempDir::new().unwrap();
    let catalog_path = temp_dir.path().join("bench_catalog.db");
    let backend = LocalSqliteBackend::new(&catalog_path);
    (temp_dir, backend)
}

/// Helper to create a sample schema for benchmarking
fn create_bench_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("value", DataType::Float64, true),
        Field::new("timestamp", DataType::Utf8, true),
        Field::new("category", DataType::Utf8, true),
    ]))
}

/// Benchmark: emit_dataset with minimal metadata
fn bench_emit_dataset_minimal(c: &mut Criterion) {
    c.bench_function("emit_dataset_minimal", |b| {
        let (_temp_dir, backend) = create_bench_backend();
        let emitter = Emitter::new(backend);
        let schema = create_bench_schema();
        let mut counter = 0;

        b.iter(|| {
            counter += 1;
            let dataset_name = format!("bench_dataset_{}", counter);

            emitter
                .emit_dataset(
                    black_box(&dataset_name),
                    black_box("/data/bench.parquet"),
                    black_box("parquet"),
                    None, // No description
                    None, // No tenant
                    None, // No domain
                    None, // No owner
                    black_box(schema.clone()),
                    None,   // No operational metadata
                    vec![], // No upstream
                    vec![], // No tags
                )
                .unwrap();
        });
    });
}

/// Benchmark: emit_dataset with full metadata
fn bench_emit_dataset_full(c: &mut Criterion) {
    c.bench_function("emit_dataset_full", |b| {
        let (_temp_dir, backend) = create_bench_backend();
        let emitter = Emitter::new(backend);
        let schema = create_bench_schema();
        let mut counter = 0;

        b.iter(|| {
            counter += 1;
            let dataset_name = format!("bench_dataset_{}", counter);

            emitter
                .emit_dataset(
                    black_box(&dataset_name),
                    black_box("/data/bench.parquet"),
                    black_box("parquet"),
                    Some("Benchmark dataset with full metadata"),
                    Some("prod"),
                    Some("analytics"),
                    Some("bench@metafuse.dev"),
                    black_box(schema.clone()),
                    Some(OperationalMeta {
                        row_count: Some(1_000_000),
                        size_bytes: Some(500_000_000),
                        partition_keys: vec![
                            "year".to_string(),
                            "month".to_string(),
                            "day".to_string(),
                        ],
                    }),
                    vec!["upstream_dataset".to_string()],
                    vec![
                        "benchmark".to_string(),
                        "test".to_string(),
                        "performance".to_string(),
                    ],
                )
                .unwrap();
        });
    });
}

/// Benchmark: emit_dataset with lineage (3 datasets in chain)
fn bench_emit_dataset_with_lineage(c: &mut Criterion) {
    c.bench_function("emit_dataset_with_lineage", |b| {
        let (_temp_dir, backend) = create_bench_backend();
        let emitter = Emitter::new(backend);
        let schema = create_bench_schema();

        // Create parent dataset once
        emitter
            .emit_dataset(
                "parent_dataset",
                "/data/parent.parquet",
                "parquet",
                Some("Parent dataset"),
                Some("prod"),
                Some("analytics"),
                Some("bench@metafuse.dev"),
                schema.clone(),
                None,
                vec![],
                vec![],
            )
            .unwrap();

        let mut counter = 0;

        b.iter(|| {
            counter += 1;
            let dataset_name = format!("child_dataset_{}", counter);

            // Emit child dataset with parent lineage
            emitter
                .emit_dataset(
                    black_box(&dataset_name),
                    black_box("/data/child.parquet"),
                    black_box("parquet"),
                    Some("Child dataset with lineage"),
                    Some("prod"),
                    Some("analytics"),
                    Some("bench@metafuse.dev"),
                    black_box(schema.clone()),
                    Some(OperationalMeta {
                        row_count: Some(500_000),
                        size_bytes: None,
                        partition_keys: vec![],
                    }),
                    vec!["parent_dataset".to_string()],
                    vec!["derived".to_string()],
                )
                .unwrap();
        });
    });
}

/// Benchmark: Full-text search (FTS5) on dataset names
fn bench_fts_search_simple(c: &mut Criterion) {
    let (_temp_dir, backend) = create_bench_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_bench_schema();

    // Emit 100 datasets with varied names for realistic search
    for i in 0..100 {
        let dataset_name = match i % 5 {
            0 => format!("transactions_daily_{}", i),
            1 => format!("users_profile_{}", i),
            2 => format!("analytics_summary_{}", i),
            3 => format!("sales_report_{}", i),
            _ => format!("inventory_snapshot_{}", i),
        };

        emitter
            .emit_dataset(
                &dataset_name,
                &format!("/data/{}.parquet", dataset_name),
                "parquet",
                Some(&format!("Description for {}", dataset_name)),
                Some("prod"),
                Some(if i % 2 == 0 { "finance" } else { "analytics" }),
                Some("bench@metafuse.dev"),
                schema.clone(),
                None,
                vec![],
                vec![],
            )
            .unwrap();
    }

    c.bench_function("fts_search_simple", |b| {
        let conn = backend.get_connection().unwrap();

        b.iter(|| {
            let mut stmt = conn
                .prepare(
                    "SELECT dataset_name FROM dataset_search \
                     WHERE dataset_search MATCH ?1 \
                     LIMIT 10",
                )
                .unwrap();

            let results: Vec<String> = stmt
                .query_map([black_box("transactions")], |row| row.get(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            black_box(results);
        });
    });
}

/// Benchmark: Full-text search with domain filter
fn bench_fts_search_with_filter(c: &mut Criterion) {
    let (_temp_dir, backend) = create_bench_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_bench_schema();

    // Emit 100 datasets
    for i in 0..100 {
        emitter
            .emit_dataset(
                &format!("dataset_{}", i),
                &format!("/data/dataset_{}.parquet", i),
                "parquet",
                Some(&format!("Benchmark dataset {}", i)),
                Some("prod"),
                Some(if i % 3 == 0 {
                    "finance"
                } else if i % 3 == 1 {
                    "analytics"
                } else {
                    "sales"
                }),
                Some("bench@metafuse.dev"),
                schema.clone(),
                Some(OperationalMeta {
                    row_count: Some((i as i64) * 1000),
                    size_bytes: None,
                    partition_keys: vec![],
                }),
                vec![],
                vec![format!("tag_{}", i % 10)],
            )
            .unwrap();
    }

    c.bench_function("fts_search_with_domain_filter", |b| {
        let conn = backend.get_connection().unwrap();

        b.iter(|| {
            let mut stmt = conn
                .prepare(
                    "SELECT ds.dataset_name
                     FROM dataset_search ds
                     JOIN datasets d ON ds.dataset_name = d.name
                     WHERE ds.dataset_search MATCH ?1
                       AND d.domain = ?2
                     LIMIT 10",
                )
                .unwrap();

            let results: Vec<String> = stmt
                .query_map([black_box("dataset"), black_box("finance")], |row| {
                    row.get(0)
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            black_box(results);
        });
    });
}

criterion_group!(
    benches,
    bench_emit_dataset_minimal,
    bench_emit_dataset_full,
    bench_emit_dataset_with_lineage,
    bench_fts_search_simple,
    bench_fts_search_with_filter
);
criterion_main!(benches);
