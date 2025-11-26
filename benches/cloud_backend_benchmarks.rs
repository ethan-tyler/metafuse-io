//! Benchmarks for MetaFuse cloud storage backends
//!
//! These benchmarks measure upload/download performance for GCS and S3 backends.
//! They require emulator setup and are NOT run in PR CI by default.
//!
//! ## Running Benchmarks
//!
//! ```bash
//! # Compile-only check (CI):
//! cargo bench --no-run
//!
//! # Run GCS benchmarks (requires fake-gcs-server):
//! RUN_CLOUD_TESTS=1 cargo bench --features gcs --bench cloud_backend_benchmarks -- gcs
//!
//! # Run S3 benchmarks (requires MinIO):
//! RUN_CLOUD_TESTS=1 cargo bench --features s3 --bench cloud_backend_benchmarks -- s3
//! ```

use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use metafuse_catalog_core::{init_sqlite_schema, DatasetMeta, FieldMeta, OperationalMeta};
use std::time::Duration;

#[cfg(any(feature = "gcs", feature = "s3"))]
use metafuse_catalog_storage::CatalogBackend;

/// Check if cloud benchmarks should run
fn should_run_cloud_benchmarks() -> bool {
    std::env::var("RUN_CLOUD_TESTS").unwrap_or_default() == "1"
}

/// Create a test dataset of specified size (KB)
fn create_test_dataset(name: &str, size_kb: usize) -> DatasetMeta {
    // Create fields to reach approximate size
    let field_count = size_kb / 10; // Rough approximation
    let fields: Vec<FieldMeta> = (0..field_count)
        .map(|i| FieldMeta {
            name: format!("field_{}", i),
            data_type: "string".to_string(),
            nullable: true,
            description: Some(format!("Test field {} for benchmark", i)),
        })
        .collect();

    DatasetMeta {
        name: name.to_string(),
        path: format!("file:///tmp/bench/{}.parquet", name),
        format: "parquet".to_string(),
        description: Some(format!("Benchmark dataset {}KB", size_kb)),
        tenant: None,
        domain: Some("bench-domain".to_string()),
        owner: Some("benchmark".to_string()),
        created_at: Utc::now(),
        last_updated: Utc::now(),
        fields,
        upstream_datasets: vec![],
        tags: vec!["benchmark".to_string()],
        operational: Some(OperationalMeta {
            row_count: Some(1000),
            size_bytes: Some((size_kb * 1024) as i64),
            partition_keys: vec![],
        }),
    }
}

#[cfg(feature = "gcs")]
mod gcs_benchmarks {
    use super::*;
    use metafuse_catalog_storage::GCSBackend;

    /// Benchmark GCS upload for different dataset sizes
    pub fn bench_gcs_upload(c: &mut Criterion) {
        if !should_run_cloud_benchmarks() {
            eprintln!("Skipping GCS benchmarks: set RUN_CLOUD_TESTS=1");
            return;
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut group = c.benchmark_group("gcs_upload");

        // Configure bucket and emulator
        std::env::set_var("STORAGE_EMULATOR_HOST", "http://127.0.0.1:4443");
        let bucket = format!("test-bucket-{}", std::process::id());
        let uri = format!("gs://{}/catalog.db", bucket);

        for size_kb in [100, 1000].iter() {
            group.throughput(Throughput::Bytes((*size_kb * 1024) as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{}KB", size_kb)),
                size_kb,
                |b, &size| {
                    // Create backend once
                    let backend = rt.block_on(async {
                        GCSBackend::new(&uri)
                            .await
                            .expect("Failed to create GCS backend")
                    });

                    let dataset = create_test_dataset(&format!("bench_dataset_{}", size), size);

                    b.to_async(&rt).iter(|| async {
                        backend
                            .initialize_catalog()
                            .await
                            .expect("Failed to initialize catalog");

                        backend
                            .save_dataset(black_box(&dataset))
                            .await
                            .expect("Failed to save dataset");
                    });
                },
            );
        }

        group.finish();
        std::env::remove_var("STORAGE_EMULATOR_HOST");
    }

    /// Benchmark GCS download for different dataset sizes
    pub fn bench_gcs_download(c: &mut Criterion) {
        if !should_run_cloud_benchmarks() {
            eprintln!("Skipping GCS benchmarks: set RUN_CLOUD_TESTS=1");
            return;
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut group = c.benchmark_group("gcs_download");

        std::env::set_var("STORAGE_EMULATOR_HOST", "http://127.0.0.1:4443");
        let bucket = format!("test-bucket-{}", std::process::id());
        let uri = format!("gs://{}/catalog.db", bucket);

        for size_kb in [100, 1000].iter() {
            group.throughput(Throughput::Bytes((*size_kb * 1024) as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{}KB", size_kb)),
                size_kb,
                |b, &size| {
                    // Create backend and pre-populate
                    let backend = rt.block_on(async {
                        let backend = GCSBackend::new(&uri)
                            .await
                            .expect("Failed to create GCS backend");
                        backend
                            .initialize_catalog()
                            .await
                            .expect("Failed to initialize");

                        let dataset = create_test_dataset(&format!("bench_dataset_{}", size), size);
                        backend
                            .save_dataset(&dataset)
                            .await
                            .expect("Failed to save");

                        backend
                    });

                    let dataset_name = format!("bench_dataset_{}", size);

                    b.to_async(&rt).iter(|| async {
                        let result = backend
                            .get_dataset(black_box(&dataset_name))
                            .await
                            .expect("Failed to get dataset");

                        assert!(result.is_some(), "Dataset should exist");
                    });
                },
            );
        }

        group.finish();
        std::env::remove_var("STORAGE_EMULATOR_HOST");
    }

    /// Benchmark GCS cache hit vs miss
    pub fn bench_gcs_cache_performance(c: &mut Criterion) {
        if !should_run_cloud_benchmarks() {
            eprintln!("Skipping GCS benchmarks: set RUN_CLOUD_TESTS=1");
            return;
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut group = c.benchmark_group("gcs_cache");
        group.measurement_time(Duration::from_secs(10));

        std::env::set_var("STORAGE_EMULATOR_HOST", "http://127.0.0.1:4443");
        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "300"); // 5 min cache

        let bucket = format!("test-bucket-{}", std::process::id());
        let uri = format!("gs://{}/catalog.db", bucket);

        // Cache hit benchmark
        group.bench_function("cache_hit", |b| {
            let backend = rt.block_on(async {
                let backend = GCSBackend::new(&uri)
                    .await
                    .expect("Failed to create GCS backend");
                backend
                    .initialize_catalog()
                    .await
                    .expect("Failed to initialize");

                let dataset = create_test_dataset("cached_dataset", 100);
                backend
                    .save_dataset(&dataset)
                    .await
                    .expect("Failed to save");

                // Prime cache
                backend.download().await.expect("Failed to prime cache");

                backend
            });

            b.to_async(&rt).iter(|| async {
                let _result = backend.download().await.expect("Failed to download");
            });
        });

        // Cache miss benchmark
        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "0"); // Disable cache

        group.bench_function("cache_miss", |b| {
            let backend = rt.block_on(async {
                let backend = GCSBackend::new(&uri)
                    .await
                    .expect("Failed to create GCS backend");
                backend
                    .initialize_catalog()
                    .await
                    .expect("Failed to initialize");

                let dataset = create_test_dataset("uncached_dataset", 100);
                backend
                    .save_dataset(&dataset)
                    .await
                    .expect("Failed to save");

                backend
            });

            b.to_async(&rt).iter(|| async {
                let _result = backend.download().await.expect("Failed to download");
            });
        });

        group.finish();
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }
}

#[cfg(feature = "s3")]
mod s3_benchmarks {
    use super::*;
    use metafuse_catalog_storage::S3Backend;

    /// Benchmark S3 upload for different dataset sizes
    pub fn bench_s3_upload(c: &mut Criterion) {
        if !should_run_cloud_benchmarks() {
            eprintln!("Skipping S3 benchmarks: set RUN_CLOUD_TESTS=1");
            return;
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut group = c.benchmark_group("s3_upload");

        // Configure MinIO emulator
        std::env::set_var("AWS_ACCESS_KEY_ID", "minioadmin");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "minioadmin");
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var("AWS_ENDPOINT_URL", "http://127.0.0.1:9000");

        let bucket = format!("test-bucket-{}", std::process::id());
        let uri = format!("s3://{}/catalog.db", bucket);

        for size_kb in [100, 1000].iter() {
            group.throughput(Throughput::Bytes((*size_kb * 1024) as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{}KB", size_kb)),
                size_kb,
                |b, &size| {
                    let backend = rt.block_on(async {
                        S3Backend::new(&uri)
                            .await
                            .expect("Failed to create S3 backend")
                    });

                    let dataset = create_test_dataset(&format!("bench_dataset_{}", size), size);

                    b.to_async(&rt).iter(|| async {
                        backend
                            .initialize_catalog()
                            .await
                            .expect("Failed to initialize catalog");

                        backend
                            .save_dataset(black_box(&dataset))
                            .await
                            .expect("Failed to save dataset");
                    });
                },
            );
        }

        group.finish();

        // Cleanup env vars
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
    }

    /// Benchmark S3 download for different dataset sizes
    pub fn bench_s3_download(c: &mut Criterion) {
        if !should_run_cloud_benchmarks() {
            eprintln!("Skipping S3 benchmarks: set RUN_CLOUD_TESTS=1");
            return;
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut group = c.benchmark_group("s3_download");

        std::env::set_var("AWS_ACCESS_KEY_ID", "minioadmin");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "minioadmin");
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var("AWS_ENDPOINT_URL", "http://127.0.0.1:9000");

        let bucket = format!("test-bucket-{}", std::process::id());
        let uri = format!("s3://{}/catalog.db", bucket);

        for size_kb in [100, 1000].iter() {
            group.throughput(Throughput::Bytes((*size_kb * 1024) as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{}KB", size_kb)),
                size_kb,
                |b, &size| {
                    let backend = rt.block_on(async {
                        let backend = S3Backend::new(&uri)
                            .await
                            .expect("Failed to create S3 backend");
                        backend
                            .initialize_catalog()
                            .await
                            .expect("Failed to initialize");

                        let dataset = create_test_dataset(&format!("bench_dataset_{}", size), size);
                        backend
                            .save_dataset(&dataset)
                            .await
                            .expect("Failed to save");

                        backend
                    });

                    let dataset_name = format!("bench_dataset_{}", size);

                    b.to_async(&rt).iter(|| async {
                        let result = backend
                            .get_dataset(black_box(&dataset_name))
                            .await
                            .expect("Failed to get dataset");

                        assert!(result.is_some(), "Dataset should exist");
                    });
                },
            );
        }

        group.finish();

        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
    }
}

// Feature-gated criterion groups
#[cfg(feature = "gcs")]
criterion_group! {
    name = gcs_benches;
    config = Criterion::default();
    targets = gcs_benchmarks::bench_gcs_upload, gcs_benchmarks::bench_gcs_download, gcs_benchmarks::bench_gcs_cache_performance
}

#[cfg(feature = "s3")]
criterion_group! {
    name = s3_benches;
    config = Criterion::default();
    targets = s3_benchmarks::bench_s3_upload, s3_benchmarks::bench_s3_download
}

// Conditional main based on features
#[cfg(all(feature = "gcs", feature = "s3"))]
criterion_main!(gcs_benches, s3_benches);

#[cfg(all(feature = "gcs", not(feature = "s3")))]
criterion_main!(gcs_benches);

#[cfg(all(not(feature = "gcs"), feature = "s3"))]
criterion_main!(s3_benches);

#[cfg(not(any(feature = "gcs", feature = "s3")))]
fn main() {
    eprintln!("Cloud backend benchmarks require 'gcs' or 's3' feature");
    eprintln!("Run with: cargo bench --features gcs --bench cloud_backend_benchmarks");
}
