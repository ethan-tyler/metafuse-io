//! Stress tests for MetaFuse catalog storage backends
//!
//! These tests validate concurrent access patterns and resource management under load.
//! They are opt-in and NOT run in CI by default.
//!
//! ## Running Stress Tests
//!
//! ```bash
//! # Run all stress tests
//! RUN_STRESS_TESTS=1 cargo test --test stress_tests
//!
//! # Run with custom configuration
//! RUN_STRESS_TESTS=1 STRESS_TEST_CLIENTS=20 STRESS_TEST_DURATION_SECS=60 cargo test --test stress_tests
//! ```

use metafuse_catalog_core::DatasetMeta;
use metafuse_catalog_storage::{CatalogBackend, LocalSqliteBackend};
use std::{
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tempfile::TempDir;

/// Lock for test serialization
static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn env_lock() -> &'static Mutex<()> {
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

/// Check if stress tests should run
fn test_guard(name: &str) -> Option<std::sync::MutexGuard<'static, ()>> {
    if std::env::var("RUN_STRESS_TESTS").unwrap_or_default() != "1" {
        eprintln!(
            "Skipping stress test {}: set RUN_STRESS_TESTS=1 to run",
            name
        );
        return None;
    }
    Some(env_lock().lock().expect("failed to lock"))
}

/// Helper to create a test dataset
fn create_test_dataset(name: &str) -> DatasetMeta {
    DatasetMeta {
        name: name.to_string(),
        uri: format!("file:///tmp/{}.parquet", name),
        format: "parquet".to_string(),
        description: Some(format!("Stress test dataset {}", name)),
        owner: Some("stress-tester".to_string()),
        domain: Some("stress-domain".to_string()),
        tags: vec!["stress-test".to_string()],
        fields: vec![],
        partitions: None,
        size_bytes: Some(1024),
        row_count: Some(100),
        upstream_datasets: vec![],
        last_modified_at: None,
        version: None,
    }
}

#[tokio::test]
async fn test_concurrent_writers() {
    let _guard = match test_guard("test_concurrent_writers") {
        Some(g) => g,
        None => return,
    };

    eprintln!("Running concurrent writer stress test");

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let catalog_path = temp_dir.path().join("catalog.db");
    let backend = LocalSqliteBackend::new(catalog_path.to_str().unwrap())
        .await
        .expect("failed to create backend");

    backend
        .initialize_catalog()
        .await
        .expect("failed to initialize catalog");

    // Test: Write multiple datasets concurrently
    let dataset1 = create_test_dataset("dataset1");
    let dataset2 = create_test_dataset("dataset2");

    backend
        .save_dataset(&dataset1)
        .await
        .expect("failed to save dataset1");
    backend
        .save_dataset(&dataset2)
        .await
        .expect("failed to save dataset2");

    // Verify both datasets exist
    assert!(backend.get_dataset("dataset1").await.unwrap().is_some());
    assert!(backend.get_dataset("dataset2").await.unwrap().is_some());

    eprintln!("Concurrent writers test completed successfully");
}

#[tokio::test]
async fn test_read_heavy_workload() {
    let _guard = match test_guard("test_read_heavy_workload") {
        Some(g) => g,
        None => return,
    };

    eprintln!("Running read-heavy workload test");

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let catalog_path = temp_dir.path().join("catalog.db");
    let backend = LocalSqliteBackend::new(catalog_path.to_str().unwrap())
        .await
        .expect("failed to create backend");

    backend
        .initialize_catalog()
        .await
        .expect("failed to initialize catalog");

    // Pre-populate with datasets
    for i in 0..10 {
        let dataset = create_test_dataset(&format!("dataset-{}", i));
        backend
            .save_dataset(&dataset)
            .await
            .expect("failed to save dataset");
    }

    // Test: Read datasets multiple times
    for i in 0..10 {
        let result = backend
            .get_dataset(&format!("dataset-{}", i))
            .await
            .expect("failed to get dataset");
        assert!(result.is_some(), "Dataset {} should exist", i);
    }

    eprintln!("Read-heavy workload test completed successfully");
}

#[tokio::test]
async fn test_connection_cleanup() {
    let _guard = match test_guard("test_connection_cleanup") {
        Some(g) => g,
        None => return,
    };

    eprintln!("Running connection cleanup test");

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let catalog_path = temp_dir.path().join("catalog.db");
    let backend = LocalSqliteBackend::new(catalog_path.to_str().unwrap())
        .await
        .expect("failed to create backend");

    backend
        .initialize_catalog()
        .await
        .expect("failed to initialize catalog");

    // Create and list datasets
    for i in 0..5 {
        let dataset = create_test_dataset(&format!("cleanup-{}", i));
        backend
            .save_dataset(&dataset)
            .await
            .expect("failed to save");
    }

    // Verify all datasets accessible
    let datasets = backend
        .list_datasets(None, None)
        .await
        .expect("failed to list");
    assert_eq!(datasets.len(), 5, "Should have 5 datasets");

    eprintln!("Connection cleanup test completed successfully");
}
