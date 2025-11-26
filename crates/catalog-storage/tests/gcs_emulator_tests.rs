//! GCS Backend Integration Tests with fake-gcs-server Emulator
//!
//! These tests validate GCS backend behavior using a local emulator.
//! Requires Docker and is gated behind the `gcs` feature flag.
//!
//! ## ⚠️ CURRENTLY DISABLED
//!
//! These tests are currently marked as `#[ignore]` due to an incompatibility between
//! the `object_store` crate's GCS implementation and `fake-gcs-server`:
//!
//! - `object_store` uses XML API PUT for uploads (`PUT /<bucket>/<object>`)
//! - `fake-gcs-server` only supports JSON API for uploads
//! - This results in 405 Method Not Allowed errors
//!
//! **Tracking Issues:**
//! - fake-gcs-server XML API support: <https://github.com/fsouza/fake-gcs-server/issues/331>
//! - arrow-rs object_store API consistency: <https://github.com/apache/arrow-rs-object-store/issues/167>
//!
//! Once fake-gcs-server merges XML API support (PR #1164), these tests can be re-enabled.
//!
//! ## Running Tests (when enabled)
//! ```bash
//! RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests
//! ```
//!
//! ## CI Environment
//! In CI, fake-gcs-server is pre-started on port 4443 by the workflow. Tests detect this
//! and use the existing container instead of starting a new one.

#[cfg(all(test, feature = "gcs"))]
mod tests {
    use metafuse_catalog_core::CatalogError;
    use metafuse_catalog_storage::{CatalogBackend, GcsBackend};
    use std::net::TcpStream;
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;
    use testcontainers::{clients::Cli, core::WaitFor, GenericImage, RunnableImage};
    use tokio::time::timeout;

    /// Default timeout for async operations to prevent indefinite hangs
    const OP_TIMEOUT: Duration = Duration::from_secs(60);

    /// Wrap an async operation with a timeout to prevent indefinite hangs in CI
    async fn with_timeout<T, F>(fut: F, ctx: &str) -> T
    where
        F: std::future::Future<Output = T>,
    {
        match timeout(OP_TIMEOUT, fut).await {
            Ok(v) => v,
            Err(_) => panic!("timed out after {:?} while {}", OP_TIMEOUT, ctx),
        }
    }

    // Serialize tests to avoid env var collisions and emulator port reuse.
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    fn env_lock() -> &'static Mutex<()> {
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    // CI port where fake-gcs-server is pre-started by the workflow
    const CI_GCS_PORT: u16 = 4443;

    /// Guard to optionally skip tests when cloud tests are disabled or Docker is unavailable.
    fn test_guard(name: &str) -> Option<std::sync::MutexGuard<'static, ()>> {
        if std::env::var("RUN_CLOUD_TESTS").unwrap_or_default() != "1" {
            eprintln!("skipping {name}: set RUN_CLOUD_TESTS=1 to run cloud emulator tests");
            return None;
        }
        if !docker_available() {
            eprintln!("skipping {name}: Docker not available");
            return None;
        }
        // Use unwrap_or_else to recover from poisoned mutex (if a previous test panicked)
        Some(env_lock().lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn docker_available() -> bool {
        Command::new("docker")
            .arg("info")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if fake-gcs-server is already running (CI environment)
    fn ci_gcs_available() -> bool {
        TcpStream::connect(("127.0.0.1", CI_GCS_PORT)).is_ok()
    }

    /// Wait for emulator to be ready
    fn wait_for_emulator_readiness(port: u16, max_attempts: u32) -> Result<(), String> {
        for attempt in 0..max_attempts {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                println!(
                    "Emulator ready on port {} after {} attempts",
                    port,
                    attempt + 1
                );
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Err(format!(
            "Emulator failed to start on port {} after {} seconds",
            port, max_attempts
        ))
    }

    /// Dummy container wrapper for CI mode (no-op Drop)
    struct CiContainerStub;
    impl Drop for CiContainerStub {
        fn drop(&mut self) {
            // No cleanup needed - CI manages the container
        }
    }

    /// Container wrapper that can be either a testcontainers container or CI stub
    #[allow(dead_code)] // Container field is used for Drop behavior
    enum ContainerWrapper<'a> {
        Testcontainers(testcontainers::Container<'a, GenericImage>),
        CiStub(CiContainerStub),
    }

    impl Drop for ContainerWrapper<'_> {
        fn drop(&mut self) {
            // Drop is handled by inner types
        }
    }

    /// Create the test bucket via GCS JSON API
    fn create_gcs_bucket(port: u16, bucket_name: &str) -> Result<(), String> {
        let url = format!("http://localhost:{}/storage/v1/b", port);
        let body = format!(r#"{{"name":"{}"}}"#, bucket_name);

        let output = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "--data-binary",
                &body,
                "-H",
                "Content-Type: application/json",
                &url,
            ])
            .output()
            .map_err(|e| format!("Failed to run curl: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to create bucket: {}", stderr));
        }

        println!(
            "Created bucket '{}': {}",
            bucket_name,
            String::from_utf8_lossy(&output.stdout)
        );
        Ok(())
    }

    /// Create a test GCS backend with emulator
    /// In CI, uses the pre-started container on port 4443
    /// Locally, starts a new container via testcontainers
    fn setup_gcs_backend<'a>(
        docker: &'a Cli,
        bucket_name: &str,
        object_name: &str,
    ) -> (ContainerWrapper<'a>, GcsBackend) {
        let (container, gcs_port) = if ci_gcs_available() {
            // CI environment: use pre-started container
            println!("Using CI-provided fake-gcs-server on port {}", CI_GCS_PORT);
            (ContainerWrapper::CiStub(CiContainerStub), CI_GCS_PORT)
        } else {
            // Local environment: start container via testcontainers
            // Use tustvold/fake-gcs-server which has better object_store compatibility
            // (supports path-style URLs used by object_store)
            println!("Starting fake-gcs-server via testcontainers");

            let gcs_image = GenericImage::new("tustvold/fake-gcs-server", "latest")
                .with_exposed_port(4443)
                .with_wait_for(WaitFor::message_on_stderr("server started at"));

            // Pass command line arguments: -scheme http -port 4443
            let args: Vec<String> = vec![
                "-scheme".to_string(),
                "http".to_string(),
                "-port".to_string(),
                "4443".to_string(),
            ];
            let runnable: RunnableImage<GenericImage> = (gcs_image, args).into();

            let gcs_container = docker.run(runnable);
            let port = gcs_container.get_host_port_ipv4(4443);

            // Wait for readiness
            wait_for_emulator_readiness(port, 30).expect("GCS emulator failed to start");

            (ContainerWrapper::Testcontainers(gcs_container), port)
        };

        // Create the test bucket via JSON API
        if let Err(e) = create_gcs_bucket(gcs_port, bucket_name) {
            eprintln!(
                "Warning: Failed to create bucket (may already exist): {}",
                e
            );
        }

        // Configure object_store to use emulator
        std::env::set_var(
            "STORAGE_EMULATOR_HOST",
            format!("http://localhost:{}", gcs_port),
        );

        // Disable caching for tests
        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "0");

        // Create backend
        let backend =
            GcsBackend::new(bucket_name, object_name).expect("Failed to create GCS backend");

        (container, backend)
    }

    #[tokio::test]
    #[ignore = "fake-gcs-server doesn't support XML API PUT (see module docs)"]
    async fn test_gcs_initialize_catalog() {
        let _guard = match test_guard("test_gcs_initialize_catalog") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_gcs_backend(&docker, "test-bucket", "catalog.db");

        // Initialize should succeed
        assert!(with_timeout(backend.initialize(), "backend.initialize()")
            .await
            .is_ok());

        // Second initialize should fail (already exists)
        assert!(matches!(
            with_timeout(backend.initialize(), "backend.initialize() second").await,
            Err(CatalogError::Other(_))
        ));

        // Cleanup
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    #[ignore = "fake-gcs-server doesn't support XML API PUT (see module docs)"]
    async fn test_gcs_exists_check() {
        let _guard = match test_guard("test_gcs_exists_check") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_gcs_backend(&docker, "test-bucket", "catalog.db");

        // Should not exist initially
        assert_eq!(
            with_timeout(backend.exists(), "backend.exists()")
                .await
                .unwrap(),
            false
        );

        // Initialize
        with_timeout(backend.initialize(), "backend.initialize()")
            .await
            .unwrap();

        // Should exist now
        assert_eq!(
            with_timeout(backend.exists(), "backend.exists() after init")
                .await
                .unwrap(),
            true
        );

        // Cleanup
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    #[ignore = "fake-gcs-server doesn't support XML API PUT (see module docs)"]
    async fn test_gcs_upload_download_roundtrip() {
        let _guard = match test_guard("test_gcs_upload_download_roundtrip") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_gcs_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        with_timeout(backend.initialize(), "backend.initialize()")
            .await
            .unwrap();

        // Download catalog
        let download = with_timeout(backend.download(), "backend.download()")
            .await
            .unwrap();
        assert!(download.path.exists());
        assert_eq!(download.catalog_version, 1);
        assert!(download.remote_version.is_some());

        // Verify generation is present
        let remote_version = download.remote_version.as_ref().unwrap();
        assert!(remote_version.generation.is_some());

        // Cleanup
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    #[ignore = "fake-gcs-server doesn't support XML API PUT (see module docs)"]
    async fn test_gcs_not_found_handling() {
        let _guard = match test_guard("test_gcs_not_found_handling") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_gcs_backend(&docker, "test-bucket", "nonexistent.db");

        // Download non-existent catalog should fail gracefully
        let result = with_timeout(backend.download(), "backend.download() not found").await;
        assert!(result.is_err());

        match result {
            Err(CatalogError::Other(msg)) => {
                assert!(msg.contains("not found") || msg.contains("run 'metafuse init'"));
            }
            _ => panic!("Expected CatalogError::Other for not found"),
        }

        // Cleanup
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    #[ignore = "fake-gcs-server doesn't support XML API PUT (see module docs)"]
    async fn test_gcs_get_connection() {
        let _guard = match test_guard("test_gcs_get_connection") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_gcs_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        with_timeout(backend.initialize(), "backend.initialize()")
            .await
            .unwrap();

        // Get connection should succeed
        let conn = with_timeout(backend.get_connection(), "backend.get_connection()")
            .await
            .unwrap();

        // Verify schema is initialized
        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
            .unwrap();
        let count: i32 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert!(count > 0, "Expected tables to be created");

        // Cleanup
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    #[ignore = "fake-gcs-server doesn't support XML API PUT (see module docs)"]
    async fn test_gcs_concurrent_write_detection() {
        let _guard = match test_guard("test_gcs_concurrent_write_detection") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend1) = setup_gcs_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        with_timeout(backend1.initialize(), "backend1.initialize()")
            .await
            .unwrap();

        // First download
        let download1 = with_timeout(backend1.download(), "backend1.download()")
            .await
            .unwrap();
        let generation1 = download1
            .remote_version
            .as_ref()
            .unwrap()
            .generation
            .clone()
            .unwrap();

        // Modify the downloaded DB to force different bytes (and thus different generation after upload)
        {
            let conn_mod = rusqlite::Connection::open(&download1.path).unwrap();
            let _ = conn_mod.execute(
                "CREATE TABLE IF NOT EXISTS _test_marker (k TEXT PRIMARY KEY, v TEXT);",
                [],
            );
            let _ = conn_mod.execute(
                "INSERT OR REPLACE INTO _test_marker (k, v) VALUES (?1, ?2)",
                rusqlite::params!["marker", "1"],
            );
        }

        // Upload modified DB - this will produce a new generation
        with_timeout(backend1.upload(&download1), "backend1.upload()")
            .await
            .unwrap();

        // Second backend with same bucket/object
        let backend2 =
            GcsBackend::new("test-bucket", "catalog.db").expect("Failed to create backend2");

        // Second download gets new generation
        let download2 = with_timeout(backend2.download(), "backend2.download()")
            .await
            .unwrap();
        let generation2 = download2
            .remote_version
            .as_ref()
            .unwrap()
            .generation
            .clone()
            .unwrap();

        // Generations should differ (generation incremented after upload)
        assert_ne!(
            generation1, generation2,
            "Generations should differ after upload"
        );

        // Try to upload with stale generation (download1)
        let result = with_timeout(backend1.upload(&download1), "backend1.upload() stale").await;

        // Should fail with conflict error (after retries exhausted)
        assert!(
            result.is_err(),
            "Expected upload with stale generation to fail"
        );

        match result {
            Err(CatalogError::ConflictError(msg)) => {
                assert!(
                    msg.contains("modified by another process") || msg.contains("generation"),
                    "Expected conflict error message, got: {}",
                    msg
                );
            }
            _ => panic!("Expected ConflictError for stale generation"),
        }

        // Cleanup
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    #[ignore = "fake-gcs-server doesn't support XML API PUT (see module docs)"]
    async fn test_gcs_cache_disabled() {
        let _guard = match test_guard("test_gcs_cache_disabled") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();

        // Explicitly disable cache
        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "0");

        let (_container, backend) = setup_gcs_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        with_timeout(backend.initialize(), "backend.initialize()")
            .await
            .unwrap();

        // First download
        let download1 = with_timeout(backend.download(), "backend.download() first")
            .await
            .unwrap();
        let path1 = download1.path.clone();

        // Second download (cache disabled, should get new temp file)
        let download2 = with_timeout(backend.download(), "backend.download() second")
            .await
            .unwrap();
        let path2 = download2.path.clone();

        // Paths should be different (no caching)
        assert_ne!(
            path1, path2,
            "Expected different temp files with cache disabled"
        );

        // Cleanup
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    #[ignore = "fake-gcs-server doesn't support XML API PUT (see module docs)"]
    async fn test_gcs_retry_logic() {
        let _guard = match test_guard("test_gcs_retry_logic") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_gcs_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        with_timeout(backend.initialize(), "backend.initialize()")
            .await
            .unwrap();

        // Download to get initial state
        let download = with_timeout(backend.download(), "backend.download()")
            .await
            .unwrap();

        // Modify the downloaded DB to force different bytes
        {
            let conn_mod = rusqlite::Connection::open(&download.path).unwrap();
            let _ = conn_mod.execute(
                "CREATE TABLE IF NOT EXISTS _test_marker (k TEXT PRIMARY KEY, v TEXT);",
                [],
            );
            let _ = conn_mod.execute(
                "INSERT OR REPLACE INTO _test_marker (k, v) VALUES (?1, ?2)",
                rusqlite::params!["marker", "1"],
            );
        }

        // First upload should succeed
        let result = with_timeout(backend.upload(&download), "backend.upload() first").await;
        assert!(result.is_ok(), "First upload should succeed");

        // Simulate external concurrent modification
        let external = with_timeout(backend.download(), "backend.download() external")
            .await
            .unwrap();
        {
            let conn_ext = rusqlite::Connection::open(&external.path).unwrap();
            let _ = conn_ext.execute(
                "CREATE TABLE IF NOT EXISTS _ext_marker (k TEXT PRIMARY KEY, v TEXT);",
                [],
            );
            let _ = conn_ext.execute(
                "INSERT OR REPLACE INTO _ext_marker (k, v) VALUES (?1, ?2)",
                rusqlite::params!["ext", "1"],
            );
        }
        with_timeout(backend.upload(&external), "backend.upload() external")
            .await
            .expect("external upload should succeed");

        // Now the original `download` is stale - upload should fail after retries
        let result = with_timeout(backend.upload(&download), "backend.upload() stale").await;
        assert!(
            result.is_err(),
            "Upload with stale version should fail after retries"
        );

        // Cleanup
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    #[ignore = "fake-gcs-server doesn't support XML API PUT (see module docs)"]
    async fn test_gcs_metadata_preservation() {
        let _guard = match test_guard("test_gcs_metadata_preservation") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_gcs_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        with_timeout(backend.initialize(), "backend.initialize()")
            .await
            .unwrap();

        // Download current remote DB
        let download = with_timeout(backend.download(), "backend.download()")
            .await
            .unwrap();

        // Modify the downloaded DB (insert test data)
        {
            let conn = rusqlite::Connection::open(&download.path).unwrap();
            conn.execute(
                "INSERT INTO datasets (name, path, format, created_at, last_updated) VALUES (?, ?, ?, datetime('now'), datetime('now'))",
                rusqlite::params!["test_dataset", "gs://bucket/data.parquet", "parquet"],
            )
            .unwrap();
        }

        // Upload modified DB to GCS
        with_timeout(backend.upload(&download), "backend.upload()")
            .await
            .unwrap();

        // Download again and verify the inserted data persisted
        let download2 = with_timeout(backend.download(), "backend.download() verify")
            .await
            .unwrap();
        let conn2 = rusqlite::Connection::open(&download2.path).unwrap();

        let mut stmt = conn2.prepare("SELECT name FROM datasets").unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(names, vec!["test_dataset"]);

        // Cleanup
        std::env::remove_var("STORAGE_EMULATOR_HOST");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }
}
