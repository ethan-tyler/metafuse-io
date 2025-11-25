//! S3 Backend Integration Tests with MinIO Emulator
//!
//! These tests validate S3 backend behavior using MinIO as a local emulator.
//! Requires Docker and is gated behind the `s3` feature flag.
//!
//! ## Running Tests
//! ```bash
//! RUN_CLOUD_TESTS=1 cargo test --features s3 --test s3_emulator_tests
//! ```
//!
//! ## CI Environment
//! In CI, MinIO is pre-started on port 9000 by the workflow. Tests detect this
//! and use the existing container instead of starting a new one.

#[cfg(all(test, feature = "s3"))]
mod tests {
    use metafuse_catalog_core::CatalogError;
    use metafuse_catalog_storage::{CatalogBackend, S3Backend};
    use std::net::TcpStream;
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;
    use testcontainers::{clients::Cli, core::WaitFor, GenericImage};

    // Serialize tests to avoid env var collisions and emulator port reuse.
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    fn env_lock() -> &'static Mutex<()> {
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    // CI port where MinIO is pre-started by the workflow
    const CI_MINIO_PORT: u16 = 9000;

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
        Some(env_lock().lock().expect("failed to lock test mutex"))
    }

    fn docker_available() -> bool {
        Command::new("docker")
            .arg("info")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if MinIO is already running (CI environment)
    fn ci_minio_available() -> bool {
        TcpStream::connect(("127.0.0.1", CI_MINIO_PORT)).is_ok()
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

    /// Create a test S3 backend with MinIO emulator
    /// In CI, uses the pre-started container on port 9000
    /// Locally, starts a new container via testcontainers
    fn setup_s3_backend<'a>(
        docker: &'a Cli,
        bucket_name: &str,
        object_key: &str,
    ) -> (ContainerWrapper<'a>, S3Backend) {
        let (container, minio_port) = if ci_minio_available() {
            // CI environment: use pre-started container
            println!("Using CI-provided MinIO on port {}", CI_MINIO_PORT);
            (ContainerWrapper::CiStub(CiContainerStub), CI_MINIO_PORT)
        } else {
            // Local environment: start container via testcontainers
            println!("Starting MinIO via testcontainers");
            let minio_image = GenericImage::new("minio/minio", "latest")
                .with_exposed_port(9000)
                .with_env_var("MINIO_ROOT_USER", "minioadmin")
                .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
                .with_wait_for(WaitFor::message_on_stdout("API:"));

            // Pass command arguments via tuple: (image, Vec<String>)
            let args: Vec<String> = vec!["server".to_string(), "/data".to_string()];
            let minio_container = docker.run((minio_image, args));
            let port = minio_container.get_host_port_ipv4(9000);

            // Wait for readiness
            wait_for_emulator_readiness(port, 30).expect("MinIO emulator failed to start");

            (ContainerWrapper::Testcontainers(minio_container), port)
        };

        // Configure AWS SDK to use MinIO
        std::env::set_var("AWS_ACCESS_KEY_ID", "minioadmin");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "minioadmin");
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var(
            "AWS_ENDPOINT_URL",
            format!("http://localhost:{}", minio_port),
        );

        // Disable caching for tests
        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "0");

        // Create backend
        let backend = S3Backend::new(bucket_name, object_key, "us-east-1")
            .expect("Failed to create S3 backend");

        // Create bucket (MinIO starts with no buckets)
        create_bucket_if_not_exists(minio_port, bucket_name);

        (container, backend)
    }

    /// Create bucket using MinIO mc client (faster than aws-cli)
    fn create_bucket_if_not_exists(port: u16, bucket_name: &str) {
        // Use minio/mc which is lighter and faster than amazon/aws-cli
        let _ = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network=host",
                "--entrypoint",
                "/bin/sh",
                "minio/mc",
                "-c",
                &format!(
                    "mc alias set local http://127.0.0.1:{} minioadmin minioadmin && mc mb local/{} 2>/dev/null || true",
                    port, bucket_name
                ),
            ])
            .output();
    }

    #[tokio::test]
    async fn test_s3_initialize_catalog() {
        let _guard = match test_guard("test_s3_initialize_catalog") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", "catalog.db");

        // Initialize should succeed
        assert!(backend.initialize().await.is_ok());

        // Second initialize should fail (already exists)
        assert!(matches!(
            backend.initialize().await,
            Err(CatalogError::Other(_))
        ));

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_exists_check() {
        let _guard = match test_guard("test_s3_exists_check") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", "catalog.db");

        // Should not exist initially
        assert_eq!(backend.exists().await.unwrap(), false);

        // Initialize
        backend.initialize().await.unwrap();

        // Should exist now
        assert_eq!(backend.exists().await.unwrap(), true);

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_upload_download_roundtrip() {
        let _guard = match test_guard("test_s3_upload_download_roundtrip") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        backend.initialize().await.unwrap();

        // Download catalog
        let download = backend.download().await.unwrap();
        assert!(download.path.exists());
        assert_eq!(download.catalog_version, 1);
        assert!(download.remote_version.is_some());

        // Verify ETag is present
        let remote_version = download.remote_version.as_ref().unwrap();
        assert!(remote_version.etag.is_some());

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_not_found_handling() {
        let _guard = match test_guard("test_s3_not_found_handling") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", "nonexistent.db");

        // Download non-existent catalog should fail gracefully
        let result = backend.download().await;
        assert!(result.is_err());

        match result {
            Err(CatalogError::Other(msg)) => {
                assert!(msg.contains("not found") || msg.contains("run 'metafuse init'"));
            }
            _ => panic!("Expected CatalogError::Other for not found"),
        }

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_get_connection() {
        let _guard = match test_guard("test_s3_get_connection") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        backend.initialize().await.unwrap();

        // Get connection should succeed
        let conn = backend.get_connection().await.unwrap();

        // Verify schema is initialized
        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
            .unwrap();
        let count: i32 = stmt.query_row([], |row| row.get(0)).unwrap();
        assert!(count > 0, "Expected tables to be created");

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_concurrent_write_detection() {
        let _guard = match test_guard("test_s3_concurrent_write_detection") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend1) = setup_s3_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        backend1.initialize().await.unwrap();

        // First download
        let download1 = backend1.download().await.unwrap();
        let etag1 = download1
            .remote_version
            .as_ref()
            .unwrap()
            .etag
            .clone()
            .unwrap();

        // Simulate concurrent modification: upload to change ETag
        backend1.upload(&download1).await.unwrap();

        // Second backend with same bucket/object
        let backend2 = S3Backend::new("test-bucket", "catalog.db", "us-east-1")
            .expect("Failed to create backend2");

        // Second download gets new ETag
        let download2 = backend2.download().await.unwrap();
        let etag2 = download2
            .remote_version
            .as_ref()
            .unwrap()
            .etag
            .clone()
            .unwrap();

        // ETags should differ (ETag changes after upload)
        assert_ne!(etag1, etag2, "ETags should differ after upload");

        // Try to upload with stale ETag (download1)
        let result = backend1.upload(&download1).await;

        // Should fail with conflict error (after retries exhausted)
        assert!(result.is_err(), "Expected upload with stale ETag to fail");

        match result {
            Err(CatalogError::ConflictError(msg)) => {
                assert!(
                    msg.contains("modified by another process") || msg.contains("ETag"),
                    "Expected conflict error message, got: {}",
                    msg
                );
            }
            _ => panic!("Expected ConflictError for stale ETag"),
        }

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_cache_disabled() {
        let _guard = match test_guard("test_s3_cache_disabled") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();

        // Explicitly disable cache
        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "0");

        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        backend.initialize().await.unwrap();

        // First download
        let download1 = backend.download().await.unwrap();
        let path1 = download1.path.clone();

        // Second download (cache disabled, should get new temp file)
        let download2 = backend.download().await.unwrap();
        let path2 = download2.path.clone();

        // Paths should be different (no caching)
        assert_ne!(
            path1, path2,
            "Expected different temp files with cache disabled"
        );

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_retry_logic() {
        let _guard = match test_guard("test_s3_retry_logic") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        backend.initialize().await.unwrap();

        // Download to get initial state
        let download = backend.download().await.unwrap();

        // First upload should succeed
        let result = backend.upload(&download).await;
        assert!(result.is_ok(), "First upload should succeed");

        // Second upload with same (now stale) download should trigger retries
        // After 3 retries with exponential backoff, it should fail
        let result = backend.upload(&download).await;
        assert!(
            result.is_err(),
            "Upload with stale version should fail after retries"
        );

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_metadata_preservation() {
        let _guard = match test_guard("test_s3_metadata_preservation") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", "catalog.db");

        // Initialize catalog
        backend.initialize().await.unwrap();

        // Insert fake dataset to verify preservation
        let conn = backend.get_connection().await.unwrap();
        conn.execute(
            "INSERT INTO datasets (name, format, uri, catalog_version) VALUES (?, ?, ?, ?)",
            rusqlite::params!["test_dataset", "parquet", "s3://bucket/data.parquet", 1],
        )
        .unwrap();

        // Download should include the inserted data
        let download = backend.download().await.unwrap();
        let conn2 = rusqlite::Connection::open(&download.path).unwrap();

        let mut stmt = conn2.prepare("SELECT name FROM datasets").unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(names, vec!["test_dataset"]);

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT_URL");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }
}
