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

        // Configure object_store AWS SDK to use MinIO
        // Note: object_store uses AWS_ENDPOINT (not AWS_ENDPOINT_URL)
        // and requires AWS_ALLOW_HTTP=true for non-HTTPS endpoints
        std::env::set_var("AWS_ACCESS_KEY_ID", "minioadmin");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "minioadmin");
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var("AWS_ENDPOINT", format!("http://localhost:{}", minio_port));
        std::env::set_var("AWS_ALLOW_HTTP", "true");

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
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network=host",
                "--entrypoint",
                "/bin/sh",
                "minio/mc:latest",
                "-c",
                &format!(
                    "mc alias set local http://127.0.0.1:{} minioadmin minioadmin && mc mb local/{} 2>/dev/null || true",
                    port, bucket_name
                ),
            ])
            .output();

        match output {
            Ok(o) => {
                if !o.status.success() {
                    eprintln!(
                        "Bucket creation command exited with {}: {}",
                        o.status,
                        String::from_utf8_lossy(&o.stderr)
                    );
                }
            }
            Err(e) => eprintln!("Failed to run bucket creation command: {}", e),
        }
    }

    /// Generate unique object key for each test to avoid conflicts
    fn unique_object_key(test_name: &str) -> String {
        format!("{}-{}.db", test_name, std::process::id())
    }

    #[tokio::test]
    async fn test_s3_initialize_catalog() {
        let _guard = match test_guard("test_s3_initialize_catalog") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let object_key = unique_object_key("init");
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", &object_key);

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
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT");
        std::env::remove_var("AWS_ALLOW_HTTP");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_exists_check() {
        let _guard = match test_guard("test_s3_exists_check") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let object_key = unique_object_key("exists");
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", &object_key);

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
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT");
        std::env::remove_var("AWS_ALLOW_HTTP");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_upload_download_roundtrip() {
        let _guard = match test_guard("test_s3_upload_download_roundtrip") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let object_key = unique_object_key("roundtrip");
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", &object_key);

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

        // Verify ETag is present
        let remote_version = download.remote_version.as_ref().unwrap();
        assert!(remote_version.etag.is_some());

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT");
        std::env::remove_var("AWS_ALLOW_HTTP");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_not_found_handling() {
        let _guard = match test_guard("test_s3_not_found_handling") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let object_key = unique_object_key("notfound");
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", &object_key);

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
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT");
        std::env::remove_var("AWS_ALLOW_HTTP");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_get_connection() {
        let _guard = match test_guard("test_s3_get_connection") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let object_key = unique_object_key("conn");
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", &object_key);

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
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT");
        std::env::remove_var("AWS_ALLOW_HTTP");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_concurrent_write_detection() {
        let _guard = match test_guard("test_s3_concurrent_write_detection") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let object_key = unique_object_key("concurrent");
        let (_container, backend1) = setup_s3_backend(&docker, "test-bucket", &object_key);

        // Initialize catalog
        with_timeout(backend1.initialize(), "backend1.initialize()")
            .await
            .unwrap();

        // First download
        let download1 = with_timeout(backend1.download(), "backend1.download()")
            .await
            .unwrap();
        let etag1 = download1
            .remote_version
            .as_ref()
            .unwrap()
            .etag
            .clone()
            .unwrap();

        // Modify the downloaded DB file so the upload will change the object bytes (and thus ETag)
        // S3/MinIO compute ETag from content - uploading identical bytes produces identical ETag
        {
            let conn_mod = rusqlite::Connection::open(&download1.path).unwrap();
            conn_mod
                .execute(
                    "CREATE TABLE IF NOT EXISTS _test_marker (k TEXT PRIMARY KEY, v TEXT)",
                    [],
                )
                .unwrap();
            conn_mod
                .execute(
                    "INSERT OR REPLACE INTO _test_marker (k, v) VALUES (?1, ?2)",
                    rusqlite::params!["marker", "1"],
                )
                .unwrap();
        }

        // Upload the modified DB to simulate a concurrent writer (this changes the ETag)
        with_timeout(backend1.upload(&download1), "backend1.upload()")
            .await
            .unwrap();

        // Second backend with same bucket/object
        let backend2 = S3Backend::new("test-bucket", &object_key, "us-east-1")
            .expect("Failed to create backend2");

        // Second download gets new ETag
        let download2 = with_timeout(backend2.download(), "backend2.download()")
            .await
            .unwrap();
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
        let result = with_timeout(backend1.upload(&download1), "backend1.upload() stale").await;

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
        std::env::remove_var("AWS_ENDPOINT");
        std::env::remove_var("AWS_ALLOW_HTTP");
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

        let object_key = unique_object_key("cache");
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", &object_key);

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
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT");
        std::env::remove_var("AWS_ALLOW_HTTP");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_retry_logic() {
        let _guard = match test_guard("test_s3_retry_logic") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let object_key = unique_object_key("retry");
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", &object_key);

        // Initialize catalog
        with_timeout(backend.initialize(), "backend.initialize()")
            .await
            .unwrap();

        // Download to get initial state
        let download = with_timeout(backend.download(), "backend.download()")
            .await
            .unwrap();

        // Modify the download so upload actually changes the content
        {
            let conn = rusqlite::Connection::open(&download.path).unwrap();
            conn.execute(
                "CREATE TABLE IF NOT EXISTS _retry_marker (k TEXT PRIMARY KEY, v TEXT)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO _retry_marker (k, v) VALUES (?1, ?2)",
                rusqlite::params!["first", "1"],
            )
            .unwrap();
        }

        // First upload should succeed
        let result = with_timeout(backend.upload(&download), "backend.upload()").await;
        assert!(result.is_ok(), "First upload should succeed");

        // Simulate an external concurrent modification to make `download` stale:
        // Download current remote, modify it, upload it (this changes ETag on server)
        let external = with_timeout(backend.download(), "backend.download() external")
            .await
            .unwrap();
        {
            let conn_ext = rusqlite::Connection::open(&external.path).unwrap();
            conn_ext
                .execute(
                    "CREATE TABLE IF NOT EXISTS _ext_marker (k TEXT PRIMARY KEY, v TEXT)",
                    [],
                )
                .unwrap();
            conn_ext
                .execute(
                    "INSERT OR REPLACE INTO _ext_marker (k, v) VALUES (?1, ?2)",
                    rusqlite::params!["ext", "1"],
                )
                .unwrap();
        }
        with_timeout(backend.upload(&external), "backend.upload() external")
            .await
            .expect("external upload should succeed");

        // Now attempt the stale upload (original `download`) which should trigger retries and fail
        let result = with_timeout(backend.upload(&download), "backend.upload() stale").await;
        assert!(
            result.is_err(),
            "Upload with stale version should fail after retries"
        );

        // Cleanup
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT");
        std::env::remove_var("AWS_ALLOW_HTTP");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[tokio::test]
    async fn test_s3_metadata_preservation() {
        let _guard = match test_guard("test_s3_metadata_preservation") {
            Some(g) => g,
            None => return,
        };
        let docker = Cli::default();
        let object_key = unique_object_key("metadata");
        let (_container, backend) = setup_s3_backend(&docker, "test-bucket", &object_key);

        // Initialize catalog
        with_timeout(backend.initialize(), "backend.initialize()")
            .await
            .unwrap();

        // Download the current remote DB, modify it locally, then upload
        // Note: get_connection() returns a local temp file - changes don't auto-sync to S3
        let download = with_timeout(backend.download(), "backend.download()")
            .await
            .unwrap();

        // Modify the downloaded DB to insert the fake dataset
        {
            let conn = rusqlite::Connection::open(&download.path).unwrap();
            conn.execute(
                "INSERT INTO datasets (name, path, format, created_at, last_updated) VALUES (?, ?, ?, datetime('now'), datetime('now'))",
                rusqlite::params!["test_dataset", "s3://bucket/data.parquet", "parquet"],
            )
            .unwrap();
        }

        // Upload the modified DB so the remote object contains the inserted row
        with_timeout(backend.upload(&download), "backend.upload()")
            .await
            .unwrap();

        // Now download again and verify the inserted data is preserved
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
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_ENDPOINT");
        std::env::remove_var("AWS_ALLOW_HTTP");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }
}
