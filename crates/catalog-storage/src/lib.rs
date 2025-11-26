//! MetaFuse Catalog Storage
//!
//! Storage backend abstraction for the MetaFuse catalog.
//! Supports local SQLite with future extensions for GCS/S3.

use metafuse_catalog_core::{init_sqlite_schema, CatalogError, Result};
use rusqlite::Connection;
use std::fmt;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
#[cfg(any(feature = "gcs", feature = "s3"))]
use tempfile::NamedTempFile;

// Cache module for cloud backends
#[cfg(any(feature = "gcs", feature = "s3"))]
mod cache;
#[cfg(any(feature = "gcs", feature = "s3"))]
use bytes::Bytes;
#[cfg(any(feature = "gcs", feature = "s3"))]
use cache::{CatalogCache, HeadCheckBackend};

/// Convenience alias for trait objects.
pub type DynCatalogBackend = dyn CatalogBackend;

/// Versioning metadata for optimistic concurrency checks on object storage.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "gcs", feature = "s3"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ObjectVersion {
    /// Generation (GCS) or similar monotonic version identifier.
    pub generation: Option<String>,
    /// ETag (S3) or checksum token.
    pub etag: Option<String>,
}

/// Information about a downloaded catalog file.
#[derive(Debug, Clone)]
pub struct CatalogDownload {
    /// Local filesystem path to the downloaded (or existing) SQLite file.
    pub path: PathBuf,
    /// Catalog version from catalog_meta table for optimistic concurrency
    pub catalog_version: i64,
    /// Optional remote version metadata (generation/ETag) for cloud backends
    pub remote_version: Option<ObjectVersion>,
}

/// Backend abstraction for catalog storage (async)
///
/// Implementations handle different storage mechanisms:
/// - Local filesystem (SQLite file)
/// - GCS (SQLite on Google Cloud Storage)
/// - S3 (SQLite on AWS S3)
///
/// # Safety
///
/// **CRITICAL**: Never hold `rusqlite::Connection` across `.await` points!
/// rusqlite::Connection is !Send and will cause compilation errors.
///
/// Always use `tokio::task::spawn_blocking` for SQLite operations.
///
/// # Manual Async Trait
///
/// This trait uses manual async implementation (`Pin<Box<dyn Future>>`)
/// instead of async-trait crate for zero-cost abstraction and explicit
/// Send bounds.
pub trait CatalogBackend: Send + Sync {
    /// Download the catalog to a local file and return its path plus version metadata.
    ///
    /// Local backends can simply return the existing path; cloud backends should
    /// download to a temporary location and capture generation/etag for later upload.
    fn download(&self) -> Pin<Box<dyn Future<Output = Result<CatalogDownload>> + Send + '_>>;

    /// Upload a modified catalog file back to remote storage with optimistic locking.
    ///
    /// Cloud backends should use `version` preconditions (generation/etag) to avoid lost updates.
    /// Local backends can replace the on-disk file or simply no-op if paths match.
    fn upload<'a>(
        &'a self,
        download: &'a CatalogDownload,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    /// Get a connection to the catalog database
    ///
    /// For local backends, this opens a direct connection.
    /// For cloud backends, this downloads the catalog file,
    /// opens it locally, and tracks the version for optimistic concurrency.
    ///
    /// IMPORTANT: Use connection immediately, do not hold across await points
    fn get_connection(&self) -> Pin<Box<dyn Future<Output = Result<Connection>> + Send + '_>>;

    /// Check if the catalog exists
    fn exists(&self) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>>;

    /// Initialize a new catalog (create the database file)
    fn initialize(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

/// Parsed representation of a catalog URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogLocation {
    Local(PathBuf),
    Gcs {
        bucket: String,
        object: String,
    },
    S3 {
        bucket: String,
        key: String,
        region: Option<String>,
    },
}

impl fmt::Display for CatalogLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CatalogLocation::Local(path) => write!(f, "file://{}", path.display()),
            CatalogLocation::Gcs { bucket, object } => write!(f, "gs://{}/{}", bucket, object),
            CatalogLocation::S3 {
                bucket,
                key,
                region,
            } => {
                if let Some(region) = region {
                    write!(f, "s3://{}/{}?region={}", bucket, key, region)
                } else {
                    write!(f, "s3://{}/{}", bucket, key)
                }
            }
        }
    }
}

/// Parse a catalog URI into a structured location.
pub fn parse_catalog_uri(uri: &str) -> Result<CatalogLocation> {
    if let Some(rest) = uri.strip_prefix("gs://") {
        let mut parts = rest.splitn(2, '/');
        let bucket = parts
            .next()
            .ok_or_else(|| CatalogError::Other("Missing bucket in gs:// uri".into()))?;
        let object = parts
            .next()
            .ok_or_else(|| CatalogError::Other("Missing object/key in gs:// uri".into()))?;
        return Ok(CatalogLocation::Gcs {
            bucket: bucket.to_string(),
            object: object.to_string(),
        });
    }

    if let Some(rest) = uri.strip_prefix("s3://") {
        let mut parts = rest.splitn(2, '/');
        let bucket = parts
            .next()
            .ok_or_else(|| CatalogError::Other("Missing bucket in s3:// uri".into()))?;
        let key_with_region = parts
            .next()
            .ok_or_else(|| CatalogError::Other("Missing object/key in s3:// uri".into()))?;

        // Optional region as query parameter: s3://bucket/key?region=us-east-1
        let mut key_parts = key_with_region.splitn(2, '?');
        let key = key_parts
            .next()
            .ok_or_else(|| CatalogError::Other("Missing key in s3:// uri".into()))?;
        let region = key_parts
            .next()
            .and_then(|q| q.strip_prefix("region=").map(|r| r.to_string()));

        return Ok(CatalogLocation::S3 {
            bucket: bucket.to_string(),
            key: key.to_string(),
            region,
        });
    }

    // file:// prefix or raw path
    let path = uri
        .strip_prefix("file://")
        .map(|p| p.to_string())
        .unwrap_or_else(|| uri.to_string());

    // Validate file paths for security issues (path traversal, null bytes)
    // Only validate if file:// prefix was present
    if uri.starts_with("file://") {
        metafuse_catalog_core::validation::validate_file_uri_path(&path)?;
    }

    Ok(CatalogLocation::Local(PathBuf::from(path)))
}

/// Build a backend from a catalog URI.
pub fn backend_from_uri(uri: &str) -> Result<Box<dyn CatalogBackend>> {
    match parse_catalog_uri(uri)? {
        CatalogLocation::Local(path) => Ok(Box::new(LocalSqliteBackend::new(path))),
        CatalogLocation::Gcs { bucket, object } => {
            #[cfg(feature = "gcs")]
            {
                Ok(Box::new(GcsBackend::new(bucket, object)?))
            }
            #[cfg(not(feature = "gcs"))]
            {
                let _ = (bucket, object);
                Err(CatalogError::Other(
                    "GCS backend requires the 'gcs' feature. Rebuild with --features gcs".into(),
                ))
            }
        }
        CatalogLocation::S3 {
            bucket,
            key,
            region,
        } => {
            #[cfg(feature = "s3")]
            {
                Ok(Box::new(S3Backend::new(
                    bucket,
                    key,
                    region.unwrap_or_default(),
                )?))
            }
            #[cfg(not(feature = "s3"))]
            {
                let _ = (bucket, key, region);
                Err(CatalogError::Other(
                    "S3 backend requires the 's3' feature. Rebuild with --features s3".into(),
                ))
            }
        }
    }
}

/// Local filesystem SQLite backend
///
/// Stores the catalog as a SQLite file on the local filesystem.
/// This is the primary backend for MVP and local development.
#[derive(Clone, Debug)]
pub struct LocalSqliteBackend {
    /// Path to the SQLite database file
    path: PathBuf,
}

impl LocalSqliteBackend {
    /// Create a new local SQLite backend
    ///
    /// # Arguments
    /// * `path` - Path to the SQLite database file
    ///
    /// # Example
    /// ```no_run
    /// use metafuse_catalog_storage::LocalSqliteBackend;
    ///
    /// let backend = LocalSqliteBackend::new("catalog.db");
    /// ```
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Get the path to the database file
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl CatalogBackend for LocalSqliteBackend {
    fn download(&self) -> Pin<Box<dyn Future<Output = Result<CatalogDownload>> + Send + '_>> {
        let path = self.path.clone();
        Box::pin(async move {
            // All SQLite operations in spawn_blocking
            tokio::task::spawn_blocking(move || {
                // Open connection to read current version
                let conn = Connection::open(&path)?;
                conn.execute_batch("PRAGMA foreign_keys = ON;")?;
                init_sqlite_schema(&conn)?;

                // Read current catalog version
                let catalog_version = metafuse_catalog_core::get_catalog_version(&conn)?;

                Ok(CatalogDownload {
                    path,
                    catalog_version,
                    remote_version: None, // Local backend has no remote versioning
                })
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
        })
    }

    fn upload<'a>(
        &'a self,
        download: &'a CatalogDownload,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let self_path = self.path.clone();
        let download_path = download.path.clone();
        Box::pin(async move {
            // File I/O in spawn_blocking (though fast, keeping pattern consistent)
            tokio::task::spawn_blocking(move || {
                // For local mode, if the download path differs, copy back; otherwise no-op.
                if download_path != self_path {
                    fs::copy(&download_path, &self_path).map_err(|e| {
                        CatalogError::Other(format!("Failed to copy catalog file: {}", e))
                    })?;
                }
                Ok(())
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
        })
    }

    fn get_connection(&self) -> Pin<Box<dyn Future<Output = Result<Connection>> + Send + '_>> {
        let path = self.path.clone();
        Box::pin(async move {
            // All SQLite operations in spawn_blocking
            tokio::task::spawn_blocking(move || {
                let conn = Connection::open(&path)?;

                // Enable foreign key constraints
                conn.execute_batch("PRAGMA foreign_keys = ON;")?;

                // Initialize schema if needed
                init_sqlite_schema(&conn)?;

                Ok(conn)
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
        })
    }

    fn exists(&self) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        let path = self.path.clone();
        Box::pin(async move {
            // File system check (fast, but keeping pattern for consistency)
            Ok(path.exists())
        })
    }

    fn initialize(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let path = self.path.clone();
        Box::pin(async move {
            // Check existence
            if path.exists() {
                return Err(CatalogError::Other(format!(
                    "Catalog already exists at {:?}",
                    path
                )));
            }

            // SQLite operations in spawn_blocking
            tokio::task::spawn_blocking(move || {
                let conn = Connection::open(&path)?;
                conn.execute_batch("PRAGMA foreign_keys = ON;")?;
                init_sqlite_schema(&conn)?;

                Ok(())
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
        })
    }
}

/// GCS backend for catalog storage
///
/// Implements the SQLite-on-object-storage pattern:
/// 1. Download catalog.db from GCS bucket to local temp file
/// 2. Open local SQLite connection
/// 3. Perform operations
/// 4. Upload back to GCS with generation-based optimistic concurrency
///
/// ## Authentication
///
/// Uses Application Default Credentials (ADC) in this order:
/// 1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable
/// 2. Workload Identity (for GKE)
/// 3. Compute Engine metadata server
/// 4. gcloud CLI credentials (development)
///
/// ## Concurrency Control
///
/// Uses GCS generation numbers for optimistic locking:
/// - Download captures current generation
/// - Upload uses `if-generation-match` precondition
/// - Returns `ConflictError` on 412 Precondition Failed
#[cfg(feature = "gcs")]
pub struct GcsBackend {
    store: std::sync::Arc<dyn object_store::ObjectStore>,
    object_path: object_store::path::Path,
    cache: Option<CatalogCache>,
}

#[cfg(feature = "gcs")]
impl GcsBackend {
    /// Create a new GCS backend
    ///
    /// # Arguments
    /// * `bucket` - GCS bucket name
    /// * `object` - Object path within the bucket
    ///
    /// # Example
    /// ```no_run
    /// use metafuse_catalog_storage::GcsBackend;
    ///
    /// let backend = GcsBackend::new("my-bucket", "catalogs/prod.db");
    /// ```
    pub fn new(bucket: impl Into<String>, object: impl Into<String>) -> Result<Self> {
        use object_store::gcp::GoogleCloudStorageBuilder;

        let bucket = bucket.into();
        let object_path = object.into();

        // Check if using emulator (skip authentication)
        let emulator_host = std::env::var("STORAGE_EMULATOR_HOST").ok();

        // Build GCS client
        let store = if let Some(ref host) = emulator_host {
            // Emulator mode: use a fake service account key with gcs_base_url pointing to emulator
            // and disable_oauth=true to skip authentication. object_store supports these custom
            // fields in the service account JSON to configure the endpoint.
            tracing::debug!(emulator_host = %host, "Using GCS emulator with custom base URL");

            let fake_key = format!(
                r#"{{
                    "gcs_base_url": "{}",
                    "disable_oauth": true,
                    "client_email": "test@test-project.iam.gserviceaccount.com",
                    "private_key_id": "1",
                    "private_key": "not-used",
                    "type": "service_account",
                    "project_id": "test-project"
                }}"#,
                host
            );

            GoogleCloudStorageBuilder::new()
                .with_bucket_name(&bucket)
                .with_service_account_key(&fake_key)
                .build()
                .map_err(|e| {
                    CatalogError::Other(format!("Failed to create GCS client for emulator: {}", e))
                })?
        } else {
            // Production mode: use Application Default Credentials
            GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(&bucket)
                .build()
                .map_err(|e| {
                    CatalogError::Other(format!(
                        "Failed to create GCS client. Check GOOGLE_APPLICATION_CREDENTIALS: {}",
                        e
                    ))
                })?
        };

        // Initialize cache (optional based on env config)
        let cache = CatalogCache::from_env().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to initialize cache, proceeding without caching");
            None
        });

        Ok(Self {
            store: std::sync::Arc::new(store),
            object_path: object_store::path::Path::from(object_path),
            cache,
        })
    }
}

#[cfg(feature = "gcs")]
impl CatalogBackend for GcsBackend {
    fn download(&self) -> Pin<Box<dyn Future<Output = Result<CatalogDownload>> + Send + '_>> {
        Box::pin(async move {
            // Check cache first
            let uri = format!("gs://{}", self.object_path);
            if let Some(ref cache) = self.cache {
                if let Some(cached) = cache.get(&uri, Some(self)).await? {
                    tracing::debug!(uri = %uri, "Using cached catalog");
                    return Ok(cached);
                }
            }

            // Native async operations (no block_on!)
            // Download object from GCS
            let get_result = self
                .store
                .get(&self.object_path)
                .await
                .map_err(|e| match e {
                    object_store::Error::NotFound { .. } => CatalogError::Other(format!(
                        "Catalog not found at gs://{} (run 'metafuse init' first)",
                        self.object_path
                    )),
                    _ => CatalogError::Other(format!("Failed to download from GCS: {}", e)),
                })?;

            // Extract generation number from metadata (GCS-specific)
            let generation =
                get_result.meta.version.clone().ok_or_else(|| {
                    CatalogError::Other("Missing generation in GCS metadata".into())
                })?;

            tracing::debug!(
                object = %self.object_path,
                generation = %generation,
                "Downloaded catalog from GCS"
            );

            // Create temp file for local operations
            let temp_file = NamedTempFile::new()
                .map_err(|e| CatalogError::Other(format!("Failed to create temp file: {}", e)))?;

            // Download data to temp file
            let data = get_result.bytes().await.map_err(|e| {
                CatalogError::Other(format!("Failed to read GCS object data: {}", e))
            })?;

            std::fs::write(temp_file.path(), &data)
                .map_err(|e| CatalogError::Other(format!("Failed to write temp file: {}", e)))?;

            // SQLite operations in spawn_blocking
            let temp_path = temp_file.path().to_path_buf();
            let catalog_version = tokio::task::spawn_blocking(move || {
                let conn = Connection::open(&temp_path)?;
                conn.execute_batch("PRAGMA foreign_keys = ON;")?;
                init_sqlite_schema(&conn)?;
                metafuse_catalog_core::get_catalog_version(&conn)
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

            // Persist temp file (keep it alive for subsequent operations)
            let temp_path = temp_file
                .into_temp_path()
                .keep()
                .map_err(|e| CatalogError::Other(format!("Failed to persist temp file: {}", e)))?;

            let download = CatalogDownload {
                path: temp_path,
                catalog_version,
                remote_version: Some(ObjectVersion {
                    generation: Some(generation),
                    etag: None,
                }),
            };

            // Cache the downloaded catalog
            if let Some(ref cache) = self.cache {
                if let Err(e) = cache.put(&uri, &download) {
                    tracing::warn!(error = %e, "Failed to cache catalog, continuing");
                }
            }

            Ok(download)
        })
    }

    fn upload<'a>(
        &'a self,
        download: &'a CatalogDownload,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            use object_store::{PutMode, PutOptions, PutPayload};

            // Validate remote version exists
            let remote_version = download.remote_version.as_ref().ok_or_else(|| {
                CatalogError::Other("Missing remote version for GCS upload".into())
            })?;

            let generation = remote_version
                .generation
                .as_ref()
                .ok_or_else(|| CatalogError::Other("Missing generation for GCS upload".into()))?;

            // Read catalog file data once; clone bytes cheaply across retries
            let data = std::fs::read(&download.path)
                .map_err(|e| CatalogError::Other(format!("Failed to read catalog file: {}", e)))?;
            let data = Bytes::from(data);

            const MAX_RETRIES: u32 = 3;
            const BASE_DELAY_MS: u64 = 100;
            let uri = format!("gs://{}", self.object_path);

            for attempt in 0..=MAX_RETRIES {
                // Native async upload (no block_on!)
                use object_store::UpdateVersion;

                let update_version = UpdateVersion {
                    e_tag: None,
                    version: Some(generation.clone()),
                };

                let put_opts = PutOptions {
                    mode: PutMode::Update(update_version),
                    ..Default::default()
                };

                let result = self
                    .store
                    .put_opts(&self.object_path, PutPayload::from(data.clone()), put_opts)
                    .await;

                match result {
                    Ok(_) => {
                        tracing::info!(
                            object = %self.object_path,
                            generation = %generation,
                            "Uploaded catalog to GCS"
                        );
                        if let Some(ref cache) = self.cache {
                            if let Err(e) = cache.invalidate(&uri) {
                                tracing::warn!(error = %e, "Failed to invalidate cache");
                            }
                        }
                        return Ok(());
                    }
                    Err(object_store::Error::Precondition { .. }) => {
                        if let Some(ref cache) = self.cache {
                            let _ = cache.invalidate(&uri);
                        }
                        if attempt < MAX_RETRIES {
                            let delay = BASE_DELAY_MS * 2u64.saturating_pow(attempt);
                            // Async sleep instead of std::thread::sleep
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                            continue;
                        }
                        return Err(CatalogError::ConflictError(format!(
                            "Catalog was modified by another process (expected generation: {}). Retry your operation.",
                            generation
                        )));
                    }
                    Err(e) => {
                        return Err(CatalogError::Other(format!(
                            "Failed to upload to GCS: {}",
                            e
                        )));
                    }
                }
            }

            Err(CatalogError::ConflictError(
                "Exceeded retry attempts for GCS upload".into(),
            ))
        })
    }

    fn get_connection(&self) -> Pin<Box<dyn Future<Output = Result<Connection>> + Send + '_>> {
        Box::pin(async move {
            let download = self.download().await?;

            // SQLite operations in spawn_blocking
            tokio::task::spawn_blocking(move || {
                let conn = Connection::open(&download.path)?;
                conn.execute_batch("PRAGMA foreign_keys = ON;")?;
                init_sqlite_schema(&conn)?;
                Ok(conn)
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
        })
    }

    fn exists(&self) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        Box::pin(async move {
            // Native async HEAD request (no block_on!)
            match self.store.head(&self.object_path).await {
                Ok(_) => Ok(true),
                Err(object_store::Error::NotFound { .. }) => Ok(false),
                Err(e) => Err(CatalogError::Other(format!(
                    "Failed to check GCS object: {}",
                    e
                ))),
            }
        })
    }

    fn initialize(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            if self.exists().await? {
                return Err(CatalogError::Other(format!(
                    "Catalog already exists at gs://{}",
                    self.object_path
                )));
            }

            // Create a new SQLite database in a temp file
            let temp_file = NamedTempFile::new()
                .map_err(|e| CatalogError::Other(format!("Failed to create temp file: {}", e)))?;

            // SQLite operations in spawn_blocking
            let temp_path = temp_file.path().to_path_buf();
            tokio::task::spawn_blocking(move || {
                let conn = Connection::open(&temp_path)?;
                conn.execute_batch("PRAGMA foreign_keys = ON;")?;
                init_sqlite_schema(&conn)?;
                Ok::<_, CatalogError>(())
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

            // Upload the initialized catalog
            let data = std::fs::read(temp_file.path())
                .map_err(|e| CatalogError::Other(format!("Failed to read temp file: {}", e)))?;

            // Native async upload (no block_on!)
            use object_store::PutPayload;

            self.store
                .put(&self.object_path, PutPayload::from(data))
                .await
                .map_err(|e| {
                    CatalogError::Other(format!("Failed to upload initial catalog: {}", e))
                })?;

            tracing::info!(
                object = %self.object_path,
                "Initialized new catalog in GCS"
            );

            Ok(())
        })
    }
}

#[cfg(feature = "gcs")]
impl HeadCheckBackend for GcsBackend {
    fn head_check(
        &self,
        _uri: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ObjectVersion>> + Send + '_>> {
        Box::pin(async move {
            // Native async HEAD request (no block_on!)
            let head_result = self
                .store
                .head(&self.object_path)
                .await
                .map_err(|e| CatalogError::Other(format!("HEAD request failed: {}", e)))?;

            let generation = head_result
                .version
                .ok_or_else(|| CatalogError::Other("Missing generation in HEAD response".into()))?;

            Ok(ObjectVersion {
                generation: Some(generation),
                etag: None,
            })
        })
    }
}

#[cfg(not(feature = "gcs"))]
pub struct GcsBackend;

#[cfg(not(feature = "gcs"))]
impl GcsBackend {
    pub fn new(_bucket: impl Into<String>, _object: impl Into<String>) -> Result<Self> {
        Err(CatalogError::Other(
            "GCS backend requires the 'gcs' feature. Rebuild with --features gcs".to_string(),
        ))
    }
}

/// S3 backend for catalog storage
///
/// Implements the SQLite-on-object-storage pattern for AWS S3:
/// 1. Download catalog.db from S3 bucket to local temp file
/// 2. Open local SQLite connection
/// 3. Perform operations
/// 4. Upload back to S3 with ETag-based optimistic concurrency
///
/// ## Authentication
///
/// Uses AWS credential provider chain in this order:
/// 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
/// 2. Web Identity Token (for EKS IRSA)
/// 3. ECS Task Role (for ECS)
/// 4. EC2 Instance Profile (for EC2)
/// 5. AWS CLI credentials (~/.aws/credentials)
///
/// ## Concurrency Control
///
/// Uses S3 ETags for optimistic locking:
/// - Download captures current ETag
/// - Upload uses `if-match` precondition
/// - Returns `ConflictError` on 412 Precondition Failed
///
/// ## Region Support
///
/// Optionally specify region via URI query parameter:
/// ```text
/// s3://my-bucket/catalog.db?region=us-west-2
/// ```
#[cfg(feature = "s3")]
pub struct S3Backend {
    store: std::sync::Arc<dyn object_store::ObjectStore>,
    object_path: object_store::path::Path,
    cache: Option<CatalogCache>,
}

#[cfg(feature = "s3")]
impl S3Backend {
    /// Create a new S3 backend
    ///
    /// # Arguments
    /// * `bucket` - S3 bucket name
    /// * `key` - Object key within the bucket
    /// * `region` - Optional AWS region (defaults to SDK's configured region)
    ///
    /// # Example
    /// ```no_run
    /// use metafuse_catalog_storage::S3Backend;
    ///
    /// let backend = S3Backend::new("my-bucket", "catalogs/prod.db", "us-east-1");
    /// ```
    pub fn new(
        bucket: impl Into<String>,
        key: impl Into<String>,
        region: impl Into<String>,
    ) -> Result<Self> {
        use object_store::aws::AmazonS3Builder;

        let bucket = bucket.into();
        let object_path = key.into();
        let region = region.into();

        // Build S3 client with AWS credential chain
        let mut builder = AmazonS3Builder::from_env().with_bucket_name(&bucket);

        if !region.is_empty() {
            builder = builder.with_region(&region);
        }

        let store = builder.build().map_err(|e| {
            CatalogError::Other(format!(
                "Failed to create S3 client. Check AWS credentials/region: {}",
                e
            ))
        })?;

        // Initialize cache (optional based on env config)
        let cache = CatalogCache::from_env().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to initialize cache, proceeding without caching");
            None
        });

        Ok(Self {
            store: std::sync::Arc::new(store),
            object_path: object_store::path::Path::from(object_path),
            cache,
        })
    }
}

#[cfg(feature = "s3")]
impl CatalogBackend for S3Backend {
    fn download(&self) -> Pin<Box<dyn Future<Output = Result<CatalogDownload>> + Send + '_>> {
        Box::pin(async move {
            // Check cache first
            let uri = format!("s3://{}", self.object_path);
            if let Some(ref cache) = self.cache {
                if let Some(cached) = cache.get(&uri, Some(self)).await? {
                    tracing::debug!(uri = %uri, "Using cached catalog");
                    return Ok(cached);
                }
            }

            // Native async operations (no block_on!)
            // Download object from S3
            let get_result = self
                .store
                .get(&self.object_path)
                .await
                .map_err(|e| match e {
                    object_store::Error::NotFound { .. } => CatalogError::Other(format!(
                        "Catalog not found at s3://{} (run 'metafuse init' first)",
                        self.object_path
                    )),
                    _ => CatalogError::Other(format!("Failed to download from S3: {}", e)),
                })?;

            // Extract ETag from metadata (S3-specific)
            let etag = get_result
                .meta
                .e_tag
                .clone()
                .ok_or_else(|| CatalogError::Other("Missing ETag in S3 metadata".into()))?;

            tracing::debug!(
                object = %self.object_path,
                etag = %etag,
                "Downloaded catalog from S3"
            );

            // Create temp file for local operations
            let temp_file = NamedTempFile::new()
                .map_err(|e| CatalogError::Other(format!("Failed to create temp file: {}", e)))?;

            // Download data to temp file
            let data = get_result.bytes().await.map_err(|e| {
                CatalogError::Other(format!("Failed to read S3 object data: {}", e))
            })?;

            std::fs::write(temp_file.path(), &data)
                .map_err(|e| CatalogError::Other(format!("Failed to write temp file: {}", e)))?;

            // SQLite operations in spawn_blocking
            let temp_path = temp_file.path().to_path_buf();
            let catalog_version = tokio::task::spawn_blocking(move || {
                let conn = Connection::open(&temp_path)?;
                conn.execute_batch("PRAGMA foreign_keys = ON;")?;
                init_sqlite_schema(&conn)?;
                metafuse_catalog_core::get_catalog_version(&conn)
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

            // Persist temp file (keep it alive for subsequent operations)
            let temp_path = temp_file
                .into_temp_path()
                .keep()
                .map_err(|e| CatalogError::Other(format!("Failed to persist temp file: {}", e)))?;

            let download = CatalogDownload {
                path: temp_path,
                catalog_version,
                remote_version: Some(ObjectVersion {
                    generation: None,
                    etag: Some(etag),
                }),
            };

            // Cache the downloaded catalog
            if let Some(ref cache) = self.cache {
                if let Err(e) = cache.put(&uri, &download) {
                    tracing::warn!(error = %e, "Failed to cache catalog, continuing");
                }
            }

            Ok(download)
        })
    }

    fn upload<'a>(
        &'a self,
        download: &'a CatalogDownload,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            use object_store::{PutMode, PutOptions, PutPayload};

            // Validate remote version exists
            let remote_version = download.remote_version.as_ref().ok_or_else(|| {
                CatalogError::Other("Missing remote version for S3 upload".into())
            })?;

            let etag = remote_version
                .etag
                .as_ref()
                .ok_or_else(|| CatalogError::Other("Missing ETag for S3 upload".into()))?;

            // Read catalog file data once; clone bytes cheaply across retries
            let data = std::fs::read(&download.path)
                .map_err(|e| CatalogError::Other(format!("Failed to read catalog file: {}", e)))?;
            let data = Bytes::from(data);

            const MAX_RETRIES: u32 = 3;
            const BASE_DELAY_MS: u64 = 100;
            let uri = format!("s3://{}", self.object_path);

            for attempt in 0..=MAX_RETRIES {
                // Upload with ETag-based precondition (optimistic locking)
                use object_store::UpdateVersion;

                let update_version = UpdateVersion {
                    e_tag: Some(etag.clone()),
                    version: None,
                };

                let put_opts = PutOptions {
                    mode: PutMode::Update(update_version),
                    ..Default::default()
                };

                let result = self
                    .store
                    .put_opts(&self.object_path, PutPayload::from(data.clone()), put_opts)
                    .await;

                match result {
                    Ok(_) => {
                        tracing::info!(
                            object = %self.object_path,
                            etag = %etag,
                            "Uploaded catalog to S3"
                        );
                        if let Some(ref cache) = self.cache {
                            if let Err(e) = cache.invalidate(&uri) {
                                tracing::warn!(error = %e, "Failed to invalidate cache");
                            }
                        }
                        return Ok(());
                    }
                    Err(object_store::Error::Precondition { .. }) => {
                        if let Some(ref cache) = self.cache {
                            let _ = cache.invalidate(&uri);
                        }
                        if attempt < MAX_RETRIES {
                            let delay = BASE_DELAY_MS * 2u64.saturating_pow(attempt);
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                            continue;
                        }
                        return Err(CatalogError::ConflictError(format!(
                            "Catalog was modified by another process (expected ETag: {}). Retry your operation.",
                            etag
                        )));
                    }
                    Err(e) => {
                        return Err(CatalogError::Other(format!(
                            "Failed to upload to S3: {}",
                            e
                        )));
                    }
                }
            }

            Err(CatalogError::ConflictError(
                "Exceeded retry attempts for S3 upload".into(),
            ))
        })
    }

    fn get_connection(&self) -> Pin<Box<dyn Future<Output = Result<Connection>> + Send + '_>> {
        Box::pin(async move {
            let download = self.download().await?;
            let path = download.path.clone();

            tokio::task::spawn_blocking(move || {
                let conn = Connection::open(&path)?;
                conn.execute_batch("PRAGMA foreign_keys = ON;")?;
                init_sqlite_schema(&conn)?;
                Ok(conn)
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
        })
    }

    fn exists(&self) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        Box::pin(async move {
            // Check if object exists using HEAD request
            match self.store.head(&self.object_path).await {
                Ok(_) => Ok(true),
                Err(object_store::Error::NotFound { .. }) => Ok(false),
                Err(e) => Err(CatalogError::Other(format!(
                    "Failed to check S3 object: {}",
                    e
                ))),
            }
        })
    }

    fn initialize(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            if self.exists().await? {
                return Err(CatalogError::Other(format!(
                    "Catalog already exists at s3://{}",
                    self.object_path
                )));
            }

            // Create a new SQLite database in a temp file
            let temp_file = NamedTempFile::new()
                .map_err(|e| CatalogError::Other(format!("Failed to create temp file: {}", e)))?;

            let temp_path = temp_file.path().to_path_buf();
            tokio::task::spawn_blocking(move || {
                let conn = Connection::open(&temp_path)?;
                conn.execute_batch("PRAGMA foreign_keys = ON;")?;
                init_sqlite_schema(&conn)?;
                drop(conn); // Close connection before uploading
                Ok::<_, CatalogError>(())
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

            // Upload the initialized catalog
            let data = std::fs::read(temp_file.path())
                .map_err(|e| CatalogError::Other(format!("Failed to read temp file: {}", e)))?;

            use object_store::PutPayload;

            self.store
                .put(&self.object_path, PutPayload::from(data))
                .await
                .map_err(|e| {
                    CatalogError::Other(format!("Failed to upload initial catalog: {}", e))
                })?;

            tracing::info!(
                object = %self.object_path,
                "Initialized new catalog in S3"
            );

            Ok(())
        })
    }
}

#[cfg(feature = "s3")]
impl HeadCheckBackend for S3Backend {
    fn head_check(
        &self,
        _uri: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ObjectVersion>> + Send + '_>> {
        Box::pin(async move {
            // Perform HEAD request to get current ETag
            let head_result = self
                .store
                .head(&self.object_path)
                .await
                .map_err(|e| CatalogError::Other(format!("HEAD request failed: {}", e)))?;

            let etag = head_result
                .e_tag
                .ok_or_else(|| CatalogError::Other("Missing ETag in HEAD response".into()))?;

            Ok(ObjectVersion {
                generation: None,
                etag: Some(etag),
            })
        })
    }
}

#[cfg(not(feature = "s3"))]
pub struct S3Backend;

#[cfg(not(feature = "s3"))]
impl S3Backend {
    pub fn new(
        _bucket: impl Into<String>,
        _path: impl Into<String>,
        _region: impl Into<String>,
    ) -> Result<Self> {
        Err(CatalogError::Other(
            "S3 backend requires the 's3' feature. Rebuild with --features s3".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_local_backend_initialize() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Remove the file so we can test initialization
        std::fs::remove_file(path).unwrap();

        let backend = LocalSqliteBackend::new(path);
        assert!(!backend.exists().await.unwrap());

        backend.initialize().await.unwrap();
        assert!(backend.exists().await.unwrap());

        let conn = backend.get_connection().await.unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(tables.contains(&"datasets".to_string()));
    }

    #[tokio::test]
    async fn test_local_backend_double_initialize() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        std::fs::remove_file(path).unwrap();

        let backend = LocalSqliteBackend::new(path);
        backend.initialize().await.unwrap();

        // Second initialize should fail
        assert!(backend.initialize().await.is_err());
    }

    #[tokio::test]
    async fn test_local_backend_connection() {
        let temp_file = NamedTempFile::new().unwrap();
        let backend = LocalSqliteBackend::new(temp_file.path());

        let conn = backend.get_connection().await.unwrap();

        // Test that foreign keys are enabled
        let fk_enabled: i32 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk_enabled, 1);
    }

    #[test]
    fn test_parse_catalog_uri_local() {
        let loc = parse_catalog_uri("/tmp/catalog.db").unwrap();
        assert_eq!(
            loc,
            CatalogLocation::Local(PathBuf::from("/tmp/catalog.db"))
        );

        let loc = parse_catalog_uri("file:///tmp/catalog.db").unwrap();
        assert_eq!(
            loc,
            CatalogLocation::Local(PathBuf::from("/tmp/catalog.db"))
        );
    }

    #[test]
    fn test_parse_catalog_uri_gcs() {
        let loc = parse_catalog_uri("gs://my-bucket/path/to/catalog.db").unwrap();
        assert_eq!(
            loc,
            CatalogLocation::Gcs {
                bucket: "my-bucket".to_string(),
                object: "path/to/catalog.db".to_string()
            }
        );
    }

    #[test]
    fn test_parse_catalog_uri_s3() {
        let loc = parse_catalog_uri("s3://bucket/path/to/catalog.db").unwrap();
        assert_eq!(
            loc,
            CatalogLocation::S3 {
                bucket: "bucket".to_string(),
                key: "path/to/catalog.db".to_string(),
                region: None
            }
        );

        let loc = parse_catalog_uri("s3://bucket/path/to/catalog.db?region=us-east-1").unwrap();
        assert_eq!(
            loc,
            CatalogLocation::S3 {
                bucket: "bucket".to_string(),
                key: "path/to/catalog.db".to_string(),
                region: Some("us-east-1".to_string())
            }
        );
    }

    #[test]
    fn test_parse_catalog_uri_file_valid() {
        // Valid file URIs should work
        let loc = parse_catalog_uri("file://catalog.db").unwrap();
        assert!(matches!(loc, CatalogLocation::Local(_)));

        let loc = parse_catalog_uri("file://data/catalog.db").unwrap();
        assert!(matches!(loc, CatalogLocation::Local(_)));

        // Raw paths (without file:// prefix) should also work
        let loc = parse_catalog_uri("catalog.db").unwrap();
        assert!(matches!(loc, CatalogLocation::Local(_)));
    }

    #[test]
    fn test_parse_catalog_uri_file_traversal_blocked() {
        // Path traversal attacks should be blocked for file:// URIs
        let result = parse_catalog_uri("file://../../../etc/passwd");
        assert!(result.is_err());

        let result = parse_catalog_uri("file://data/../../../etc/passwd");
        assert!(result.is_err());

        // Null bytes should also be blocked
        let result = parse_catalog_uri("file://data\0hidden");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_catalog_uri_raw_path_no_validation() {
        // Raw paths (without file:// prefix) are NOT validated
        // This allows users to use relative paths for development
        let loc = parse_catalog_uri("../data/catalog.db").unwrap();
        assert!(matches!(loc, CatalogLocation::Local(_)));

        let loc = parse_catalog_uri("/absolute/path/catalog.db").unwrap();
        assert!(matches!(loc, CatalogLocation::Local(_)));
    }
}
