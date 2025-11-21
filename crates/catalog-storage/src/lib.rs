//! MetaFuse Catalog Storage
//!
//! Storage backend abstraction for the MetaFuse catalog.
//! Supports local SQLite with future extensions for GCS/S3.

use metafuse_catalog_core::{init_sqlite_schema, CatalogError, Result};
use rusqlite::Connection;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(any(feature = "gcs", feature = "s3"))]
use tempfile::NamedTempFile;

/// Convenience alias for trait objects.
pub type DynCatalogBackend = dyn CatalogBackend;

/// Versioning metadata for optimistic concurrency checks on object storage.
#[derive(Debug, Clone)]
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

/// Backend abstraction for catalog storage
///
/// Implementations handle different storage mechanisms:
/// - Local filesystem (SQLite file)
/// - GCS (SQLite on Google Cloud Storage)
/// - S3 (SQLite on AWS S3)
pub trait CatalogBackend: Send + Sync {
    /// Download the catalog to a local file and return its path plus version metadata.
    ///
    /// Local backends can simply return the existing path; cloud backends should
    /// download to a temporary location and capture generation/etag for later upload.
    fn download(&self) -> Result<CatalogDownload>;

    /// Upload a modified catalog file back to remote storage with optimistic locking.
    ///
    /// Cloud backends should use `version` preconditions (generation/etag) to avoid lost updates.
    /// Local backends can replace the on-disk file or simply no-op if paths match.
    fn upload(&self, download: &CatalogDownload) -> Result<()>;

    /// Get a connection to the catalog database
    ///
    /// For local backends, this opens a direct connection.
    /// For cloud backends, this downloads the catalog file,
    /// opens it locally, and tracks the version for optimistic concurrency.
    fn get_connection(&self) -> Result<Connection>;

    /// Check if the catalog exists
    fn exists(&self) -> Result<bool>;

    /// Initialize a new catalog (create the database file)
    fn initialize(&self) -> Result<()>;
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

    Ok(CatalogLocation::Local(PathBuf::from(path)))
}

/// Build a backend from a catalog URI.
pub fn backend_from_uri(uri: &str) -> Result<Box<dyn CatalogBackend>> {
    match parse_catalog_uri(uri)? {
        CatalogLocation::Local(path) => Ok(Box::new(LocalSqliteBackend::new(path))),
        CatalogLocation::Gcs { bucket, object } => {
            #[cfg(feature = "gcs")]
            {
                Ok(Box::new(GcsBackend::new(bucket, object)))
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
                )))
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
    /// ```
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
    fn download(&self) -> Result<CatalogDownload> {
        // Open connection to read current version
        let conn = Connection::open(&self.path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        init_sqlite_schema(&conn)?;

        // Read current catalog version
        let catalog_version = metafuse_catalog_core::get_catalog_version(&conn)?;

        Ok(CatalogDownload {
            path: self.path.clone(),
            catalog_version,
            remote_version: None, // Local backend has no remote versioning
        })
    }

    fn upload(&self, download: &CatalogDownload) -> Result<()> {
        // For local mode, if the download path differs, copy back; otherwise no-op.
        if download.path != self.path {
            fs::copy(&download.path, &self.path)
                .map_err(|e| CatalogError::Other(format!("Failed to copy catalog file: {}", e)))?;
        }
        Ok(())
    }

    fn get_connection(&self) -> Result<Connection> {
        let download = self.download()?;
        let conn = Connection::open(&download.path)?;

        // Enable foreign key constraints
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        // Initialize schema if needed
        init_sqlite_schema(&conn)?;

        Ok(conn)
    }

    fn exists(&self) -> Result<bool> {
        Ok(self.path.exists())
    }

    fn initialize(&self) -> Result<()> {
        if self.exists()? {
            return Err(CatalogError::Other(format!(
                "Catalog already exists at {:?}",
                self.path
            )));
        }

        let conn = Connection::open(&self.path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        init_sqlite_schema(&conn)?;

        Ok(())
    }
}

/// GCS backend for catalog storage (future implementation)
///
/// This will implement the SQLite-on-object-storage pattern:
/// 1. Download catalog.db from GCS bucket
/// 2. Open local connection
/// 3. Perform operations
/// 4. Upload back to GCS with generation number check (optimistic concurrency)
///
/// ## Feature Flag (Not Yet Implemented)
///
/// To enable GCS support, add a feature flag to Cargo.toml:
/// ```toml
/// [features]
/// gcs = ["object_store/gcp"]
/// ```
///
/// Real implementation should use the `object_store` crate for unified cloud storage access.
#[allow(dead_code)]
pub struct GcsBackend {
    bucket: String,
    path: String,
}

impl GcsBackend {
    pub fn new(bucket: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            path: path.into(),
        }
    }
}

#[cfg(feature = "gcs")]
impl CatalogBackend for GcsBackend {
    fn download(&self) -> Result<CatalogDownload> {
        let _file = NamedTempFile::new().map_err(|e| {
            CatalogError::Other(format!(
                "Failed to create temp file for GCS download: {}",
                e
            ))
        })?;
        // TODO: Implement download using google-cloud-storage with generation tracking.
        // Example implementation:
        // 1. Create a temp file using NamedTempFile::new()?
        // 2. Download object from GCS bucket to temp file
        // 3. Capture the current generation number from object metadata
        // 4. Return CatalogDownload { path: temp_path, version: Some(ObjectVersion { generation: Some(gen), etag: None }) }
        Err(CatalogError::Other(
            "GCS backend not implemented; enable gcs feature and add download logic".to_string(),
        ))
    }

    fn upload(&self, download: &CatalogDownload) -> Result<()> {
        // TODO: Implement upload with generation precondition checks for optimistic concurrency.
        // Example implementation:
        // 1. Validate catalog_version was incremented (sanity check)
        // 2. Extract generation number from download.remote_version
        // 3. Upload file with if-generation-match precondition set to the captured generation
        // 4. If GCS returns 412 Precondition Failed, return CatalogError::ConflictError
        // 5. If upload succeeds, the generation number is automatically incremented by GCS
        //
        // Pseudocode:
        // let Some(remote_version) = &download.remote_version else {
        //     return Err(CatalogError::Other("Missing remote version for upload".into()));
        // };
        // let Some(generation) = &remote_version.generation else {
        //     return Err(CatalogError::Other("Missing generation for GCS upload".into()));
        // };
        //
        // let request = storage_client.upload()
        //     .bucket(&self.bucket)
        //     .object(&self.path)
        //     .if_generation_match(generation.parse::<i64>()?)
        //     .file(&download.path);
        //
        // match request.send().await {
        //     Ok(_) => Ok(()),
        //     Err(e) if is_precondition_failed(&e) => {
        //         Err(CatalogError::ConflictError(format!(
        //             "Catalog was modified by another process (expected generation: {})",
        //             generation
        //         )))
        //     }
        //     Err(e) => Err(e.into()),
        // }
        let _ = download; // Silence unused warning
        Err(CatalogError::Other(
            "GCS backend not implemented; enable gcs feature and add upload logic".to_string(),
        ))
    }

    fn get_connection(&self) -> Result<Connection> {
        let download = self.download()?;
        let conn = Connection::open(&download.path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(CatalogError::from)?;
        init_sqlite_schema(&conn)?;
        Ok(conn)
    }

    fn exists(&self) -> Result<bool> {
        Err(CatalogError::Other(
            "GCS backend not implemented; enable gcs feature and add exists logic".to_string(),
        ))
    }

    fn initialize(&self) -> Result<()> {
        Err(CatalogError::Other(
            "GCS backend not implemented; enable gcs feature and add initialize logic".to_string(),
        ))
    }
}

#[cfg(not(feature = "gcs"))]
impl CatalogBackend for GcsBackend {
    fn download(&self) -> Result<CatalogDownload> {
        Err(CatalogError::Other(
            "GCS backend requires the 'gcs' feature. Rebuild with --features gcs".to_string(),
        ))
    }

    fn upload(&self, _download: &CatalogDownload) -> Result<()> {
        Err(CatalogError::Other(
            "GCS backend requires the 'gcs' feature. Rebuild with --features gcs".to_string(),
        ))
    }

    fn get_connection(&self) -> Result<Connection> {
        Err(CatalogError::Other(
            "GCS backend requires the 'gcs' feature. Rebuild with --features gcs".to_string(),
        ))
    }

    fn exists(&self) -> Result<bool> {
        Err(CatalogError::Other(
            "GCS backend requires the 'gcs' feature. Rebuild with --features gcs".to_string(),
        ))
    }

    fn initialize(&self) -> Result<()> {
        Err(CatalogError::Other(
            "GCS backend requires the 'gcs' feature. Rebuild with --features gcs".to_string(),
        ))
    }
}

/// S3 backend for catalog storage (future implementation)
///
/// Similar to GCS backend but using AWS S3.
///
/// ## Feature Flag (Not Yet Implemented)
///
/// To enable S3 support, add a feature flag to Cargo.toml:
/// ```toml
/// [features]
/// s3 = ["object_store/aws"]
/// ```
///
/// Real implementation should use the `object_store` crate for unified cloud storage access.
#[allow(dead_code)]
pub struct S3Backend {
    bucket: String,
    path: String,
    region: String,
}

impl S3Backend {
    pub fn new(
        bucket: impl Into<String>,
        path: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            path: path.into(),
            region: region.into(),
        }
    }
}

#[cfg(feature = "s3")]
impl CatalogBackend for S3Backend {
    fn download(&self) -> Result<CatalogDownload> {
        let _file = NamedTempFile::new().map_err(|e| {
            CatalogError::Other(format!("Failed to create temp file for S3 download: {}", e))
        })?;
        // TODO: Implement download using aws-sdk-s3 with etag tracking.
        // Example implementation:
        // 1. Create a temp file using NamedTempFile::new()?
        // 2. Download object from S3 bucket to temp file
        // 3. Capture the current ETag from object metadata
        // 4. Return CatalogDownload { path: temp_path, version: Some(ObjectVersion { generation: None, etag: Some(etag) }) }
        Err(CatalogError::Other(
            "S3 backend not implemented; enable s3 feature and add download logic".to_string(),
        ))
    }

    fn upload(&self, download: &CatalogDownload) -> Result<()> {
        // TODO: Implement upload with ETag precondition checks for optimistic concurrency.
        // Example implementation:
        // 1. Validate catalog_version was incremented (sanity check)
        // 2. Extract ETag from download.remote_version
        // 3. Upload file with if-match precondition set to the captured ETag
        // 4. If S3 returns 412 Precondition Failed, return CatalogError::ConflictError
        // 5. If upload succeeds, S3 generates a new ETag for the updated object
        //
        // Pseudocode:
        // let Some(remote_version) = &download.remote_version else {
        //     return Err(CatalogError::Other("Missing remote version for upload".into()));
        // };
        // let Some(etag) = &remote_version.etag else {
        //     return Err(CatalogError::Other("Missing ETag for S3 upload".into()));
        // };
        //
        // let request = s3_client.put_object()
        //     .bucket(&self.bucket)
        //     .key(&self.path)
        //     .if_match(etag)
        //     .body(ByteStream::from_path(&download.path).await?);
        //
        // match request.send().await {
        //     Ok(_) => Ok(()),
        //     Err(e) if is_precondition_failed(&e) => {
        //         Err(CatalogError::ConflictError(format!(
        //             "Catalog was modified by another process (expected ETag: {})",
        //             etag
        //         )))
        //     }
        //     Err(e) => Err(e.into()),
        // }
        let _ = download; // Silence unused warning
        Err(CatalogError::Other(
            "S3 backend not implemented; enable s3 feature and add upload logic".to_string(),
        ))
    }

    fn get_connection(&self) -> Result<Connection> {
        let download = self.download()?;
        let conn = Connection::open(&download.path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(CatalogError::from)?;
        init_sqlite_schema(&conn)?;
        Ok(conn)
    }

    fn exists(&self) -> Result<bool> {
        Err(CatalogError::Other(
            "S3 backend not implemented; enable s3 feature and add exists logic".to_string(),
        ))
    }

    fn initialize(&self) -> Result<()> {
        Err(CatalogError::Other(
            "S3 backend not implemented; enable s3 feature and add initialize logic".to_string(),
        ))
    }
}

#[cfg(not(feature = "s3"))]
impl CatalogBackend for S3Backend {
    fn download(&self) -> Result<CatalogDownload> {
        Err(CatalogError::Other(
            "S3 backend requires the 's3' feature. Rebuild with --features s3".to_string(),
        ))
    }

    fn upload(&self, _download: &CatalogDownload) -> Result<()> {
        Err(CatalogError::Other(
            "S3 backend requires the 's3' feature. Rebuild with --features s3".to_string(),
        ))
    }

    fn get_connection(&self) -> Result<Connection> {
        Err(CatalogError::Other(
            "S3 backend requires the 's3' feature. Rebuild with --features s3".to_string(),
        ))
    }

    fn exists(&self) -> Result<bool> {
        Err(CatalogError::Other(
            "S3 backend requires the 's3' feature. Rebuild with --features s3".to_string(),
        ))
    }

    fn initialize(&self) -> Result<()> {
        Err(CatalogError::Other(
            "S3 backend requires the 's3' feature. Rebuild with --features s3".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_local_backend_initialize() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Remove the file so we can test initialization
        std::fs::remove_file(path).unwrap();

        let backend = LocalSqliteBackend::new(path);
        assert!(!backend.exists().unwrap());

        backend.initialize().unwrap();
        assert!(backend.exists().unwrap());

        let conn = backend.get_connection().unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(tables.contains(&"datasets".to_string()));
    }

    #[test]
    fn test_local_backend_double_initialize() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        std::fs::remove_file(path).unwrap();

        let backend = LocalSqliteBackend::new(path);
        backend.initialize().unwrap();

        // Second initialize should fail
        assert!(backend.initialize().is_err());
    }

    #[test]
    fn test_local_backend_connection() {
        let temp_file = NamedTempFile::new().unwrap();
        let backend = LocalSqliteBackend::new(temp_file.path());

        let conn = backend.get_connection().unwrap();

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
}
