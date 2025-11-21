//! Caching layer for cloud storage backends
//!
//! Provides optional local file system caching for catalog downloads to reduce
//! cloud API calls and improve performance for read-heavy workloads.
//!
//! ## Configuration
//!
//! Cache behavior is controlled via environment variables:
//! - `METAFUSE_CACHE_TTL_SECS`: Cache time-to-live in seconds (default: 60, 0 to disable)
//! - Cache location: `$XDG_CACHE_HOME/metafuse` or `~/.cache/metafuse` on Unix
//!
//! ## Cache Invalidation
//!
//! - **TTL expiration**: Cache entries older than TTL are considered stale
//! - **Write invalidation**: Cache is cleared after uploads to ensure consistency
//! - **Conflict invalidation**: Cache is cleared when optimistic concurrency conflicts occur

#[cfg(any(feature = "gcs", feature = "s3"))]
use crate::{CatalogDownload, ObjectVersion, Result};
#[cfg(any(feature = "gcs", feature = "s3"))]
use metafuse_catalog_core::CatalogError;
#[cfg(any(feature = "gcs", feature = "s3"))]
use std::collections::hash_map::DefaultHasher;
#[cfg(any(feature = "gcs", feature = "s3"))]
use std::hash::{Hash, Hasher};
#[cfg(any(feature = "gcs", feature = "s3"))]
use std::path::PathBuf;
#[cfg(any(feature = "gcs", feature = "s3"))]
use std::time::{Duration, SystemTime};

/// Cache for cloud-downloaded catalogs
///
/// Reduces cloud API calls by maintaining local copies of catalog files
/// with metadata for version tracking and TTL-based expiration.
#[cfg(any(feature = "gcs", feature = "s3"))]
pub struct CatalogCache {
    /// Base directory for cache storage (XDG-compliant)
    base_dir: PathBuf,
    /// Time-to-live for cache entries
    ttl: Duration,
}

#[cfg(any(feature = "gcs", feature = "s3"))]
impl CatalogCache {
    /// Create a new cache instance from environment configuration
    ///
    /// # Environment Variables
    /// - `METAFUSE_CACHE_TTL_SECS`: TTL in seconds (default: 60)
    ///
    /// # Returns
    /// - `Ok(Some(cache))` if caching is enabled (TTL > 0)
    /// - `Ok(None)` if caching is disabled (TTL = 0)
    /// - `Err(...)` if cache directory cannot be created
    pub fn from_env() -> Result<Option<Self>> {
        let ttl_secs = std::env::var("METAFUSE_CACHE_TTL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60);

        if ttl_secs == 0 {
            tracing::debug!("Catalog caching disabled (METAFUSE_CACHE_TTL_SECS=0)");
            return Ok(None);
        }

        let base_dir = Self::cache_dir()?;
        std::fs::create_dir_all(&base_dir).map_err(|e| {
            CatalogError::Other(format!("Failed to create cache directory: {}", e))
        })?;

        tracing::debug!(
            path = %base_dir.display(),
            ttl_secs = ttl_secs,
            "Initialized catalog cache"
        );

        Ok(Some(Self {
            base_dir,
            ttl: Duration::from_secs(ttl_secs),
        }))
    }

    /// Get XDG-compliant cache directory
    fn cache_dir() -> Result<PathBuf> {
        dirs::cache_dir()
            .ok_or_else(|| CatalogError::Other("Cannot determine cache directory".into()))
            .map(|d| d.join("metafuse"))
    }

    /// Get cached catalog if it exists and is not expired
    ///
    /// # Arguments
    /// * `uri` - Unique identifier for the catalog (e.g., "gs://bucket/path")
    ///
    /// # Returns
    /// - `Ok(Some(download))` if cached and not expired
    /// - `Ok(None)` if not cached or expired
    /// - `Err(...)` on I/O errors
    pub fn get(&self, uri: &str) -> Result<Option<CatalogDownload>> {
        let cache_key = self.cache_path(uri);
        let meta_path = self.meta_path(uri);

        // Check if cache files exist
        if !cache_key.exists() || !meta_path.exists() {
            return Ok(None);
        }

        // Check TTL
        let metadata = std::fs::metadata(&cache_key)
            .map_err(|e| CatalogError::Other(format!("Failed to read cache metadata: {}", e)))?;

        let modified = metadata
            .modified()
            .map_err(|e| CatalogError::Other(format!("Failed to get modification time: {}", e)))?;

        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::MAX);

        if age > self.ttl {
            tracing::debug!(
                uri = uri,
                age_secs = age.as_secs(),
                ttl_secs = self.ttl.as_secs(),
                "Cache expired"
            );
            return Ok(None);
        }

        // Read remote version from metadata file
        let version_json = std::fs::read_to_string(&meta_path)
            .map_err(|e| CatalogError::Other(format!("Failed to read cache metadata: {}", e)))?;

        let remote_version: ObjectVersion = serde_json::from_str(&version_json)
            .map_err(|e| CatalogError::Other(format!("Failed to parse cache metadata: {}", e)))?;

        // Read catalog version (requires opening SQLite connection)
        let conn = rusqlite::Connection::open(&cache_key)?;
        let catalog_version = metafuse_catalog_core::get_catalog_version(&conn)?;

        tracing::debug!(
            uri = uri,
            age_secs = age.as_secs(),
            "Cache hit"
        );

        Ok(Some(CatalogDownload {
            path: cache_key,
            catalog_version,
            remote_version: Some(remote_version),
        }))
    }

    /// Store catalog in cache
    ///
    /// # Arguments
    /// * `uri` - Unique identifier for the catalog
    /// * `download` - Catalog download info including path and version
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(...)` on I/O or serialization errors
    pub fn put(&self, uri: &str, download: &CatalogDownload) -> Result<()> {
        let cache_key = self.cache_path(uri);
        let meta_path = self.meta_path(uri);

        // Copy catalog file to cache
        std::fs::copy(&download.path, &cache_key).map_err(|e| {
            CatalogError::Other(format!("Failed to copy catalog to cache: {}", e))
        })?;

        // Write version metadata
        if let Some(ref remote_version) = download.remote_version {
            let version_json = serde_json::to_string(remote_version)
                .map_err(|e| CatalogError::Other(format!("Failed to serialize metadata: {}", e)))?;

            std::fs::write(&meta_path, version_json)
                .map_err(|e| CatalogError::Other(format!("Failed to write metadata: {}", e)))?;
        }

        tracing::debug!(uri = uri, "Cached catalog");

        Ok(())
    }

    /// Invalidate cache for a specific URI
    ///
    /// Removes both the catalog file and metadata from cache.
    ///
    /// # Arguments
    /// * `uri` - Unique identifier for the catalog to invalidate
    pub fn invalidate(&self, uri: &str) -> Result<()> {
        let cache_key = self.cache_path(uri);
        let meta_path = self.meta_path(uri);

        // Ignore errors if files don't exist
        let _ = std::fs::remove_file(&cache_key);
        let _ = std::fs::remove_file(&meta_path);

        tracing::debug!(uri = uri, "Invalidated cache");

        Ok(())
    }

    /// Get cache file path for a URI
    fn cache_path(&self, uri: &str) -> PathBuf {
        let hash = self.hash_uri(uri);
        self.base_dir.join(format!("catalog_{:x}.db", hash))
    }

    /// Get metadata file path for a URI
    fn meta_path(&self, uri: &str) -> PathBuf {
        let hash = self.hash_uri(uri);
        self.base_dir.join(format!("catalog_{:x}.meta", hash))
    }

    /// Hash URI to create filesystem-safe cache key
    fn hash_uri(&self, uri: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        uri.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
#[cfg(any(feature = "gcs", feature = "s3"))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_disabled_with_zero_ttl() {
        // Use a lock to serialize environment variable tests
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "0");
        let cache = CatalogCache::from_env().unwrap();
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        assert!(cache.is_none());
    }

    #[test]
    fn test_cache_enabled_with_nonzero_ttl() {
        // Use a lock to serialize environment variable tests
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        let cache = CatalogCache::from_env().unwrap();
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        assert!(cache.is_some());
    }

    #[test]
    fn test_cache_miss_nonexistent_uri() {
        // Use a lock to serialize environment variable tests
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        let cache = CatalogCache::from_env().unwrap().unwrap();
        let result = cache.get("gs://nonexistent/catalog.db");
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_hash_uri_consistency() {
        // Use a lock to serialize environment variable tests
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        let cache = CatalogCache::from_env().unwrap().unwrap();
        let uri = "gs://test-bucket/catalog.db";

        let hash1 = cache.hash_uri(uri);
        let hash2 = cache.hash_uri(uri);

        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn test_invalidate_cache() {
        // Use a lock to serialize environment variable tests
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        let cache = CatalogCache::from_env().unwrap().unwrap();
        let uri = "gs://test-bucket/catalog.db";

        // Invalidating non-existent cache should not error
        let result = cache.invalidate(uri);
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        assert!(result.is_ok());
    }
}
