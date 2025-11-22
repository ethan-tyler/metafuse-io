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
//! - **Staleness trade-off**: Cache hits trust TTL without remote HEAD revalidation to avoid extra
//!   cloud calls; keep TTL small for higher freshness.

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

/// Trait for backends that support HEAD requests for cache revalidation (async)
///
/// Allows cache to check if a remote object has changed without downloading it.
#[cfg(any(feature = "gcs", feature = "s3"))]
pub trait HeadCheckBackend: Send + Sync {
    /// Perform a HEAD request to get the remote object version
    ///
    /// # Arguments
    /// * `uri` - The URI that was used to cache the object
    ///
    /// # Returns
    /// - `Ok(version)` if HEAD request succeeded
    /// - `Err(...)` if HEAD request failed (cache should gracefully fall back)
    fn head_check(
        &self,
        uri: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ObjectVersion>> + Send + '_>>;
}

/// Cache for cloud-downloaded catalogs
///
/// Reduces cloud API calls by maintaining local copies of catalog files
/// with metadata for version tracking and TTL-based expiration.
///
/// ## Revalidation
///
/// When `revalidate` is enabled, the cache performs a HEAD request to check
/// if the cached version matches the remote version before returning the cached copy.
/// This adds latency (~50-200ms) but ensures freshness.
#[cfg(any(feature = "gcs", feature = "s3"))]
pub struct CatalogCache {
    /// Base directory for cache storage (XDG-compliant)
    base_dir: PathBuf,
    /// Time-to-live for cache entries
    ttl: Duration,
    /// Whether to revalidate cached entries with HEAD requests
    revalidate: bool,
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

        let revalidate = std::env::var("METAFUSE_CACHE_REVALIDATE")
            .ok()
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);

        let base_dir = Self::cache_dir()?;
        std::fs::create_dir_all(&base_dir)
            .map_err(|e| CatalogError::Other(format!("Failed to create cache directory: {}", e)))?;

        tracing::debug!(
            path = %base_dir.display(),
            ttl_secs = ttl_secs,
            revalidate = revalidate,
            "Initialized catalog cache"
        );

        Ok(Some(Self {
            base_dir,
            ttl: Duration::from_secs(ttl_secs),
            revalidate,
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
    /// * `backend` - Optional backend for revalidation (required if revalidate=true)
    ///
    /// # Returns
    /// - `Ok(Some(download))` if cached and not expired
    /// - `Ok(None)` if not cached or expired
    /// - `Err(...)` on I/O errors
    ///
    /// # Revalidation
    /// If `revalidate` is enabled and a backend is provided, performs a HEAD
    /// request to check if the cached version matches the remote version.
    /// On HEAD failure, falls back gracefully to cached copy with a warning.
    pub fn get<'a>(
        &'a self,
        uri: &'a str,
        backend: Option<&'a dyn HeadCheckBackend>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<CatalogDownload>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let cache_key = self.cache_path(uri);
            let meta_path = self.meta_path(uri);

            // Check if cache files exist
            if !cache_key.exists() || !meta_path.exists() {
                return Ok(None);
            }

            // Check TTL
            let metadata = std::fs::metadata(&cache_key).map_err(|e| {
                CatalogError::Other(format!("Failed to read cache metadata: {}", e))
            })?;

            let modified = metadata.modified().map_err(|e| {
                CatalogError::Other(format!("Failed to get modification time: {}", e))
            })?;

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
            let version_json = std::fs::read_to_string(&meta_path).map_err(|e| {
                CatalogError::Other(format!("Failed to read cache metadata: {}", e))
            })?;

            let remote_version: ObjectVersion =
                serde_json::from_str(&version_json).map_err(|e| {
                    CatalogError::Other(format!("Failed to parse cache metadata: {}", e))
                })?;

            // Read catalog version (requires opening SQLite connection)
            let cache_key_clone = cache_key.clone();
            let catalog_version = tokio::task::spawn_blocking(move || {
                let conn = rusqlite::Connection::open(&cache_key_clone)?;
                metafuse_catalog_core::get_catalog_version(&conn)
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

            // Perform revalidation if enabled
            if self.revalidate {
                if let Some(backend) = backend {
                    let mut attempts = 0u32;
                    let mut last_err: Option<CatalogError> = None;
                    while attempts < 3 {
                        match backend.head_check(uri).await {
                            Ok(current_remote_version) => {
                                // Compare cached version with current remote version
                                if remote_version != current_remote_version {
                                    tracing::debug!(
                                        uri = uri,
                                        cached_version = ?remote_version,
                                        remote_version = ?current_remote_version,
                                        "Cache stale after revalidation"
                                    );
                                    return Ok(None);
                                }
                                tracing::debug!(uri = uri, "Cache revalidation succeeded");
                                break;
                            }
                            Err(e) => {
                                last_err = Some(e);
                                attempts += 1;
                                if attempts >= 3 {
                                    break;
                                }
                                // small backoff before retry
                                tokio::time::sleep(Duration::from_millis(
                                    50 * 2u64.saturating_pow(attempts - 1),
                                ))
                                .await;
                            }
                        }
                    }

                    if let Some(e) = last_err {
                        // Graceful fallback: log warning and use cached copy
                        tracing::warn!(
                            uri = uri,
                            error = %e,
                            "Cache revalidation failed after retries, falling back to cached copy"
                        );
                    }
                } else {
                    tracing::warn!(
                        uri = uri,
                        "Cache revalidation enabled but no backend provided"
                    );
                }
            }

            tracing::debug!(uri = uri, age_secs = age.as_secs(), "Cache hit");

            Ok(Some(CatalogDownload {
                path: cache_key,
                catalog_version,
                remote_version: Some(remote_version),
            }))
        })
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
        std::fs::copy(&download.path, &cache_key)
            .map_err(|e| CatalogError::Other(format!("Failed to copy catalog to cache: {}", e)))?;

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
    use std::sync::Mutex;

    // Shared lock to serialize all cache tests that modify environment variables
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_cache_disabled_with_zero_ttl() {
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "0");
        let cache = CatalogCache::from_env().unwrap();
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        assert!(cache.is_none());
    }

    #[test]
    fn test_cache_enabled_with_nonzero_ttl() {
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        let cache = CatalogCache::from_env().unwrap();
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        assert!(cache.is_some());
    }

    #[tokio::test]
    async fn test_cache_miss_nonexistent_uri() {
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        let cache = CatalogCache::from_env().unwrap().unwrap();
        let result = cache.get("gs://nonexistent/catalog.db", None).await;
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_hash_uri_consistency() {
        let _guard = ENV_LOCK.lock().unwrap();

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
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        let cache = CatalogCache::from_env().unwrap().unwrap();
        let uri = "gs://test-bucket/catalog.db";

        // Invalidating non-existent cache should not error
        let result = cache.invalidate(uri);
        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        assert!(result.is_ok());
    }

    #[test]
    fn test_revalidation_disabled_by_default() {
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        // Don't set METAFUSE_CACHE_REVALIDATE
        let cache = CatalogCache::from_env().unwrap().unwrap();

        // Revalidation should be disabled by default
        assert_eq!(cache.revalidate, false);

        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
    }

    #[test]
    fn test_revalidation_enabled() {
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        std::env::set_var("METAFUSE_CACHE_REVALIDATE", "true");

        let cache = CatalogCache::from_env().unwrap().unwrap();

        // Revalidation should be enabled
        assert_eq!(cache.revalidate, true);

        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        std::env::remove_var("METAFUSE_CACHE_REVALIDATE");
    }

    #[test]
    fn test_revalidation_explicit_disable() {
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::set_var("METAFUSE_CACHE_TTL_SECS", "60");
        std::env::set_var("METAFUSE_CACHE_REVALIDATE", "false");

        let cache = CatalogCache::from_env().unwrap().unwrap();

        // Revalidation should be disabled
        assert_eq!(cache.revalidate, false);

        std::env::remove_var("METAFUSE_CACHE_TTL_SECS");
        std::env::remove_var("METAFUSE_CACHE_REVALIDATE");
    }
}
