//! LRU metadata cache with TTL-based expiration.
//!
//! Follows the caching pattern established in `catalog-delta`:
//! - LRU eviction when capacity is reached
//! - TTL-based expiration with lazy evaluation
//! - Thread-safe access via `RwLock`
//!
//! # Staleness Behavior
//!
//! Cache entries are lazily evicted on access when their TTL expires.
//! Stale entries remain in the cache until accessed or evicted by LRU pressure.
//! Call `clear()` if strict freshness is required.
//!
//! # Schema-Level Caching
//!
//! The cache also supports caching domain (schema) dataset lists to reduce
//! HTTP calls when listing tables in a DataFusion schema. This is especially
//! useful for `SchemaProvider::table_names()` which is called frequently.
//!
//! # Staleness and Mutation Behavior
//!
//! **Important:** The cache is read-through only. When datasets are created,
//! deleted, or renamed via external means (API, CLI, etc.), the cache may
//! serve stale data until:
//!
//! - The TTL expires (default: 5 minutes)
//! - `invalidate_domain()` is called explicitly
//! - `clear()` is called
//!
//! If your application mutates datasets, call `invalidate_domain_cache()`
//! after mutations to ensure `table_names()` returns fresh data.

use crate::types::Dataset;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Cached entry with timestamp for TTL-based expiration.
#[derive(Debug, Clone)]
struct CachedEntry<T> {
    value: T,
    cached_at: Instant,
}

impl<T> CachedEntry<T> {
    fn new(value: T) -> Self {
        Self {
            value,
            cached_at: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() >= ttl
    }
}

/// Thread-safe metadata cache with LRU eviction and TTL expiration.
///
/// Supports caching both individual datasets and domain dataset lists.
pub struct MetadataCache {
    datasets: Arc<RwLock<LruCache<String, CachedEntry<Dataset>>>>,
    /// Cached domain -> list of dataset names
    domain_datasets: Arc<RwLock<LruCache<String, CachedEntry<Vec<String>>>>>,
    ttl: Duration,
}

impl MetadataCache {
    /// Create a new cache with the given capacity and TTL.
    ///
    /// Set `ttl` to `Duration::ZERO` to effectively disable caching
    /// (entries will always be considered expired).
    ///
    /// The capacity applies separately to datasets and domain lists.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let capacity = NonZeroUsize::new(capacity.max(1)).unwrap();
        // Use smaller capacity for domain cache (typically fewer domains than datasets)
        let domain_capacity = NonZeroUsize::new((capacity.get() / 10).max(10)).unwrap();
        Self {
            datasets: Arc::new(RwLock::new(LruCache::new(capacity))),
            domain_datasets: Arc::new(RwLock::new(LruCache::new(domain_capacity))),
            ttl,
        }
    }

    /// Get a cached dataset if present and not expired.
    pub async fn get_dataset(&self, name: &str) -> Option<Dataset> {
        if self.ttl.is_zero() {
            return None;
        }

        let cache = self.datasets.read().await;
        if let Some(entry) = cache.peek(name) {
            if !entry.is_expired(self.ttl) {
                tracing::debug!(dataset = %name, "Cache hit");
                return Some(entry.value.clone());
            }
            tracing::debug!(dataset = %name, "Cache entry expired");
        }
        None
    }

    /// Store a dataset in the cache.
    pub async fn put_dataset(&self, name: String, dataset: Dataset) {
        if self.ttl.is_zero() {
            return;
        }

        let mut cache = self.datasets.write().await;
        cache.put(name.clone(), CachedEntry::new(dataset));
        tracing::debug!(dataset = %name, "Cached dataset");
    }

    // =========================================================================
    // Domain (Schema) Cache
    // =========================================================================

    /// Get cached dataset names for a domain (schema).
    ///
    /// Returns the list of dataset names if cached and not expired.
    pub async fn get_domain_datasets(&self, domain: &str) -> Option<Vec<String>> {
        if self.ttl.is_zero() {
            return None;
        }

        let cache = self.domain_datasets.read().await;
        if let Some(entry) = cache.peek(domain) {
            if !entry.is_expired(self.ttl) {
                tracing::debug!(domain = %domain, count = entry.value.len(), "Domain cache hit");
                return Some(entry.value.clone());
            }
            tracing::debug!(domain = %domain, "Domain cache entry expired");
        }
        None
    }

    /// Store dataset names for a domain (schema).
    pub async fn put_domain_datasets(&self, domain: String, dataset_names: Vec<String>) {
        if self.ttl.is_zero() {
            return;
        }

        let count = dataset_names.len();
        let mut cache = self.domain_datasets.write().await;
        cache.put(domain.clone(), CachedEntry::new(dataset_names));
        tracing::debug!(domain = %domain, count = count, "Cached domain datasets");
    }

    /// Invalidate a specific dataset cache entry.
    pub async fn invalidate(&self, name: &str) {
        let mut cache = self.datasets.write().await;
        if cache.pop(name).is_some() {
            tracing::debug!(dataset = %name, "Cache entry invalidated");
        }
    }

    /// Invalidate a domain's cached dataset list.
    pub async fn invalidate_domain(&self, domain: &str) {
        let mut cache = self.domain_datasets.write().await;
        if cache.pop(domain).is_some() {
            tracing::debug!(domain = %domain, "Domain cache entry invalidated");
        }
    }

    /// Clear all cache entries (both datasets and domain lists).
    pub async fn clear(&self) {
        {
            let mut cache = self.datasets.write().await;
            cache.clear();
        }
        {
            let mut cache = self.domain_datasets.write().await;
            cache.clear();
        }
        tracing::debug!("All caches cleared");
    }

    /// Returns the current number of entries in the cache.
    ///
    /// Note: This includes potentially expired entries that haven't
    /// been lazily evicted yet.
    pub async fn len(&self) -> usize {
        let cache = self.datasets.read().await;
        cache.len()
    }

    /// Returns true if the cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Returns cache statistics.
    pub async fn stats(&self) -> CacheStats {
        let now = Instant::now();

        // Dataset cache stats
        let dataset_cache = self.datasets.read().await;
        let dataset_total = dataset_cache.len();
        let mut dataset_expired = 0;
        for (_, entry) in dataset_cache.iter() {
            if now.duration_since(entry.cached_at) >= self.ttl {
                dataset_expired += 1;
            }
        }
        drop(dataset_cache);

        // Domain cache stats
        let domain_cache = self.domain_datasets.read().await;
        let domain_total = domain_cache.len();
        let mut domain_expired = 0;
        for (_, entry) in domain_cache.iter() {
            if now.duration_since(entry.cached_at) >= self.ttl {
                domain_expired += 1;
            }
        }

        CacheStats {
            dataset_entries: dataset_total,
            dataset_expired,
            domain_entries: domain_total,
            domain_expired,
            ttl: self.ttl,
        }
    }
}

/// Cache statistics for monitoring.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of dataset entries in cache
    pub dataset_entries: usize,
    /// Number of expired dataset entries (not yet evicted)
    pub dataset_expired: usize,
    /// Total number of domain (schema) entries in cache
    pub domain_entries: usize,
    /// Number of expired domain entries (not yet evicted)
    pub domain_expired: usize,
    /// Current TTL setting
    pub ttl: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Dataset;
    use chrono::Utc;

    fn test_dataset(name: &str) -> Dataset {
        Dataset {
            name: name.to_string(),
            path: format!("s3://bucket/{}", name),
            format: "delta".to_string(),
            description: None,
            tenant: None,
            domain: Some("test".to_string()),
            owner: None,
            created_at: Utc::now(),
            last_updated: Utc::now(),
            fields: vec![],
            upstream_datasets: vec![],
            tags: vec![],
            row_count: Some(100),
            size_bytes: Some(1024),
            partition_keys: vec![],
            delta_location: None,
            delta: None,
            quality: None,
            classification: None,
        }
    }

    #[tokio::test]
    async fn test_cache_put_get() {
        let cache = MetadataCache::new(10, Duration::from_secs(60));

        let dataset = test_dataset("test");
        cache.put_dataset("test".to_string(), dataset.clone()).await;

        let cached = cache.get_dataset("test").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().name, "test");
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = MetadataCache::new(10, Duration::from_secs(60));

        let cached = cache.get_dataset("nonexistent").await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = MetadataCache::new(10, Duration::from_millis(50));

        let dataset = test_dataset("test");
        cache.put_dataset("test".to_string(), dataset).await;

        // Should be in cache
        assert!(cache.get_dataset("test").await.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be expired
        assert!(cache.get_dataset("test").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_disabled() {
        let cache = MetadataCache::new(10, Duration::ZERO);

        let dataset = test_dataset("test");
        cache.put_dataset("test".to_string(), dataset).await;

        // Should not be cached when TTL is zero
        assert!(cache.get_dataset("test").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_invalidate() {
        let cache = MetadataCache::new(10, Duration::from_secs(60));

        let dataset = test_dataset("test");
        cache.put_dataset("test".to_string(), dataset).await;

        assert!(cache.get_dataset("test").await.is_some());

        cache.invalidate("test").await;

        assert!(cache.get_dataset("test").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = MetadataCache::new(10, Duration::from_secs(60));

        cache
            .put_dataset("test1".to_string(), test_dataset("test1"))
            .await;
        cache
            .put_dataset("test2".to_string(), test_dataset("test2"))
            .await;

        assert_eq!(cache.len().await, 2);

        cache.clear().await;

        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn test_lru_eviction() {
        let cache = MetadataCache::new(2, Duration::from_secs(60));

        cache
            .put_dataset("test1".to_string(), test_dataset("test1"))
            .await;
        cache
            .put_dataset("test2".to_string(), test_dataset("test2"))
            .await;
        cache
            .put_dataset("test3".to_string(), test_dataset("test3"))
            .await;

        // test1 should have been evicted (LRU)
        assert!(cache.get_dataset("test1").await.is_none());
        assert!(cache.get_dataset("test2").await.is_some());
        assert!(cache.get_dataset("test3").await.is_some());
    }

    // =========================================================================
    // Domain Cache Tests
    // =========================================================================

    #[tokio::test]
    async fn test_domain_cache_put_get() {
        let cache = MetadataCache::new(10, Duration::from_secs(60));

        let datasets = vec!["dataset1".to_string(), "dataset2".to_string()];
        cache
            .put_domain_datasets("analytics".to_string(), datasets.clone())
            .await;

        let cached = cache.get_domain_datasets("analytics").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), datasets);
    }

    #[tokio::test]
    async fn test_domain_cache_miss() {
        let cache = MetadataCache::new(10, Duration::from_secs(60));

        let cached = cache.get_domain_datasets("nonexistent").await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_domain_cache_expiration() {
        let cache = MetadataCache::new(10, Duration::from_millis(50));

        let datasets = vec!["dataset1".to_string()];
        cache
            .put_domain_datasets("analytics".to_string(), datasets)
            .await;

        // Should be in cache
        assert!(cache.get_domain_datasets("analytics").await.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be expired
        assert!(cache.get_domain_datasets("analytics").await.is_none());
    }

    #[tokio::test]
    async fn test_domain_cache_invalidate() {
        let cache = MetadataCache::new(10, Duration::from_secs(60));

        let datasets = vec!["dataset1".to_string()];
        cache
            .put_domain_datasets("analytics".to_string(), datasets)
            .await;

        assert!(cache.get_domain_datasets("analytics").await.is_some());

        cache.invalidate_domain("analytics").await;

        assert!(cache.get_domain_datasets("analytics").await.is_none());
    }

    #[tokio::test]
    async fn test_clear_clears_both_caches() {
        let cache = MetadataCache::new(10, Duration::from_secs(60));

        cache
            .put_dataset("test".to_string(), test_dataset("test"))
            .await;
        cache
            .put_domain_datasets("analytics".to_string(), vec!["ds1".to_string()])
            .await;

        cache.clear().await;

        assert!(cache.get_dataset("test").await.is_none());
        assert!(cache.get_domain_datasets("analytics").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats_includes_both() {
        let cache = MetadataCache::new(10, Duration::from_secs(60));

        cache
            .put_dataset("test".to_string(), test_dataset("test"))
            .await;
        cache
            .put_domain_datasets("analytics".to_string(), vec!["ds1".to_string()])
            .await;

        let stats = cache.stats().await;
        assert_eq!(stats.dataset_entries, 1);
        assert_eq!(stats.domain_entries, 1);
        assert_eq!(stats.dataset_expired, 0);
        assert_eq!(stats.domain_expired, 0);
    }
}
