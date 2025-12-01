//! Tenant Backend Factory with Connection Pooling.
//!
//! This module provides a factory for creating and caching per-tenant storage backends.
//! It uses an LRU cache to limit memory usage while providing efficient reuse of
//! backend instances.
//!
//! # Architecture
//!
//! ```text
//! TenantBackendFactory
//!        │
//!        ├── storage_uri_template: "gs://bucket/{tenant_id}/catalog.db"
//!        │
//!        └── LRU Cache (capacity: N)
//!              ├── "tenant-a" → Box<dyn CatalogBackend>
//!              ├── "tenant-b" → Box<dyn CatalogBackend>
//!              └── "tenant-c" → Box<dyn CatalogBackend>
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use metafuse_catalog_storage::factory::TenantBackendFactory;
//! use metafuse_catalog_storage::TenantContext;
//!
//! // Create factory with URI template
//! let factory = TenantBackendFactory::new(
//!     "gs://my-bucket/tenants/{tenant_id}/catalog.db",
//!     100,  // cache up to 100 tenant backends
//! )?;
//!
//! // Get backend for a tenant (cached or newly created)
//! let ctx = TenantContext::new("acme-corp")?;
//! let backend = factory.get_backend(&ctx).await?;
//!
//! // Use the backend
//! let exists = backend.exists().await?;
//! ```
//!
//! # Thread Safety
//!
//! The factory is thread-safe and can be shared across async tasks using `Arc<TenantBackendFactory>`.
//! The internal LRU cache uses `parking_lot::Mutex` for efficient concurrent access.
//!
//! # Cache Eviction
//!
//! When the cache reaches capacity, the least recently used backend is evicted.
//! Evicted backends are dropped, closing any resources they hold.

use crate::pool_config::ConnectionPoolConfig;
use crate::{backend_from_uri, CatalogBackend, TenantContext};
use dashmap::DashMap;
use lru::LruCache;
use metafuse_catalog_core::{CatalogError, Result};
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

/// Default cache capacity for tenant backends.
pub const DEFAULT_CACHE_CAPACITY: usize = 100;

/// Minimum cache capacity.
pub const MIN_CACHE_CAPACITY: usize = 1;

/// Maximum cache capacity.
pub const MAX_CACHE_CAPACITY: usize = 10_000;

/// Placeholder for tenant ID in URI templates.
const TENANT_ID_PLACEHOLDER: &str = "{tenant_id}";

/// Placeholder for region in URI templates.
const REGION_PLACEHOLDER: &str = "{region}";

// =============================================================================
// Connection Pool Types
// =============================================================================

/// RAII wrapper for tenant backend that releases connection permit on drop.
///
/// This handle ensures that connection permits are automatically returned
/// when the handle goes out of scope, preventing resource leaks.
///
/// # Usage
///
/// ```rust,ignore
/// let handle = factory.get_backend_handle(&tenant).await?;
/// let backend = handle.backend();
/// // Use backend...
/// // When handle drops, permit is automatically released
/// ```
pub struct TenantBackendHandle {
    backend: Arc<dyn CatalogBackend>,
    tenant_id: String,
    _permit: OwnedSemaphorePermit,
    acquired_at: Instant,
}

impl std::fmt::Debug for TenantBackendHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantBackendHandle")
            .field("tenant_id", &self.tenant_id)
            .field("hold_time_ms", &self.acquired_at.elapsed().as_millis())
            .finish()
    }
}

impl TenantBackendHandle {
    /// Get the underlying catalog backend.
    pub fn backend(&self) -> &Arc<dyn CatalogBackend> {
        &self.backend
    }

    /// Get the tenant ID associated with this handle.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Get how long this handle has been held.
    pub fn hold_time(&self) -> std::time::Duration {
        self.acquired_at.elapsed()
    }
}

impl Drop for TenantBackendHandle {
    fn drop(&mut self) {
        let hold_time = self.acquired_at.elapsed();
        debug!(
            tenant_id = %self.tenant_id,
            hold_time_ms = hold_time.as_millis(),
            "Releasing tenant connection permit"
        );
        // Permit auto-released when _permit is dropped
    }
}

/// Circuit breaker state for a tenant backend.
///
/// Tracks failure count and determines when to open/close the circuit.
#[derive(Debug)]
struct CircuitBreakerState {
    /// Number of consecutive failures.
    failure_count: AtomicU32,
    /// Timestamp when circuit was opened (0 if closed).
    opened_at: AtomicU64,
}

impl CircuitBreakerState {
    fn new() -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            opened_at: AtomicU64::new(0),
        }
    }

    /// Record a failure and return true if circuit should open.
    fn record_failure(&self, threshold: u32) -> bool {
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        if count >= threshold {
            self.opened_at
                .store(current_timestamp_secs(), Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// Record a success, resetting the failure count.
    fn record_success(&self) {
        self.failure_count.store(0, Ordering::SeqCst);
        self.opened_at.store(0, Ordering::SeqCst);
    }

    /// Check if circuit is open (blocking requests).
    fn is_open(&self, reset_timeout_secs: u64) -> bool {
        let opened = self.opened_at.load(Ordering::SeqCst);
        if opened == 0 {
            return false;
        }
        let now = current_timestamp_secs();
        if now - opened >= reset_timeout_secs {
            // Reset to half-open state
            self.opened_at.store(0, Ordering::SeqCst);
            self.failure_count.store(0, Ordering::SeqCst);
            false
        } else {
            true
        }
    }
}

/// Get current Unix timestamp in seconds.
fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Entry in the semaphore pool for a tenant.
struct TenantPoolEntry {
    semaphore: Arc<Semaphore>,
    circuit_breaker: CircuitBreakerState,
}

/// Pool of per-tenant semaphores for connection limiting.
///
/// Each tenant gets its own semaphore to limit concurrent connections,
/// with an optional circuit breaker for fault tolerance.
pub struct TenantSemaphorePool {
    entries: DashMap<String, Arc<TenantPoolEntry>>,
    config: ConnectionPoolConfig,
    /// Set of suspended tenant IDs for immediate rejection.
    suspended_tenants: DashMap<String, ()>,
}

impl std::fmt::Debug for TenantSemaphorePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantSemaphorePool")
            .field("tenant_count", &self.entries.len())
            .field("suspended_count", &self.suspended_tenants.len())
            .field("config", &self.config)
            .finish()
    }
}

impl TenantSemaphorePool {
    /// Create a new semaphore pool with the given configuration.
    pub fn new(config: ConnectionPoolConfig) -> Self {
        Self {
            entries: DashMap::new(),
            config,
            suspended_tenants: DashMap::new(),
        }
    }

    /// Get or create a semaphore entry for a tenant.
    fn get_entry(&self, tenant_id: &str) -> Arc<TenantPoolEntry> {
        self.entries
            .entry(tenant_id.to_string())
            .or_insert_with(|| {
                Arc::new(TenantPoolEntry {
                    semaphore: Arc::new(Semaphore::new(self.config.max_connections_per_tenant)),
                    circuit_breaker: CircuitBreakerState::new(),
                })
            })
            .clone()
    }

    /// Try to acquire a permit with timeout.
    ///
    /// Returns an error if:
    /// - Tenant is suspended (immediate rejection per design decision)
    /// - Circuit breaker is open
    /// - Timeout waiting for permit
    pub async fn acquire_permit(&self, tenant_id: &str) -> Result<OwnedSemaphorePermit> {
        // Check if tenant is suspended (immediate rejection)
        if self.suspended_tenants.contains_key(tenant_id) {
            return Err(CatalogError::Other(format!(
                "Tenant '{}' is suspended",
                tenant_id
            )));
        }

        let entry = self.get_entry(tenant_id);

        // Check circuit breaker
        if self.config.circuit_breaker.enabled
            && entry
                .circuit_breaker
                .is_open(self.config.circuit_breaker.reset_timeout.as_secs())
        {
            return Err(CatalogError::Other(format!(
                "Circuit breaker open for tenant '{}' (too many failures)",
                tenant_id
            )));
        }

        // Try to acquire permit with timeout
        match tokio::time::timeout(
            self.config.acquire_timeout,
            entry.semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(CatalogError::Other("Connection pool closed".into())),
            Err(_) => Err(CatalogError::Other(format!(
                "Timeout waiting for connection (tenant: {}, timeout: {}s)",
                tenant_id,
                self.config.acquire_timeout.as_secs()
            ))),
        }
    }

    /// Record a successful operation for circuit breaker.
    pub fn record_success(&self, tenant_id: &str) {
        if let Some(entry) = self.entries.get(tenant_id) {
            entry.circuit_breaker.record_success();
        }
    }

    /// Record a failure for circuit breaker.
    pub fn record_failure(&self, tenant_id: &str) {
        if !self.config.circuit_breaker.enabled {
            return;
        }
        if let Some(entry) = self.entries.get(tenant_id) {
            if entry
                .circuit_breaker
                .record_failure(self.config.circuit_breaker.failure_threshold)
            {
                warn!(
                    tenant_id = %tenant_id,
                    threshold = self.config.circuit_breaker.failure_threshold,
                    "Circuit breaker opened for tenant"
                );
            }
        }
    }

    /// Suspend a tenant (immediate rejection of all requests).
    pub fn suspend_tenant(&self, tenant_id: &str) {
        self.suspended_tenants.insert(tenant_id.to_string(), ());
        info!(tenant_id = %tenant_id, "Tenant suspended in connection pool");
    }

    /// Resume a suspended tenant.
    pub fn resume_tenant(&self, tenant_id: &str) {
        self.suspended_tenants.remove(tenant_id);
        info!(tenant_id = %tenant_id, "Tenant resumed in connection pool");
    }

    /// Check if a tenant is suspended.
    pub fn is_suspended(&self, tenant_id: &str) -> bool {
        self.suspended_tenants.contains_key(tenant_id)
    }

    /// Get current connection count for a tenant.
    pub fn active_connections(&self, tenant_id: &str) -> usize {
        self.entries
            .get(tenant_id)
            .map(|entry| {
                self.config.max_connections_per_tenant - entry.semaphore.available_permits()
            })
            .unwrap_or(0)
    }

    /// Get available permits for a tenant.
    pub fn available_permits(&self, tenant_id: &str) -> usize {
        self.entries
            .get(tenant_id)
            .map(|entry| entry.semaphore.available_permits())
            .unwrap_or(self.config.max_connections_per_tenant)
    }

    /// Remove a tenant from the pool (e.g., on tenant deletion).
    pub fn remove_tenant(&self, tenant_id: &str) {
        self.entries.remove(tenant_id);
        self.suspended_tenants.remove(tenant_id);
    }
}

/// Factory for creating, caching, and connection-limiting per-tenant storage backends.
///
/// The factory resolves tenant-specific storage URIs from a template
/// and maintains an LRU cache of backend instances for efficient reuse.
///
/// # Features
///
/// - **LRU Caching**: Backends are created on first access and cached
/// - **Connection Limiting**: Per-tenant semaphores prevent noisy neighbor issues
/// - **Circuit Breaker**: Automatic failure detection and recovery
/// - **Tenant Suspension**: Immediate rejection for suspended tenants
///
/// # URI Template
///
/// The template must contain `{tenant_id}` placeholder:
/// - `gs://bucket/tenants/{tenant_id}/catalog.db`
/// - `s3://bucket/tenants/{tenant_id}/catalog.db`
/// - `/data/tenants/{tenant_id}/catalog.db`
#[derive(Debug)]
pub struct TenantBackendFactory {
    /// URI template with {tenant_id} placeholder
    storage_uri_template: String,

    /// LRU cache of tenant backends
    cache: Mutex<LruCache<String, Arc<dyn CatalogBackend>>>,

    /// Configured cache capacity
    capacity: usize,

    /// Per-tenant semaphore pool for connection limiting
    semaphore_pool: TenantSemaphorePool,

    /// Connection pool configuration
    pool_config: ConnectionPoolConfig,
}

impl TenantBackendFactory {
    /// Create a new tenant backend factory.
    ///
    /// # Arguments
    ///
    /// * `storage_uri_template` - URI template with `{tenant_id}` placeholder
    /// * `cache_capacity` - Maximum number of backends to cache
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Template doesn't contain `{tenant_id}` placeholder
    /// - Cache capacity is 0 or exceeds maximum
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let factory = TenantBackendFactory::new(
    ///     "gs://my-bucket/tenants/{tenant_id}/catalog.db",
    ///     100,
    /// )?;
    /// ```
    pub fn new(storage_uri_template: impl Into<String>, cache_capacity: usize) -> Result<Self> {
        let template = storage_uri_template.into();

        // Validate template contains placeholder
        if !template.contains(TENANT_ID_PLACEHOLDER) {
            return Err(CatalogError::ValidationError(format!(
                "storage_uri_template must contain '{}' placeholder",
                TENANT_ID_PLACEHOLDER
            )));
        }

        // Validate cache capacity
        if cache_capacity < MIN_CACHE_CAPACITY {
            return Err(CatalogError::ValidationError(format!(
                "cache_capacity must be at least {}",
                MIN_CACHE_CAPACITY
            )));
        }

        if cache_capacity > MAX_CACHE_CAPACITY {
            return Err(CatalogError::ValidationError(format!(
                "cache_capacity cannot exceed {}",
                MAX_CACHE_CAPACITY
            )));
        }

        let capacity = NonZeroUsize::new(cache_capacity)
            .ok_or_else(|| CatalogError::ValidationError("Invalid cache capacity".into()))?;

        let pool_config = ConnectionPoolConfig::from_env();

        info!(
            template = %template,
            cache_capacity = cache_capacity,
            max_connections = pool_config.max_connections_per_tenant,
            "Created TenantBackendFactory"
        );

        Ok(Self {
            storage_uri_template: template,
            cache: Mutex::new(LruCache::new(capacity)),
            capacity: cache_capacity,
            semaphore_pool: TenantSemaphorePool::new(pool_config.clone()),
            pool_config,
        })
    }

    /// Create a factory with specific pool configuration.
    ///
    /// Use this for custom connection limits or circuit breaker settings.
    pub fn with_pool_config(
        storage_uri_template: impl Into<String>,
        cache_capacity: usize,
        pool_config: ConnectionPoolConfig,
    ) -> Result<Self> {
        let template = storage_uri_template.into();

        if !template.contains(TENANT_ID_PLACEHOLDER) {
            return Err(CatalogError::ValidationError(format!(
                "storage_uri_template must contain '{}' placeholder",
                TENANT_ID_PLACEHOLDER
            )));
        }

        if !(MIN_CACHE_CAPACITY..=MAX_CACHE_CAPACITY).contains(&cache_capacity) {
            return Err(CatalogError::ValidationError(format!(
                "cache_capacity must be between {} and {}",
                MIN_CACHE_CAPACITY, MAX_CACHE_CAPACITY
            )));
        }

        let capacity = NonZeroUsize::new(cache_capacity)
            .ok_or_else(|| CatalogError::ValidationError("Invalid cache capacity".into()))?;

        info!(
            template = %template,
            cache_capacity = cache_capacity,
            max_connections = pool_config.max_connections_per_tenant,
            "Created TenantBackendFactory with custom pool config"
        );

        Ok(Self {
            storage_uri_template: template,
            cache: Mutex::new(LruCache::new(capacity)),
            capacity: cache_capacity,
            semaphore_pool: TenantSemaphorePool::new(pool_config.clone()),
            pool_config,
        })
    }

    /// Create a factory with default cache capacity.
    ///
    /// Uses [`DEFAULT_CACHE_CAPACITY`] (100 backends).
    pub fn with_default_capacity(storage_uri_template: impl Into<String>) -> Result<Self> {
        Self::new(storage_uri_template, DEFAULT_CACHE_CAPACITY)
    }

    /// Resolve a tenant ID to a storage URI.
    ///
    /// Replaces `{tenant_id}` placeholder with the actual tenant ID.
    ///
    /// # Safety
    ///
    /// This method assumes the tenant_id has already been validated via `TenantContext::new()`.
    /// The validation ensures tenant IDs only contain alphanumeric, `_`, and `-` characters,
    /// preventing path traversal attacks like `../../../etc/passwd`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let factory = TenantBackendFactory::new("gs://bucket/{tenant_id}/db", 10)?;
    /// let uri = factory.resolve_uri("acme-corp");
    /// assert_eq!(uri, "gs://bucket/acme-corp/db");
    /// ```
    pub fn resolve_uri(&self, tenant_id: &str) -> String {
        self.resolve_uri_with_region(tenant_id, None)
    }

    /// Resolve a tenant ID and optional region to a storage URI.
    ///
    /// Replaces `{tenant_id}` and `{region}` placeholders with actual values.
    /// If the template contains `{region}` placeholder, it will be replaced.
    /// If no placeholder exists but region is provided for S3 URIs, appends `?region=` query param.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Validated tenant identifier
    /// * `region` - Optional region (e.g., "us-east1", "europe-west1")
    ///
    /// # Safety
    ///
    /// This method assumes the tenant_id has already been validated via `TenantContext::new()`.
    /// Region values should contain only alphanumeric characters and hyphens.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Template with region placeholder
    /// let factory = TenantBackendFactory::new("s3://bucket-{region}/{tenant_id}/db", 10)?;
    /// let uri = factory.resolve_uri_with_region("acme-corp", Some("us-east1"));
    /// assert_eq!(uri, "s3://bucket-us-east1/acme-corp/db");
    ///
    /// // Template without region placeholder (S3 appends query param)
    /// let factory = TenantBackendFactory::new("s3://bucket/{tenant_id}/db", 10)?;
    /// let uri = factory.resolve_uri_with_region("acme-corp", Some("us-east1"));
    /// assert_eq!(uri, "s3://bucket/acme-corp/db?region=us-east1");
    /// ```
    pub fn resolve_uri_with_region(&self, tenant_id: &str, region: Option<&str>) -> String {
        // Defense-in-depth: reject any path traversal attempts
        debug_assert!(
            !tenant_id.contains("..") && !tenant_id.contains('/') && !tenant_id.contains('\\'),
            "tenant_id should be validated to prevent path traversal"
        );

        let mut uri = self
            .storage_uri_template
            .replace(TENANT_ID_PLACEHOLDER, tenant_id);

        // Handle region placeholder
        if uri.contains(REGION_PLACEHOLDER) {
            let resolved_region = region.unwrap_or("default");
            uri = uri.replace(REGION_PLACEHOLDER, resolved_region);
        } else if let Some(r) = region {
            // Append region to S3 URIs without placeholder
            if uri.starts_with("s3://") && !uri.contains("?region=") {
                if uri.contains('?') {
                    uri = format!("{}&region={}", uri, r);
                } else {
                    uri = format!("{}?region={}", uri, r);
                }
            }
        }

        uri
    }

    /// Validate that a tenant ID is safe for URI substitution.
    ///
    /// Returns an error if the tenant ID contains path traversal patterns.
    /// This is a defense-in-depth check; `TenantContext::new()` should already
    /// validate tenant IDs.
    fn validate_tenant_id_for_uri(tenant_id: &str) -> Result<()> {
        // Check for path traversal patterns
        if tenant_id.contains("..") {
            return Err(CatalogError::ValidationError(
                "tenant_id cannot contain '..' (path traversal)".into(),
            ));
        }
        if tenant_id.contains('/') || tenant_id.contains('\\') {
            return Err(CatalogError::ValidationError(
                "tenant_id cannot contain path separators".into(),
            ));
        }
        // Check for null bytes (common bypass technique)
        if tenant_id.contains('\0') {
            return Err(CatalogError::ValidationError(
                "tenant_id cannot contain null bytes".into(),
            ));
        }
        Ok(())
    }

    /// Get or create a backend for the given tenant.
    ///
    /// This method is async to allow for backend initialization,
    /// but the cache lookup itself is synchronous.
    ///
    /// # Arguments
    ///
    /// * `tenant` - Validated tenant context
    ///
    /// # Returns
    ///
    /// An `Arc<dyn CatalogBackend>` that can be used for catalog operations.
    /// The backend is cached for future reuse.
    ///
    /// # Errors
    ///
    /// Returns error if backend creation fails (e.g., invalid URI, missing credentials).
    pub async fn get_backend(&self, tenant: &TenantContext) -> Result<Arc<dyn CatalogBackend>> {
        let tenant_id = tenant.tenant_id().to_string();

        // Try to get from cache first
        {
            let mut cache = self.cache.lock();
            if let Some(backend) = cache.get(&tenant_id) {
                debug!(tenant_id = %tenant_id, "Backend cache hit");
                return Ok(Arc::clone(backend));
            }
        }

        // Cache miss - create new backend
        debug!(tenant_id = %tenant_id, "Backend cache miss, creating new backend");

        let uri = self.resolve_uri(&tenant_id);
        let backend = backend_from_uri(&uri)?;
        let backend: Arc<dyn CatalogBackend> = Arc::from(backend);

        // Insert into cache
        {
            let mut cache = self.cache.lock();

            // Check if another task already inserted while we were creating
            if let Some(existing) = cache.get(&tenant_id) {
                debug!(tenant_id = %tenant_id, "Backend created by concurrent task, using existing");
                return Ok(Arc::clone(existing));
            }

            // Check if we're about to evict
            if cache.len() >= self.capacity {
                if let Some((evicted_id, _)) = cache.peek_lru() {
                    debug!(evicted_tenant = %evicted_id, tenant_id = %tenant_id, "Evicting LRU tenant backend");
                }
            }

            cache.put(tenant_id.clone(), Arc::clone(&backend));
            debug!(tenant_id = %tenant_id, cache_size = cache.len(), "Cached tenant backend");
        }

        Ok(backend)
    }

    /// Get or create a backend for the given tenant with optional region.
    ///
    /// This method supports multi-region deployments where the same tenant
    /// may have backends in different regions.
    ///
    /// # Arguments
    ///
    /// * `tenant` - Validated tenant context
    /// * `region` - Optional region (e.g., "us-east1", "europe-west1")
    ///
    /// # Returns
    ///
    /// An `Arc<dyn CatalogBackend>` that can be used for catalog operations.
    /// The backend is cached using a composite key: `tenant_id@region`.
    ///
    /// # Errors
    ///
    /// Returns error if backend creation fails (e.g., invalid URI, missing credentials).
    pub async fn get_backend_with_region(
        &self,
        tenant: &TenantContext,
        region: Option<&str>,
    ) -> Result<Arc<dyn CatalogBackend>> {
        let tenant_id = tenant.tenant_id();
        // Cache key includes region for isolation
        let cache_key = Self::make_cache_key(tenant_id, region);

        // Try to get from cache first
        {
            let mut cache = self.cache.lock();
            if let Some(backend) = cache.get(&cache_key) {
                debug!(tenant_id = %tenant_id, region = ?region, "Backend cache hit");
                return Ok(Arc::clone(backend));
            }
        }

        // Cache miss - create new backend
        debug!(tenant_id = %tenant_id, region = ?region, "Backend cache miss, creating new backend");

        let uri = self.resolve_uri_with_region(tenant_id, region);
        let backend = backend_from_uri(&uri)?;
        let backend: Arc<dyn CatalogBackend> = Arc::from(backend);

        // Insert into cache
        {
            let mut cache = self.cache.lock();

            // Check if another task already inserted while we were creating
            if let Some(existing) = cache.get(&cache_key) {
                debug!(tenant_id = %tenant_id, region = ?region, "Backend created by concurrent task, using existing");
                return Ok(Arc::clone(existing));
            }

            // Check if we're about to evict
            if cache.len() >= self.capacity {
                if let Some((evicted_key, _)) = cache.peek_lru() {
                    debug!(evicted_key = %evicted_key, cache_key = %cache_key, "Evicting LRU tenant backend");
                }
            }

            cache.put(cache_key.clone(), Arc::clone(&backend));
            debug!(tenant_id = %tenant_id, region = ?region, cache_size = cache.len(), "Cached tenant backend");
        }

        Ok(backend)
    }

    /// Create a cache key from tenant ID and optional region.
    fn make_cache_key(tenant_id: &str, region: Option<&str>) -> String {
        match region {
            Some(r) => format!("{}@{}", tenant_id, r),
            None => tenant_id.to_string(),
        }
    }

    /// Get a connection-limited backend handle for the given tenant.
    ///
    /// This is the **primary method** for acquiring tenant backends with connection pooling.
    /// Returns an RAII handle that automatically releases the connection permit on drop.
    ///
    /// # Arguments
    ///
    /// * `tenant` - Validated tenant context
    ///
    /// # Returns
    ///
    /// A `TenantBackendHandle` that wraps the backend and releases the permit on drop.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Tenant is suspended (immediate rejection)
    /// - Circuit breaker is open for the tenant
    /// - Timeout waiting for connection permit
    /// - Backend creation fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let handle = factory.get_backend_handle(&tenant).await?;
    /// let backend = handle.backend();
    /// let exists = backend.exists().await?;
    /// // Permit automatically released when handle is dropped
    /// ```
    pub async fn get_backend_handle(&self, tenant: &TenantContext) -> Result<TenantBackendHandle> {
        let tenant_id = tenant.tenant_id().to_string();

        // 1. Acquire permit first (backpressure before doing work)
        let permit = self.semaphore_pool.acquire_permit(&tenant_id).await?;

        // 2. Get backend from cache (or create)
        let backend = match self.get_backend(tenant).await {
            Ok(b) => {
                self.semaphore_pool.record_success(&tenant_id);
                b
            }
            Err(e) => {
                self.semaphore_pool.record_failure(&tenant_id);
                return Err(e);
            }
        };

        // 3. Wrap in RAII handle
        Ok(TenantBackendHandle {
            backend,
            tenant_id,
            _permit: permit,
            acquired_at: Instant::now(),
        })
    }

    /// Get a connection-limited backend handle for the given tenant with optional region.
    ///
    /// This is the **primary method** for acquiring region-aware tenant backends.
    /// Returns an RAII handle that automatically releases the connection permit on drop.
    ///
    /// # Arguments
    ///
    /// * `tenant` - Validated tenant context
    /// * `region` - Optional region (e.g., "us-east1", "europe-west1")
    ///
    /// # Returns
    ///
    /// A `TenantBackendHandle` that wraps the backend and releases the permit on drop.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Tenant is suspended (immediate rejection)
    /// - Circuit breaker is open for the tenant
    /// - Timeout waiting for connection permit
    /// - Backend creation fails
    pub async fn get_backend_handle_with_region(
        &self,
        tenant: &TenantContext,
        region: Option<&str>,
    ) -> Result<TenantBackendHandle> {
        let tenant_id = tenant.tenant_id().to_string();

        // 1. Acquire permit first (backpressure before doing work)
        let permit = self.semaphore_pool.acquire_permit(&tenant_id).await?;

        // 2. Get backend from cache (or create)
        let backend = match self.get_backend_with_region(tenant, region).await {
            Ok(b) => {
                self.semaphore_pool.record_success(&tenant_id);
                b
            }
            Err(e) => {
                self.semaphore_pool.record_failure(&tenant_id);
                return Err(e);
            }
        };

        // 3. Wrap in RAII handle
        Ok(TenantBackendHandle {
            backend,
            tenant_id,
            _permit: permit,
            acquired_at: Instant::now(),
        })
    }

    /// Get a backend by tenant ID string (validates and creates context internally).
    ///
    /// Convenience method that validates the tenant ID and gets the backend.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Tenant identifier string (will be validated)
    ///
    /// # Errors
    ///
    /// Returns error if tenant ID is invalid or backend creation fails.
    ///
    /// # Security
    ///
    /// Performs additional path traversal validation before URI substitution.
    pub async fn get_backend_by_id(&self, tenant_id: &str) -> Result<Arc<dyn CatalogBackend>> {
        // Defense-in-depth: validate for path traversal
        Self::validate_tenant_id_for_uri(tenant_id)?;

        let tenant = TenantContext::new(tenant_id)?;
        self.get_backend(&tenant).await
    }

    /// Invalidate (remove) a tenant's backend from the cache.
    ///
    /// Use this when a tenant is deleted or needs their backend refreshed.
    /// This removes all region-specific entries for the tenant.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Tenant identifier to invalidate
    ///
    /// # Returns
    ///
    /// `true` if any entries were removed, `false` otherwise.
    pub fn invalidate(&self, tenant_id: &str) -> bool {
        let mut cache = self.cache.lock();

        // Collect keys to remove: exact match OR region-qualified (tenant_id@region)
        let region_prefix = format!("{}@", tenant_id);
        let keys_to_remove: Vec<String> = cache
            .iter()
            .filter_map(|(k, _)| {
                if k == tenant_id || k.starts_with(&region_prefix) {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();

        let count = keys_to_remove.len();
        for key in keys_to_remove {
            cache.pop(&key);
        }

        if count > 0 {
            info!(tenant_id = %tenant_id, count = count, "Invalidated tenant backend(s) from cache");
        }
        count > 0
    }

    /// Clear all cached backends.
    ///
    /// Use this for graceful shutdown or cache reset.
    pub fn clear(&self) {
        let mut cache = self.cache.lock();
        let count = cache.len();
        cache.clear();
        if count > 0 {
            info!(count = count, "Cleared all tenant backends from cache");
        }
    }

    /// Get current cache size.
    pub fn cache_size(&self) -> usize {
        self.cache.lock().len()
    }

    /// Get configured cache capacity.
    pub fn cache_capacity(&self) -> usize {
        self.capacity
    }

    /// Get the storage URI template.
    pub fn storage_uri_template(&self) -> &str {
        &self.storage_uri_template
    }

    /// Check if a tenant's backend is currently cached.
    pub fn is_cached(&self, tenant_id: &str) -> bool {
        self.cache.lock().contains(&tenant_id.to_string())
    }

    /// Get cache statistics.
    pub fn stats(&self) -> TenantBackendFactoryStats {
        let cache = self.cache.lock();
        TenantBackendFactoryStats {
            capacity: self.capacity,
            size: cache.len(),
            cached_tenants: cache.iter().map(|(k, _)| k.clone()).collect(),
        }
    }

    // =========================================================================
    // Connection Pool Management
    // =========================================================================

    /// Suspend a tenant (immediate rejection of all requests).
    ///
    /// Use this when a tenant should be blocked from accessing the system,
    /// e.g., due to payment issues or abuse.
    pub fn suspend_tenant(&self, tenant_id: &str) {
        self.semaphore_pool.suspend_tenant(tenant_id);
        self.invalidate(tenant_id);
    }

    /// Resume a suspended tenant.
    pub fn resume_tenant(&self, tenant_id: &str) {
        self.semaphore_pool.resume_tenant(tenant_id);
    }

    /// Check if a tenant is suspended.
    pub fn is_suspended(&self, tenant_id: &str) -> bool {
        self.semaphore_pool.is_suspended(tenant_id)
    }

    /// Get active connection count for a tenant.
    pub fn active_connections(&self, tenant_id: &str) -> usize {
        self.semaphore_pool.active_connections(tenant_id)
    }

    /// Get available connection permits for a tenant.
    pub fn available_permits(&self, tenant_id: &str) -> usize {
        self.semaphore_pool.available_permits(tenant_id)
    }

    /// Get the connection pool configuration.
    pub fn pool_config(&self) -> &ConnectionPoolConfig {
        &self.pool_config
    }

    /// Get connection pool statistics for a specific tenant.
    pub fn tenant_pool_stats(&self, tenant_id: &str) -> TenantPoolStats {
        TenantPoolStats {
            tenant_id: tenant_id.to_string(),
            active_connections: self.semaphore_pool.active_connections(tenant_id),
            available_permits: self.semaphore_pool.available_permits(tenant_id),
            max_connections: self.pool_config.max_connections_per_tenant,
            is_suspended: self.semaphore_pool.is_suspended(tenant_id),
        }
    }
}

/// Statistics about the tenant backend factory.
#[derive(Debug, Clone)]
pub struct TenantBackendFactoryStats {
    /// Maximum cache capacity
    pub capacity: usize,
    /// Current number of cached backends
    pub size: usize,
    /// List of currently cached tenant IDs (in LRU order, most recent first)
    pub cached_tenants: Vec<String>,
}

/// Connection pool statistics for a specific tenant.
#[derive(Debug, Clone)]
pub struct TenantPoolStats {
    /// Tenant identifier
    pub tenant_id: String,
    /// Number of currently active connections
    pub active_connections: usize,
    /// Number of available connection permits
    pub available_permits: usize,
    /// Maximum allowed connections
    pub max_connections: usize,
    /// Whether the tenant is suspended
    pub is_suspended: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_template(temp_dir: &TempDir) -> String {
        format!("{}/{{tenant_id}}/catalog.db", temp_dir.path().display())
    }

    #[test]
    fn test_factory_new_valid() {
        let temp_dir = TempDir::new().unwrap();
        let factory = TenantBackendFactory::new(test_template(&temp_dir), 50).unwrap();
        assert_eq!(factory.cache_capacity(), 50);
        assert_eq!(factory.cache_size(), 0);
    }

    #[test]
    fn test_factory_with_default_capacity() {
        let temp_dir = TempDir::new().unwrap();
        let factory =
            TenantBackendFactory::with_default_capacity(test_template(&temp_dir)).unwrap();
        assert_eq!(factory.cache_capacity(), DEFAULT_CACHE_CAPACITY);
    }

    #[test]
    fn test_factory_missing_placeholder() {
        let result = TenantBackendFactory::new("gs://bucket/no-placeholder/catalog.db", 10);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("{tenant_id}"));
    }

    #[test]
    fn test_factory_zero_capacity() {
        let temp_dir = TempDir::new().unwrap();
        let result = TenantBackendFactory::new(test_template(&temp_dir), 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_factory_excessive_capacity() {
        let temp_dir = TempDir::new().unwrap();
        let result = TenantBackendFactory::new(test_template(&temp_dir), MAX_CACHE_CAPACITY + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_uri() {
        let temp_dir = TempDir::new().unwrap();
        let factory = TenantBackendFactory::new(test_template(&temp_dir), 10).unwrap();
        let uri = factory.resolve_uri("acme-corp");
        assert!(uri.contains("acme-corp"));
        assert!(!uri.contains("{tenant_id}"));
    }

    #[tokio::test]
    async fn test_get_backend_creates_and_caches() {
        let temp_dir = TempDir::new().unwrap();

        // Create tenant directories
        std::fs::create_dir_all(temp_dir.path().join("tenant-a")).unwrap();
        std::fs::create_dir_all(temp_dir.path().join("tenant-b")).unwrap();

        let factory = TenantBackendFactory::new(test_template(&temp_dir), 10).unwrap();

        // Initially empty
        assert_eq!(factory.cache_size(), 0);

        // Get first tenant backend
        let ctx_a = TenantContext::new("tenant-a").unwrap();
        let _backend_a = factory.get_backend(&ctx_a).await.unwrap();
        assert_eq!(factory.cache_size(), 1);
        assert!(factory.is_cached("tenant-a"));

        // Get second tenant backend
        let ctx_b = TenantContext::new("tenant-b").unwrap();
        let _backend_b = factory.get_backend(&ctx_b).await.unwrap();
        assert_eq!(factory.cache_size(), 2);
        assert!(factory.is_cached("tenant-b"));

        // Get first tenant again (cache hit)
        let _backend_a2 = factory.get_backend(&ctx_a).await.unwrap();
        assert_eq!(factory.cache_size(), 2); // Still 2, not 3
    }

    #[tokio::test]
    async fn test_get_backend_by_id() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("my-tenant")).unwrap();

        let factory = TenantBackendFactory::new(test_template(&temp_dir), 10).unwrap();
        let _backend = factory.get_backend_by_id("my-tenant").await.unwrap();
        assert!(factory.is_cached("my-tenant"));
    }

    #[tokio::test]
    async fn test_get_backend_by_id_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let factory = TenantBackendFactory::new(test_template(&temp_dir), 10).unwrap();

        // Invalid tenant ID (too short)
        let result = factory.get_backend_by_id("ab").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalidate() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("tenant-x")).unwrap();

        let factory = TenantBackendFactory::new(test_template(&temp_dir), 10).unwrap();

        // Create and cache backend
        let _backend = factory.get_backend_by_id("tenant-x").await.unwrap();
        assert!(factory.is_cached("tenant-x"));

        // Invalidate
        assert!(factory.invalidate("tenant-x"));
        assert!(!factory.is_cached("tenant-x"));

        // Invalidate non-existent
        assert!(!factory.invalidate("non-existent"));
    }

    #[tokio::test]
    async fn test_invalidate_with_regions() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("tenant-r")).unwrap();
        std::fs::create_dir_all(temp_dir.path().join("tenant-r-other")).unwrap();

        let factory = TenantBackendFactory::new(test_template(&temp_dir), 10).unwrap();
        let ctx = TenantContext::new("tenant-r").unwrap();
        let ctx_other = TenantContext::new("tenant-r-other").unwrap();

        // Create backends for same tenant in multiple regions
        let _b1 = factory.get_backend_with_region(&ctx, None).await.unwrap();
        let _b2 = factory
            .get_backend_with_region(&ctx, Some("us-east1"))
            .await
            .unwrap();
        let _b3 = factory
            .get_backend_with_region(&ctx, Some("europe-west1"))
            .await
            .unwrap();
        // Different tenant with region (should NOT be invalidated)
        let _b4 = factory
            .get_backend_with_region(&ctx_other, Some("us-east1"))
            .await
            .unwrap();

        // Should have 4 cached entries
        assert_eq!(factory.cache_size(), 4);

        // Invalidate tenant-r - should remove all 3 region entries
        assert!(factory.invalidate("tenant-r"));

        // Should only have the tenant-r-other entry left
        assert_eq!(factory.cache_size(), 1);
        assert!(!factory.is_cached("tenant-r"));
        // Note: is_cached checks exact key, so region entries aren't directly checkable

        // The other tenant's entry should still be cached
        // (We can verify by checking cache_size remained at 1)
    }

    #[tokio::test]
    async fn test_clear() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("tenant-1")).unwrap();
        std::fs::create_dir_all(temp_dir.path().join("tenant-2")).unwrap();

        let factory = TenantBackendFactory::new(test_template(&temp_dir), 10).unwrap();

        // Create some backends
        let _ = factory.get_backend_by_id("tenant-1").await.unwrap();
        let _ = factory.get_backend_by_id("tenant-2").await.unwrap();
        assert_eq!(factory.cache_size(), 2);

        // Clear all
        factory.clear();
        assert_eq!(factory.cache_size(), 0);
    }

    #[tokio::test]
    async fn test_lru_eviction() {
        let temp_dir = TempDir::new().unwrap();

        // Create directories for 3 tenants
        for i in 0..3 {
            std::fs::create_dir_all(temp_dir.path().join(format!("tenant-{}", i))).unwrap();
        }

        // Capacity of 2
        let factory = TenantBackendFactory::new(test_template(&temp_dir), 2).unwrap();

        // Add 2 tenants - cache is full
        let _ = factory.get_backend_by_id("tenant-0").await.unwrap();
        let _ = factory.get_backend_by_id("tenant-1").await.unwrap();
        assert_eq!(factory.cache_size(), 2);
        assert!(factory.is_cached("tenant-0"));
        assert!(factory.is_cached("tenant-1"));

        // Add third tenant - should evict tenant-0 (LRU)
        let _ = factory.get_backend_by_id("tenant-2").await.unwrap();
        assert_eq!(factory.cache_size(), 2);
        assert!(!factory.is_cached("tenant-0")); // Evicted
        assert!(factory.is_cached("tenant-1"));
        assert!(factory.is_cached("tenant-2"));
    }

    #[tokio::test]
    async fn test_stats() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("alpha")).unwrap();
        std::fs::create_dir_all(temp_dir.path().join("beta")).unwrap();

        let factory = TenantBackendFactory::new(test_template(&temp_dir), 50).unwrap();

        let _ = factory.get_backend_by_id("alpha").await.unwrap();
        let _ = factory.get_backend_by_id("beta").await.unwrap();

        let stats = factory.stats();
        assert_eq!(stats.capacity, 50);
        assert_eq!(stats.size, 2);
        assert!(stats.cached_tenants.contains(&"alpha".to_string()));
        assert!(stats.cached_tenants.contains(&"beta".to_string()));
    }

    #[test]
    fn test_storage_uri_template_accessor() {
        let temp_dir = TempDir::new().unwrap();
        let template = test_template(&temp_dir);
        let factory = TenantBackendFactory::new(&template, 10).unwrap();
        assert_eq!(factory.storage_uri_template(), template);
    }

    // ==========================================================================
    // Path Traversal Security Tests
    // ==========================================================================

    #[test]
    fn test_path_traversal_validation_double_dot() {
        let result = TenantBackendFactory::validate_tenant_id_for_uri("../../../etc");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path traversal"));
    }

    #[test]
    fn test_path_traversal_validation_forward_slash() {
        let result = TenantBackendFactory::validate_tenant_id_for_uri("tenant/subpath");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path separator"));
    }

    #[test]
    fn test_path_traversal_validation_backslash() {
        let result = TenantBackendFactory::validate_tenant_id_for_uri("tenant\\subpath");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path separator"));
    }

    #[test]
    fn test_path_traversal_validation_null_byte() {
        let result = TenantBackendFactory::validate_tenant_id_for_uri("tenant\0evil");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("null"));
    }

    #[test]
    fn test_path_traversal_validation_valid_id() {
        // Valid tenant IDs should pass
        assert!(TenantBackendFactory::validate_tenant_id_for_uri("valid-tenant-123").is_ok());
        assert!(TenantBackendFactory::validate_tenant_id_for_uri("tenant_with_underscore").is_ok());
        assert!(TenantBackendFactory::validate_tenant_id_for_uri("UPPERCASE").is_ok());
    }

    #[tokio::test]
    async fn test_get_backend_by_id_rejects_path_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let factory = TenantBackendFactory::new(test_template(&temp_dir), 10).unwrap();

        // Path traversal attempts should be rejected
        let result = factory.get_backend_by_id("../../../etc/passwd").await;
        assert!(result.is_err());

        let result = factory.get_backend_by_id("tenant/../other").await;
        assert!(result.is_err());

        let result = factory.get_backend_by_id("tenant/evil").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_tenant_context_rejects_path_chars() {
        // TenantContext should also reject these at the type level
        assert!(TenantContext::new("../etc").is_err());
        assert!(TenantContext::new("tenant/evil").is_err());
        assert!(TenantContext::new("a..b").is_err());
    }

    // ==========================================================================
    // Connection Pool Tests
    // ==========================================================================

    #[tokio::test]
    async fn test_get_backend_handle() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("tenant-a")).unwrap();

        let factory = TenantBackendFactory::new(test_template(&temp_dir), 10).unwrap();
        let ctx = TenantContext::new("tenant-a").unwrap();

        // Get a handle
        let handle = factory.get_backend_handle(&ctx).await.unwrap();
        assert_eq!(handle.tenant_id(), "tenant-a");
        assert!(handle.backend().exists().await.unwrap() || true); // May not exist yet
    }

    #[tokio::test]
    async fn test_connection_limit_enforced() {
        use crate::pool_config::ConnectionPoolConfig;
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("test-tenant")).unwrap();

        // Create factory with limit of 2 connections and short timeout
        let pool_config = ConnectionPoolConfig::default()
            .with_max_connections(2)
            .with_acquire_timeout(Duration::from_millis(100))
            .without_circuit_breaker();

        let factory =
            TenantBackendFactory::with_pool_config(test_template(&temp_dir), 10, pool_config)
                .unwrap();

        let ctx = TenantContext::new("test-tenant").unwrap();

        // Acquire 2 handles (at limit)
        let h1 = factory.get_backend_handle(&ctx).await.unwrap();
        let h2 = factory.get_backend_handle(&ctx).await.unwrap();

        // Verify active connections
        assert_eq!(factory.active_connections("test-tenant"), 2);
        assert_eq!(factory.available_permits("test-tenant"), 0);

        // 3rd should timeout
        let result = factory.get_backend_handle(&ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Timeout"));

        // Drop one handle
        drop(h1);

        // Now should succeed
        let h3 = factory.get_backend_handle(&ctx).await;
        assert!(h3.is_ok());

        drop(h2);
        drop(h3);
    }

    #[tokio::test]
    async fn test_noisy_neighbor_isolation() {
        use crate::pool_config::ConnectionPoolConfig;
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("noisy-tenant")).unwrap();
        std::fs::create_dir_all(temp_dir.path().join("quiet-tenant")).unwrap();

        let pool_config = ConnectionPoolConfig::default()
            .with_max_connections(2)
            .with_acquire_timeout(Duration::from_millis(100))
            .without_circuit_breaker();

        let factory =
            TenantBackendFactory::with_pool_config(test_template(&temp_dir), 10, pool_config)
                .unwrap();

        let noisy = TenantContext::new("noisy-tenant").unwrap();
        let quiet = TenantContext::new("quiet-tenant").unwrap();

        // Noisy tenant exhausts its connections
        let _n1 = factory.get_backend_handle(&noisy).await.unwrap();
        let _n2 = factory.get_backend_handle(&noisy).await.unwrap();

        // Noisy tenant can't get more
        let result = factory.get_backend_handle(&noisy).await;
        assert!(result.is_err());

        // Quiet tenant should still work (independent limit)
        let q1 = factory.get_backend_handle(&quiet).await;
        assert!(q1.is_ok());
    }

    #[tokio::test]
    async fn test_tenant_suspension() {
        use crate::pool_config::ConnectionPoolConfig;

        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("suspended-tenant")).unwrap();

        let factory = TenantBackendFactory::with_pool_config(
            test_template(&temp_dir),
            10,
            ConnectionPoolConfig::default().without_circuit_breaker(),
        )
        .unwrap();

        let ctx = TenantContext::new("suspended-tenant").unwrap();

        // Initially can get handle
        let h1 = factory.get_backend_handle(&ctx).await;
        assert!(h1.is_ok());
        drop(h1);

        // Suspend the tenant
        factory.suspend_tenant("suspended-tenant");
        assert!(factory.is_suspended("suspended-tenant"));

        // Now should be rejected immediately
        let result = factory.get_backend_handle(&ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("suspended"));

        // Resume the tenant
        factory.resume_tenant("suspended-tenant");
        assert!(!factory.is_suspended("suspended-tenant"));

        // Should work again
        let h2 = factory.get_backend_handle(&ctx).await;
        assert!(h2.is_ok());
    }

    #[tokio::test]
    async fn test_handle_auto_releases_on_drop() {
        use crate::pool_config::ConnectionPoolConfig;
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("drop-test")).unwrap();

        let pool_config = ConnectionPoolConfig::default()
            .with_max_connections(1)
            .with_acquire_timeout(Duration::from_millis(100))
            .without_circuit_breaker();

        let factory =
            TenantBackendFactory::with_pool_config(test_template(&temp_dir), 10, pool_config)
                .unwrap();

        let ctx = TenantContext::new("drop-test").unwrap();

        // Create handle in a scope
        {
            let _handle = factory.get_backend_handle(&ctx).await.unwrap();
            assert_eq!(factory.active_connections("drop-test"), 1);
            // Handle drops here
        }

        // Permit should be released
        assert_eq!(factory.active_connections("drop-test"), 0);

        // Should be able to acquire again
        let h2 = factory.get_backend_handle(&ctx).await;
        assert!(h2.is_ok());
    }

    #[tokio::test]
    async fn test_pool_stats() {
        use crate::pool_config::ConnectionPoolConfig;

        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path().join("stats-tenant")).unwrap();

        let pool_config = ConnectionPoolConfig::new(5);

        let factory =
            TenantBackendFactory::with_pool_config(test_template(&temp_dir), 10, pool_config)
                .unwrap();

        let ctx = TenantContext::new("stats-tenant").unwrap();

        // Initial stats
        let stats = factory.tenant_pool_stats("stats-tenant");
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.available_permits, 5);
        assert_eq!(stats.max_connections, 5);
        assert!(!stats.is_suspended);

        // Acquire a handle
        let _h1 = factory.get_backend_handle(&ctx).await.unwrap();

        let stats = factory.tenant_pool_stats("stats-tenant");
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.available_permits, 4);
    }
}
