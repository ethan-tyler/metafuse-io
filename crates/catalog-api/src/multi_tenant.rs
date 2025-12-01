// Allow dead_code for public API items used by library consumers
// (multi-tenant building blocks, region support, backend wrappers)
#![allow(dead_code)]

//! Multi-Tenant Integration Layer
//!
//! This module provides the glue code for integrating multi-tenancy into the API server.
//! It includes:
//! - Extended application state with tenant support
//! - Middleware for injecting tenant-specific backends
//! - Helper functions for handlers to get the appropriate backend
//!
//! # Architecture
//!
//! ```text
//! Request → Tenant Resolution → Backend Injection → Handler
//!                  ↓                    ↓
//!           ResolvedTenant      TenantBackend (or default)
//! ```
//!
//! # Backward Compatibility
//!
//! When multi-tenancy is disabled or no tenant is resolved:
//! - Requests use the default backend configured at startup
//! - All existing handlers continue to work unchanged
//!
//! # Usage
//!
//! ```rust,ignore
//! use metafuse_catalog_api::multi_tenant::{MultiTenantState, get_backend};
//!
//! async fn my_handler(
//!     State(state): State<MultiTenantState>,
//!     Extension(request_id): Extension<RequestId>,
//!     tenant: Option<Extension<ResolvedTenant>>,
//! ) -> Result<Json<Response>, Error> {
//!     let backend = get_backend(&state, tenant.as_ref()).await?;
//!     let conn = backend.get_connection().await?;
//!     // ... use connection
//! }
//! ```

use metafuse_catalog_core::Result;
use metafuse_catalog_storage::{
    CatalogBackend, TenantBackendFactory, TenantBackendHandle, TenantContext,
};
use std::sync::Arc;

#[cfg(feature = "api-keys")]
use crate::control_plane::ControlPlane;
#[cfg(feature = "api-keys")]
use crate::tenant_resolver::ResolvedTenant;

/// Configuration for multi-tenant mode.
#[derive(Debug, Clone)]
pub struct MultiTenantConfig {
    /// Enable multi-tenant mode
    pub enabled: bool,
    /// Storage URI template for tenant catalogs (must contain {tenant_id})
    pub storage_uri_template: String,
    /// Maximum number of tenant backends to cache
    pub cache_capacity: usize,
    /// Path to the control plane database
    pub control_plane_db_path: String,
    /// Allow header-only tenant resolution (X-Tenant-ID without API key).
    ///
    /// **Security Warning**: When enabled, any request can specify a tenant via header,
    /// which is only safe in trusted internal networks. In production with external
    /// traffic, this should be `false` to require API key authentication.
    ///
    /// Default: `false` (require API key for tenant resolution)
    /// Reserved for main.rs integration in a future phase.
    #[allow(dead_code)]
    pub allow_header_only_resolution: bool,
}

impl Default for MultiTenantConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage_uri_template: String::new(),
            cache_capacity: 100,
            control_plane_db_path: "control_plane.db".to_string(),
            allow_header_only_resolution: false, // Secure default
        }
    }
}

impl MultiTenantConfig {
    /// Create config from environment variables.
    ///
    /// Reads:
    /// - `METAFUSE_MULTI_TENANT_ENABLED`: "true" to enable
    /// - `METAFUSE_TENANT_STORAGE_TEMPLATE`: URI template with {tenant_id}
    /// - `METAFUSE_TENANT_CACHE_CAPACITY`: Max cached backends (default: 100)
    /// - `METAFUSE_CONTROL_PLANE_DB`: Path to control plane database
    /// - `METAFUSE_ALLOW_HEADER_ONLY_RESOLUTION`: "true" to allow X-Tenant-ID without API key
    ///   (default: false for security)
    pub fn from_env() -> Self {
        let enabled = std::env::var("METAFUSE_MULTI_TENANT_ENABLED")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        let storage_uri_template =
            std::env::var("METAFUSE_TENANT_STORAGE_TEMPLATE").unwrap_or_default();

        let cache_capacity = std::env::var("METAFUSE_TENANT_CACHE_CAPACITY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let control_plane_db_path = std::env::var("METAFUSE_CONTROL_PLANE_DB")
            .unwrap_or_else(|_| "control_plane.db".to_string());

        // Header-only resolution disabled by default for security
        let allow_header_only_resolution = std::env::var("METAFUSE_ALLOW_HEADER_ONLY_RESOLUTION")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            enabled,
            storage_uri_template,
            cache_capacity,
            control_plane_db_path,
            allow_header_only_resolution,
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.enabled && !self.storage_uri_template.contains("{tenant_id}") {
            return Err(metafuse_catalog_core::CatalogError::ValidationError(
                "METAFUSE_TENANT_STORAGE_TEMPLATE must contain {tenant_id} when multi-tenant is enabled".into()
            ));
        }
        Ok(())
    }
}

/// Extension providing tenant-specific backend.
///
/// This is injected into request extensions by the tenant backend middleware.
/// Handlers can extract this to use the tenant-specific backend.
#[derive(Clone)]
pub struct TenantBackend {
    backend: Arc<dyn CatalogBackend>,
    tenant_id: String,
    /// Region for multi-region deployments (e.g., "us-east1", "europe-west1").
    region: Option<String>,
}

impl TenantBackend {
    /// Create a new tenant backend wrapper.
    /// Reserved for direct instantiation in future multi-tenant handlers.
    #[allow(dead_code)]
    pub fn new(backend: Arc<dyn CatalogBackend>, tenant_id: impl Into<String>) -> Self {
        Self {
            backend,
            tenant_id: tenant_id.into(),
            region: None,
        }
    }

    /// Create a new tenant backend wrapper with region.
    pub fn with_region(
        backend: Arc<dyn CatalogBackend>,
        tenant_id: impl Into<String>,
        region: Option<String>,
    ) -> Self {
        Self {
            backend,
            tenant_id: tenant_id.into(),
            region,
        }
    }

    /// Create from a connection handle (extracts the backend reference).
    ///
    /// Note: The handle should be stored separately in request extensions
    /// to keep the connection permit alive for the request duration.
    pub fn from_handle(handle: &TenantBackendHandle) -> Self {
        Self {
            backend: Arc::clone(handle.backend()),
            tenant_id: handle.tenant_id().to_string(),
            region: None,
        }
    }

    /// Create from a connection handle with region.
    pub fn from_handle_with_region(handle: &TenantBackendHandle, region: Option<String>) -> Self {
        Self {
            backend: Arc::clone(handle.backend()),
            tenant_id: handle.tenant_id().to_string(),
            region,
        }
    }

    /// Get the backend.
    pub fn backend(&self) -> &Arc<dyn CatalogBackend> {
        &self.backend
    }

    /// Get the tenant ID.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Get the region.
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// Get an owned Arc to the backend.
    /// Reserved for consuming the wrapper in migration scenarios.
    #[allow(dead_code)]
    pub fn into_backend(self) -> Arc<dyn CatalogBackend> {
        self.backend
    }
}

/// Holds the connection permit for the duration of a request.
///
/// This is stored in request extensions to ensure the permit stays alive
/// until the response is sent. Wrapped in Arc to satisfy Extension's Clone requirement.
#[derive(Clone)]
#[cfg(feature = "api-keys")]
pub struct TenantConnectionPermit {
    _handle: Arc<TenantBackendHandle>,
}

#[cfg(feature = "api-keys")]
impl TenantConnectionPermit {
    /// Create a permit holder from a backend handle.
    pub fn new(handle: TenantBackendHandle) -> Self {
        Self {
            _handle: Arc::new(handle),
        }
    }
}

/// Multi-tenant application state.
///
/// Extends the basic application state with optional multi-tenant support.
/// When multi-tenant mode is disabled, the factory and control plane are None.
#[derive(Clone)]
pub struct MultiTenantResources {
    /// Tenant backend factory (None if multi-tenant disabled)
    factory: Option<Arc<TenantBackendFactory>>,
    /// Control plane for tenant management (None if multi-tenant disabled)
    #[cfg(feature = "api-keys")]
    control_plane: Option<Arc<ControlPlane>>,
}

impl MultiTenantResources {
    /// Create multi-tenant resources from configuration.
    pub async fn new(config: &MultiTenantConfig) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                factory: None,
                #[cfg(feature = "api-keys")]
                control_plane: None,
            });
        }

        let factory =
            TenantBackendFactory::new(&config.storage_uri_template, config.cache_capacity)?;

        #[cfg(feature = "api-keys")]
        let control_plane = ControlPlane::new(
            config.control_plane_db_path.clone(),
            config.storage_uri_template.clone(),
        )?;

        Ok(Self {
            factory: Some(Arc::new(factory)),
            #[cfg(feature = "api-keys")]
            control_plane: Some(Arc::new(control_plane)),
        })
    }

    /// Check if multi-tenant mode is enabled.
    pub fn is_enabled(&self) -> bool {
        self.factory.is_some()
    }

    /// Get the tenant backend factory.
    pub fn factory(&self) -> Option<&Arc<TenantBackendFactory>> {
        self.factory.as_ref()
    }

    /// Get the control plane.
    #[cfg(feature = "api-keys")]
    pub fn control_plane(&self) -> Option<&Arc<ControlPlane>> {
        self.control_plane.as_ref()
    }

    /// Get backend for a tenant with connection limiting.
    ///
    /// Returns the tenant-specific backend handle if multi-tenant is enabled,
    /// or None to indicate the caller should use the default backend.
    ///
    /// The returned handle maintains a connection permit that is released when dropped.
    /// Reserved for main.rs handler integration in a future phase.
    #[allow(dead_code)]
    pub async fn get_tenant_backend(
        &self,
        tenant: &TenantContext,
    ) -> Result<Option<TenantBackendHandle>> {
        match &self.factory {
            Some(factory) => {
                let handle = factory.get_backend_handle(tenant).await?;
                Ok(Some(handle))
            }
            None => Ok(None),
        }
    }

    /// Get backend for a tenant (deprecated, use get_tenant_backend instead).
    ///
    /// This method bypasses connection limiting.
    #[deprecated(
        since = "0.5.0",
        note = "Use get_tenant_backend() which returns a connection-limited handle"
    )]
    #[allow(dead_code)]
    pub async fn get_tenant_backend_unchecked(
        &self,
        tenant: &TenantContext,
    ) -> Result<Option<Arc<dyn CatalogBackend>>> {
        match &self.factory {
            Some(factory) => {
                let backend = factory.get_backend(tenant).await?;
                Ok(Some(backend))
            }
            None => Ok(None),
        }
    }

    /// Invalidate a tenant's cached backend.
    ///
    /// Call this when a tenant's status changes (suspended, deleted, etc.)
    /// to ensure subsequent requests create a fresh backend or are rejected.
    ///
    /// # Returns
    ///
    /// `true` if the tenant was in the cache and removed, `false` otherwise.
    /// Reserved for tenant lifecycle management integration.
    #[allow(dead_code)]
    pub fn invalidate_tenant_cache(&self, tenant_id: &str) -> bool {
        match &self.factory {
            Some(factory) => {
                let removed = factory.invalidate(tenant_id);
                if removed {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        "Invalidated tenant backend cache due to status change"
                    );
                }
                removed
            }
            None => false,
        }
    }

    /// Clear all cached tenant backends.
    ///
    /// Use during graceful shutdown or when needing to refresh all connections.
    /// Reserved for graceful shutdown integration.
    #[allow(dead_code)]
    pub fn clear_all_caches(&self) {
        if let Some(factory) = &self.factory {
            factory.clear();
            tracing::info!("Cleared all tenant backend caches");
        }
    }

    /// Get cache statistics.
    /// Reserved for /metrics endpoint integration.
    #[allow(dead_code)]
    pub fn cache_stats(&self) -> Option<(usize, usize)> {
        self.factory
            .as_ref()
            .map(|f| (f.cache_size(), f.cache_capacity()))
    }
}

/// Helper to get the appropriate backend for a request.
///
/// Priority:
/// 1. If `TenantBackend` is in extensions (from middleware), use it
/// 2. Otherwise use the default backend
///
/// # Arguments
///
/// * `default_backend` - The default shared backend
/// * `tenant_backend` - Optional tenant backend from request extensions
///
/// # Returns
///
/// An Arc to the appropriate backend for this request.
pub fn resolve_backend(
    default_backend: &Arc<dyn CatalogBackend>,
    tenant_backend: Option<&TenantBackend>,
) -> Arc<dyn CatalogBackend> {
    match tenant_backend {
        Some(tb) => Arc::clone(tb.backend()),
        None => Arc::clone(default_backend),
    }
}

/// Error response type for RBAC permission checks.
///
/// This matches the ErrorResponse used in main.rs handlers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RbacErrorResponse {
    pub error: String,
    pub request_id: String,
}

/// Get the tenant ID for logging, preferring ResolvedTenant over TenantBackend.
///
/// This ensures audit logs reflect the authenticated tenant identity, not just
/// the storage handle. Falls back to "default" when running in single-tenant mode.
/// Reserved for audit logging integration in handlers.
#[cfg(feature = "api-keys")]
#[allow(dead_code)]
pub fn get_tenant_id_for_logging<'a>(
    resolved_tenant: Option<&'a ResolvedTenant>,
    tenant_backend: Option<&'a TenantBackend>,
) -> &'a str {
    if let Some(tenant) = resolved_tenant {
        tenant.tenant_id()
    } else if let Some(tb) = tenant_backend {
        tb.tenant_id()
    } else {
        "default"
    }
}

/// Get the tenant ID for logging (non-api-keys feature version).
/// Reserved for audit logging integration in handlers.
#[cfg(not(feature = "api-keys"))]
#[allow(dead_code)]
pub fn get_tenant_id_for_logging<'a>(
    _resolved_tenant: Option<&'a ()>,
    tenant_backend: Option<&'a TenantBackend>,
) -> &'a str {
    if let Some(tb) = tenant_backend {
        tb.tenant_id()
    } else {
        "default"
    }
}

/// Check if the request has write permission in multi-tenant mode.
///
/// Returns Ok(()) if:
/// - Multi-tenant mode is disabled (no ResolvedTenant present), OR
/// - The ResolvedTenant has write permission (Editor or Admin role)
///
/// Returns Err with a 403 Forbidden response if write permission is denied.
#[cfg(feature = "api-keys")]
pub fn require_write_permission(
    resolved_tenant: Option<&ResolvedTenant>,
    request_id: &str,
) -> std::result::Result<(), (axum::http::StatusCode, axum::Json<RbacErrorResponse>)> {
    if let Some(tenant) = resolved_tenant {
        if !tenant.can_write() {
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(RbacErrorResponse {
                    error: "Write permission denied. Requires Editor or Admin role.".to_string(),
                    request_id: request_id.to_string(),
                }),
            ));
        }
    }
    Ok(())
}

/// Check if the request has delete permission in multi-tenant mode.
///
/// Returns Ok(()) if:
/// - Multi-tenant mode is disabled (no ResolvedTenant present), OR
/// - The ResolvedTenant has delete permission (Admin role)
///
/// Returns Err with a 403 Forbidden response if delete permission is denied.
#[cfg(feature = "api-keys")]
pub fn require_delete_permission(
    resolved_tenant: Option<&ResolvedTenant>,
    request_id: &str,
) -> std::result::Result<(), (axum::http::StatusCode, axum::Json<RbacErrorResponse>)> {
    if let Some(tenant) = resolved_tenant {
        if !tenant.can_delete() {
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(RbacErrorResponse {
                    error: "Delete permission denied. Requires Admin role.".to_string(),
                    request_id: request_id.to_string(),
                }),
            ));
        }
    }
    Ok(())
}

/// Check if the request has API key management permission in multi-tenant mode.
///
/// Returns Ok(()) if:
/// - Multi-tenant mode is disabled (no ResolvedTenant present), OR
/// - The ResolvedTenant has key management permission (Admin role)
///
/// Returns Err with a 403 Forbidden response if permission is denied.
/// Reserved for tenant API key management endpoints.
#[cfg(feature = "api-keys")]
#[allow(dead_code)]
pub fn require_admin_permission(
    resolved_tenant: Option<&ResolvedTenant>,
    request_id: &str,
) -> std::result::Result<(), (axum::http::StatusCode, axum::Json<RbacErrorResponse>)> {
    if let Some(tenant) = resolved_tenant {
        if !tenant.can_manage_keys() {
            return Err((
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(RbacErrorResponse {
                    error: "Admin permission denied. Requires Admin role.".to_string(),
                    request_id: request_id.to_string(),
                }),
            ));
        }
    }
    Ok(())
}

/// Middleware to inject tenant-specific backend into request extensions.
///
/// This middleware:
/// 1. Checks for ResolvedTenant in extensions (from tenant_resolver_middleware)
/// 2. If present, acquires a connection-limited backend handle from the factory
/// 3. Injects TenantBackend (for handler access) and TenantConnectionPermit (for permit lifetime)
///
/// The connection permit is automatically released when the request completes.
/// Supports multi-region deployments by passing the tenant's region to the factory.
///
/// # Error Responses
///
/// - 503 Service Unavailable: Connection limit reached or circuit breaker open
/// - 403 Forbidden: Tenant is suspended
/// - 500 Internal Server Error: Backend creation failed
///
/// Requires:
/// - TenantBackendFactory as Extension
/// - tenant_resolver_middleware to run first
#[cfg(feature = "api-keys")]
pub async fn tenant_backend_middleware(
    axum::extract::Extension(factory): axum::extract::Extension<Arc<TenantBackendFactory>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Check if tenant was resolved
    if let Some(resolved) = req.extensions().get::<ResolvedTenant>().cloned() {
        // Get tenant region for multi-region deployments
        let region = resolved.region().map(String::from);

        // Get connection-limited backend handle with region
        match factory
            .get_backend_handle_with_region(resolved.context(), region.as_deref())
            .await
        {
            Ok(handle) => {
                let tenant_backend =
                    TenantBackend::from_handle_with_region(&handle, region.clone());
                let permit = TenantConnectionPermit::new(handle);

                // Insert both: TenantBackend for handler access, permit for lifetime
                req.extensions_mut().insert(tenant_backend);
                req.extensions_mut().insert(permit);

                tracing::debug!(
                    tenant_id = %resolved.tenant_id(),
                    region = ?region,
                    "Injected tenant backend with connection permit"
                );
            }
            Err(e) => {
                let error_msg = e.to_string();
                tracing::error!(
                    tenant_id = %resolved.tenant_id(),
                    region = ?region,
                    error = %error_msg,
                    "Failed to get tenant backend"
                );

                // Return appropriate error response based on error type
                if error_msg.contains("suspended") {
                    return axum::response::Response::builder()
                        .status(axum::http::StatusCode::FORBIDDEN)
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(
                            r#"{"error": "Tenant is suspended"}"#,
                        ))
                        .unwrap();
                } else if error_msg.contains("Timeout") || error_msg.contains("Circuit breaker") {
                    return axum::response::Response::builder()
                        .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .header(axum::http::header::RETRY_AFTER, "5")
                        .body(axum::body::Body::from(
                            r#"{"error": "Service temporarily overloaded", "retry_after": 5}"#,
                        ))
                        .unwrap();
                } else {
                    return axum::response::Response::builder()
                        .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(format!(
                            r#"{{"error": "Failed to initialize tenant backend", "details": "{}"}}"#,
                            error_msg
                        )))
                        .unwrap();
                }
            }
        }
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env_defaults() {
        // Clear any existing env vars
        std::env::remove_var("METAFUSE_MULTI_TENANT_ENABLED");
        std::env::remove_var("METAFUSE_TENANT_STORAGE_TEMPLATE");
        std::env::remove_var("METAFUSE_TENANT_CACHE_CAPACITY");
        std::env::remove_var("METAFUSE_CONTROL_PLANE_DB");
        std::env::remove_var("METAFUSE_ALLOW_HEADER_ONLY_RESOLUTION");

        let config = MultiTenantConfig::from_env();
        assert!(!config.enabled);
        assert!(config.storage_uri_template.is_empty());
        assert_eq!(config.cache_capacity, 100);
        assert_eq!(config.control_plane_db_path, "control_plane.db");
        assert!(!config.allow_header_only_resolution); // Secure default
    }

    #[test]
    fn test_config_validate_enabled_without_template() {
        let config = MultiTenantConfig {
            enabled: true,
            storage_uri_template: "invalid".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_enabled_with_template() {
        let config = MultiTenantConfig {
            enabled: true,
            storage_uri_template: "/data/{tenant_id}/catalog.db".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_disabled() {
        let config = MultiTenantConfig::default();
        assert!(config.validate().is_ok());
    }

    #[cfg(feature = "tempfile")]
    #[test]
    fn test_tenant_backend_accessors() {
        use metafuse_catalog_storage::LocalSqliteBackend;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test.db");
        let backend: Arc<dyn CatalogBackend> = Arc::new(LocalSqliteBackend::new(&path));

        let tb = TenantBackend::new(Arc::clone(&backend), "test-tenant");
        assert_eq!(tb.tenant_id(), "test-tenant");
        assert!(Arc::ptr_eq(tb.backend(), &backend));
    }

    #[tokio::test]
    async fn test_multi_tenant_resources_disabled() {
        let config = MultiTenantConfig::default();
        let resources = MultiTenantResources::new(&config).await.unwrap();
        assert!(!resources.is_enabled());
        assert!(resources.factory().is_none());
    }

    #[cfg(feature = "tempfile")]
    #[tokio::test]
    async fn test_multi_tenant_resources_enabled() {
        let temp = tempfile::TempDir::new().unwrap();
        let config = MultiTenantConfig {
            enabled: true,
            storage_uri_template: format!("{}/{{tenant_id}}/catalog.db", temp.path().display()),
            cache_capacity: 50,
            control_plane_db_path: temp.path().join("control.db").to_string_lossy().to_string(),
            allow_header_only_resolution: false,
        };

        let resources = MultiTenantResources::new(&config).await.unwrap();
        assert!(resources.is_enabled());
        assert!(resources.factory().is_some());
    }

    #[cfg(feature = "tempfile")]
    #[test]
    fn test_resolve_backend_with_tenant() {
        use metafuse_catalog_storage::LocalSqliteBackend;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();

        let default_backend: Arc<dyn CatalogBackend> =
            Arc::new(LocalSqliteBackend::new(temp.path().join("default.db")));
        let tenant_backend: Arc<dyn CatalogBackend> =
            Arc::new(LocalSqliteBackend::new(temp.path().join("tenant.db")));

        let tb = TenantBackend::new(tenant_backend.clone(), "test");
        let resolved = resolve_backend(&default_backend, Some(&tb));

        // Should return tenant backend, not default
        assert!(Arc::ptr_eq(&resolved, &tenant_backend));
        assert!(!Arc::ptr_eq(&resolved, &default_backend));
    }

    #[cfg(feature = "tempfile")]
    #[test]
    fn test_resolve_backend_without_tenant() {
        use metafuse_catalog_storage::LocalSqliteBackend;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();

        let default_backend: Arc<dyn CatalogBackend> =
            Arc::new(LocalSqliteBackend::new(temp.path().join("default.db")));

        let resolved = resolve_backend(&default_backend, None);
        assert!(Arc::ptr_eq(&resolved, &default_backend));
    }

    #[cfg(feature = "tempfile")]
    #[tokio::test]
    async fn test_cache_invalidation() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path().join("tenant-a")).unwrap();

        let config = MultiTenantConfig {
            enabled: true,
            storage_uri_template: format!("{}/{{tenant_id}}/catalog.db", temp.path().display()),
            cache_capacity: 50,
            control_plane_db_path: temp.path().join("control.db").to_string_lossy().to_string(),
            allow_header_only_resolution: false,
        };

        let resources = MultiTenantResources::new(&config).await.unwrap();

        // Get a tenant backend (caches it)
        let ctx = TenantContext::new("tenant-a").unwrap();
        let _backend = resources.get_tenant_backend(&ctx).await.unwrap();

        // Verify it's cached
        let (size, _cap) = resources.cache_stats().unwrap();
        assert_eq!(size, 1);

        // Invalidate the tenant
        assert!(resources.invalidate_tenant_cache("tenant-a"));

        // Verify it's removed
        let (size, _cap) = resources.cache_stats().unwrap();
        assert_eq!(size, 0);

        // Invalidating non-existent tenant returns false
        assert!(!resources.invalidate_tenant_cache("non-existent"));
    }

    #[cfg(feature = "tempfile")]
    #[tokio::test]
    async fn test_clear_all_caches() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path().join("tenant-a")).unwrap();
        std::fs::create_dir_all(temp.path().join("tenant-b")).unwrap();

        let config = MultiTenantConfig {
            enabled: true,
            storage_uri_template: format!("{}/{{tenant_id}}/catalog.db", temp.path().display()),
            cache_capacity: 50,
            control_plane_db_path: temp.path().join("control.db").to_string_lossy().to_string(),
            allow_header_only_resolution: false,
        };

        let resources = MultiTenantResources::new(&config).await.unwrap();

        // Cache multiple tenants
        let _a = resources
            .get_tenant_backend(&TenantContext::new("tenant-a").unwrap())
            .await
            .unwrap();
        let _b = resources
            .get_tenant_backend(&TenantContext::new("tenant-b").unwrap())
            .await
            .unwrap();

        let (size, _) = resources.cache_stats().unwrap();
        assert_eq!(size, 2);

        // Clear all
        resources.clear_all_caches();

        let (size, _) = resources.cache_stats().unwrap();
        assert_eq!(size, 0);
    }

    #[test]
    fn test_cache_stats_disabled() {
        let resources = MultiTenantResources {
            factory: None,
            #[cfg(feature = "api-keys")]
            control_plane: None,
        };

        // When disabled, cache stats returns None
        assert!(resources.cache_stats().is_none());
        // Invalidation returns false
        assert!(!resources.invalidate_tenant_cache("any"));
    }
}
