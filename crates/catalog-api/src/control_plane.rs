//! Control Plane for Multi-Tenant Management
//!
//! Provides tenant lifecycle management, tenant-scoped API keys, and audit logging
//! for control plane operations. This module operates on the control plane database,
//! which is separate from per-tenant data catalogs.
//!
//! # Architecture
//!
//! ```text
//! Control Plane DB                Per-Tenant Catalogs
//! ┌──────────────────┐           ┌──────────────────┐
//! │ tenants          │──────────▶│ tenant-a/catalog │
//! │ tenant_api_keys  │           ├──────────────────┤
//! │ tenant_audit_log │           │ tenant-b/catalog │
//! └──────────────────┘           └──────────────────┘
//! ```
//!
//! # Security Model
//!
//! - **Platform Admin**: Can create, suspend, delete tenants; manage all API keys
//! - **Tenant Admin**: Can manage API keys for their own tenant
//! - **Editor/Viewer**: No control plane access
//!
//! # Usage
//!
//! ```rust,ignore
//! use metafuse_catalog_api::control_plane::{ControlPlane, CreateTenantRequest};
//!
//! let control_plane = ControlPlane::new("control_plane.db", "gs://bucket/tenants/{tenant_id}/catalog.db")?;
//!
//! // Create a new tenant
//! let tenant = control_plane.create_tenant(CreateTenantRequest {
//!     tenant_id: "acme-corp".to_string(),
//!     display_name: "Acme Corporation".to_string(),
//!     admin_email: "admin@acme.com".to_string(),
//!     tier: Some("premium".to_string()),
//! }, "platform-admin@example.com").await?;
//! ```

use metafuse_catalog_core::{CatalogError, Result};
use metafuse_catalog_storage::{TenantContext, TenantStatus, TenantTier};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[cfg(feature = "api-keys")]
use bcrypt::{hash, verify};
#[cfg(feature = "api-keys")]
use dashmap::DashMap;
#[cfg(feature = "api-keys")]
use rand::RngCore;
#[cfg(feature = "api-keys")]
use std::collections::hash_map::DefaultHasher;
#[cfg(feature = "api-keys")]
use std::hash::{Hash, Hasher};
#[cfg(feature = "api-keys")]
use std::sync::Arc;
#[cfg(feature = "api-keys")]
use std::time::{Duration, Instant};
#[cfg(feature = "api-keys")]
use tracing::debug;

/// Default bcrypt cost for API key hashing.
#[cfg(feature = "api-keys")]
const DEFAULT_BCRYPT_COST: u32 = 12;

/// Default API key prefix for tenant keys.
#[cfg(feature = "api-keys")]
const DEFAULT_API_KEY_PREFIX: &str = "mft_"; // "mft_" for tenant keys vs "mf_" for global

/// Cache TTL for API key validation.
#[cfg(feature = "api-keys")]
const CACHE_TTL_SECS: u64 = 300;

/// Role-based access control for tenant API keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TenantRole {
    /// Full access to tenant data + can manage API keys
    Admin,
    /// CRUD on datasets, lineage, tags
    Editor,
    /// Read-only access
    #[default]
    Viewer,
}

impl TenantRole {
    /// Get role as string.
    pub fn as_str(&self) -> &'static str {
        match self {
            TenantRole::Admin => "admin",
            TenantRole::Editor => "editor",
            TenantRole::Viewer => "viewer",
        }
    }

    /// Check if role can read data.
    pub fn can_read(&self) -> bool {
        true
    }

    /// Check if role can write data.
    pub fn can_write(&self) -> bool {
        matches!(self, TenantRole::Admin | TenantRole::Editor)
    }

    /// Check if role can delete data.
    pub fn can_delete(&self) -> bool {
        matches!(self, TenantRole::Admin)
    }

    /// Check if role can manage API keys.
    pub fn can_manage_keys(&self) -> bool {
        matches!(self, TenantRole::Admin)
    }
}

impl std::str::FromStr for TenantRole {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(TenantRole::Admin),
            "editor" => Ok(TenantRole::Editor),
            "viewer" => Ok(TenantRole::Viewer),
            _ => Err(format!("unknown role: {}", s)),
        }
    }
}

impl std::fmt::Display for TenantRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Tenant record from the control plane database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: i64,
    pub tenant_id: String,
    pub display_name: String,
    pub status: String,
    pub tier: String,
    pub storage_uri: String,
    pub quota_max_datasets: i64,
    pub quota_max_storage_bytes: i64,
    pub quota_max_api_calls_per_hour: i64,
    pub admin_email: String,
    pub created_at: String,
    pub updated_at: String,
    pub suspended_at: Option<String>,
    pub deleted_at: Option<String>,
    /// Region for multi-region deployments (e.g., "us-east1", "europe-west1").
    /// When None, uses the default region from environment.
    pub region: Option<String>,
}

impl Tenant {
    /// Get the tenant status as an enum.
    pub fn status_enum(&self) -> Option<TenantStatus> {
        self.status.parse().ok()
    }

    /// Get the tenant tier as an enum.
    #[allow(dead_code)] // Used by library consumers
    pub fn tier_enum(&self) -> Option<TenantTier> {
        self.tier.parse().ok()
    }

    /// Check if tenant is operational (can make data plane requests).
    pub fn is_operational(&self) -> bool {
        self.status_enum()
            .map(|s| s.is_operational())
            .unwrap_or(false)
    }
}

/// Request to create a new tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTenantRequest {
    pub tenant_id: String,
    pub display_name: String,
    pub admin_email: String,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub quota_max_datasets: Option<i64>,
    #[serde(default)]
    pub quota_max_storage_bytes: Option<i64>,
    #[serde(default)]
    pub quota_max_api_calls_per_hour: Option<i64>,
    /// Region for tenant data storage (e.g., "us-east1", "europe-west1").
    /// When None, uses the default region from environment.
    #[serde(default)]
    pub region: Option<String>,
}

/// Request to update an existing tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTenantRequest {
    pub display_name: Option<String>,
    pub tier: Option<String>,
    pub admin_email: Option<String>,
    pub quota_max_datasets: Option<i64>,
    pub quota_max_storage_bytes: Option<i64>,
    pub quota_max_api_calls_per_hour: Option<i64>,
    /// Region for tenant data storage (e.g., "us-east1", "europe-west1").
    pub region: Option<String>,
}

/// Tenant API key metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantApiKey {
    pub id: i64,
    pub tenant_id: String,
    pub name: String,
    pub role: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
}

/// Validated tenant API key information.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used by tenant_resolver module
pub struct ValidatedTenantKey {
    pub key_hash: String,
    pub tenant_id: String,
    pub name: String,
    pub role: TenantRole,
    pub tier: TenantTier,
    /// Region for multi-region deployments.
    pub region: Option<String>,
}

/// Audit log entry for control plane operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: i64,
    pub timestamp: String,
    pub action: String,
    pub tenant_id: String,
    pub actor: String,
    pub details: Option<String>,
    pub request_id: Option<String>,
    pub client_ip: Option<String>,
}

/// Audit context for control plane operations.
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    pub actor: String,
    pub request_id: Option<String>,
    pub client_ip: Option<String>,
}

#[cfg(feature = "api-keys")]
/// Cached tenant API key.
struct CachedTenantKey {
    key_hash: String,
    tenant_id: String,
    name: String,
    role: TenantRole,
    tier: TenantTier,
    region: Option<String>,
    cached_at: Instant,
}

/// Control Plane manager for multi-tenant operations.
///
/// Manages tenant lifecycle, tenant-scoped API keys, and audit logging.
/// Uses a separate control plane database from per-tenant data catalogs.
pub struct ControlPlane {
    /// Path to the control plane database.
    db_path: String,
    /// Template for tenant storage URIs (e.g., "gs://bucket/tenants/{tenant_id}/catalog.db").
    storage_uri_template: String,
    /// Cache for validated tenant API keys.
    #[cfg(feature = "api-keys")]
    key_cache: Arc<DashMap<u64, CachedTenantKey>>,
    /// Pending last_used_at updates for background flush.
    #[cfg(feature = "api-keys")]
    pending_updates: Arc<DashMap<String, Instant>>,
}

impl ControlPlane {
    /// Create a new control plane manager.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the control plane SQLite database
    /// * `storage_uri_template` - Template for tenant storage URIs
    ///
    /// The template should contain `{tenant_id}` placeholder, e.g.:
    /// - Local: `/var/metafuse/tenants/{tenant_id}/catalog.db`
    /// - GCS: `gs://bucket/tenants/{tenant_id}/catalog.db`
    /// - S3: `s3://bucket/tenants/{tenant_id}/catalog.db`
    pub fn new(db_path: String, storage_uri_template: String) -> Result<Self> {
        // Validate template contains placeholder
        if !storage_uri_template.contains("{tenant_id}") {
            return Err(CatalogError::ValidationError(
                "storage_uri_template must contain {tenant_id} placeholder".to_string(),
            ));
        }

        Ok(Self {
            db_path,
            storage_uri_template,
            #[cfg(feature = "api-keys")]
            key_cache: Arc::new(DashMap::new()),
            #[cfg(feature = "api-keys")]
            pending_updates: Arc::new(DashMap::new()),
        })
    }

    /// Initialize the control plane database schema.
    #[allow(dead_code)] // Called during server startup
    pub async fn initialize(&self) -> Result<()> {
        let db_path = self.db_path.clone();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;
            metafuse_catalog_core::init_sqlite_schema(&conn)?;
            metafuse_catalog_core::migrations::run_migrations(&conn)?;
            Ok::<_, CatalogError>(())
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        info!(db_path = %self.db_path, "Initialized control plane database");
        Ok(())
    }

    /// Generate storage URI for a tenant.
    pub fn storage_uri_for_tenant(&self, tenant_id: &str) -> String {
        self.storage_uri_template.replace("{tenant_id}", tenant_id)
    }

    /// Get the default region from environment.
    /// Returns None if METAFUSE_DEFAULT_REGION is not set.
    pub fn get_default_region() -> Option<String> {
        std::env::var("METAFUSE_DEFAULT_REGION").ok()
    }

    // =========================================================================
    // Tenant CRUD Operations
    // =========================================================================

    /// Create a new tenant.
    ///
    /// Returns the created tenant and the initial admin API key (plaintext).
    /// **Store the API key securely - it cannot be retrieved again!**
    #[cfg(feature = "api-keys")]
    pub async fn create_tenant(
        &self,
        req: CreateTenantRequest,
        audit: AuditContext,
    ) -> Result<(Tenant, String)> {
        // Validate tenant_id
        let _ctx = TenantContext::new(&req.tenant_id)?;

        let storage_uri = self.storage_uri_for_tenant(&req.tenant_id);
        let tier = req.tier.unwrap_or_else(|| "standard".to_string());
        let quota_max_datasets = req.quota_max_datasets.unwrap_or(10000);
        let quota_max_storage_bytes = req.quota_max_storage_bytes.unwrap_or(10737418240);
        let quota_max_api_calls_per_hour = req.quota_max_api_calls_per_hour.unwrap_or(10000);
        // Use provided region or fall back to default from environment
        let region = req.region.or_else(Self::get_default_region);

        // Validate tier
        if tier.parse::<TenantTier>().is_err() {
            return Err(CatalogError::ValidationError(format!(
                "Invalid tier '{}'. Valid values: free, standard, premium, enterprise",
                tier
            )));
        }

        // Validate quotas
        if quota_max_datasets <= 0 {
            return Err(CatalogError::ValidationError(
                "quota_max_datasets must be positive".to_string(),
            ));
        }
        if quota_max_storage_bytes <= 0 {
            return Err(CatalogError::ValidationError(
                "quota_max_storage_bytes must be positive".to_string(),
            ));
        }
        if quota_max_api_calls_per_hour <= 0 {
            return Err(CatalogError::ValidationError(
                "quota_max_api_calls_per_hour must be positive".to_string(),
            ));
        }

        let db_path = self.db_path.clone();
        let tenant_id = req.tenant_id.clone();
        let display_name = req.display_name.clone();
        let admin_email = req.admin_email.clone();

        // Insert tenant
        let tenant = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;

            conn.execute(
                r#"
                INSERT INTO tenants (tenant_id, display_name, storage_uri, tier, admin_email,
                    quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour, region)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                rusqlite::params![
                    tenant_id,
                    display_name,
                    storage_uri,
                    tier,
                    admin_email,
                    quota_max_datasets,
                    quota_max_storage_bytes,
                    quota_max_api_calls_per_hour,
                    region
                ],
            )?;

            // Fetch the created tenant
            let mut stmt = conn.prepare(
                "SELECT id, tenant_id, display_name, status, tier, storage_uri,
                        quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour,
                        admin_email, created_at, updated_at, suspended_at, deleted_at, region
                 FROM tenants WHERE tenant_id = ?1",
            )?;

            let tenant = stmt.query_row([&tenant_id], |row| {
                Ok(Tenant {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    display_name: row.get(2)?,
                    status: row.get(3)?,
                    tier: row.get(4)?,
                    storage_uri: row.get(5)?,
                    quota_max_datasets: row.get(6)?,
                    quota_max_storage_bytes: row.get(7)?,
                    quota_max_api_calls_per_hour: row.get(8)?,
                    admin_email: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                    suspended_at: row.get(12)?,
                    deleted_at: row.get(13)?,
                    region: row.get(14)?,
                })
            })?;

            Ok::<Tenant, CatalogError>(tenant)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        // Create initial admin API key
        let api_key = self
            .create_tenant_api_key(
                &tenant.tenant_id,
                "Initial Admin Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await?;

        // Audit log
        self.audit_log(
            "create",
            &tenant.tenant_id,
            &audit.actor,
            Some(
                serde_json::json!({
                    "tier": tenant.tier,
                    "admin_email": tenant.admin_email,
                })
                .to_string(),
            ),
            audit.request_id.as_deref(),
            audit.client_ip.as_deref(),
        )
        .await?;

        // Record lifecycle metric
        #[cfg(feature = "metrics")]
        crate::metrics::record_tenant_created();

        info!(tenant_id = %tenant.tenant_id, tier = %tenant.tier, "Created tenant");
        Ok((tenant, api_key))
    }

    /// Create a new tenant (without initial API key).
    #[cfg(not(feature = "api-keys"))]
    pub async fn create_tenant(
        &self,
        req: CreateTenantRequest,
        audit: AuditContext,
    ) -> Result<Tenant> {
        // Validate tenant_id
        let _ctx = TenantContext::new(&req.tenant_id)?;

        let storage_uri = self.storage_uri_for_tenant(&req.tenant_id);
        let tier = req.tier.unwrap_or_else(|| "standard".to_string());
        let quota_max_datasets = req.quota_max_datasets.unwrap_or(10000);
        let quota_max_storage_bytes = req.quota_max_storage_bytes.unwrap_or(10737418240);
        let quota_max_api_calls_per_hour = req.quota_max_api_calls_per_hour.unwrap_or(10000);
        // Use provided region or fall back to default from environment
        let region = req.region.or_else(Self::get_default_region);

        // Validate tier
        if tier.parse::<TenantTier>().is_err() {
            return Err(CatalogError::ValidationError(format!(
                "Invalid tier '{}'. Valid values: free, standard, premium, enterprise",
                tier
            )));
        }

        let db_path = self.db_path.clone();
        let tenant_id = req.tenant_id.clone();
        let display_name = req.display_name.clone();
        let admin_email = req.admin_email.clone();

        // Insert tenant
        let tenant = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;

            conn.execute(
                r#"
                INSERT INTO tenants (tenant_id, display_name, storage_uri, tier, admin_email,
                    quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour, region)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                rusqlite::params![
                    tenant_id,
                    display_name,
                    storage_uri,
                    tier,
                    admin_email,
                    quota_max_datasets,
                    quota_max_storage_bytes,
                    quota_max_api_calls_per_hour,
                    region
                ],
            )?;

            // Fetch the created tenant
            let mut stmt = conn.prepare(
                "SELECT id, tenant_id, display_name, status, tier, storage_uri,
                        quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour,
                        admin_email, created_at, updated_at, suspended_at, deleted_at, region
                 FROM tenants WHERE tenant_id = ?1",
            )?;

            let tenant = stmt.query_row([&tenant_id], |row| {
                Ok(Tenant {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    display_name: row.get(2)?,
                    status: row.get(3)?,
                    tier: row.get(4)?,
                    storage_uri: row.get(5)?,
                    quota_max_datasets: row.get(6)?,
                    quota_max_storage_bytes: row.get(7)?,
                    quota_max_api_calls_per_hour: row.get(8)?,
                    admin_email: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                    suspended_at: row.get(12)?,
                    deleted_at: row.get(13)?,
                    region: row.get(14)?,
                })
            })?;

            Ok::<Tenant, CatalogError>(tenant)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        // Audit log
        self.audit_log(
            "create",
            &tenant.tenant_id,
            &audit.actor,
            Some(
                serde_json::json!({
                    "tier": tenant.tier,
                    "admin_email": tenant.admin_email,
                })
                .to_string(),
            ),
            audit.request_id.as_deref(),
            audit.client_ip.as_deref(),
        )
        .await?;

        // Record lifecycle metric
        #[cfg(feature = "metrics")]
        crate::metrics::record_tenant_created();

        info!(tenant_id = %tenant.tenant_id, tier = %tenant.tier, "Created tenant");
        Ok(tenant)
    }

    /// Get a tenant by ID.
    pub async fn get_tenant(&self, tenant_id: &str) -> Result<Option<Tenant>> {
        let db_path = self.db_path.clone();
        let tenant_id = tenant_id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            let mut stmt = conn.prepare(
                "SELECT id, tenant_id, display_name, status, tier, storage_uri,
                        quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour,
                        admin_email, created_at, updated_at, suspended_at, deleted_at, region
                 FROM tenants WHERE tenant_id = ?1",
            )?;

            let tenant = stmt
                .query_row([&tenant_id], |row| {
                    Ok(Tenant {
                        id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        display_name: row.get(2)?,
                        status: row.get(3)?,
                        tier: row.get(4)?,
                        storage_uri: row.get(5)?,
                        quota_max_datasets: row.get(6)?,
                        quota_max_storage_bytes: row.get(7)?,
                        quota_max_api_calls_per_hour: row.get(8)?,
                        admin_email: row.get(9)?,
                        created_at: row.get(10)?,
                        updated_at: row.get(11)?,
                        suspended_at: row.get(12)?,
                        deleted_at: row.get(13)?,
                        region: row.get(14)?,
                    })
                })
                .optional()?;

            Ok(tenant)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
    }

    /// List all tenants with optional status filter.
    pub async fn list_tenants(&self, status_filter: Option<&str>) -> Result<Vec<Tenant>> {
        let db_path = self.db_path.clone();
        let status_filter = status_filter.map(String::from);

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            let tenants: Vec<Tenant> = if let Some(ref status) = status_filter {
                let mut stmt = conn.prepare(
                    "SELECT id, tenant_id, display_name, status, tier, storage_uri,
                            quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour,
                            admin_email, created_at, updated_at, suspended_at, deleted_at, region
                     FROM tenants WHERE status = ?1 ORDER BY created_at DESC",
                )?;
                let rows = stmt.query_map([status], |row| {
                    Ok(Tenant {
                        id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        display_name: row.get(2)?,
                        status: row.get(3)?,
                        tier: row.get(4)?,
                        storage_uri: row.get(5)?,
                        quota_max_datasets: row.get(6)?,
                        quota_max_storage_bytes: row.get(7)?,
                        quota_max_api_calls_per_hour: row.get(8)?,
                        admin_email: row.get(9)?,
                        created_at: row.get(10)?,
                        updated_at: row.get(11)?,
                        suspended_at: row.get(12)?,
                        deleted_at: row.get(13)?,
                        region: row.get(14)?,
                    })
                })?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            } else {
                let mut stmt = conn.prepare(
                    "SELECT id, tenant_id, display_name, status, tier, storage_uri,
                            quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour,
                            admin_email, created_at, updated_at, suspended_at, deleted_at, region
                     FROM tenants ORDER BY created_at DESC",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok(Tenant {
                        id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        display_name: row.get(2)?,
                        status: row.get(3)?,
                        tier: row.get(4)?,
                        storage_uri: row.get(5)?,
                        quota_max_datasets: row.get(6)?,
                        quota_max_storage_bytes: row.get(7)?,
                        quota_max_api_calls_per_hour: row.get(8)?,
                        admin_email: row.get(9)?,
                        created_at: row.get(10)?,
                        updated_at: row.get(11)?,
                        suspended_at: row.get(12)?,
                        deleted_at: row.get(13)?,
                        region: row.get(14)?,
                    })
                })?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            };

            Ok(tenants)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
    }

    /// Update a tenant.
    pub async fn update_tenant(
        &self,
        tenant_id: &str,
        req: UpdateTenantRequest,
        audit: AuditContext,
    ) -> Result<Tenant> {
        let db_path = self.db_path.clone();
        let tenant_id_owned = tenant_id.to_string();

        // Validate tier if provided
        if let Some(ref tier) = req.tier {
            if tier.parse::<TenantTier>().is_err() {
                return Err(CatalogError::ValidationError(format!(
                    "Invalid tier '{}'. Valid values: free, standard, premium, enterprise",
                    tier
                )));
            }
        }

        // Serialize request for audit before move
        let req_json = serde_json::to_string(&req).unwrap_or_default();
        #[cfg(feature = "api-keys")]
        let tier_updated = req.tier.is_some();

        let tenant = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;

            // Build dynamic UPDATE query
            let mut updates = Vec::new();
            let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

            if let Some(display_name) = req.display_name {
                updates.push("display_name = ?");
                params.push(Box::new(display_name));
            }
            if let Some(tier) = req.tier {
                updates.push("tier = ?");
                params.push(Box::new(tier));
            }
            if let Some(admin_email) = req.admin_email {
                updates.push("admin_email = ?");
                params.push(Box::new(admin_email));
            }
            if let Some(quota) = req.quota_max_datasets {
                updates.push("quota_max_datasets = ?");
                params.push(Box::new(quota));
            }
            if let Some(quota) = req.quota_max_storage_bytes {
                updates.push("quota_max_storage_bytes = ?");
                params.push(Box::new(quota));
            }
            if let Some(quota) = req.quota_max_api_calls_per_hour {
                updates.push("quota_max_api_calls_per_hour = ?");
                params.push(Box::new(quota));
            }
            if let Some(region) = req.region {
                updates.push("region = ?");
                params.push(Box::new(region));
            }

            if updates.is_empty() {
                return Err(CatalogError::ValidationError(
                    "No fields to update".to_string(),
                ));
            }

            let sql = format!(
                "UPDATE tenants SET {} WHERE tenant_id = ? AND status != 'deleted'",
                updates.join(", ")
            );

            params.push(Box::new(tenant_id_owned.clone()));

            let params_refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let rows_affected = conn.execute(&sql, params_refs.as_slice())?;

            if rows_affected == 0 {
                return Err(CatalogError::DatasetNotFound(format!(
                    "Tenant not found or already deleted: {}",
                    tenant_id_owned
                )));
            }

            // Fetch updated tenant
            let mut stmt = conn.prepare(
                "SELECT id, tenant_id, display_name, status, tier, storage_uri,
                        quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour,
                        admin_email, created_at, updated_at, suspended_at, deleted_at, region
                 FROM tenants WHERE tenant_id = ?1",
            )?;

            let tenant = stmt.query_row([&tenant_id_owned], |row| {
                Ok(Tenant {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    display_name: row.get(2)?,
                    status: row.get(3)?,
                    tier: row.get(4)?,
                    storage_uri: row.get(5)?,
                    quota_max_datasets: row.get(6)?,
                    quota_max_storage_bytes: row.get(7)?,
                    quota_max_api_calls_per_hour: row.get(8)?,
                    admin_email: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                    suspended_at: row.get(12)?,
                    deleted_at: row.get(13)?,
                    region: row.get(14)?,
                })
            })?;

            Ok(tenant)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        // If tier was updated, invalidate cached keys so new limits take effect immediately.
        #[cfg(feature = "api-keys")]
        if tier_updated {
            self.invalidate_tenant_cache(tenant_id);
        }

        // Audit log
        self.audit_log(
            "update",
            tenant_id,
            &audit.actor,
            Some(req_json),
            audit.request_id.as_deref(),
            audit.client_ip.as_deref(),
        )
        .await?;

        info!(tenant_id = %tenant_id, "Updated tenant");
        Ok(tenant)
    }

    /// Suspend a tenant (immediate effect).
    pub async fn suspend_tenant(&self, tenant_id: &str, audit: AuditContext) -> Result<Tenant> {
        let db_path = self.db_path.clone();
        let tenant_id_owned = tenant_id.to_string();

        let tenant = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            let rows_affected = conn.execute(
                "UPDATE tenants SET status = 'suspended', suspended_at = datetime('now')
                 WHERE tenant_id = ?1 AND status = 'active'",
                rusqlite::params![&tenant_id_owned],
            )?;

            if rows_affected == 0 {
                return Err(CatalogError::ValidationError(format!(
                    "Tenant not found or not active: {}",
                    tenant_id_owned
                )));
            }

            // Fetch updated tenant
            let mut stmt = conn.prepare(
                "SELECT id, tenant_id, display_name, status, tier, storage_uri,
                        quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour,
                        admin_email, created_at, updated_at, suspended_at, deleted_at, region
                 FROM tenants WHERE tenant_id = ?1",
            )?;

            let tenant = stmt.query_row([&tenant_id_owned], |row| {
                Ok(Tenant {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    display_name: row.get(2)?,
                    status: row.get(3)?,
                    tier: row.get(4)?,
                    storage_uri: row.get(5)?,
                    quota_max_datasets: row.get(6)?,
                    quota_max_storage_bytes: row.get(7)?,
                    quota_max_api_calls_per_hour: row.get(8)?,
                    admin_email: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                    suspended_at: row.get(12)?,
                    deleted_at: row.get(13)?,
                    region: row.get(14)?,
                })
            })?;

            Ok(tenant)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        // Clear API key cache for this tenant
        #[cfg(feature = "api-keys")]
        self.invalidate_tenant_cache(tenant_id);

        // Audit log
        self.audit_log(
            "suspend",
            tenant_id,
            &audit.actor,
            None,
            audit.request_id.as_deref(),
            audit.client_ip.as_deref(),
        )
        .await?;

        // Record lifecycle metric
        #[cfg(feature = "metrics")]
        crate::metrics::record_tenant_suspended();

        info!(tenant_id = %tenant_id, "Suspended tenant");
        Ok(tenant)
    }

    /// Reactivate a suspended tenant.
    pub async fn reactivate_tenant(&self, tenant_id: &str, audit: AuditContext) -> Result<Tenant> {
        let db_path = self.db_path.clone();
        let tenant_id_owned = tenant_id.to_string();

        let tenant = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            let rows_affected = conn.execute(
                "UPDATE tenants SET status = 'active', suspended_at = NULL
                 WHERE tenant_id = ?1 AND status = 'suspended'",
                rusqlite::params![&tenant_id_owned],
            )?;

            if rows_affected == 0 {
                return Err(CatalogError::ValidationError(format!(
                    "Tenant not found or not suspended: {}",
                    tenant_id_owned
                )));
            }

            // Fetch updated tenant
            let mut stmt = conn.prepare(
                "SELECT id, tenant_id, display_name, status, tier, storage_uri,
                        quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour,
                        admin_email, created_at, updated_at, suspended_at, deleted_at, region
                 FROM tenants WHERE tenant_id = ?1",
            )?;

            let tenant = stmt.query_row([&tenant_id_owned], |row| {
                Ok(Tenant {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    display_name: row.get(2)?,
                    status: row.get(3)?,
                    tier: row.get(4)?,
                    storage_uri: row.get(5)?,
                    quota_max_datasets: row.get(6)?,
                    quota_max_storage_bytes: row.get(7)?,
                    quota_max_api_calls_per_hour: row.get(8)?,
                    admin_email: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                    suspended_at: row.get(12)?,
                    deleted_at: row.get(13)?,
                    region: row.get(14)?,
                })
            })?;

            Ok(tenant)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        // Audit log
        self.audit_log(
            "reactivate",
            tenant_id,
            &audit.actor,
            None,
            audit.request_id.as_deref(),
            audit.client_ip.as_deref(),
        )
        .await?;

        // Record lifecycle metric
        #[cfg(feature = "metrics")]
        crate::metrics::record_tenant_reactivated();

        info!(tenant_id = %tenant_id, "Reactivated tenant");
        Ok(tenant)
    }

    /// Request tenant deletion (soft delete, starts grace period).
    pub async fn delete_tenant(&self, tenant_id: &str, audit: AuditContext) -> Result<Tenant> {
        let db_path = self.db_path.clone();
        let tenant_id_owned = tenant_id.to_string();

        let tenant = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            let rows_affected = conn.execute(
                "UPDATE tenants SET status = 'pending_deletion', deleted_at = datetime('now')
                 WHERE tenant_id = ?1 AND status IN ('active', 'suspended')",
                rusqlite::params![&tenant_id_owned],
            )?;

            if rows_affected == 0 {
                return Err(CatalogError::ValidationError(format!(
                    "Tenant not found or already deleted: {}",
                    tenant_id_owned
                )));
            }

            // Fetch updated tenant
            let mut stmt = conn.prepare(
                "SELECT id, tenant_id, display_name, status, tier, storage_uri,
                        quota_max_datasets, quota_max_storage_bytes, quota_max_api_calls_per_hour,
                        admin_email, created_at, updated_at, suspended_at, deleted_at, region
                 FROM tenants WHERE tenant_id = ?1",
            )?;

            let tenant = stmt.query_row([&tenant_id_owned], |row| {
                Ok(Tenant {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    display_name: row.get(2)?,
                    status: row.get(3)?,
                    tier: row.get(4)?,
                    storage_uri: row.get(5)?,
                    quota_max_datasets: row.get(6)?,
                    quota_max_storage_bytes: row.get(7)?,
                    quota_max_api_calls_per_hour: row.get(8)?,
                    admin_email: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                    suspended_at: row.get(12)?,
                    deleted_at: row.get(13)?,
                    region: row.get(14)?,
                })
            })?;

            Ok(tenant)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        // Clear API key cache for this tenant
        #[cfg(feature = "api-keys")]
        self.invalidate_tenant_cache(tenant_id);

        // Audit log
        self.audit_log(
            "delete",
            tenant_id,
            &audit.actor,
            Some(r#"{"action": "soft_delete", "grace_period": "30 days"}"#.to_string()),
            audit.request_id.as_deref(),
            audit.client_ip.as_deref(),
        )
        .await?;

        // Record lifecycle metric
        #[cfg(feature = "metrics")]
        crate::metrics::record_tenant_deleted();

        warn!(tenant_id = %tenant_id, "Tenant marked for deletion");
        Ok(tenant)
    }

    /// Purge a deleted tenant (GDPR erasure - permanent data deletion).
    ///
    /// **WARNING**: This permanently deletes all tenant data and cannot be undone.
    /// Only works for tenants in 'pending_deletion' status.
    #[allow(dead_code)] // GDPR feature - exposed via admin API in future
    pub async fn purge_tenant(&self, tenant_id: &str, audit: AuditContext) -> Result<()> {
        let db_path = self.db_path.clone();
        let tenant_id_owned = tenant_id.to_string();

        // First, verify tenant is in pending_deletion state
        let tenant = self.get_tenant(tenant_id).await?;
        let tenant = tenant.ok_or_else(|| {
            CatalogError::DatasetNotFound(format!("Tenant not found: {}", tenant_id))
        })?;

        if tenant.status != "pending_deletion" {
            return Err(CatalogError::ValidationError(format!(
                "Tenant must be in 'pending_deletion' status to purge. Current: {}",
                tenant.status
            )));
        }

        // Delete tenant (cascade will delete API keys)
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;

            conn.execute(
                "UPDATE tenants SET status = 'deleted' WHERE tenant_id = ?1",
                rusqlite::params![&tenant_id_owned],
            )?;

            // Note: In a full implementation, we would also:
            // 1. Delete the tenant's catalog.db from storage
            // 2. Anonymize audit logs (replace tenant_id with hash)
            // 3. Delete any backup copies

            Ok::<_, CatalogError>(())
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        // Clear API key cache for this tenant
        #[cfg(feature = "api-keys")]
        self.invalidate_tenant_cache(tenant_id);

        // Audit log (this will be anonymized in future)
        self.audit_log(
            "purge",
            tenant_id,
            &audit.actor,
            Some(r#"{"action": "permanent_delete", "gdpr": true}"#.to_string()),
            audit.request_id.as_deref(),
            audit.client_ip.as_deref(),
        )
        .await?;

        // Record lifecycle metric
        #[cfg(feature = "metrics")]
        crate::metrics::record_tenant_purged();

        warn!(tenant_id = %tenant_id, "Tenant purged permanently");
        Ok(())
    }

    // =========================================================================
    // Tenant API Key Management
    // =========================================================================

    #[cfg(feature = "api-keys")]
    /// Create a tenant-scoped API key.
    ///
    /// Returns the plaintext key. **Store securely - cannot be retrieved again!**
    pub async fn create_tenant_api_key(
        &self,
        tenant_id: &str,
        name: String,
        role: TenantRole,
        expires_at: Option<String>,
    ) -> Result<String> {
        // Generate key
        let plaintext = self.generate_api_key();

        // Hash with bcrypt
        let key_hash = {
            let plaintext_clone = plaintext.clone();
            tokio::task::spawn_blocking(move || {
                hash(&plaintext_clone, DEFAULT_BCRYPT_COST).map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
            .map_err(|e| CatalogError::Other(format!("Hash error: {}", e)))?
        };

        let db_path = self.db_path.clone();
        let tenant_id_owned = tenant_id.to_string();
        let name_owned = name.clone();
        let role_str = role.as_str().to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;

            conn.execute(
                "INSERT INTO tenant_api_keys (tenant_id, key_hash, name, role, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![tenant_id_owned, key_hash, name_owned, role_str, expires_at],
            )?;

            Ok::<_, CatalogError>(())
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        info!(tenant_id = %tenant_id, name = %name, role = %role, "Created tenant API key");
        Ok(plaintext)
    }

    #[cfg(feature = "api-keys")]
    /// Validate a tenant API key and return identity information.
    pub async fn validate_tenant_api_key(
        &self,
        plaintext: &str,
    ) -> Result<Option<ValidatedTenantKey>> {
        let cache_key = self.cache_key_from_plaintext(plaintext);

        // Check cache first
        if let Some(cached) = self.key_cache.get(&cache_key) {
            let age = cached.cached_at.elapsed();
            if age < Duration::from_secs(CACHE_TTL_SECS) {
                debug!("Tenant API key validation: cache hit");
                self.mark_key_used(&cached.key_hash);
                return Ok(Some(ValidatedTenantKey {
                    key_hash: cached.key_hash.clone(),
                    tenant_id: cached.tenant_id.clone(),
                    name: cached.name.clone(),
                    role: cached.role,
                    tier: cached.tier,
                    region: cached.region.clone(),
                }));
            } else {
                debug!("Tenant API key validation: cache expired");
                self.key_cache.remove(&cache_key);
            }
        }

        // Cache miss - query database
        let db_path = self.db_path.clone();
        let plaintext = plaintext.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            // Get all valid (non-revoked, non-expired) keys for active tenants
            // Include region for multi-region deployments
            let mut stmt = conn.prepare(
                r#"
                SELECT k.key_hash, k.tenant_id, k.name, k.role, t.tier, t.region
                FROM tenant_api_keys k
                JOIN tenants t ON k.tenant_id = t.tenant_id
                WHERE k.revoked_at IS NULL
                  AND (k.expires_at IS NULL OR k.expires_at > datetime('now'))
                  AND t.status = 'active'
                "#,
            )?;

            let keys: Vec<(String, String, String, String, String, Option<String>)> = stmt
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            // Verify against each hash
            for (key_hash, tenant_id, name, role, tier_str, region) in keys {
                if verify(&plaintext, &key_hash).unwrap_or(false) {
                    let role = role.parse::<TenantRole>().unwrap_or_default();
                    let tier = tier_str.parse::<TenantTier>().unwrap_or_default();
                    return Ok::<
                        Option<(
                            String,
                            String,
                            String,
                            TenantRole,
                            TenantTier,
                            Option<String>,
                        )>,
                        CatalogError,
                    >(Some((
                        key_hash, tenant_id, name, role, tier, region,
                    )));
                }
            }

            Ok(None)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        if let Some((key_hash, tenant_id, name, role, tier, region)) = result {
            // Cache the valid key
            self.key_cache.insert(
                cache_key,
                CachedTenantKey {
                    key_hash: key_hash.clone(),
                    tenant_id: tenant_id.clone(),
                    name: name.clone(),
                    role,
                    tier,
                    region: region.clone(),
                    cached_at: Instant::now(),
                },
            );

            self.mark_key_used(&key_hash);

            debug!(tenant_id = %tenant_id, name = %name, tier = ?tier, region = ?region, "Tenant API key validated");
            Ok(Some(ValidatedTenantKey {
                key_hash,
                tenant_id,
                name,
                role,
                tier,
                region,
            }))
        } else {
            warn!("Tenant API key validation failed");
            Ok(None)
        }
    }

    #[cfg(feature = "api-keys")]
    /// List API keys for a tenant.
    pub async fn list_tenant_api_keys(&self, tenant_id: &str) -> Result<Vec<TenantApiKey>> {
        let db_path = self.db_path.clone();
        let tenant_id = tenant_id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            let mut stmt = conn.prepare(
                "SELECT id, tenant_id, name, role, created_at, revoked_at, last_used_at, expires_at
                 FROM tenant_api_keys WHERE tenant_id = ?1 ORDER BY created_at DESC, id DESC",
            )?;

            let keys = stmt
                .query_map([&tenant_id], |row| {
                    Ok(TenantApiKey {
                        id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        name: row.get(2)?,
                        role: row.get(3)?,
                        created_at: row.get(4)?,
                        revoked_at: row.get(5)?,
                        last_used_at: row.get(6)?,
                        expires_at: row.get(7)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            Ok(keys)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
    }

    #[cfg(feature = "api-keys")]
    /// Revoke a tenant API key.
    pub async fn revoke_tenant_api_key(&self, tenant_id: &str, key_id: i64) -> Result<bool> {
        let db_path = self.db_path.clone();
        let tenant_id_owned = tenant_id.to_string();

        let rows_affected = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            let rows = conn.execute(
                "UPDATE tenant_api_keys SET revoked_at = datetime('now')
                 WHERE id = ?1 AND tenant_id = ?2 AND revoked_at IS NULL",
                rusqlite::params![key_id, &tenant_id_owned],
            )?;

            Ok::<usize, CatalogError>(rows)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        if rows_affected > 0 {
            info!(tenant_id = %tenant_id, key_id = key_id, "Revoked tenant API key");
            // Clear entire cache for this tenant to ensure immediate invalidation
            self.invalidate_tenant_cache(tenant_id);
            Ok(true)
        } else {
            warn!(tenant_id = %tenant_id, key_id = key_id, "API key not found or already revoked");
            Ok(false)
        }
    }

    #[cfg(feature = "api-keys")]
    /// Invalidate all cached keys for a tenant.
    fn invalidate_tenant_cache(&self, tenant_id: &str) {
        self.key_cache.retain(|_, v| v.tenant_id != tenant_id);
        self.pending_updates.clear();
        debug!(tenant_id = %tenant_id, "Invalidated tenant API key cache");
    }

    #[cfg(feature = "api-keys")]
    /// Generate a cryptographically secure API key.
    fn generate_api_key(&self) -> String {
        let mut rng = rand::rngs::OsRng;
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        format!("{}{}", DEFAULT_API_KEY_PREFIX, hex::encode(&bytes))
    }

    #[cfg(feature = "api-keys")]
    /// Compute cache key from plaintext.
    fn cache_key_from_plaintext(&self, plaintext: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        plaintext.hash(&mut hasher);
        hasher.finish()
    }

    #[cfg(feature = "api-keys")]
    /// Mark a key as recently used.
    fn mark_key_used(&self, key_hash: &str) {
        self.pending_updates
            .insert(key_hash.to_string(), Instant::now());
    }

    #[cfg(feature = "api-keys")]
    /// Flush pending last_used_at updates to the database.
    #[allow(dead_code)] // Background task operation
    pub async fn flush_pending_updates(&self) -> Result<usize> {
        if self.pending_updates.is_empty() {
            return Ok(0);
        }

        let updates: Vec<String> = self
            .pending_updates
            .iter()
            .map(|e| e.key().clone())
            .collect();

        let count = updates.len();
        if count == 0 {
            return Ok(0);
        }

        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            let tx = conn.unchecked_transaction()?;

            for key_hash in &updates {
                tx.execute(
                    "UPDATE tenant_api_keys SET last_used_at = datetime('now') WHERE key_hash = ?1",
                    rusqlite::params![key_hash],
                )?;
            }

            tx.commit()?;
            Ok::<_, CatalogError>(())
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))??;

        self.pending_updates.clear();
        debug!(count = count, "Flushed tenant API key last_used_at updates");
        Ok(count)
    }

    // =========================================================================
    // Audit Logging
    // =========================================================================

    /// Log a control plane operation.
    pub async fn audit_log(
        &self,
        action: &str,
        tenant_id: &str,
        actor: &str,
        details: Option<String>,
        request_id: Option<&str>,
        client_ip: Option<&str>,
    ) -> Result<()> {
        let db_path = self.db_path.clone();
        let action = action.to_string();
        let tenant_id = tenant_id.to_string();
        let actor = actor.to_string();
        let request_id = request_id.map(String::from);
        let client_ip = client_ip.map(String::from);

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            conn.execute(
                "INSERT INTO tenant_audit_log (action, tenant_id, actor, details, request_id, client_ip)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![action, tenant_id, actor, details, request_id, client_ip],
            )?;

            Ok::<_, CatalogError>(())
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
    }

    /// Get audit log entries for a tenant.
    pub async fn get_audit_log(
        &self,
        tenant_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditLogEntry>> {
        let db_path = self.db_path.clone();
        let tenant_id = tenant_id.map(String::from);

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;

            let entries: Vec<AuditLogEntry> = if let Some(ref tid) = tenant_id {
                let mut stmt = conn.prepare(
                    "SELECT id, timestamp, action, tenant_id, actor, details, request_id, client_ip
                     FROM tenant_audit_log WHERE tenant_id = ?1
                     ORDER BY timestamp DESC LIMIT ?2",
                )?;
                let rows = stmt.query_map(rusqlite::params![tid, limit], |row| {
                    Ok(AuditLogEntry {
                        id: row.get(0)?,
                        timestamp: row.get(1)?,
                        action: row.get(2)?,
                        tenant_id: row.get(3)?,
                        actor: row.get(4)?,
                        details: row.get(5)?,
                        request_id: row.get(6)?,
                        client_ip: row.get(7)?,
                    })
                })?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            } else {
                let mut stmt = conn.prepare(
                    "SELECT id, timestamp, action, tenant_id, actor, details, request_id, client_ip
                     FROM tenant_audit_log
                     ORDER BY timestamp DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map(rusqlite::params![limit], |row| {
                    Ok(AuditLogEntry {
                        id: row.get(0)?,
                        timestamp: row.get(1)?,
                        action: row.get(2)?,
                        tenant_id: row.get(3)?,
                        actor: row.get(4)?,
                        details: row.get(5)?,
                        request_id: row.get(6)?,
                        client_ip: row.get(7)?,
                    })
                })?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            };

            Ok(entries)
        })
        .await
        .map_err(|e| CatalogError::Other(format!("Task join error: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_role_parsing() {
        assert_eq!("admin".parse::<TenantRole>().unwrap(), TenantRole::Admin);
        assert_eq!("ADMIN".parse::<TenantRole>().unwrap(), TenantRole::Admin);
        assert_eq!("editor".parse::<TenantRole>().unwrap(), TenantRole::Editor);
        assert_eq!("viewer".parse::<TenantRole>().unwrap(), TenantRole::Viewer);
        assert!("unknown".parse::<TenantRole>().is_err());
    }

    #[test]
    fn test_tenant_role_permissions() {
        assert!(TenantRole::Admin.can_read());
        assert!(TenantRole::Admin.can_write());
        assert!(TenantRole::Admin.can_delete());
        assert!(TenantRole::Admin.can_manage_keys());

        assert!(TenantRole::Editor.can_read());
        assert!(TenantRole::Editor.can_write());
        assert!(!TenantRole::Editor.can_delete()); // Only Admin can delete
        assert!(!TenantRole::Editor.can_manage_keys());

        assert!(TenantRole::Viewer.can_read());
        assert!(!TenantRole::Viewer.can_write());
        assert!(!TenantRole::Viewer.can_delete());
        assert!(!TenantRole::Viewer.can_manage_keys());
    }

    #[tokio::test]
    async fn test_control_plane_new() {
        // Valid template
        let cp = ControlPlane::new(
            "/tmp/test.db".to_string(),
            "gs://bucket/tenants/{tenant_id}/catalog.db".to_string(),
        );
        assert!(cp.is_ok());

        // Invalid template (missing placeholder)
        let cp = ControlPlane::new(
            "/tmp/test.db".to_string(),
            "gs://bucket/catalog.db".to_string(),
        );
        assert!(cp.is_err());
    }

    #[test]
    fn test_storage_uri_for_tenant() {
        let cp = ControlPlane::new(
            "/tmp/test.db".to_string(),
            "gs://bucket/tenants/{tenant_id}/catalog.db".to_string(),
        )
        .unwrap();

        assert_eq!(
            cp.storage_uri_for_tenant("acme-corp"),
            "gs://bucket/tenants/acme-corp/catalog.db"
        );
    }

    #[cfg(feature = "tempfile")]
    #[tokio::test]
    async fn test_tenant_lifecycle() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("control.db");

        let cp = ControlPlane::new(
            db_path.to_str().unwrap().to_string(),
            "/tmp/tenants/{tenant_id}/catalog.db".to_string(),
        )
        .unwrap();

        // Initialize
        cp.initialize().await.unwrap();

        // Create tenant
        #[cfg(feature = "api-keys")]
        let (tenant, _api_key) = cp
            .create_tenant(
                CreateTenantRequest {
                    tenant_id: "test-tenant".to_string(),
                    display_name: "Test Tenant".to_string(),
                    admin_email: "admin@test.com".to_string(),
                    tier: Some("premium".to_string()),
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext {
                    actor: "test".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();

        #[cfg(not(feature = "api-keys"))]
        let tenant = cp
            .create_tenant(
                CreateTenantRequest {
                    tenant_id: "test-tenant".to_string(),
                    display_name: "Test Tenant".to_string(),
                    admin_email: "admin@test.com".to_string(),
                    tier: Some("premium".to_string()),
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext {
                    actor: "test".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(tenant.tenant_id, "test-tenant");
        assert_eq!(tenant.status, "active");
        assert_eq!(tenant.tier, "premium");

        // Get tenant
        let fetched = cp.get_tenant("test-tenant").await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().display_name, "Test Tenant");

        // List tenants
        let tenants = cp.list_tenants(None).await.unwrap();
        assert_eq!(tenants.len(), 1);

        // Update tenant
        let updated = cp
            .update_tenant(
                "test-tenant",
                UpdateTenantRequest {
                    display_name: Some("Updated Name".to_string()),
                    tier: None,
                    admin_email: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext {
                    actor: "test".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.display_name, "Updated Name");

        // Suspend tenant
        let suspended = cp
            .suspend_tenant(
                "test-tenant",
                AuditContext {
                    actor: "test".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(suspended.status, "suspended");

        // Reactivate tenant
        let reactivated = cp
            .reactivate_tenant(
                "test-tenant",
                AuditContext {
                    actor: "test".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(reactivated.status, "active");

        // Delete tenant
        let deleted = cp
            .delete_tenant(
                "test-tenant",
                AuditContext {
                    actor: "test".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(deleted.status, "pending_deletion");

        // Purge tenant
        cp.purge_tenant(
            "test-tenant",
            AuditContext {
                actor: "test".to_string(),
                request_id: None,
                client_ip: None,
            },
        )
        .await
        .unwrap();

        // Verify audit log
        let audit_logs = cp.get_audit_log(Some("test-tenant"), 100).await.unwrap();
        assert!(audit_logs.len() >= 5); // create, update, suspend, reactivate, delete, purge
    }

    #[tokio::test]
    #[cfg(feature = "api-keys")]
    async fn test_tenant_api_keys() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir
            .path()
            .join("control.db")
            .to_string_lossy()
            .to_string();
        let storage = temp_dir
            .path()
            .join("{tenant_id}/db")
            .to_string_lossy()
            .to_string();

        let cp = ControlPlane::new(db_path, storage).unwrap();
        cp.initialize().await.unwrap();

        // Create tenant and initial admin key
        let (_tenant, admin_key) = cp
            .create_tenant(
                CreateTenantRequest {
                    tenant_id: "tenant1".to_string(),
                    display_name: "Tenant One".to_string(),
                    admin_email: "admin@test.com".to_string(),
                    tier: Some("standard".to_string()),
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext {
                    actor: "platform-admin".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();

        // Validate admin key
        let validated = cp.validate_tenant_api_key(&admin_key).await.unwrap();
        let validated = validated.expect("admin key should validate");
        assert_eq!(validated.tenant_id, "tenant1");
        assert_eq!(validated.role, TenantRole::Admin);

        // List keys (should include admin)
        let keys = cp.list_tenant_api_keys("tenant1").await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].role, "admin");

        // Create an editor key
        let editor_key = cp
            .create_tenant_api_key(
                "tenant1",
                "editor-key".to_string(),
                TenantRole::Editor,
                None,
            )
            .await
            .unwrap();

        // Validate editor key
        let validated = cp.validate_tenant_api_key(&editor_key).await.unwrap();
        let validated = validated.expect("editor key should validate");
        assert_eq!(validated.role, TenantRole::Editor);

        // List keys again (should include both)
        let keys = cp.list_tenant_api_keys("tenant1").await.unwrap();
        assert_eq!(keys.len(), 2);
        let editor = keys.iter().find(|k| k.name == "editor-key").unwrap();

        // Revoke editor key
        let revoked = cp
            .revoke_tenant_api_key("tenant1", editor.id)
            .await
            .unwrap();
        assert!(revoked);

        // Editor key should no longer validate
        let validated = cp.validate_tenant_api_key(&editor_key).await.unwrap();
        assert!(validated.is_none());
    }

    // ==========================================================================
    // Status-Based API Key Rejection Tests
    // ==========================================================================

    #[tokio::test]
    #[cfg(feature = "api-keys")]
    async fn test_api_key_rejected_when_tenant_suspended() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir
            .path()
            .join("control.db")
            .to_string_lossy()
            .to_string();
        let storage = temp_dir
            .path()
            .join("{tenant_id}/db")
            .to_string_lossy()
            .to_string();

        let cp = ControlPlane::new(db_path, storage).unwrap();
        cp.initialize().await.unwrap();

        let (_tenant, key) = cp
            .create_tenant(
                CreateTenantRequest {
                    tenant_id: "suspendme".to_string(),
                    display_name: "Tenant Suspend".to_string(),
                    admin_email: "admin@test.com".to_string(),
                    tier: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext {
                    actor: "platform-admin".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();

        // Key works before suspension
        assert!(cp.validate_tenant_api_key(&key).await.unwrap().is_some());

        // Suspend tenant
        cp.suspend_tenant(
            "suspendme",
            AuditContext {
                actor: "platform-admin".to_string(),
                request_id: None,
                client_ip: None,
            },
        )
        .await
        .unwrap();

        // Key should now be rejected
        assert!(cp.validate_tenant_api_key(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    #[cfg(feature = "api-keys")]
    async fn test_api_key_rejected_when_tenant_pending_deletion() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir
            .path()
            .join("control.db")
            .to_string_lossy()
            .to_string();
        let storage = temp_dir
            .path()
            .join("{tenant_id}/db")
            .to_string_lossy()
            .to_string();

        let cp = ControlPlane::new(db_path, storage).unwrap();
        cp.initialize().await.unwrap();

        let (_tenant, key) = cp
            .create_tenant(
                CreateTenantRequest {
                    tenant_id: "deleteme".to_string(),
                    display_name: "Tenant Delete".to_string(),
                    admin_email: "admin@test.com".to_string(),
                    tier: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext {
                    actor: "platform-admin".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();

        // Key works before deletion
        assert!(cp.validate_tenant_api_key(&key).await.unwrap().is_some());

        // Delete (soft) tenant
        cp.delete_tenant(
            "deleteme",
            AuditContext {
                actor: "platform-admin".to_string(),
                request_id: None,
                client_ip: None,
            },
        )
        .await
        .unwrap();

        // Key should now be rejected
        assert!(cp.validate_tenant_api_key(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    #[cfg(feature = "api-keys")]
    async fn test_api_key_works_after_reactivation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir
            .path()
            .join("control.db")
            .to_string_lossy()
            .to_string();
        let storage = temp_dir
            .path()
            .join("{tenant_id}/db")
            .to_string_lossy()
            .to_string();

        let cp = ControlPlane::new(db_path, storage).unwrap();
        cp.initialize().await.unwrap();

        let (_tenant, key) = cp
            .create_tenant(
                CreateTenantRequest {
                    tenant_id: "reactivate".to_string(),
                    display_name: "Tenant Reactivate".to_string(),
                    admin_email: "admin@test.com".to_string(),
                    tier: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext {
                    actor: "platform-admin".to_string(),
                    request_id: None,
                    client_ip: None,
                },
            )
            .await
            .unwrap();

        // Works initially
        assert!(cp.validate_tenant_api_key(&key).await.unwrap().is_some());

        // Suspend
        cp.suspend_tenant(
            "reactivate",
            AuditContext {
                actor: "platform-admin".to_string(),
                request_id: None,
                client_ip: None,
            },
        )
        .await
        .unwrap();
        assert!(cp.validate_tenant_api_key(&key).await.unwrap().is_none());

        // Reactivate
        cp.reactivate_tenant(
            "reactivate",
            AuditContext {
                actor: "platform-admin".to_string(),
                request_id: None,
                client_ip: None,
            },
        )
        .await
        .unwrap();

        // Key works again
        assert!(cp.validate_tenant_api_key(&key).await.unwrap().is_some());
    }

    // ==========================================================================
    // Duplicate Constraint Tests
    // ==========================================================================

    #[cfg(feature = "tempfile")]
    #[tokio::test]
    async fn test_duplicate_tenant_id_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir
            .path()
            .join("control.db")
            .to_string_lossy()
            .to_string();
        let storage = temp_dir
            .path()
            .join("{tenant_id}/db")
            .to_string_lossy()
            .to_string();

        let cp = ControlPlane::new(db_path, storage).unwrap();
        cp.initialize().await.unwrap();

        // Create first tenant
        let result1 = cp
            .create_tenant(
                CreateTenantRequest {
                    tenant_id: "duplicate-test".to_string(),
                    display_name: "First Tenant".to_string(),
                    admin_email: "admin1@test.com".to_string(),
                    tier: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext::default(),
            )
            .await;
        assert!(result1.is_ok(), "First tenant creation should succeed");

        // Attempt to create second tenant with same ID
        let result2 = cp
            .create_tenant(
                CreateTenantRequest {
                    tenant_id: "duplicate-test".to_string(),
                    display_name: "Second Tenant".to_string(),
                    admin_email: "admin2@test.com".to_string(),
                    tier: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext::default(),
            )
            .await;
        assert!(result2.is_err(), "Duplicate tenant ID should be rejected");
        let err = result2.unwrap_err().to_string();
        assert!(
            err.contains("UNIQUE") || err.contains("already exists") || err.contains("constraint"),
            "Error should indicate uniqueness violation: {}",
            err
        );
    }

    #[tokio::test]
    #[cfg(feature = "api-keys")]
    async fn test_multiple_api_keys_per_tenant_allowed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir
            .path()
            .join("control.db")
            .to_string_lossy()
            .to_string();
        let storage = temp_dir
            .path()
            .join("{tenant_id}/db")
            .to_string_lossy()
            .to_string();

        let cp = ControlPlane::new(db_path, storage).unwrap();
        cp.initialize().await.unwrap();

        let (_tenant, admin_key) = cp
            .create_tenant(
                CreateTenantRequest {
                    tenant_id: "multi-keys".to_string(),
                    display_name: "Multi Keys".to_string(),
                    admin_email: "admin@test.com".to_string(),
                    tier: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                AuditContext::default(),
            )
            .await
            .unwrap();

        // Create two additional keys
        let editor_key = cp
            .create_tenant_api_key("multi-keys", "editor".to_string(), TenantRole::Editor, None)
            .await
            .unwrap();
        let viewer_key = cp
            .create_tenant_api_key("multi-keys", "viewer".to_string(), TenantRole::Viewer, None)
            .await
            .unwrap();

        // Validate all keys work
        assert!(cp
            .validate_tenant_api_key(&admin_key)
            .await
            .unwrap()
            .is_some());
        assert!(cp
            .validate_tenant_api_key(&editor_key)
            .await
            .unwrap()
            .is_some());
        assert!(cp
            .validate_tenant_api_key(&viewer_key)
            .await
            .unwrap()
            .is_some());

        // List keys should include all three
        let keys = cp.list_tenant_api_keys("multi-keys").await.unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[tokio::test]
    #[cfg(feature = "api-keys")]
    async fn test_api_key_for_nonexistent_tenant_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir
            .path()
            .join("control.db")
            .to_string_lossy()
            .to_string();
        let storage = temp_dir
            .path()
            .join("{tenant_id}/db")
            .to_string_lossy()
            .to_string();

        let cp = ControlPlane::new(db_path, storage).unwrap();
        cp.initialize().await.unwrap();

        // Attempt to create API key for a tenant that does not exist should fail
        let result = cp
            .create_tenant_api_key("missing", "missing".to_string(), TenantRole::Admin, None)
            .await;
        assert!(result.is_err());
    }
}
