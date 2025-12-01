//! Test Utilities Module
//!
//! Provides shared test infrastructure for integration testing the catalog API.
//! Enable via the `test-utils` feature flag.
//!
//! # Features
//!
//! - `TestDb`: Temporary SQLite database with automatic cleanup
//! - `TestControlPlane`: Pre-configured control plane for testing
//! - Fixtures for tenants, API keys, and requests
//! - `AuthenticatedRequest` builder for testing authenticated endpoints
//!
//! # Usage
//!
//! ```rust,ignore
//! use metafuse_catalog_api::test_utils::{TestControlPlane, TestTenantBuilder};
//!
//! #[tokio::test]
//! async fn test_tenant_creation() {
//!     let cp = TestControlPlane::new().await.unwrap();
//!     let tenant = TestTenantBuilder::new("test-corp")
//!         .tier("premium")
//!         .region("us-east1")
//!         .build(&cp)
//!         .await
//!         .unwrap();
//!     assert_eq!(tenant.tenant_id, "test-corp");
//! }
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};

use crate::control_plane::{AuditContext, ControlPlane, CreateTenantRequest, Tenant};
use metafuse_catalog_core::{CatalogError, Result};

#[cfg(feature = "api-keys")]
use crate::control_plane::TenantRole;
#[cfg(feature = "api-keys")]
use crate::tenant_resolver::{ResolvedTenant, TenantSource};
#[cfg(feature = "api-keys")]
use metafuse_catalog_storage::TenantTier;

// ============================================================================
// Test Database Infrastructure
// ============================================================================

/// A temporary test database that is automatically cleaned up when dropped.
///
/// Wraps a temporary directory containing the SQLite database file.
/// Use this for isolated test runs that don't interfere with each other.
pub struct TestDb {
    _temp_dir: TempDir,
    db_path: PathBuf,
}

impl TestDb {
    /// Create a new temporary test database.
    ///
    /// The database file is created in a temporary directory that will be
    /// automatically deleted when the `TestDb` is dropped.
    pub fn new() -> Result<Self> {
        let temp_dir = tempdir()
            .map_err(|e| CatalogError::Other(format!("Failed to create temp dir: {}", e)))?;
        let db_path = temp_dir.path().join("test_control_plane.db");
        Ok(Self {
            _temp_dir: temp_dir,
            db_path,
        })
    }

    /// Get the path to the database file.
    pub fn path(&self) -> &std::path::Path {
        &self.db_path
    }

    /// Get the path as a string.
    pub fn path_string(&self) -> String {
        self.db_path.to_string_lossy().to_string()
    }
}

impl Default for TestDb {
    fn default() -> Self {
        Self::new().expect("Failed to create test database")
    }
}

// ============================================================================
// Test Control Plane
// ============================================================================

/// A test control plane with a temporary database.
///
/// Provides a fully initialized control plane for integration testing.
/// The database is automatically cleaned up when this struct is dropped.
pub struct TestControlPlane {
    _test_db: TestDb,
    control_plane: Arc<ControlPlane>,
    storage_uri_template: String,
}

impl TestControlPlane {
    /// Create a new test control plane with default settings.
    ///
    /// Uses a temporary database and a test storage URI template.
    pub async fn new() -> Result<Self> {
        Self::with_template("gs://test-bucket/tenants/{tenant_id}/catalog.db").await
    }

    /// Create a new test control plane with a custom storage URI template.
    pub async fn with_template(storage_uri_template: &str) -> Result<Self> {
        let test_db = TestDb::new()?;
        let control_plane =
            ControlPlane::new(test_db.path_string(), storage_uri_template.to_string())?;

        // Initialize the database schema
        control_plane.initialize().await?;

        Ok(Self {
            _test_db: test_db,
            control_plane: Arc::new(control_plane),
            storage_uri_template: storage_uri_template.to_string(),
        })
    }

    /// Create a test control plane with region support.
    pub async fn with_region_template(region: &str) -> Result<Self> {
        let template = format!(
            "gs://test-bucket-{}/tenants/{{tenant_id}}/catalog.db",
            region
        );
        Self::with_template(&template).await
    }

    /// Get the underlying control plane.
    pub fn control_plane(&self) -> &Arc<ControlPlane> {
        &self.control_plane
    }

    /// Get the storage URI template.
    pub fn storage_uri_template(&self) -> &str {
        &self.storage_uri_template
    }

    /// Create a tenant using the builder pattern.
    pub fn tenant(&self, tenant_id: &str) -> TestTenantBuilder {
        TestTenantBuilder::new(tenant_id)
    }
}

// ============================================================================
// Test Tenant Builder
// ============================================================================

/// Builder for creating test tenants with customizable properties.
///
/// # Example
///
/// ```rust,ignore
/// let tenant = TestTenantBuilder::new("acme-corp")
///     .display_name("Acme Corporation")
///     .tier("enterprise")
///     .region("us-east1")
///     .quota_max_datasets(50000)
///     .build(&control_plane)
///     .await?;
/// ```
pub struct TestTenantBuilder {
    tenant_id: String,
    display_name: Option<String>,
    admin_email: Option<String>,
    tier: Option<String>,
    region: Option<String>,
    quota_max_datasets: Option<i64>,
    quota_max_storage_bytes: Option<i64>,
    quota_max_api_calls_per_hour: Option<i64>,
}

impl TestTenantBuilder {
    /// Create a new tenant builder with the given tenant ID.
    pub fn new(tenant_id: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            display_name: None,
            admin_email: None,
            tier: None,
            region: None,
            quota_max_datasets: None,
            quota_max_storage_bytes: None,
            quota_max_api_calls_per_hour: None,
        }
    }

    /// Set the display name.
    pub fn display_name(mut self, name: &str) -> Self {
        self.display_name = Some(name.to_string());
        self
    }

    /// Set the admin email.
    pub fn admin_email(mut self, email: &str) -> Self {
        self.admin_email = Some(email.to_string());
        self
    }

    /// Set the tier (free, standard, premium, enterprise).
    pub fn tier(mut self, tier: &str) -> Self {
        self.tier = Some(tier.to_string());
        self
    }

    /// Set the region.
    pub fn region(mut self, region: &str) -> Self {
        self.region = Some(region.to_string());
        self
    }

    /// Set the maximum datasets quota.
    pub fn quota_max_datasets(mut self, quota: i64) -> Self {
        self.quota_max_datasets = Some(quota);
        self
    }

    /// Set the maximum storage bytes quota.
    pub fn quota_max_storage_bytes(mut self, quota: i64) -> Self {
        self.quota_max_storage_bytes = Some(quota);
        self
    }

    /// Set the maximum API calls per hour quota.
    pub fn quota_max_api_calls_per_hour(mut self, quota: i64) -> Self {
        self.quota_max_api_calls_per_hour = Some(quota);
        self
    }

    /// Build and create the tenant using the control plane.
    #[cfg(feature = "api-keys")]
    pub async fn build(self, cp: &TestControlPlane) -> Result<Tenant> {
        let request = CreateTenantRequest {
            tenant_id: self.tenant_id.clone(),
            display_name: self
                .display_name
                .unwrap_or_else(|| format!("Test Tenant {}", self.tenant_id)),
            admin_email: self
                .admin_email
                .unwrap_or_else(|| format!("admin@{}.test", self.tenant_id)),
            tier: self.tier,
            region: self.region,
            quota_max_datasets: self.quota_max_datasets,
            quota_max_storage_bytes: self.quota_max_storage_bytes,
            quota_max_api_calls_per_hour: self.quota_max_api_calls_per_hour,
        };

        // When api-keys feature is enabled, create_tenant returns (Tenant, storage_uri)
        let (tenant, _storage_uri) = cp
            .control_plane()
            .create_tenant(request, test_audit_context())
            .await?;
        Ok(tenant)
    }

    /// Build and create the tenant using the control plane.
    #[cfg(not(feature = "api-keys"))]
    pub async fn build(self, cp: &TestControlPlane) -> Result<Tenant> {
        let request = CreateTenantRequest {
            tenant_id: self.tenant_id.clone(),
            display_name: self
                .display_name
                .unwrap_or_else(|| format!("Test Tenant {}", self.tenant_id)),
            admin_email: self
                .admin_email
                .unwrap_or_else(|| format!("admin@{}.test", self.tenant_id)),
            tier: self.tier,
            region: self.region,
            quota_max_datasets: self.quota_max_datasets,
            quota_max_storage_bytes: self.quota_max_storage_bytes,
            quota_max_api_calls_per_hour: self.quota_max_api_calls_per_hour,
        };

        cp.control_plane()
            .create_tenant(request, test_audit_context())
            .await
    }

    /// Build the CreateTenantRequest without creating the tenant.
    pub fn build_request(self) -> CreateTenantRequest {
        CreateTenantRequest {
            tenant_id: self.tenant_id.clone(),
            display_name: self
                .display_name
                .unwrap_or_else(|| format!("Test Tenant {}", self.tenant_id)),
            admin_email: self
                .admin_email
                .unwrap_or_else(|| format!("admin@{}.test", self.tenant_id)),
            tier: self.tier,
            region: self.region,
            quota_max_datasets: self.quota_max_datasets,
            quota_max_storage_bytes: self.quota_max_storage_bytes,
            quota_max_api_calls_per_hour: self.quota_max_api_calls_per_hour,
        }
    }
}

// ============================================================================
// Test API Key Helpers (requires api-keys feature)
// ============================================================================

/// Test API key information returned after creation.
#[cfg(feature = "api-keys")]
pub struct TestApiKey {
    /// The plaintext API key (only available at creation time)
    pub plaintext: String,
    /// The tenant this key belongs to
    pub tenant_id: String,
    /// The name of the key
    pub name: String,
    /// The role granted by this key
    pub role: TenantRole,
}

#[cfg(feature = "api-keys")]
impl TestApiKey {
    /// Create a new API key for testing.
    pub async fn create(
        cp: &TestControlPlane,
        tenant_id: &str,
        name: &str,
        role: TenantRole,
    ) -> Result<Self> {
        let plaintext = cp
            .control_plane()
            .create_tenant_api_key(tenant_id, name.to_string(), role, None)
            .await?;

        Ok(Self {
            plaintext,
            tenant_id: tenant_id.to_string(),
            name: name.to_string(),
            role,
        })
    }

    /// Create an admin API key.
    pub async fn admin(cp: &TestControlPlane, tenant_id: &str) -> Result<Self> {
        Self::create(cp, tenant_id, "test-admin-key", TenantRole::Admin).await
    }

    /// Create an editor API key.
    pub async fn editor(cp: &TestControlPlane, tenant_id: &str) -> Result<Self> {
        Self::create(cp, tenant_id, "test-editor-key", TenantRole::Editor).await
    }

    /// Create a viewer API key.
    pub async fn viewer(cp: &TestControlPlane, tenant_id: &str) -> Result<Self> {
        Self::create(cp, tenant_id, "test-viewer-key", TenantRole::Viewer).await
    }

    /// Get the Authorization header value for this key.
    pub fn auth_header(&self) -> String {
        format!("Bearer {}", self.plaintext)
    }
}

// ============================================================================
// Test Audit Context
// ============================================================================

/// Create a test audit context with default values.
pub fn test_audit_context() -> AuditContext {
    AuditContext {
        actor: "test-system".to_string(),
        request_id: Some("test-request-id".to_string()),
        client_ip: Some("127.0.0.1".to_string()),
    }
}

/// Create a test audit context with a custom actor.
pub fn test_audit_context_with_actor(actor: &str) -> AuditContext {
    AuditContext {
        actor: actor.to_string(),
        request_id: Some(format!("test-{}-request", actor)),
        client_ip: Some("127.0.0.1".to_string()),
    }
}

// ============================================================================
// Test ResolvedTenant Helpers (requires api-keys feature)
// ============================================================================

#[cfg(feature = "api-keys")]
/// Create a test ResolvedTenant for unit testing handlers.
///
/// # Example
///
/// ```rust,ignore
/// let tenant = create_test_tenant("acme", TenantRole::Admin, TenantSource::ApiKey);
/// ```
pub fn create_test_tenant(
    tenant_id: &str,
    role: TenantRole,
    source: TenantSource,
) -> ResolvedTenant {
    ResolvedTenant::for_testing(tenant_id, Some(role), source)
}

#[cfg(feature = "api-keys")]
/// Create a ResolvedTenant as if resolved from header only.
pub fn create_header_tenant(tenant_id: &str) -> ResolvedTenant {
    ResolvedTenant::for_testing(tenant_id, None, TenantSource::Header)
}

#[cfg(feature = "api-keys")]
/// Create a ResolvedTenant with specific tier for rate limiting tests.
pub fn create_tenant_with_tier(
    tenant_id: &str,
    role: TenantRole,
    tier: TenantTier,
    source: TenantSource,
) -> ResolvedTenant {
    ResolvedTenant::for_testing_with_tier(tenant_id, Some(role), Some(tier), source)
}

// ============================================================================
// Test Fixtures
// ============================================================================

/// Standard test tenant configurations for consistent testing.
pub mod fixtures {
    use super::*;

    /// Standard free-tier tenant fixture.
    pub fn free_tenant() -> TestTenantBuilder {
        TestTenantBuilder::new("free-tenant")
            .display_name("Free Tier Corp")
            .tier("free")
            .quota_max_datasets(100)
            .quota_max_storage_bytes(1_073_741_824) // 1GB
            .quota_max_api_calls_per_hour(1000)
    }

    /// Standard premium tenant fixture.
    pub fn premium_tenant() -> TestTenantBuilder {
        TestTenantBuilder::new("premium-tenant")
            .display_name("Premium Corp")
            .tier("premium")
            .quota_max_datasets(50000)
            .quota_max_storage_bytes(107_374_182_400) // 100GB
            .quota_max_api_calls_per_hour(100000)
    }

    /// Enterprise tenant fixture with region.
    pub fn enterprise_tenant(region: &str) -> TestTenantBuilder {
        TestTenantBuilder::new("enterprise-tenant")
            .display_name("Enterprise Corp")
            .tier("enterprise")
            .region(region)
            .quota_max_datasets(1_000_000)
            .quota_max_storage_bytes(1_099_511_627_776) // 1TB
            .quota_max_api_calls_per_hour(1_000_000)
    }

    /// Multi-region test tenants for region isolation tests.
    pub fn regional_tenants() -> Vec<(&'static str, &'static str)> {
        vec![
            ("us-tenant", "us-east1"),
            ("eu-tenant", "europe-west1"),
            ("asia-tenant", "asia-east1"),
        ]
    }

    /// Invalid tenant IDs for validation tests.
    pub fn invalid_tenant_ids() -> Vec<&'static str> {
        vec![
            "",                  // Empty
            "ab",                // Too short
            "UPPERCASE",         // Invalid case
            "has spaces",        // Spaces not allowed
            "has@special",       // Special chars
            "-starts-with-dash", // Cannot start with dash
            "ends-with-dash-",   // Cannot end with dash
            "double--dash",      // No consecutive dashes
        ]
    }

    /// Get a too-long tenant ID for validation tests (owned String).
    pub fn too_long_tenant_id() -> String {
        "a".repeat(64)
    }

    /// Valid tenant IDs for testing.
    pub fn valid_tenant_ids() -> Vec<&'static str> {
        vec!["abc", "acme-corp", "tenant123", "my-test-tenant", "a1b2c3"]
    }
}

// ============================================================================
// Assertion Helpers
// ============================================================================

/// Assert that a tenant has the expected status.
pub fn assert_tenant_status(tenant: &Tenant, expected_status: &str) {
    assert_eq!(
        tenant.status, expected_status,
        "Expected tenant {} to have status '{}', but got '{}'",
        tenant.tenant_id, expected_status, tenant.status
    );
}

/// Assert that a tenant has the expected tier.
pub fn assert_tenant_tier(tenant: &Tenant, expected_tier: &str) {
    assert_eq!(
        tenant.tier, expected_tier,
        "Expected tenant {} to have tier '{}', but got '{}'",
        tenant.tenant_id, expected_tier, tenant.tier
    );
}

/// Assert that a tenant has the expected region.
pub fn assert_tenant_region(tenant: &Tenant, expected_region: Option<&str>) {
    assert_eq!(
        tenant.region.as_deref(),
        expected_region,
        "Expected tenant {} to have region {:?}, but got {:?}",
        tenant.tenant_id,
        expected_region,
        tenant.region
    );
}

// ============================================================================
// Test Setup Macros
// ============================================================================

/// Macro for setting up a test control plane with common boilerplate.
///
/// # Example
///
/// ```rust,ignore
/// setup_test_control_plane!(cp);
/// // cp is now a TestControlPlane
/// ```
#[macro_export]
macro_rules! setup_test_control_plane {
    ($name:ident) => {
        let $name = $crate::test_utils::TestControlPlane::new()
            .await
            .expect("Failed to create test control plane");
    };
}

/// Macro for setting up a test tenant.
///
/// # Example
///
/// ```rust,ignore
/// setup_test_control_plane!(cp);
/// setup_test_tenant!(cp, tenant, "my-tenant");
/// // tenant is now a Tenant struct
/// ```
#[macro_export]
macro_rules! setup_test_tenant {
    ($cp:ident, $name:ident, $tenant_id:expr) => {
        let $name = $crate::test_utils::TestTenantBuilder::new($tenant_id)
            .build(&$cp)
            .await
            .expect("Failed to create test tenant");
    };
    ($cp:ident, $name:ident, $tenant_id:expr, tier: $tier:expr) => {
        let $name = $crate::test_utils::TestTenantBuilder::new($tenant_id)
            .tier($tier)
            .build(&$cp)
            .await
            .expect("Failed to create test tenant");
    };
    ($cp:ident, $name:ident, $tenant_id:expr, region: $region:expr) => {
        let $name = $crate::test_utils::TestTenantBuilder::new($tenant_id)
            .region($region)
            .build(&$cp)
            .await
            .expect("Failed to create test tenant");
    };
}

// ============================================================================
// Unit Tests for Test Utilities
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_db_creation() {
        let db = TestDb::new().unwrap();
        assert!(db.path().parent().unwrap().exists());
    }

    #[tokio::test]
    async fn test_control_plane_creation() {
        let cp = TestControlPlane::new().await.unwrap();
        assert!(cp.storage_uri_template().contains("{tenant_id}"));
    }

    #[tokio::test]
    async fn test_tenant_builder() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("test-builder")
            .display_name("Test Builder Corp")
            .tier("premium")
            .admin_email("admin@builder.test")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.tenant_id, "test-builder");
        assert_eq!(tenant.display_name, "Test Builder Corp");
        assert_eq!(tenant.tier, "premium");
        assert_eq!(tenant.admin_email, "admin@builder.test");
        assert_eq!(tenant.status, "active");
    }

    #[tokio::test]
    async fn test_tenant_builder_defaults() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("default-test")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.tenant_id, "default-test");
        assert_eq!(tenant.display_name, "Test Tenant default-test");
        assert_eq!(tenant.admin_email, "admin@default-test.test");
        assert_eq!(tenant.tier, "standard");
    }

    #[tokio::test]
    async fn test_tenant_with_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("regional-test")
            .region("us-east1")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.region, Some("us-east1".to_string()));
    }

    #[tokio::test]
    async fn test_fixture_free_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = fixtures::free_tenant().build(&cp).await.unwrap();

        assert_eq!(tenant.tier, "free");
        assert_eq!(tenant.quota_max_datasets, 100);
    }

    #[tokio::test]
    async fn test_fixture_premium_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = fixtures::premium_tenant().build(&cp).await.unwrap();

        assert_eq!(tenant.tier, "premium");
        assert_eq!(tenant.quota_max_datasets, 50000);
    }

    #[tokio::test]
    async fn test_fixture_enterprise_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = fixtures::enterprise_tenant("us-east1")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.tier, "enterprise");
        assert_eq!(tenant.region, Some("us-east1".to_string()));
    }

    #[tokio::test]
    async fn test_audit_context_creation() {
        let ctx = super::test_audit_context();
        assert_eq!(ctx.actor, "test-system");
        assert!(ctx.request_id.is_some());
        assert!(ctx.client_ip.is_some());
    }

    #[tokio::test]
    async fn test_audit_context_custom_actor() {
        let ctx = super::test_audit_context_with_actor("custom-actor");
        assert_eq!(ctx.actor, "custom-actor");
    }

    #[tokio::test]
    async fn test_assertion_helpers() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("assert-test")
            .tier("premium")
            .region("us-east1")
            .build(&cp)
            .await
            .unwrap();

        assert_tenant_status(&tenant, "active");
        assert_tenant_tier(&tenant, "premium");
        assert_tenant_region(&tenant, Some("us-east1"));
    }

    #[cfg(feature = "api-keys")]
    #[tokio::test]
    async fn test_api_key_creation() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create a tenant first
        TestTenantBuilder::new("api-key-test")
            .build(&cp)
            .await
            .unwrap();

        // Create API keys with different roles
        let admin_key = TestApiKey::admin(&cp, "api-key-test").await.unwrap();
        assert!(admin_key.plaintext.starts_with("mft_"));
        assert_eq!(admin_key.role, TenantRole::Admin);

        let editor_key = TestApiKey::editor(&cp, "api-key-test").await.unwrap();
        assert_eq!(editor_key.role, TenantRole::Editor);

        let viewer_key = TestApiKey::viewer(&cp, "api-key-test").await.unwrap();
        assert_eq!(viewer_key.role, TenantRole::Viewer);
    }

    #[cfg(feature = "api-keys")]
    #[tokio::test]
    async fn test_auth_header() {
        let cp = TestControlPlane::new().await.unwrap();

        TestTenantBuilder::new("auth-test")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "auth-test").await.unwrap();
        let header = key.auth_header();

        assert!(header.starts_with("Bearer mft_"));
    }

    #[cfg(feature = "api-keys")]
    #[test]
    fn test_resolved_tenant_helpers() {
        let tenant = create_test_tenant("test-tenant", TenantRole::Admin, TenantSource::ApiKey);
        assert_eq!(tenant.tenant_id(), "test-tenant");
        assert_eq!(tenant.role(), Some(TenantRole::Admin));
        assert_eq!(tenant.source(), TenantSource::ApiKey);

        let header_tenant = create_header_tenant("header-only");
        assert_eq!(header_tenant.tenant_id(), "header-only");
        assert_eq!(header_tenant.role(), None);
        assert_eq!(header_tenant.source(), TenantSource::Header);
    }

    #[cfg(feature = "api-keys")]
    #[test]
    fn test_tenant_with_tier_helper() {
        let tenant = create_tenant_with_tier(
            "tiered-tenant",
            TenantRole::Editor,
            TenantTier::Premium,
            TenantSource::ApiKey,
        );
        assert_eq!(tenant.tenant_id(), "tiered-tenant");
        assert_eq!(tenant.role(), Some(TenantRole::Editor));
        assert_eq!(tenant.tier(), Some(TenantTier::Premium));
    }
}
