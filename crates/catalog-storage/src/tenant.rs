//! Multi-tenant support for MetaFuse catalog.
//!
//! This module provides tenant isolation through per-tenant SQLite databases.
//! Each tenant gets their own catalog file, ensuring complete data isolation
//! and simplified GDPR compliance.
//!
//! # Architecture
//!
//! ```text
//! TenantContext → TenantBackendFactory → Per-Tenant SQLite DBs
//!       ↓                  ↓
//!   Validation      Connection Pooling + LRU Cache
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use metafuse_catalog_storage::tenant::TenantContext;
//!
//! // Create validated tenant context
//! let ctx = TenantContext::new("acme-corp")?;
//! assert_eq!(ctx.tenant_id(), "acme-corp");
//! ```

use metafuse_catalog_core::{validation, CatalogError, Result};
use std::fmt;
use std::hash::{Hash, Hasher};

/// Minimum length for tenant identifiers.
pub const MIN_TENANT_ID_LEN: usize = 3;

/// Maximum length for tenant identifiers.
pub const MAX_TENANT_ID_LEN: usize = 63;

/// Validated tenant context for multi-tenant operations.
///
/// Represents a validated tenant identifier that can be used to route
/// requests to tenant-specific storage backends.
///
/// # Validation Rules
///
/// - Length: 3-63 characters
/// - Characters: lowercase alphanumeric, underscore, hyphen
/// - Must start with alphanumeric character
/// - Cannot end with hyphen
///
/// # Examples
///
/// ```rust,ignore
/// use metafuse_catalog_storage::tenant::TenantContext;
///
/// // Valid tenant IDs
/// let ctx = TenantContext::new("acme-corp").unwrap();
/// let ctx = TenantContext::new("tenant_123").unwrap();
///
/// // Invalid tenant IDs
/// assert!(TenantContext::new("ab").is_err());        // Too short
/// assert!(TenantContext::new("My Tenant").is_err()); // Invalid chars
/// assert!(TenantContext::new("-invalid").is_err()); // Starts with hyphen
/// ```
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Validated tenant identifier
    tenant_id: String,
}

impl TenantContext {
    /// Create a new validated tenant context.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Tenant identifier to validate
    ///
    /// # Errors
    ///
    /// Returns `CatalogError::ValidationError` if the tenant ID:
    /// - Is empty or too short (< 3 chars)
    /// - Is too long (> 63 chars)
    /// - Contains invalid characters
    /// - Starts with a hyphen or underscore
    /// - Ends with a hyphen
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let ctx = TenantContext::new("my-tenant")?;
    /// assert_eq!(ctx.tenant_id(), "my-tenant");
    /// ```
    pub fn new(tenant_id: impl Into<String>) -> Result<Self> {
        let id = tenant_id.into();

        // Additional validation for tenant-specific rules
        Self::validate_tenant_id(&id)?;

        Ok(Self { tenant_id: id })
    }

    /// Get the tenant identifier.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Convert to owned String.
    pub fn into_tenant_id(self) -> String {
        self.tenant_id
    }

    /// Validate tenant ID with stricter rules than generic identifiers.
    fn validate_tenant_id(id: &str) -> Result<()> {
        // Use existing validation for basic checks
        validation::validate_identifier(id, "tenant_id")?;

        // Additional length checks for tenant IDs
        if id.len() < MIN_TENANT_ID_LEN {
            return Err(CatalogError::ValidationError(format!(
                "tenant_id too short: {} < {} characters",
                id.len(),
                MIN_TENANT_ID_LEN
            )));
        }

        if id.len() > MAX_TENANT_ID_LEN {
            return Err(CatalogError::ValidationError(format!(
                "tenant_id too long: {} > {} characters",
                id.len(),
                MAX_TENANT_ID_LEN
            )));
        }

        // Must start with alphanumeric
        if let Some(first) = id.chars().next() {
            if !first.is_alphanumeric() {
                return Err(CatalogError::ValidationError(
                    "tenant_id must start with alphanumeric character".to_string(),
                ));
            }
        }

        // Cannot end with hyphen
        if id.ends_with('-') {
            return Err(CatalogError::ValidationError(
                "tenant_id cannot end with hyphen".to_string(),
            ));
        }

        Ok(())
    }
}

impl PartialEq for TenantContext {
    fn eq(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
    }
}

impl Eq for TenantContext {}

impl Hash for TenantContext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tenant_id.hash(state);
    }
}

impl fmt::Display for TenantContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.tenant_id)
    }
}

impl AsRef<str> for TenantContext {
    fn as_ref(&self) -> &str {
        &self.tenant_id
    }
}

/// Tenant tier for quota and rate limiting.
///
/// # Default Behavior
///
/// The default tier is `Standard`. This is used as a fallback when:
/// - Parsing an invalid tier string (e.g., `"invalid".parse::<TenantTier>().unwrap_or_default()`)
/// - Header-only tenant resolution where tier is looked up from DB
///
/// Note: Tier values are validated at API boundaries (tenant creation/update),
/// so invalid tiers in the database would only occur via direct DB manipulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TenantTier {
    /// Free tier with basic quotas (100 req/min rate limit)
    Free,
    /// Standard tier with higher quotas (1000 req/min rate limit)
    #[default]
    Standard,
    /// Premium tier with generous quotas (5000 req/min rate limit)
    Premium,
    /// Enterprise tier with custom quotas (10000 req/min rate limit)
    Enterprise,
}

impl TenantTier {
    /// Get tier as string.
    pub fn as_str(&self) -> &'static str {
        match self {
            TenantTier::Free => "free",
            TenantTier::Standard => "standard",
            TenantTier::Premium => "premium",
            TenantTier::Enterprise => "enterprise",
        }
    }
}

impl std::str::FromStr for TenantTier {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "free" => Ok(TenantTier::Free),
            "standard" => Ok(TenantTier::Standard),
            "premium" => Ok(TenantTier::Premium),
            "enterprise" => Ok(TenantTier::Enterprise),
            _ => Err(format!("unknown tier: {}", s)),
        }
    }
}

impl fmt::Display for TenantTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Tenant status for lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TenantStatus {
    /// Tenant is active and can make requests
    #[default]
    Active,
    /// Tenant is suspended (billing, abuse, etc.)
    Suspended,
    /// Tenant has requested deletion, in grace period
    PendingDeletion,
    /// Tenant has been purged (data deleted)
    Deleted,
}

impl TenantStatus {
    /// Get status as string.
    pub fn as_str(&self) -> &'static str {
        match self {
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
            TenantStatus::PendingDeletion => "pending_deletion",
            TenantStatus::Deleted => "deleted",
        }
    }

    /// Check if tenant can make data plane requests.
    pub fn is_operational(&self) -> bool {
        matches!(self, TenantStatus::Active)
    }
}

impl std::str::FromStr for TenantStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(TenantStatus::Active),
            "suspended" => Ok(TenantStatus::Suspended),
            "pending_deletion" => Ok(TenantStatus::PendingDeletion),
            "deleted" => Ok(TenantStatus::Deleted),
            _ => Err(format!("unknown status: {}", s)),
        }
    }
}

impl fmt::Display for TenantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tenant_ids() {
        assert!(TenantContext::new("acme").is_ok());
        assert!(TenantContext::new("acme-corp").is_ok());
        assert!(TenantContext::new("tenant_123").is_ok());
        assert!(TenantContext::new("my-tenant-name").is_ok());
        assert!(TenantContext::new("abc").is_ok()); // Minimum length
        assert!(TenantContext::new("a".repeat(63)).is_ok()); // Maximum length
    }

    #[test]
    fn test_invalid_tenant_ids() {
        // Too short
        assert!(TenantContext::new("ab").is_err());
        assert!(TenantContext::new("a").is_err());
        assert!(TenantContext::new("").is_err());

        // Too long
        assert!(TenantContext::new("a".repeat(64)).is_err());

        // Invalid characters
        assert!(TenantContext::new("My Tenant").is_err()); // Space
        assert!(TenantContext::new("tenant@corp").is_err()); // @
        assert!(TenantContext::new("tenant.corp").is_err()); // Dot
        assert!(TenantContext::new("tenant/corp").is_err()); // Slash

        // Starts with non-alphanumeric
        assert!(TenantContext::new("-invalid").is_err());
        assert!(TenantContext::new("_invalid").is_err());

        // Ends with hyphen
        assert!(TenantContext::new("invalid-").is_err());
    }

    #[test]
    fn test_tenant_context_equality() {
        let a = TenantContext::new("acme").unwrap();
        let b = TenantContext::new("acme").unwrap();
        let c = TenantContext::new("other").unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_tenant_context_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(TenantContext::new("acme").unwrap());
        set.insert(TenantContext::new("acme").unwrap()); // Duplicate

        assert_eq!(set.len(), 1);

        set.insert(TenantContext::new("other").unwrap());
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_tenant_context_display() {
        let ctx = TenantContext::new("acme-corp").unwrap();
        assert_eq!(format!("{}", ctx), "acme-corp");
    }

    #[test]
    fn test_tenant_tier_parsing() {
        assert_eq!("free".parse::<TenantTier>().ok(), Some(TenantTier::Free));
        assert_eq!("FREE".parse::<TenantTier>().ok(), Some(TenantTier::Free));
        assert_eq!(
            "standard".parse::<TenantTier>().ok(),
            Some(TenantTier::Standard)
        );
        assert_eq!(
            "premium".parse::<TenantTier>().ok(),
            Some(TenantTier::Premium)
        );
        assert_eq!(
            "enterprise".parse::<TenantTier>().ok(),
            Some(TenantTier::Enterprise)
        );
        assert!("unknown".parse::<TenantTier>().is_err());
    }

    #[test]
    fn test_tenant_tier_default_is_standard() {
        // Documents intentional behavior: TenantTier defaults to Standard.
        // This fallback is used when parsing fails (e.g., invalid DB value).
        // Note: Tier strings are validated at API boundaries; invalid values
        // should only occur via direct DB manipulation or migration issues.
        assert_eq!(TenantTier::default(), TenantTier::Standard);

        // Demonstrate the unwrap_or_default pattern used in rate limiting
        let invalid_tier: std::result::Result<TenantTier, _> = "invalid".parse();
        assert!(invalid_tier.is_err());
        let fallback = invalid_tier.unwrap_or_default();
        assert_eq!(fallback, TenantTier::Standard);
    }

    #[test]
    fn test_tenant_status_parsing() {
        assert_eq!(
            "active".parse::<TenantStatus>().ok(),
            Some(TenantStatus::Active)
        );
        assert_eq!(
            "suspended".parse::<TenantStatus>().ok(),
            Some(TenantStatus::Suspended)
        );
        assert_eq!(
            "pending_deletion".parse::<TenantStatus>().ok(),
            Some(TenantStatus::PendingDeletion)
        );
        assert_eq!(
            "deleted".parse::<TenantStatus>().ok(),
            Some(TenantStatus::Deleted)
        );
        assert!("unknown".parse::<TenantStatus>().is_err());
    }

    #[test]
    fn test_tenant_status_operational() {
        assert!(TenantStatus::Active.is_operational());
        assert!(!TenantStatus::Suspended.is_operational());
        assert!(!TenantStatus::PendingDeletion.is_operational());
        assert!(!TenantStatus::Deleted.is_operational());
    }
}
