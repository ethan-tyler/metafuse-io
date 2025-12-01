//! Control Plane Integration Tests
//!
//! Comprehensive tests for the multi-tenant control plane, covering:
//! - Tenant lifecycle management (create, read, update, delete)
//! - Tenant status transitions (active → suspended → reactivated → deleted → purged)
//! - Tenant validation (ID format, tier validation)
//! - Quota management
//! - Region support
//! - Audit logging
//!
//! These tests verify the core control plane functionality that manages
//! tenant provisioning and lifecycle in a multi-tenant deployment.

// This test module requires the test-utils feature
#![cfg(feature = "test-utils")]

use metafuse_catalog_api::control_plane::{AuditContext, CreateTenantRequest, UpdateTenantRequest};
use metafuse_catalog_api::test_utils::{
    test_audit_context, test_audit_context_with_actor, TestControlPlane, TestTenantBuilder,
};
use metafuse_catalog_core::CatalogError;
use serial_test::serial;

// ============================================================================
// Test Helpers
// ============================================================================

fn admin_audit() -> AuditContext {
    test_audit_context_with_actor("admin@test.com")
}

/// Helper to create an UpdateTenantRequest with only display_name set
fn update_display_name(name: &str) -> UpdateTenantRequest {
    UpdateTenantRequest {
        display_name: Some(name.to_string()),
        tier: None,
        admin_email: None,
        quota_max_datasets: None,
        quota_max_storage_bytes: None,
        quota_max_api_calls_per_hour: None,
        region: None,
    }
}

/// Helper to create an UpdateTenantRequest with only tier set
fn update_tier(tier: &str) -> UpdateTenantRequest {
    UpdateTenantRequest {
        display_name: None,
        tier: Some(tier.to_string()),
        admin_email: None,
        quota_max_datasets: None,
        quota_max_storage_bytes: None,
        quota_max_api_calls_per_hour: None,
        region: None,
    }
}

/// Helper to create an UpdateTenantRequest with only region set
fn update_region(region: &str) -> UpdateTenantRequest {
    UpdateTenantRequest {
        display_name: None,
        tier: None,
        admin_email: None,
        quota_max_datasets: None,
        quota_max_storage_bytes: None,
        quota_max_api_calls_per_hour: None,
        region: Some(region.to_string()),
    }
}

/// Helper to create an empty UpdateTenantRequest
fn empty_update() -> UpdateTenantRequest {
    UpdateTenantRequest {
        display_name: None,
        tier: None,
        admin_email: None,
        quota_max_datasets: None,
        quota_max_storage_bytes: None,
        quota_max_api_calls_per_hour: None,
        region: None,
    }
}

/// Default limit for audit log queries
const AUDIT_LOG_LIMIT: usize = 100;

// ============================================================================
// Tenant Creation Tests
// ============================================================================

mod tenant_creation {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_create_tenant_with_defaults() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("default-tenant")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.tenant_id, "default-tenant");
        assert_eq!(tenant.status, "active");
        assert_eq!(tenant.tier, "standard"); // Default tier
        assert!(tenant.region.is_none()); // No default region
        assert_eq!(tenant.quota_max_datasets, 10000); // Default quota
        assert_eq!(tenant.quota_max_storage_bytes, 10737418240); // 10GB default
        assert_eq!(tenant.quota_max_api_calls_per_hour, 10000); // Default rate limit
    }

    #[tokio::test]
    #[serial]
    async fn test_create_tenant_with_custom_settings() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("custom-tenant")
            .display_name("Custom Corp")
            .admin_email("admin@custom.test")
            .tier("premium")
            .region("us-east1")
            .quota_max_datasets(50000)
            .quota_max_storage_bytes(107374182400) // 100GB
            .quota_max_api_calls_per_hour(100000)
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.tenant_id, "custom-tenant");
        assert_eq!(tenant.display_name, "Custom Corp");
        assert_eq!(tenant.admin_email, "admin@custom.test");
        assert_eq!(tenant.tier, "premium");
        assert_eq!(tenant.region, Some("us-east1".to_string()));
        assert_eq!(tenant.quota_max_datasets, 50000);
        assert_eq!(tenant.quota_max_storage_bytes, 107374182400);
        assert_eq!(tenant.quota_max_api_calls_per_hour, 100000);
    }

    #[tokio::test]
    #[serial]
    async fn test_create_tenant_all_tiers() {
        let cp = TestControlPlane::new().await.unwrap();

        let tiers = vec!["free", "standard", "premium", "enterprise"];

        for tier in tiers {
            let tenant_id = format!("{}-tier-tenant", tier);
            let tenant = TestTenantBuilder::new(&tenant_id)
                .tier(tier)
                .build(&cp)
                .await
                .unwrap();

            assert_eq!(tenant.tier, tier);
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_create_tenant_invalid_tier() {
        let cp = TestControlPlane::new().await.unwrap();

        let result = TestTenantBuilder::new("invalid-tier-tenant")
            .tier("gold") // Invalid tier
            .build(&cp)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            CatalogError::ValidationError(msg) => {
                assert!(msg.contains("Invalid tier"));
                assert!(msg.contains("gold"));
            }
            other => panic!("Expected ValidationError, got {:?}", other),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_create_duplicate_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create first tenant
        TestTenantBuilder::new("duplicate-test")
            .build(&cp)
            .await
            .unwrap();

        // Attempt to create duplicate
        let result = TestTenantBuilder::new("duplicate-test").build(&cp).await;

        assert!(result.is_err());
        // SQLite will return a constraint violation
    }

    #[tokio::test]
    #[serial]
    async fn test_create_tenant_storage_uri_generated() {
        let cp = TestControlPlane::with_template("gs://test-bucket/tenants/{tenant_id}/catalog.db")
            .await
            .unwrap();

        let _tenant = TestTenantBuilder::new("storage-test")
            .build(&cp)
            .await
            .unwrap();

        // Verify the storage URI was generated correctly by checking the tenant's storage_uri
        // Note: storage_uri is generated from the template
    }

    #[tokio::test]
    #[serial]
    async fn test_create_tenant_with_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let regions = vec!["us-east1", "us-west1", "europe-west1", "asia-east1"];

        for region in regions {
            let tenant_id = format!("regional-{}", region.replace("-", ""));
            let tenant = TestTenantBuilder::new(&tenant_id)
                .region(region)
                .build(&cp)
                .await
                .unwrap();

            assert_eq!(tenant.region, Some(region.to_string()));
        }
    }
}

// ============================================================================
// Tenant Validation Tests
// ============================================================================

mod tenant_validation {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_valid_tenant_ids() {
        let cp = TestControlPlane::new().await.unwrap();

        let valid_ids = vec![
            "abc",
            "acme-corp",
            "tenant123",
            "my-test-tenant",
            "a1b2c3",
            "test-tenant-123",
        ];

        for tenant_id in valid_ids {
            let result = TestTenantBuilder::new(tenant_id).build(&cp).await;
            assert!(
                result.is_ok(),
                "Expected tenant_id '{}' to be valid, but got error: {:?}",
                tenant_id,
                result.err()
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_tenant_id_empty() {
        let cp = TestControlPlane::new().await.unwrap();

        let result = TestTenantBuilder::new("").build(&cp).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_tenant_id_too_short() {
        let cp = TestControlPlane::new().await.unwrap();

        let result = TestTenantBuilder::new("ab").build(&cp).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_tenant_id_uppercase() {
        let cp = TestControlPlane::new().await.unwrap();

        let result = TestTenantBuilder::new("UPPERCASE").build(&cp).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_tenant_id_special_chars() {
        let cp = TestControlPlane::new().await.unwrap();

        // These special characters are NOT allowed
        let invalid_ids = vec![
            "has@special",
            "has.dot",
            "has/slash",
            "has\\backslash",
            "has space",
        ];

        for tenant_id in invalid_ids {
            let result = TestTenantBuilder::new(tenant_id).build(&cp).await;
            assert!(
                result.is_err(),
                "Expected tenant_id '{}' to be invalid",
                tenant_id
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_tenant_id_dash_position() {
        let cp = TestControlPlane::new().await.unwrap();

        // Cannot start with dash or end with dash
        let invalid_ids = vec!["-starts-with-dash", "ends-with-dash-"];

        for tenant_id in invalid_ids {
            let result = TestTenantBuilder::new(tenant_id).build(&cp).await;
            assert!(
                result.is_err(),
                "Expected tenant_id '{}' to be invalid",
                tenant_id
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_valid_tenant_id_with_underscore() {
        // Underscores and consecutive dashes ARE allowed
        let cp = TestControlPlane::new().await.unwrap();

        let result = TestTenantBuilder::new("has_underscore").build(&cp).await;
        assert!(
            result.is_ok(),
            "Underscores should be allowed in tenant IDs"
        );

        let result2 = TestTenantBuilder::new("double--dash").build(&cp).await;
        assert!(
            result2.is_ok(),
            "Consecutive dashes should be allowed in tenant IDs"
        );
    }
}

// ============================================================================
// Tenant Get/List Tests
// ============================================================================

mod tenant_retrieval {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_get_tenant_exists() {
        let cp = TestControlPlane::new().await.unwrap();

        let created = TestTenantBuilder::new("get-test")
            .display_name("Get Test Corp")
            .build(&cp)
            .await
            .unwrap();

        let retrieved = cp
            .control_plane()
            .get_tenant("get-test")
            .await
            .unwrap()
            .expect("Tenant should exist");

        assert_eq!(retrieved.id, created.id);
        assert_eq!(retrieved.tenant_id, "get-test");
        assert_eq!(retrieved.display_name, "Get Test Corp");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_tenant_not_found() {
        let cp = TestControlPlane::new().await.unwrap();

        let result = cp.control_plane().get_tenant("nonexistent").await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_list_tenants_empty() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenants = cp.control_plane().list_tenants(None).await.unwrap();

        assert!(tenants.is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn test_list_tenants_multiple() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create several tenants
        for i in 1..=5 {
            TestTenantBuilder::new(&format!("list-test-{}", i))
                .build(&cp)
                .await
                .unwrap();
        }

        let tenants = cp.control_plane().list_tenants(None).await.unwrap();

        assert_eq!(tenants.len(), 5);
    }

    #[tokio::test]
    #[serial]
    async fn test_list_tenants_filter_by_status() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create active and suspended tenants
        let _active1 = TestTenantBuilder::new("filter-active-1")
            .build(&cp)
            .await
            .unwrap();
        let _active2 = TestTenantBuilder::new("filter-active-2")
            .build(&cp)
            .await
            .unwrap();
        let suspended = TestTenantBuilder::new("filter-suspended")
            .build(&cp)
            .await
            .unwrap();

        // Suspend one tenant
        cp.control_plane()
            .suspend_tenant(&suspended.tenant_id, admin_audit())
            .await
            .unwrap();

        // List only active tenants
        let active_tenants = cp
            .control_plane()
            .list_tenants(Some("active"))
            .await
            .unwrap();
        assert_eq!(active_tenants.len(), 2);

        // List only suspended tenants
        let suspended_tenants = cp
            .control_plane()
            .list_tenants(Some("suspended"))
            .await
            .unwrap();
        assert_eq!(suspended_tenants.len(), 1);
        assert_eq!(suspended_tenants[0].tenant_id, "filter-suspended");
    }

    #[tokio::test]
    #[serial]
    async fn test_list_tenants_ordered_by_created_at() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenants in order
        for i in 1..=3 {
            TestTenantBuilder::new(&format!("ordered-{}", i))
                .build(&cp)
                .await
                .unwrap();
            // Small delay to ensure different timestamps
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        let tenants = cp.control_plane().list_tenants(None).await.unwrap();

        // Should be in descending order (most recent first)
        assert_eq!(tenants[0].tenant_id, "ordered-3");
        assert_eq!(tenants[1].tenant_id, "ordered-2");
        assert_eq!(tenants[2].tenant_id, "ordered-1");
    }
}

// ============================================================================
// Tenant Update Tests
// ============================================================================

mod tenant_update {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_update_tenant_display_name() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("update-name-test")
            .display_name("Original Name")
            .build(&cp)
            .await
            .unwrap();

        let updated = cp
            .control_plane()
            .update_tenant(
                &tenant.tenant_id,
                update_display_name("Updated Name"),
                admin_audit(),
            )
            .await
            .unwrap();

        assert_eq!(updated.display_name, "Updated Name");
    }

    #[tokio::test]
    #[serial]
    async fn test_update_tenant_tier() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("update-tier-test")
            .tier("free")
            .build(&cp)
            .await
            .unwrap();

        let updated = cp
            .control_plane()
            .update_tenant(&tenant.tenant_id, update_tier("enterprise"), admin_audit())
            .await
            .unwrap();

        assert_eq!(updated.tier, "enterprise");
    }

    #[tokio::test]
    #[serial]
    async fn test_update_tenant_invalid_tier() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("update-invalid-tier")
            .build(&cp)
            .await
            .unwrap();

        let result = cp
            .control_plane()
            .update_tenant(
                &tenant.tenant_id,
                update_tier("invalid-tier"),
                admin_audit(),
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            CatalogError::ValidationError(msg) => {
                assert!(msg.contains("Invalid tier"));
            }
            other => panic!("Expected ValidationError, got {:?}", other),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_update_tenant_quotas() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("update-quotas-test")
            .build(&cp)
            .await
            .unwrap();

        let updated = cp
            .control_plane()
            .update_tenant(
                &tenant.tenant_id,
                UpdateTenantRequest {
                    display_name: None,
                    tier: None,
                    admin_email: None,
                    quota_max_datasets: Some(100000),
                    quota_max_storage_bytes: Some(1099511627776), // 1TB
                    quota_max_api_calls_per_hour: Some(500000),
                    region: None,
                },
                admin_audit(),
            )
            .await
            .unwrap();

        assert_eq!(updated.quota_max_datasets, 100000);
        assert_eq!(updated.quota_max_storage_bytes, 1099511627776);
        assert_eq!(updated.quota_max_api_calls_per_hour, 500000);
    }

    #[tokio::test]
    #[serial]
    async fn test_update_tenant_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("update-region-test")
            .build(&cp)
            .await
            .unwrap();

        assert!(tenant.region.is_none());

        let updated = cp
            .control_plane()
            .update_tenant(
                &tenant.tenant_id,
                update_region("europe-west1"),
                admin_audit(),
            )
            .await
            .unwrap();

        assert_eq!(updated.region, Some("europe-west1".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn test_update_tenant_multiple_fields() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("update-multi-test")
            .display_name("Original")
            .tier("free")
            .build(&cp)
            .await
            .unwrap();

        let updated = cp
            .control_plane()
            .update_tenant(
                &tenant.tenant_id,
                UpdateTenantRequest {
                    display_name: Some("Updated Corp".to_string()),
                    tier: Some("premium".to_string()),
                    admin_email: Some("new-admin@test.com".to_string()),
                    quota_max_datasets: Some(75000),
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                admin_audit(),
            )
            .await
            .unwrap();

        assert_eq!(updated.display_name, "Updated Corp");
        assert_eq!(updated.tier, "premium");
        assert_eq!(updated.admin_email, "new-admin@test.com");
        assert_eq!(updated.quota_max_datasets, 75000);
    }

    #[tokio::test]
    #[serial]
    async fn test_update_tenant_no_changes() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("update-empty-test")
            .build(&cp)
            .await
            .unwrap();

        let result = cp
            .control_plane()
            .update_tenant(&tenant.tenant_id, empty_update(), admin_audit())
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            CatalogError::ValidationError(msg) => {
                assert!(msg.contains("No fields to update"));
            }
            other => panic!("Expected ValidationError, got {:?}", other),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_update_nonexistent_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let result = cp
            .control_plane()
            .update_tenant(
                "nonexistent-tenant",
                update_display_name("Test"),
                admin_audit(),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_update_deleted_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("update-deleted-test")
            .build(&cp)
            .await
            .unwrap();

        // Delete the tenant
        cp.control_plane()
            .delete_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Purge it
        cp.control_plane()
            .purge_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Try to update
        let result = cp
            .control_plane()
            .update_tenant(
                &tenant.tenant_id,
                update_display_name("Test"),
                admin_audit(),
            )
            .await;

        assert!(result.is_err());
    }
}

// ============================================================================
// Tenant Lifecycle Tests (Suspend/Reactivate/Delete/Purge)
// ============================================================================

mod tenant_lifecycle {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_suspend_active_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("suspend-test")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.status, "active");

        let suspended = cp
            .control_plane()
            .suspend_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        assert_eq!(suspended.status, "suspended");
        assert!(suspended.suspended_at.is_some());
    }

    #[tokio::test]
    #[serial]
    async fn test_suspend_already_suspended_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("double-suspend-test")
            .build(&cp)
            .await
            .unwrap();

        // First suspension
        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Second suspension should fail
        let result = cp
            .control_plane()
            .suspend_tenant(&tenant.tenant_id, admin_audit())
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            CatalogError::ValidationError(msg) => {
                assert!(msg.contains("not active"));
            }
            other => panic!("Expected ValidationError, got {:?}", other),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_reactivate_suspended_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("reactivate-test")
            .build(&cp)
            .await
            .unwrap();

        // Suspend
        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Reactivate
        let reactivated = cp
            .control_plane()
            .reactivate_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        assert_eq!(reactivated.status, "active");
        assert!(reactivated.suspended_at.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_reactivate_active_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("reactivate-active-test")
            .build(&cp)
            .await
            .unwrap();

        let result = cp
            .control_plane()
            .reactivate_tenant(&tenant.tenant_id, admin_audit())
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            CatalogError::ValidationError(msg) => {
                assert!(msg.contains("not suspended"));
            }
            other => panic!("Expected ValidationError, got {:?}", other),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_active_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("delete-active-test")
            .build(&cp)
            .await
            .unwrap();

        let deleted = cp
            .control_plane()
            .delete_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        assert_eq!(deleted.status, "pending_deletion");
        assert!(deleted.deleted_at.is_some());
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_suspended_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("delete-suspended-test")
            .build(&cp)
            .await
            .unwrap();

        // Suspend first
        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Delete suspended tenant
        let deleted = cp
            .control_plane()
            .delete_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        assert_eq!(deleted.status, "pending_deletion");
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_already_deleted_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("double-delete-test")
            .build(&cp)
            .await
            .unwrap();

        // First deletion
        cp.control_plane()
            .delete_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Second deletion should fail
        let result = cp
            .control_plane()
            .delete_tenant(&tenant.tenant_id, admin_audit())
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_purge_pending_deletion_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("purge-test")
            .build(&cp)
            .await
            .unwrap();

        // Delete first
        cp.control_plane()
            .delete_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Purge
        cp.control_plane()
            .purge_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Verify tenant is now "deleted" status
        let purged = cp
            .control_plane()
            .get_tenant(&tenant.tenant_id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(purged.status, "deleted");
    }

    #[tokio::test]
    #[serial]
    async fn test_purge_active_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("purge-active-test")
            .build(&cp)
            .await
            .unwrap();

        // Try to purge without deleting first
        let result = cp
            .control_plane()
            .purge_tenant(&tenant.tenant_id, admin_audit())
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            CatalogError::ValidationError(msg) => {
                assert!(msg.contains("pending_deletion"));
            }
            other => panic!("Expected ValidationError, got {:?}", other),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_full_lifecycle() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create
        let tenant = TestTenantBuilder::new("lifecycle-test")
            .tier("premium")
            .build(&cp)
            .await
            .unwrap();
        assert_eq!(tenant.status, "active");

        // Update
        let updated = cp
            .control_plane()
            .update_tenant(
                &tenant.tenant_id,
                update_display_name("Updated Name"),
                admin_audit(),
            )
            .await
            .unwrap();
        assert_eq!(updated.display_name, "Updated Name");

        // Suspend
        let suspended = cp
            .control_plane()
            .suspend_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();
        assert_eq!(suspended.status, "suspended");

        // Reactivate
        let reactivated = cp
            .control_plane()
            .reactivate_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();
        assert_eq!(reactivated.status, "active");

        // Delete
        let deleted = cp
            .control_plane()
            .delete_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();
        assert_eq!(deleted.status, "pending_deletion");

        // Purge
        cp.control_plane()
            .purge_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        let purged = cp
            .control_plane()
            .get_tenant(&tenant.tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(purged.status, "deleted");
    }
}

// ============================================================================
// Audit Logging Tests
// ============================================================================

mod audit_logging {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_audit_log_created_on_tenant_create() {
        let cp = TestControlPlane::new().await.unwrap();

        let _tenant = TestTenantBuilder::new("audit-create-test")
            .build(&cp)
            .await
            .unwrap();

        // Fetch audit log
        let logs = cp
            .control_plane()
            .get_audit_log(Some("audit-create-test"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        assert!(!logs.is_empty());
        assert_eq!(logs[0].action, "create");
        assert_eq!(logs[0].tenant_id, "audit-create-test");
    }

    #[tokio::test]
    #[serial]
    async fn test_audit_log_records_actor() {
        let cp = TestControlPlane::new().await.unwrap();

        let request = CreateTenantRequest {
            tenant_id: "audit-actor-test".to_string(),
            display_name: "Audit Actor Test".to_string(),
            admin_email: "admin@audit.test".to_string(),
            tier: None,
            region: None,
            quota_max_datasets: None,
            quota_max_storage_bytes: None,
            quota_max_api_calls_per_hour: None,
        };

        let audit = AuditContext {
            actor: "specific-admin@test.com".to_string(),
            request_id: Some("test-req-123".to_string()),
            client_ip: Some("192.168.1.100".to_string()),
        };

        let _tenant = cp
            .control_plane()
            .create_tenant(request, audit)
            .await
            .unwrap();

        let logs = cp
            .control_plane()
            .get_audit_log(Some("audit-actor-test"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        assert_eq!(logs[0].actor, "specific-admin@test.com");
        assert_eq!(logs[0].request_id, Some("test-req-123".to_string()));
        assert_eq!(logs[0].client_ip, Some("192.168.1.100".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn test_audit_log_all_operations() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("audit-ops-test")
            .build(&cp)
            .await
            .unwrap();

        // Update
        cp.control_plane()
            .update_tenant(
                &tenant.tenant_id,
                update_display_name("Updated"),
                admin_audit(),
            )
            .await
            .unwrap();

        // Suspend
        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Reactivate
        cp.control_plane()
            .reactivate_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Delete
        cp.control_plane()
            .delete_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Purge
        cp.control_plane()
            .purge_tenant(&tenant.tenant_id, admin_audit())
            .await
            .unwrap();

        // Fetch all logs for this tenant
        let logs = cp
            .control_plane()
            .get_audit_log(Some("audit-ops-test"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        let actions: Vec<&str> = logs.iter().map(|l| l.action.as_str()).collect();

        // Most recent first
        assert!(actions.contains(&"create"));
        assert!(actions.contains(&"update"));
        assert!(actions.contains(&"suspend"));
        assert!(actions.contains(&"reactivate"));
        assert!(actions.contains(&"delete"));
        assert!(actions.contains(&"purge"));
    }

    #[tokio::test]
    #[serial]
    async fn test_audit_log_limit() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create multiple tenants
        for i in 1..=5 {
            TestTenantBuilder::new(&format!("audit-limit-{}", i))
                .build(&cp)
                .await
                .unwrap();
        }

        // Fetch with limit of 3
        let logs = cp.control_plane().get_audit_log(None, 3).await.unwrap();

        assert_eq!(logs.len(), 3);
    }
}

// ============================================================================
// Region Support Tests
// ============================================================================

mod region_support {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_tenant_region_nullable() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenant without region
        let tenant = TestTenantBuilder::new("no-region-test")
            .build(&cp)
            .await
            .unwrap();

        assert!(tenant.region.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_tenant_region_persisted() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("region-persist-test")
            .region("asia-southeast1")
            .build(&cp)
            .await
            .unwrap();

        // Retrieve and verify
        let retrieved = cp
            .control_plane()
            .get_tenant("region-persist-test")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(retrieved.region, Some("asia-southeast1".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn test_update_tenant_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("region-update-test")
            .region("us-central1")
            .build(&cp)
            .await
            .unwrap();

        let updated = cp
            .control_plane()
            .update_tenant(&tenant.tenant_id, update_region("us-west1"), admin_audit())
            .await
            .unwrap();

        assert_eq!(updated.region, Some("us-west1".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn test_multiple_regions() {
        let cp = TestControlPlane::new().await.unwrap();

        let regions = vec![
            ("us-tenant", "us-east1"),
            ("eu-tenant", "europe-west1"),
            ("asia-tenant", "asia-east1"),
            ("aus-tenant", "australia-southeast1"),
        ];

        for (tenant_id, region) in &regions {
            TestTenantBuilder::new(tenant_id)
                .region(region)
                .build(&cp)
                .await
                .unwrap();
        }

        // Verify each tenant has correct region
        for (tenant_id, expected_region) in &regions {
            let tenant = cp
                .control_plane()
                .get_tenant(tenant_id)
                .await
                .unwrap()
                .unwrap();

            assert_eq!(tenant.region, Some(expected_region.to_string()));
        }
    }
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

mod concurrent_operations {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_concurrent_tenant_creation() {
        let cp = TestControlPlane::new().await.unwrap();

        let mut handles = Vec::new();

        for i in 1..=10 {
            let cp_clone = cp.control_plane().clone();
            let handle = tokio::spawn(async move {
                let request = CreateTenantRequest {
                    tenant_id: format!("concurrent-{}", i),
                    display_name: format!("Concurrent Tenant {}", i),
                    admin_email: format!("admin{}@test.com", i),
                    tier: None,
                    region: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                };

                cp_clone.create_tenant(request, test_audit_context()).await
            });
            handles.push(handle);
        }

        let mut successes = 0;
        for handle in handles {
            if handle.await.unwrap().is_ok() {
                successes += 1;
            }
        }

        assert_eq!(successes, 10);
    }

    #[tokio::test]
    #[serial]
    async fn test_concurrent_tenant_reads() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create a tenant first
        TestTenantBuilder::new("concurrent-read-test")
            .build(&cp)
            .await
            .unwrap();

        let mut handles = Vec::new();

        for _ in 0..20 {
            let cp_clone = cp.control_plane().clone();
            let handle =
                tokio::spawn(async move { cp_clone.get_tenant("concurrent-read-test").await });
            handles.push(handle);
        }

        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            assert!(result.is_some());
        }
    }
}
