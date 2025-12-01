//! Multi-Region Tests
//!
//! Integration tests for MetaFuse multi-region deployment capabilities:
//! - Regional tenant configuration
//! - Region-based filtering and isolation
//! - API key region context
//! - Environment-based region defaults

// This test module requires the test-utils feature
#![cfg(feature = "test-utils")]

use metafuse_catalog_api::test_utils::{
    assert_tenant_region, fixtures, TestControlPlane, TestTenantBuilder,
};

// ============================================================================
// Regional Tenant Configuration Tests
// ============================================================================

mod regional_tenant_configuration {
    use super::*;

    #[tokio::test]
    async fn test_create_tenant_with_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("region-test-tenant")
            .region("us-east1")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.region, Some("us-east1".to_string()));
    }

    #[tokio::test]
    async fn test_create_tenant_without_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("no-region-tenant")
            .build(&cp)
            .await
            .unwrap();

        // Without explicit region, should be None (or env default)
        // In test environment, METAFUSE_DEFAULT_REGION typically not set
        assert!(tenant.region.is_none());
    }

    #[tokio::test]
    async fn test_create_tenant_with_europe_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("europe-tenant")
            .region("europe-west1")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.region, Some("europe-west1".to_string()));
    }

    #[tokio::test]
    async fn test_create_tenant_with_asia_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("asia-tenant")
            .region("asia-northeast1")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.region, Some("asia-northeast1".to_string()));
    }

    #[tokio::test]
    async fn test_tenant_region_persists_after_retrieval() {
        let cp = TestControlPlane::new().await.unwrap();

        TestTenantBuilder::new("persist-region-test")
            .region("us-central1")
            .build(&cp)
            .await
            .unwrap();

        // Retrieve the tenant again
        let retrieved = cp
            .control_plane()
            .get_tenant("persist-region-test")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(retrieved.region, Some("us-central1".to_string()));
    }

    #[tokio::test]
    async fn test_multiple_tenants_different_regions() {
        let cp = TestControlPlane::new().await.unwrap();

        let us_tenant = TestTenantBuilder::new("multi-region-us")
            .region("us-east1")
            .build(&cp)
            .await
            .unwrap();

        let eu_tenant = TestTenantBuilder::new("multi-region-eu")
            .region("europe-west1")
            .build(&cp)
            .await
            .unwrap();

        let asia_tenant = TestTenantBuilder::new("multi-region-asia")
            .region("asia-northeast1")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(us_tenant.region, Some("us-east1".to_string()));
        assert_eq!(eu_tenant.region, Some("europe-west1".to_string()));
        assert_eq!(asia_tenant.region, Some("asia-northeast1".to_string()));
    }
}

// ============================================================================
// Regional Tenant Listing Tests
// ============================================================================

mod regional_tenant_listing {
    use super::*;

    #[tokio::test]
    async fn test_list_all_tenants_includes_regions() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenants in different regions
        TestTenantBuilder::new("list-region-us")
            .region("us-east1")
            .build(&cp)
            .await
            .unwrap();

        TestTenantBuilder::new("list-region-eu")
            .region("europe-west1")
            .build(&cp)
            .await
            .unwrap();

        let tenants = cp.control_plane().list_tenants(None).await.unwrap();

        let us_tenant = tenants.iter().find(|t| t.tenant_id == "list-region-us");
        let eu_tenant = tenants.iter().find(|t| t.tenant_id == "list-region-eu");

        assert!(us_tenant.is_some());
        assert!(eu_tenant.is_some());
        assert_eq!(us_tenant.unwrap().region, Some("us-east1".to_string()));
        assert_eq!(eu_tenant.unwrap().region, Some("europe-west1".to_string()));
    }

    #[tokio::test]
    async fn test_list_tenants_with_mixed_regions() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenants with and without regions
        TestTenantBuilder::new("mixed-with-region")
            .region("us-west1")
            .build(&cp)
            .await
            .unwrap();

        TestTenantBuilder::new("mixed-no-region")
            .build(&cp)
            .await
            .unwrap();

        let tenants = cp.control_plane().list_tenants(None).await.unwrap();

        let with_region = tenants.iter().find(|t| t.tenant_id == "mixed-with-region");
        let without_region = tenants.iter().find(|t| t.tenant_id == "mixed-no-region");

        assert!(with_region.is_some());
        assert!(without_region.is_some());
        assert_eq!(with_region.unwrap().region, Some("us-west1".to_string()));
        assert!(without_region.unwrap().region.is_none());
    }
}

// ============================================================================
// Enterprise Fixture Region Tests
// ============================================================================

mod enterprise_fixture_regions {
    use super::*;

    #[tokio::test]
    async fn test_enterprise_tenant_fixture_with_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = fixtures::enterprise_tenant("us-east1")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.region, Some("us-east1".to_string()));
        assert_eq!(tenant.tier, "enterprise");
    }

    #[tokio::test]
    async fn test_regional_tenant_fixtures() {
        let cp = TestControlPlane::new().await.unwrap();

        let regional_pairs = fixtures::regional_tenants();

        for (tenant_id, region) in regional_pairs {
            let tenant = TestTenantBuilder::new(tenant_id)
                .region(region)
                .build(&cp)
                .await
                .unwrap();

            assert_eq!(tenant.region, Some(region.to_string()));
        }
    }
}

// ============================================================================
// Region Assertion Helper Tests
// ============================================================================

mod region_assertion_helpers {
    use super::*;

    #[tokio::test]
    async fn test_assert_tenant_region_succeeds() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("assert-region-test")
            .region("europe-west1")
            .build(&cp)
            .await
            .unwrap();

        // This should not panic
        assert_tenant_region(&tenant, Some("europe-west1"));
    }

    #[tokio::test]
    async fn test_assert_tenant_region_none() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("assert-no-region")
            .build(&cp)
            .await
            .unwrap();

        // This should not panic
        assert_tenant_region(&tenant, None);
    }
}

// ============================================================================
// Region Update Tests
// ============================================================================

mod region_updates {
    use super::*;
    use metafuse_catalog_api::control_plane::{AuditContext, UpdateTenantRequest};

    #[tokio::test]
    async fn test_update_tenant_region() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenant with initial region
        TestTenantBuilder::new("update-region-tenant")
            .region("us-east1")
            .build(&cp)
            .await
            .unwrap();

        // Update to new region
        let update = UpdateTenantRequest {
            display_name: None,
            admin_email: None,
            tier: None,
            region: Some("europe-west1".to_string()),
            quota_max_datasets: None,
            quota_max_storage_bytes: None,
            quota_max_api_calls_per_hour: None,
        };

        let audit = AuditContext {
            actor: "test@example.com".to_string(),
            request_id: Some("update-region-test".to_string()),
            client_ip: None,
        };

        let updated = cp
            .control_plane()
            .update_tenant("update-region-tenant", update, audit)
            .await
            .unwrap();

        assert_eq!(updated.region, Some("europe-west1".to_string()));
    }

    #[tokio::test]
    async fn test_add_region_to_regionless_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenant without region
        TestTenantBuilder::new("add-region-tenant")
            .build(&cp)
            .await
            .unwrap();

        // Add region
        let update = UpdateTenantRequest {
            display_name: None,
            admin_email: None,
            tier: None,
            region: Some("asia-northeast1".to_string()),
            quota_max_datasets: None,
            quota_max_storage_bytes: None,
            quota_max_api_calls_per_hour: None,
        };

        let audit = AuditContext {
            actor: "test@example.com".to_string(),
            request_id: Some("add-region-test".to_string()),
            client_ip: None,
        };

        let updated = cp
            .control_plane()
            .update_tenant("add-region-tenant", update, audit)
            .await
            .unwrap();

        assert_eq!(updated.region, Some("asia-northeast1".to_string()));
    }
}

// ============================================================================
// Region with Tenant Lifecycle Tests
// ============================================================================

mod region_lifecycle {
    use super::*;
    use metafuse_catalog_api::control_plane::AuditContext;

    fn test_audit_ctx() -> AuditContext {
        AuditContext {
            actor: "lifecycle-test@example.com".to_string(),
            request_id: None,
            client_ip: None,
        }
    }

    #[tokio::test]
    async fn test_region_preserved_through_suspend() {
        let cp = TestControlPlane::new().await.unwrap();

        TestTenantBuilder::new("suspend-region-test")
            .region("us-central1")
            .build(&cp)
            .await
            .unwrap();

        // Suspend the tenant
        let suspended = cp
            .control_plane()
            .suspend_tenant("suspend-region-test", test_audit_ctx())
            .await
            .unwrap();

        assert_eq!(suspended.region, Some("us-central1".to_string()));
        assert_eq!(suspended.status, "suspended");
    }

    #[tokio::test]
    async fn test_region_preserved_through_reactivate() {
        let cp = TestControlPlane::new().await.unwrap();

        TestTenantBuilder::new("reactivate-region-test")
            .region("europe-west1")
            .build(&cp)
            .await
            .unwrap();

        // Suspend then reactivate
        cp.control_plane()
            .suspend_tenant("reactivate-region-test", test_audit_ctx())
            .await
            .unwrap();

        let reactivated = cp
            .control_plane()
            .reactivate_tenant("reactivate-region-test", test_audit_ctx())
            .await
            .unwrap();

        assert_eq!(reactivated.region, Some("europe-west1".to_string()));
        assert_eq!(reactivated.status, "active");
    }

    #[tokio::test]
    async fn test_region_preserved_through_delete() {
        let cp = TestControlPlane::new().await.unwrap();

        TestTenantBuilder::new("delete-region-test")
            .region("asia-southeast1")
            .build(&cp)
            .await
            .unwrap();

        // Delete (soft delete - sets to pending_deletion)
        let deleted = cp
            .control_plane()
            .delete_tenant("delete-region-test", test_audit_ctx())
            .await
            .unwrap();

        assert_eq!(deleted.region, Some("asia-southeast1".to_string()));
        assert_eq!(deleted.status, "pending_deletion");
    }
}

// ============================================================================
// API Key with Region Context Tests
// ============================================================================

mod api_key_region_context {
    use super::*;
    use metafuse_catalog_api::control_plane::TenantRole;

    #[tokio::test]
    async fn test_api_key_for_regional_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create regional tenant
        TestTenantBuilder::new("apikey-regional-tenant")
            .region("us-west1")
            .build(&cp)
            .await
            .unwrap();

        // Create API key for the tenant
        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "apikey-regional-tenant",
                "regional-key".to_string(),
                TenantRole::Admin,
                None, // expires_at
            )
            .await
            .unwrap();

        // Key should be created successfully
        assert!(!key.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_api_keys_for_regional_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create regional tenant
        TestTenantBuilder::new("multi-key-regional")
            .region("europe-north1")
            .build(&cp)
            .await
            .unwrap();

        // Get initial key count (TestTenantBuilder may create a default key)
        let initial_keys = cp
            .control_plane()
            .list_tenant_api_keys("multi-key-regional")
            .await
            .unwrap();
        let initial_count = initial_keys.len();

        // Create additional keys
        cp.control_plane()
            .create_tenant_api_key(
                "multi-key-regional",
                "admin-key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        cp.control_plane()
            .create_tenant_api_key(
                "multi-key-regional",
                "editor-key".to_string(),
                TenantRole::Editor,
                None,
            )
            .await
            .unwrap();

        let keys = cp
            .control_plane()
            .list_tenant_api_keys("multi-key-regional")
            .await
            .unwrap();

        // Should have initial keys + 2 new keys
        assert_eq!(keys.len(), initial_count + 2);
    }
}

// ============================================================================
// Region Validation Edge Cases
// ============================================================================

mod region_validation {
    use super::*;

    #[tokio::test]
    async fn test_region_with_hyphen() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("hyphen-region")
            .region("us-east-1")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.region, Some("us-east-1".to_string()));
    }

    #[tokio::test]
    async fn test_region_with_numbers() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("number-region")
            .region("region-123")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.region, Some("region-123".to_string()));
    }

    #[tokio::test]
    async fn test_lowercase_region() {
        let cp = TestControlPlane::new().await.unwrap();

        let tenant = TestTenantBuilder::new("lowercase-region")
            .region("us-west")
            .build(&cp)
            .await
            .unwrap();

        assert_eq!(tenant.region, Some("us-west".to_string()));
    }
}

// ============================================================================
// Cross-Region Tenant Isolation Tests
// ============================================================================

mod cross_region_isolation {
    use super::*;

    #[tokio::test]
    async fn test_tenants_across_regions_independent() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenants in different regions with same display name pattern
        let us_tenant = TestTenantBuilder::new("isolation-us-tenant")
            .display_name("Test Corp")
            .region("us-east1")
            .build(&cp)
            .await
            .unwrap();

        let eu_tenant = TestTenantBuilder::new("isolation-eu-tenant")
            .display_name("Test Corp")
            .region("europe-west1")
            .build(&cp)
            .await
            .unwrap();

        // They should be separate tenants
        assert_ne!(us_tenant.tenant_id, eu_tenant.tenant_id);
        assert_eq!(us_tenant.display_name, eu_tenant.display_name);
        assert_ne!(us_tenant.region, eu_tenant.region);
    }

    #[tokio::test]
    async fn test_regional_tenant_count() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenants in multiple regions
        let regions = vec!["us-east1", "us-west1", "europe-west1", "asia-northeast1"];

        for (i, region) in regions.iter().enumerate() {
            TestTenantBuilder::new(&format!("count-test-{}", i))
                .region(region)
                .build(&cp)
                .await
                .unwrap();
        }

        let all_tenants = cp.control_plane().list_tenants(None).await.unwrap();

        // Count tenants by region
        let us_east_count = all_tenants
            .iter()
            .filter(|t| t.region == Some("us-east1".to_string()))
            .count();
        let europe_count = all_tenants
            .iter()
            .filter(|t| t.region == Some("europe-west1".to_string()))
            .count();

        assert!(us_east_count >= 1);
        assert!(europe_count >= 1);
    }
}
