//! Tenant API Key Integration Tests
//!
//! Comprehensive tests for tenant API key lifecycle, validation, permissions,
//! caching, and security.
//!
//! Run with: `cargo test -p metafuse-catalog-api --features "api-keys,test-utils" --test tenant_api_key_tests`

// This test module requires both api-keys and test-utils features
#![cfg(all(feature = "api-keys", feature = "test-utils"))]

use metafuse_catalog_api::control_plane::TenantRole;
use metafuse_catalog_api::test_utils::{
    test_audit_context, TestApiKey, TestControlPlane, TestTenantBuilder,
};

// ============================================================================
// API Key Lifecycle Tests
// ============================================================================

mod api_key_lifecycle {
    use super::*;

    #[tokio::test]
    async fn test_create_admin_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("admin-key-test")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "admin-key-test",
                "Admin Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        // Key should have correct prefix
        assert!(key.starts_with("mft_"), "Key should start with mft_ prefix");
        // Key should be sufficiently long (prefix + 64 hex chars)
        assert!(key.len() >= 68, "Key should be at least 68 chars");
    }

    #[tokio::test]
    async fn test_create_editor_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("editor-key-test")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "editor-key-test",
                "Editor Key".to_string(),
                TenantRole::Editor,
                None,
            )
            .await
            .unwrap();

        assert!(key.starts_with("mft_"));

        // Verify key can be validated and has correct role
        let validated = cp
            .control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap()
            .expect("Key should be valid");

        assert_eq!(validated.tenant_id, "editor-key-test");
        assert_eq!(validated.role, TenantRole::Editor);
        assert_eq!(validated.name, "Editor Key");
    }

    #[tokio::test]
    async fn test_create_viewer_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("viewer-key-test")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "viewer-key-test",
                "Viewer Key".to_string(),
                TenantRole::Viewer,
                None,
            )
            .await
            .unwrap();

        assert!(key.starts_with("mft_"));

        let validated = cp
            .control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap()
            .expect("Key should be valid");

        assert_eq!(validated.role, TenantRole::Viewer);
    }

    #[tokio::test]
    async fn test_create_multiple_keys_for_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("multi-key-test")
            .build(&cp)
            .await
            .unwrap();

        // Create multiple keys with different roles
        let admin_key = cp
            .control_plane()
            .create_tenant_api_key(
                "multi-key-test",
                "Admin Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        let editor_key = cp
            .control_plane()
            .create_tenant_api_key(
                "multi-key-test",
                "Editor Key".to_string(),
                TenantRole::Editor,
                None,
            )
            .await
            .unwrap();

        let viewer_key = cp
            .control_plane()
            .create_tenant_api_key(
                "multi-key-test",
                "Viewer Key".to_string(),
                TenantRole::Viewer,
                None,
            )
            .await
            .unwrap();

        // All keys should be unique
        assert_ne!(admin_key, editor_key);
        assert_ne!(editor_key, viewer_key);
        assert_ne!(admin_key, viewer_key);

        // All keys should be valid
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&admin_key)
            .await
            .unwrap()
            .is_some());
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&editor_key)
            .await
            .unwrap()
            .is_some());
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&viewer_key)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn test_list_tenant_api_keys() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("list-keys-test")
            .build(&cp)
            .await
            .unwrap();

        // Create a few keys (note: create_tenant already creates an initial admin key)
        cp.control_plane()
            .create_tenant_api_key(
                "list-keys-test",
                "Extra Admin".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        cp.control_plane()
            .create_tenant_api_key(
                "list-keys-test",
                "Editor Key".to_string(),
                TenantRole::Editor,
                None,
            )
            .await
            .unwrap();

        let keys = cp
            .control_plane()
            .list_tenant_api_keys("list-keys-test")
            .await
            .unwrap();

        // Should have initial admin key + 2 more = 3 keys
        assert_eq!(keys.len(), 3, "Should have 3 keys");

        // Verify all keys belong to correct tenant
        for key in &keys {
            assert_eq!(key.tenant_id, "list-keys-test");
        }

        // Verify keys are ordered by created_at DESC (most recent first)
        // The most recent key should be "Editor Key"
        assert_eq!(keys[0].name, "Editor Key");
        assert_eq!(keys[1].name, "Extra Admin");
    }

    #[tokio::test]
    async fn test_list_keys_empty_for_other_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("tenant-a").build(&cp).await.unwrap();

        // Try to list keys for a tenant that doesn't exist
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("nonexistent-tenant")
            .await
            .unwrap();

        assert!(
            keys.is_empty(),
            "Should return empty list for nonexistent tenant"
        );
    }

    #[tokio::test]
    async fn test_revoke_api_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("revoke-test")
            .build(&cp)
            .await
            .unwrap();

        // Create a key
        let plaintext = cp
            .control_plane()
            .create_tenant_api_key(
                "revoke-test",
                "To Be Revoked".to_string(),
                TenantRole::Editor,
                None,
            )
            .await
            .unwrap();

        // Verify it's valid
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&plaintext)
            .await
            .unwrap()
            .is_some());

        // Get the key ID
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("revoke-test")
            .await
            .unwrap();
        let key_to_revoke = keys.iter().find(|k| k.name == "To Be Revoked").unwrap();

        // Revoke the key
        let revoked = cp
            .control_plane()
            .revoke_tenant_api_key("revoke-test", key_to_revoke.id)
            .await
            .unwrap();
        assert!(revoked, "Revoke should succeed");

        // Verify it's no longer valid
        let result = cp
            .control_plane()
            .validate_tenant_api_key(&plaintext)
            .await
            .unwrap();
        assert!(result.is_none(), "Revoked key should not validate");
    }

    #[tokio::test]
    async fn test_revoke_already_revoked_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("double-revoke")
            .build(&cp)
            .await
            .unwrap();

        let plaintext = cp
            .control_plane()
            .create_tenant_api_key(
                "double-revoke",
                "Double Revoke Test".to_string(),
                TenantRole::Viewer,
                None,
            )
            .await
            .unwrap();

        let keys = cp
            .control_plane()
            .list_tenant_api_keys("double-revoke")
            .await
            .unwrap();
        let key = keys
            .iter()
            .find(|k| k.name == "Double Revoke Test")
            .unwrap();

        // First revoke should succeed
        let first = cp
            .control_plane()
            .revoke_tenant_api_key("double-revoke", key.id)
            .await
            .unwrap();
        assert!(first, "First revoke should succeed");

        // Second revoke should return false (already revoked)
        let second = cp
            .control_plane()
            .revoke_tenant_api_key("double-revoke", key.id)
            .await
            .unwrap();
        assert!(!second, "Second revoke should return false");

        // Key should still be invalid
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&plaintext)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("revoke-missing")
            .build(&cp)
            .await
            .unwrap();

        // Try to revoke a key that doesn't exist
        let result = cp
            .control_plane()
            .revoke_tenant_api_key("revoke-missing", 99999)
            .await
            .unwrap();

        assert!(!result, "Revoking nonexistent key should return false");
    }

    #[tokio::test]
    async fn test_revoke_key_wrong_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("tenant-owner")
            .build(&cp)
            .await
            .unwrap();
        TestTenantBuilder::new("tenant-other")
            .build(&cp)
            .await
            .unwrap();

        // Create a key for tenant-owner
        cp.control_plane()
            .create_tenant_api_key(
                "tenant-owner",
                "Owner's Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        let keys = cp
            .control_plane()
            .list_tenant_api_keys("tenant-owner")
            .await
            .unwrap();
        let owner_key = keys.iter().find(|k| k.name == "Owner's Key").unwrap();

        // Try to revoke tenant-owner's key using tenant-other
        let result = cp
            .control_plane()
            .revoke_tenant_api_key("tenant-other", owner_key.id)
            .await
            .unwrap();

        // Should fail because tenant_id doesn't match
        assert!(!result, "Should not be able to revoke another tenant's key");
    }
}

// ============================================================================
// Key Validation Tests
// ============================================================================

mod key_validation {
    use super::*;

    #[tokio::test]
    async fn test_validate_valid_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("valid-key-test")
            .tier("premium")
            .region("us-east1")
            .build(&cp)
            .await
            .unwrap();

        let plaintext = cp
            .control_plane()
            .create_tenant_api_key(
                "valid-key-test",
                "Valid Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        let validated = cp
            .control_plane()
            .validate_tenant_api_key(&plaintext)
            .await
            .unwrap()
            .expect("Key should be valid");

        assert_eq!(validated.tenant_id, "valid-key-test");
        assert_eq!(validated.name, "Valid Key");
        assert_eq!(validated.role, TenantRole::Admin);
        // Tier should be propagated from tenant
        assert_eq!(
            validated.tier,
            metafuse_catalog_storage::TenantTier::Premium
        );
        // Region should be propagated
        assert_eq!(validated.region, Some("us-east1".to_string()));
    }

    #[tokio::test]
    async fn test_validate_invalid_key_wrong_format() {
        let cp = TestControlPlane::new().await.unwrap();

        // Wrong prefix
        let result = cp
            .control_plane()
            .validate_tenant_api_key("mf_notatenantkey")
            .await
            .unwrap();
        assert!(result.is_none(), "Key with wrong prefix should be invalid");

        // Random garbage
        let result = cp
            .control_plane()
            .validate_tenant_api_key("random_garbage_key")
            .await
            .unwrap();
        assert!(result.is_none(), "Random key should be invalid");
    }

    #[tokio::test]
    async fn test_validate_invalid_key_fake_tenant_key() {
        let cp = TestControlPlane::new().await.unwrap();

        // Correctly formatted but non-existent key
        let fake_key = format!("mft_{}", "a".repeat(64));
        let result = cp
            .control_plane()
            .validate_tenant_api_key(&fake_key)
            .await
            .unwrap();

        assert!(result.is_none(), "Fake key should not validate");
    }

    #[tokio::test]
    async fn test_validate_empty_key() {
        let cp = TestControlPlane::new().await.unwrap();

        let result = cp
            .control_plane()
            .validate_tenant_api_key("")
            .await
            .unwrap();
        assert!(result.is_none(), "Empty key should be invalid");
    }

    #[tokio::test]
    async fn test_validate_key_after_tenant_suspended() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("suspend-key-test")
            .build(&cp)
            .await
            .unwrap();

        // Create a key
        let plaintext = cp
            .control_plane()
            .create_tenant_api_key(
                "suspend-key-test",
                "Pre-Suspend Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        // Verify key works initially
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&plaintext)
            .await
            .unwrap()
            .is_some());

        // Suspend the tenant
        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        // Key should no longer work
        let result = cp
            .control_plane()
            .validate_tenant_api_key(&plaintext)
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "Key should be invalid after tenant suspension"
        );
    }

    #[tokio::test]
    async fn test_validate_key_after_tenant_reactivated() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("reactivate-key-test")
            .build(&cp)
            .await
            .unwrap();

        let plaintext = cp
            .control_plane()
            .create_tenant_api_key(
                "reactivate-key-test",
                "Reactivation Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        // Suspend tenant
        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        // Reactivate tenant
        cp.control_plane()
            .reactivate_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        // Key should work again
        let result = cp
            .control_plane()
            .validate_tenant_api_key(&plaintext)
            .await
            .unwrap();
        assert!(
            result.is_some(),
            "Key should be valid after tenant reactivation"
        );
    }

    #[tokio::test]
    async fn test_validate_key_after_tenant_deleted() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("delete-key-test")
            .build(&cp)
            .await
            .unwrap();

        let plaintext = cp
            .control_plane()
            .create_tenant_api_key(
                "delete-key-test",
                "Delete Test Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        // Delete the tenant (soft delete)
        cp.control_plane()
            .delete_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        // Key should no longer work
        let result = cp
            .control_plane()
            .validate_tenant_api_key(&plaintext)
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "Key should be invalid after tenant deletion"
        );
    }

    #[tokio::test]
    async fn test_validate_preserves_tier_from_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenants with different tiers
        for (tenant_id, tier, expected_tier) in [
            (
                "free-tier-tenant",
                "free",
                metafuse_catalog_storage::TenantTier::Free,
            ),
            (
                "standard-tenant",
                "standard",
                metafuse_catalog_storage::TenantTier::Standard,
            ),
            (
                "premium-tenant",
                "premium",
                metafuse_catalog_storage::TenantTier::Premium,
            ),
            (
                "enterprise-tenant",
                "enterprise",
                metafuse_catalog_storage::TenantTier::Enterprise,
            ),
        ] {
            TestTenantBuilder::new(tenant_id)
                .tier(tier)
                .build(&cp)
                .await
                .unwrap();

            let key = cp
                .control_plane()
                .create_tenant_api_key(
                    tenant_id,
                    "Tier Test Key".to_string(),
                    TenantRole::Viewer,
                    None,
                )
                .await
                .unwrap();

            let validated = cp
                .control_plane()
                .validate_tenant_api_key(&key)
                .await
                .unwrap()
                .expect("Key should be valid");

            assert_eq!(
                validated.tier, expected_tier,
                "Tier mismatch for {}",
                tenant_id
            );
        }
    }
}

// ============================================================================
// Cache Behavior Tests
// ============================================================================

mod cache_behavior {
    use super::*;

    #[tokio::test]
    async fn test_cache_hit_on_second_validation() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("cache-test")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "cache-test",
                "Cache Test".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        // First validation (cache miss)
        let first = cp
            .control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap();
        assert!(first.is_some());

        // Second validation (should be cache hit)
        let second = cp
            .control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap();
        assert!(second.is_some());

        // Results should be identical
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.tenant_id, second.tenant_id);
        assert_eq!(first.role, second.role);
        assert_eq!(first.name, second.name);
    }

    #[tokio::test]
    async fn test_cache_invalidation_on_revoke() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("cache-revoke")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "cache-revoke",
                "Cache Revoke Test".to_string(),
                TenantRole::Editor,
                None,
            )
            .await
            .unwrap();

        // Validate to populate cache
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap()
            .is_some());

        // Get key ID and revoke
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("cache-revoke")
            .await
            .unwrap();
        let key_record = keys.iter().find(|k| k.name == "Cache Revoke Test").unwrap();

        cp.control_plane()
            .revoke_tenant_api_key("cache-revoke", key_record.id)
            .await
            .unwrap();

        // Should now be invalid (cache should have been cleared)
        let result = cp
            .control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "Key should be invalid immediately after revoke (cache invalidated)"
        );
    }

    #[tokio::test]
    async fn test_multiple_keys_independent_caching() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("multi-cache")
            .build(&cp)
            .await
            .unwrap();

        let key1 = cp
            .control_plane()
            .create_tenant_api_key("multi-cache", "Key 1".to_string(), TenantRole::Admin, None)
            .await
            .unwrap();

        let key2 = cp
            .control_plane()
            .create_tenant_api_key("multi-cache", "Key 2".to_string(), TenantRole::Viewer, None)
            .await
            .unwrap();

        // Validate both to populate cache
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key1)
            .await
            .unwrap()
            .is_some());
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key2)
            .await
            .unwrap()
            .is_some());

        // Revoke key1
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("multi-cache")
            .await
            .unwrap();
        let key1_record = keys.iter().find(|k| k.name == "Key 1").unwrap();
        cp.control_plane()
            .revoke_tenant_api_key("multi-cache", key1_record.id)
            .await
            .unwrap();

        // Key1 should be invalid, but key2 should still work
        // Note: cache is cleared per-tenant, so key2 will need re-validation
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key1)
            .await
            .unwrap()
            .is_none());
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key2)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn test_flush_pending_updates() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("flush-test")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "flush-test",
                "Flush Test".to_string(),
                TenantRole::Viewer,
                None,
            )
            .await
            .unwrap();

        // Validate key to trigger last_used tracking
        cp.control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap();

        // Flush pending updates
        let count = cp.control_plane().flush_pending_updates().await.unwrap();
        // Should have flushed at least one update
        assert!(count >= 1, "Should have flushed at least 1 pending update");

        // Second flush should have nothing to flush
        let count2 = cp.control_plane().flush_pending_updates().await.unwrap();
        assert_eq!(count2, 0, "Second flush should have nothing pending");
    }
}

// ============================================================================
// Role Permission Tests
// ============================================================================

mod role_permissions {
    use super::*;
    use metafuse_catalog_api::tenant_resolver::{ResolvedTenant, TenantSource};

    #[test]
    fn test_admin_role_permissions() {
        let tenant =
            ResolvedTenant::for_testing("test", Some(TenantRole::Admin), TenantSource::ApiKey);

        assert!(tenant.can_read(), "Admin should be able to read");
        assert!(tenant.can_write(), "Admin should be able to write");
        assert!(tenant.can_delete(), "Admin should be able to delete");
        assert!(
            tenant.can_manage_keys(),
            "Admin should be able to manage keys"
        );
    }

    #[test]
    fn test_editor_role_permissions() {
        let tenant =
            ResolvedTenant::for_testing("test", Some(TenantRole::Editor), TenantSource::ApiKey);

        assert!(tenant.can_read(), "Editor should be able to read");
        assert!(tenant.can_write(), "Editor should be able to write");
        assert!(!tenant.can_delete(), "Editor should NOT be able to delete");
        assert!(
            !tenant.can_manage_keys(),
            "Editor should NOT be able to manage keys"
        );
    }

    #[test]
    fn test_viewer_role_permissions() {
        let tenant =
            ResolvedTenant::for_testing("test", Some(TenantRole::Viewer), TenantSource::ApiKey);

        assert!(tenant.can_read(), "Viewer should be able to read");
        assert!(!tenant.can_write(), "Viewer should NOT be able to write");
        assert!(!tenant.can_delete(), "Viewer should NOT be able to delete");
        assert!(
            !tenant.can_manage_keys(),
            "Viewer should NOT be able to manage keys"
        );
    }

    #[test]
    fn test_header_only_defaults_to_viewer() {
        let tenant = ResolvedTenant::for_testing("test", None, TenantSource::Header);

        assert_eq!(tenant.effective_role(), TenantRole::Viewer);
        assert!(tenant.can_read());
        assert!(!tenant.can_write());
        assert!(!tenant.can_delete());
        assert!(!tenant.can_manage_keys());
    }

    #[tokio::test]
    async fn test_validated_key_provides_correct_role() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("role-test")
            .build(&cp)
            .await
            .unwrap();

        // Test each role
        for (name, role, expected) in [
            ("Admin Key", TenantRole::Admin, TenantRole::Admin),
            ("Editor Key", TenantRole::Editor, TenantRole::Editor),
            ("Viewer Key", TenantRole::Viewer, TenantRole::Viewer),
        ] {
            let key = cp
                .control_plane()
                .create_tenant_api_key("role-test", name.to_string(), role, None)
                .await
                .unwrap();

            let validated = cp
                .control_plane()
                .validate_tenant_api_key(&key)
                .await
                .unwrap()
                .expect("Key should be valid");

            assert_eq!(validated.role, expected, "Role mismatch for {}", name);
        }
    }
}

// ============================================================================
// Security Tests
// ============================================================================

mod security {
    use super::*;

    #[tokio::test]
    async fn test_key_cannot_access_other_tenant() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create two tenants
        TestTenantBuilder::new("tenant-alpha")
            .build(&cp)
            .await
            .unwrap();
        TestTenantBuilder::new("tenant-beta")
            .build(&cp)
            .await
            .unwrap();

        // Create key for alpha
        let alpha_key = cp
            .control_plane()
            .create_tenant_api_key(
                "tenant-alpha",
                "Alpha Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        // Validate alpha key - it should identify as tenant-alpha
        let validated = cp
            .control_plane()
            .validate_tenant_api_key(&alpha_key)
            .await
            .unwrap()
            .expect("Key should be valid");

        assert_eq!(validated.tenant_id, "tenant-alpha");
        assert_ne!(
            validated.tenant_id, "tenant-beta",
            "Key should not identify as wrong tenant"
        );
    }

    #[tokio::test]
    async fn test_unique_keys_per_creation() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("unique-test")
            .build(&cp)
            .await
            .unwrap();

        // Create multiple keys with same parameters
        let mut keys = Vec::new();
        for i in 0..5 {
            let key = cp
                .control_plane()
                .create_tenant_api_key(
                    "unique-test",
                    format!("Key {}", i),
                    TenantRole::Viewer,
                    None,
                )
                .await
                .unwrap();
            keys.push(key);
        }

        // All keys should be unique
        for (i, key_i) in keys.iter().enumerate() {
            for (j, key_j) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(key_i, key_j, "Keys {} and {} should be unique", i, j);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_key_hash_not_exposed() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("hash-test")
            .build(&cp)
            .await
            .unwrap();

        let plaintext = cp
            .control_plane()
            .create_tenant_api_key(
                "hash-test",
                "Hash Test".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        // The validated key info includes the hash for internal use
        let validated = cp
            .control_plane()
            .validate_tenant_api_key(&plaintext)
            .await
            .unwrap()
            .unwrap();

        // Hash should be a bcrypt hash (starts with $2b$ or similar)
        assert!(
            validated.key_hash.starts_with("$2"),
            "Key hash should be bcrypt format"
        );

        // Hash should NOT be the same as plaintext
        assert_ne!(
            validated.key_hash, plaintext,
            "Hash should not equal plaintext"
        );
    }

    #[tokio::test]
    async fn test_revoked_key_stays_revoked() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("stay-revoked")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "stay-revoked",
                "Permanent Revoke".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        // Revoke the key
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("stay-revoked")
            .await
            .unwrap();
        let key_record = keys.iter().find(|k| k.name == "Permanent Revoke").unwrap();
        cp.control_plane()
            .revoke_tenant_api_key("stay-revoked", key_record.id)
            .await
            .unwrap();

        // Try validating multiple times - should stay invalid
        for _ in 0..3 {
            let result = cp
                .control_plane()
                .validate_tenant_api_key(&key)
                .await
                .unwrap();
            assert!(result.is_none(), "Revoked key should stay invalid");
        }
    }

    #[tokio::test]
    async fn test_key_with_expiration() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("expiry-test")
            .build(&cp)
            .await
            .unwrap();

        // Create key with past expiration
        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "expiry-test",
                "Expired Key".to_string(),
                TenantRole::Admin,
                Some("2020-01-01T00:00:00".to_string()), // Past date
            )
            .await
            .unwrap();

        // Key should be invalid because it's expired
        let result = cp
            .control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap();
        assert!(result.is_none(), "Expired key should be invalid");
    }

    #[tokio::test]
    async fn test_key_with_future_expiration() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("future-expiry")
            .build(&cp)
            .await
            .unwrap();

        // Create key with future expiration
        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "future-expiry",
                "Future Key".to_string(),
                TenantRole::Admin,
                Some("2099-12-31T23:59:59".to_string()), // Far future
            )
            .await
            .unwrap();

        // Key should be valid because it hasn't expired yet
        let result = cp
            .control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap();
        assert!(
            result.is_some(),
            "Key with future expiration should be valid"
        );
    }
}

// ============================================================================
// Test API Key Helper Tests
// ============================================================================

mod test_api_key_helper {
    use super::*;

    #[tokio::test]
    async fn test_api_key_helper_admin() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("helper-admin")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "helper-admin").await.unwrap();

        assert!(key.plaintext.starts_with("mft_"));
        assert_eq!(key.tenant_id, "helper-admin");
        assert_eq!(key.role, TenantRole::Admin);
    }

    #[tokio::test]
    async fn test_api_key_helper_editor() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("helper-editor")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::editor(&cp, "helper-editor").await.unwrap();

        assert_eq!(key.role, TenantRole::Editor);
    }

    #[tokio::test]
    async fn test_api_key_helper_viewer() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("helper-viewer")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::viewer(&cp, "helper-viewer").await.unwrap();

        assert_eq!(key.role, TenantRole::Viewer);
    }

    #[tokio::test]
    async fn test_api_key_helper_auth_header() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("helper-header")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "helper-header").await.unwrap();
        let header = key.auth_header();

        assert!(header.starts_with("Bearer mft_"));
    }

    #[tokio::test]
    async fn test_api_key_custom_create() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("custom-create")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::create(&cp, "custom-create", "Custom Name", TenantRole::Editor)
            .await
            .unwrap();

        assert_eq!(key.name, "Custom Name");
        assert_eq!(key.role, TenantRole::Editor);

        // Verify it validates correctly
        let validated = cp
            .control_plane()
            .validate_tenant_api_key(&key.plaintext)
            .await
            .unwrap()
            .expect("Key should be valid");

        assert_eq!(validated.name, "Custom Name");
    }
}

// ============================================================================
// Initial Admin Key Tests
// ============================================================================

mod initial_admin_key {
    use super::*;

    #[tokio::test]
    async fn test_tenant_creation_creates_initial_admin_key() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenant - this should automatically create an initial admin key
        TestTenantBuilder::new("auto-admin")
            .build(&cp)
            .await
            .unwrap();

        // List keys - should have at least one
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("auto-admin")
            .await
            .unwrap();

        assert!(!keys.is_empty(), "Should have at least one key");

        // Should have an initial admin key
        let initial_key = keys.iter().find(|k| k.name == "Initial Admin Key");
        assert!(initial_key.is_some(), "Should have 'Initial Admin Key'");

        let initial_key = initial_key.unwrap();
        assert_eq!(initial_key.role, "admin");
        assert!(initial_key.revoked_at.is_none());
    }
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

mod concurrent_operations {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_concurrent_key_validations() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("concurrent-valid")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "concurrent-valid",
                "Concurrent Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        let cp = Arc::new(cp);
        let key = Arc::new(key);

        // Spawn multiple concurrent validations
        let mut handles = vec![];
        for _ in 0..10 {
            let cp_clone = Arc::clone(&cp);
            let key_clone = Arc::clone(&key);
            handles.push(tokio::spawn(async move {
                cp_clone
                    .control_plane()
                    .validate_tenant_api_key(&key_clone)
                    .await
            }));
        }

        // All should succeed
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            assert!(result.is_some(), "Concurrent validation should succeed");
        }
    }

    #[tokio::test]
    async fn test_concurrent_key_creation() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("concurrent-create")
            .build(&cp)
            .await
            .unwrap();

        let cp = Arc::new(cp);

        // Create multiple keys concurrently
        let mut handles = vec![];
        for i in 0..5 {
            let cp_clone = Arc::clone(&cp);
            handles.push(tokio::spawn(async move {
                cp_clone
                    .control_plane()
                    .create_tenant_api_key(
                        "concurrent-create",
                        format!("Concurrent Key {}", i),
                        TenantRole::Viewer,
                        None,
                    )
                    .await
            }));
        }

        // All should succeed and produce unique keys
        let mut created_keys = vec![];
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            created_keys.push(result);
        }

        // All keys should be unique
        let unique_count = created_keys
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert_eq!(
            unique_count, 5,
            "All concurrently created keys should be unique"
        );
    }
}

// ============================================================================
// Audit Trail Tests
// ============================================================================

mod audit_trail {
    use super::*;

    #[tokio::test]
    async fn test_key_shows_in_list_with_timestamps() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("timestamp-test")
            .build(&cp)
            .await
            .unwrap();

        // Create a key
        let _key = cp
            .control_plane()
            .create_tenant_api_key(
                "timestamp-test",
                "Timestamp Key".to_string(),
                TenantRole::Editor,
                None,
            )
            .await
            .unwrap();

        // List keys
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("timestamp-test")
            .await
            .unwrap();

        let timestamp_key = keys.iter().find(|k| k.name == "Timestamp Key").unwrap();

        // Should have created_at
        assert!(
            !timestamp_key.created_at.is_empty(),
            "Should have created_at"
        );

        // Should not have revoked_at (not revoked yet)
        assert!(timestamp_key.revoked_at.is_none(), "Should not be revoked");

        // last_used_at may or may not be set (depends on whether we validated it)
    }

    #[tokio::test]
    async fn test_revoked_key_shows_revoked_at() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("revoked-timestamp")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "revoked-timestamp",
                "Revoked Timestamp Key".to_string(),
                TenantRole::Viewer,
                None,
            )
            .await
            .unwrap();

        // Get and revoke
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("revoked-timestamp")
            .await
            .unwrap();
        let key_record = keys
            .iter()
            .find(|k| k.name == "Revoked Timestamp Key")
            .unwrap();
        cp.control_plane()
            .revoke_tenant_api_key("revoked-timestamp", key_record.id)
            .await
            .unwrap();

        // List again - should show revoked_at
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("revoked-timestamp")
            .await
            .unwrap();
        let revoked_key = keys
            .iter()
            .find(|k| k.name == "Revoked Timestamp Key")
            .unwrap();

        assert!(
            revoked_key.revoked_at.is_some(),
            "Revoked key should have revoked_at"
        );

        // Key should still not validate
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_last_used_updated_on_validation() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("last-used-test")
            .build(&cp)
            .await
            .unwrap();

        let key = cp
            .control_plane()
            .create_tenant_api_key(
                "last-used-test",
                "Last Used Key".to_string(),
                TenantRole::Admin,
                None,
            )
            .await
            .unwrap();

        // Validate the key
        cp.control_plane()
            .validate_tenant_api_key(&key)
            .await
            .unwrap();

        // Flush pending updates to persist last_used_at
        cp.control_plane().flush_pending_updates().await.unwrap();

        // Check that last_used_at is now set
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("last-used-test")
            .await
            .unwrap();
        let used_key = keys.iter().find(|k| k.name == "Last Used Key").unwrap();

        assert!(
            used_key.last_used_at.is_some(),
            "last_used_at should be set after validation and flush"
        );
    }
}
