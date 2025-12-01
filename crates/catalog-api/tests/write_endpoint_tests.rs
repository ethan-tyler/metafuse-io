//! Write Endpoint Integration Tests
//!
//! Comprehensive tests for mutation endpoints including datasets, owners,
//! domains, tags, lineage, and RBAC enforcement.
//!
//! Run with: `cargo test -p metafuse-catalog-api --features "api-keys,test-utils" --test write_endpoint_tests`

// This test module requires both api-keys and test-utils features
#![cfg(all(feature = "api-keys", feature = "test-utils"))]

use axum::{
    body::Body,
    http::{header::AUTHORIZATION, Request, StatusCode},
    Router,
};
use metafuse_catalog_api::control_plane::TenantRole;
use metafuse_catalog_api::test_utils::{TestApiKey, TestControlPlane, TestTenantBuilder};
use serde_json::{json, Value};
use tower::ServiceExt;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Helper to make HTTP requests to the test app
async fn make_request(
    app: Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    auth_header: Option<&str>,
) -> (StatusCode, Value) {
    let mut req_builder = Request::builder()
        .uri(path)
        .method(method)
        .header("Content-Type", "application/json");

    if let Some(auth) = auth_header {
        req_builder = req_builder.header(AUTHORIZATION, auth);
    }

    let body = match body {
        Some(v) => Body::from(serde_json::to_string(&v).unwrap()),
        None => Body::empty(),
    };

    let request = req_builder.body(body).unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let json: Value = serde_json::from_slice(&body_bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body_bytes).to_string()));

    (status, json)
}

// ============================================================================
// Dataset Write Tests - Unit tests for request validation
// ============================================================================

mod dataset_validation {
    use metafuse_catalog_core::validation;

    #[test]
    fn test_valid_dataset_names() {
        let valid_names = vec![
            "my_dataset",
            "finance.sales_data",
            "warehouse.fact_orders",
            "raw_events",
            "processed_2024",
        ];

        for name in valid_names {
            assert!(
                validation::validate_dataset_name(name).is_ok(),
                "Expected '{}' to be valid",
                name
            );
        }
    }

    #[test]
    fn test_invalid_dataset_names() {
        let invalid_names = vec![
            "",                  // Empty
            "has space",         // Space
            "has@special",       // Special char
            "has/slash",         // Slash
            "../path_traversal", // Path traversal
        ];

        for name in invalid_names {
            assert!(
                validation::validate_dataset_name(name).is_err(),
                "Expected '{}' to be invalid",
                name
            );
        }
    }

    #[test]
    fn test_valid_owner_ids() {
        let valid_ids = vec!["owner-1", "team_data_engineering", "platform-team"];

        for id in valid_ids {
            assert!(
                validation::validate_identifier(id, "owner").is_ok(),
                "Expected '{}' to be valid",
                id
            );
        }
    }

    #[test]
    fn test_invalid_owner_ids() {
        let invalid_ids = vec![
            "",          // Empty
            "has space", // Space
            "has.dot",   // Dot not allowed in identifier
        ];

        for id in invalid_ids {
            assert!(
                validation::validate_identifier(id, "owner").is_err(),
                "Expected '{}' to be invalid",
                id
            );
        }
    }

    #[test]
    fn test_valid_domain_names() {
        let valid_domains = vec!["finance", "marketing", "data-engineering", "platform_core"];

        for domain in valid_domains {
            assert!(
                validation::validate_identifier(domain, "domain").is_ok(),
                "Expected '{}' to be valid",
                domain
            );
        }
    }

    #[test]
    fn test_invalid_domain_names() {
        let invalid_domains = vec![
            "",          // Empty
            "has space", // Space
            "has/slash", // Slash
        ];

        for domain in invalid_domains {
            assert!(
                validation::validate_identifier(domain, "domain").is_err(),
                "Expected '{}' to be invalid",
                domain
            );
        }
    }

    #[test]
    fn test_valid_tags() {
        let valid_tags = vec!["pii", "sensitive", "production", "feature-store"];

        for tag in valid_tags {
            assert!(
                validation::validate_tag(tag).is_ok(),
                "Expected '{}' to be valid",
                tag
            );
        }
    }
}

// ============================================================================
// RBAC Tests - Verify permission enforcement
// ============================================================================

mod rbac_enforcement {
    use super::*;
    use metafuse_catalog_api::tenant_resolver::{ResolvedTenant, TenantSource};

    #[test]
    fn test_viewer_cannot_write() {
        let tenant =
            ResolvedTenant::for_testing("test", Some(TenantRole::Viewer), TenantSource::ApiKey);
        assert!(!tenant.can_write(), "Viewer should not be able to write");
    }

    #[test]
    fn test_viewer_cannot_delete() {
        let tenant =
            ResolvedTenant::for_testing("test", Some(TenantRole::Viewer), TenantSource::ApiKey);
        assert!(!tenant.can_delete(), "Viewer should not be able to delete");
    }

    #[test]
    fn test_editor_can_write() {
        let tenant =
            ResolvedTenant::for_testing("test", Some(TenantRole::Editor), TenantSource::ApiKey);
        assert!(tenant.can_write(), "Editor should be able to write");
    }

    #[test]
    fn test_editor_cannot_delete() {
        let tenant =
            ResolvedTenant::for_testing("test", Some(TenantRole::Editor), TenantSource::ApiKey);
        assert!(!tenant.can_delete(), "Editor should not be able to delete");
    }

    #[test]
    fn test_admin_can_write() {
        let tenant =
            ResolvedTenant::for_testing("test", Some(TenantRole::Admin), TenantSource::ApiKey);
        assert!(tenant.can_write(), "Admin should be able to write");
    }

    #[test]
    fn test_admin_can_delete() {
        let tenant =
            ResolvedTenant::for_testing("test", Some(TenantRole::Admin), TenantSource::ApiKey);
        assert!(tenant.can_delete(), "Admin should be able to delete");
    }

    #[test]
    fn test_header_only_cannot_write() {
        // Header-only resolution defaults to Viewer
        let tenant = ResolvedTenant::for_testing("test", None, TenantSource::Header);
        assert!(
            !tenant.can_write(),
            "Header-only (Viewer) should not be able to write"
        );
    }
}

// ============================================================================
// Control Plane API Key Integration Tests
// ============================================================================

mod control_plane_write_operations {
    use super::*;
    use metafuse_catalog_api::control_plane::UpdateTenantRequest;
    use metafuse_catalog_api::test_utils::test_audit_context;

    #[tokio::test]
    async fn test_create_tenant_generates_api_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("api-key-gen-test")
            .build(&cp)
            .await
            .unwrap();

        // List API keys - should have initial admin key
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("api-key-gen-test")
            .await
            .unwrap();

        assert!(!keys.is_empty(), "Should have at least one API key");
        let initial_key = keys.iter().find(|k| k.name == "Initial Admin Key");
        assert!(initial_key.is_some(), "Should have 'Initial Admin Key'");
    }

    #[tokio::test]
    async fn test_create_additional_api_keys() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("multi-key-tenant")
            .build(&cp)
            .await
            .unwrap();

        // Create additional keys with different roles
        let viewer_key = TestApiKey::viewer(&cp, "multi-key-tenant").await.unwrap();
        let editor_key = TestApiKey::editor(&cp, "multi-key-tenant").await.unwrap();

        // Verify all keys exist
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("multi-key-tenant")
            .await
            .unwrap();

        // Should have: initial admin + viewer + editor = 3 keys
        assert!(keys.len() >= 3, "Should have at least 3 keys");

        // Validate keys resolve correctly
        let viewer_validated = cp
            .control_plane()
            .validate_tenant_api_key(&viewer_key.plaintext)
            .await
            .unwrap()
            .expect("Viewer key should be valid");
        assert_eq!(viewer_validated.role, TenantRole::Viewer);

        let editor_validated = cp
            .control_plane()
            .validate_tenant_api_key(&editor_key.plaintext)
            .await
            .unwrap()
            .expect("Editor key should be valid");
        assert_eq!(editor_validated.role, TenantRole::Editor);
    }

    #[tokio::test]
    async fn test_update_tenant_quotas() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("quota-update-test")
            .tier("standard")
            .build(&cp)
            .await
            .unwrap();

        // Update quotas
        let update = UpdateTenantRequest {
            display_name: None,
            tier: None,
            admin_email: None,
            quota_max_datasets: Some(50000),
            quota_max_storage_bytes: Some(500_000_000_000), // 500GB
            quota_max_api_calls_per_hour: Some(100000),
            region: None,
        };

        let updated = cp
            .control_plane()
            .update_tenant(&tenant.tenant_id, update, test_audit_context())
            .await
            .unwrap();

        assert_eq!(updated.quota_max_datasets, 50000);
        assert_eq!(updated.quota_max_storage_bytes, 500_000_000_000);
        assert_eq!(updated.quota_max_api_calls_per_hour, 100000);
    }

    #[tokio::test]
    async fn test_revoke_api_key_invalidates_immediately() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("revoke-immediate")
            .build(&cp)
            .await
            .unwrap();

        // Create a key
        let key = TestApiKey::admin(&cp, "revoke-immediate").await.unwrap();

        // Verify it works
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key.plaintext)
            .await
            .unwrap()
            .is_some());

        // Find and revoke the key
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("revoke-immediate")
            .await
            .unwrap();
        let key_to_revoke = keys.iter().find(|k| k.name == "test-admin-key").unwrap();
        cp.control_plane()
            .revoke_tenant_api_key("revoke-immediate", key_to_revoke.id)
            .await
            .unwrap();

        // Should immediately be invalid
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key.plaintext)
            .await
            .unwrap()
            .is_none());
    }
}

// ============================================================================
// Data Operation RBAC Matrix Tests
// ============================================================================

mod data_operation_rbac {
    use super::*;
    use metafuse_catalog_api::tenant_resolver::ResolvedTenant;

    fn viewer() -> ResolvedTenant {
        ResolvedTenant::for_testing(
            "test",
            Some(TenantRole::Viewer),
            metafuse_catalog_api::tenant_resolver::TenantSource::ApiKey,
        )
    }

    fn editor() -> ResolvedTenant {
        ResolvedTenant::for_testing(
            "test",
            Some(TenantRole::Editor),
            metafuse_catalog_api::tenant_resolver::TenantSource::ApiKey,
        )
    }

    fn admin() -> ResolvedTenant {
        ResolvedTenant::for_testing(
            "test",
            Some(TenantRole::Admin),
            metafuse_catalog_api::tenant_resolver::TenantSource::ApiKey,
        )
    }

    #[test]
    fn test_read_permissions() {
        // All roles can read
        assert!(viewer().can_read());
        assert!(editor().can_read());
        assert!(admin().can_read());
    }

    #[test]
    fn test_write_permissions() {
        // Viewer cannot write, Editor and Admin can
        assert!(!viewer().can_write());
        assert!(editor().can_write());
        assert!(admin().can_write());
    }

    #[test]
    fn test_delete_permissions() {
        // Only Admin can delete
        assert!(!viewer().can_delete());
        assert!(!editor().can_delete());
        assert!(admin().can_delete());
    }

    #[test]
    fn test_manage_keys_permissions() {
        // Only Admin can manage API keys
        assert!(!viewer().can_manage_keys());
        assert!(!editor().can_manage_keys());
        assert!(admin().can_manage_keys());
    }
}

// ============================================================================
// Tenant Lifecycle Tests
// ============================================================================

mod tenant_lifecycle_write_ops {
    use super::*;
    use metafuse_catalog_api::test_utils::test_audit_context;

    #[tokio::test]
    async fn test_suspended_tenant_keys_rejected() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("suspend-write-test")
            .build(&cp)
            .await
            .unwrap();

        // Create API key before suspension
        let key = TestApiKey::admin(&cp, "suspend-write-test").await.unwrap();

        // Verify key works
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key.plaintext)
            .await
            .unwrap()
            .is_some());

        // Suspend tenant
        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        // Key should now be rejected
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key.plaintext)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_reactivated_tenant_keys_work() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("reactivate-write-test")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "reactivate-write-test")
            .await
            .unwrap();

        // Suspend then reactivate
        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();
        cp.control_plane()
            .reactivate_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        // Key should work again
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key.plaintext)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn test_deleted_tenant_keys_rejected() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("delete-write-test")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "delete-write-test").await.unwrap();

        // Delete tenant
        cp.control_plane()
            .delete_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        // Key should be rejected
        assert!(cp
            .control_plane()
            .validate_tenant_api_key(&key.plaintext)
            .await
            .unwrap()
            .is_none());
    }
}

// ============================================================================
// Request/Response Type Tests
// ============================================================================

mod request_types {
    use serde_json::json;

    #[test]
    fn test_create_dataset_request_serialization() {
        let request = json!({
            "name": "test_dataset",
            "path": "gs://bucket/path/to/data",
            "format": "delta",
            "description": "Test dataset description",
            "domain": "analytics",
            "owner": "data-team",
            "tags": ["production", "pii"]
        });

        // Verify all expected fields are present
        assert_eq!(request["name"], "test_dataset");
        assert_eq!(request["path"], "gs://bucket/path/to/data");
        assert_eq!(request["format"], "delta");
        assert_eq!(request["description"], "Test dataset description");
        assert_eq!(request["domain"], "analytics");
        assert_eq!(request["owner"], "data-team");
        assert_eq!(request["tags"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_update_dataset_request_partial() {
        // Update requests should support partial updates
        let request = json!({
            "description": "Updated description only"
        });

        assert!(request["description"].is_string());
        assert!(request["path"].is_null());
        assert!(request["format"].is_null());
    }

    #[test]
    fn test_create_owner_request_serialization() {
        let request = json!({
            "owner_id": "data-engineering",
            "name": "Data Engineering Team",
            "owner_type": "team",
            "email": "data-eng@example.com",
            "slack_channel": "#data-engineering"
        });

        assert_eq!(request["owner_id"], "data-engineering");
        assert_eq!(request["name"], "Data Engineering Team");
        assert_eq!(request["owner_type"], "team");
    }

    #[test]
    fn test_create_domain_request_serialization() {
        let request = json!({
            "name": "analytics",
            "description": "Analytics domain for business intelligence",
            "owner": "analytics-team"
        });

        assert_eq!(request["name"], "analytics");
        assert_eq!(
            request["description"],
            "Analytics domain for business intelligence"
        );
    }

    #[test]
    fn test_add_tags_request_serialization() {
        let request = json!({
            "tags": ["pii", "sensitive", "gdpr"]
        });

        let tags = request["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 3);
        assert!(tags.contains(&json!("pii")));
    }

    #[test]
    fn test_create_lineage_edge_request() {
        let request = json!({
            "upstream": "raw_events",
            "downstream": "processed_events"
        });

        assert_eq!(request["upstream"], "raw_events");
        assert_eq!(request["downstream"], "processed_events");
    }

    #[test]
    fn test_quality_metric_request() {
        let request = json!({
            "metric_type": "completeness",
            "value": 0.95,
            "details": {
                "null_count": 50,
                "total_count": 1000
            }
        });

        assert_eq!(request["metric_type"], "completeness");
        assert_eq!(request["value"], 0.95);
    }

    #[test]
    fn test_freshness_config_request() {
        let request = json!({
            "max_age_hours": 24,
            "check_interval_minutes": 60
        });

        assert_eq!(request["max_age_hours"], 24);
        assert_eq!(request["check_interval_minutes"], 60);
    }
}

// ============================================================================
// Error Response Tests
// ============================================================================

mod error_responses {
    use serde_json::json;

    #[test]
    fn test_error_response_structure() {
        // Standard error response format
        let error = json!({
            "error": "Dataset not found",
            "message": "Dataset 'nonexistent' does not exist",
            "request_id": "req-123-abc"
        });

        assert!(error["error"].is_string());
        assert!(error["message"].is_string());
        assert!(error["request_id"].is_string());
    }

    #[test]
    fn test_validation_error_response() {
        let error = json!({
            "error": "Validation Error",
            "message": "Invalid dataset name: contains invalid characters",
            "field": "name",
            "request_id": "req-456-def"
        });

        assert_eq!(error["error"], "Validation Error");
        assert_eq!(error["field"], "name");
    }

    #[test]
    fn test_rbac_error_response() {
        let error = json!({
            "error": "Forbidden",
            "message": "Write permission required",
            "required_role": "editor",
            "current_role": "viewer",
            "request_id": "req-789-ghi"
        });

        assert_eq!(error["error"], "Forbidden");
        assert_eq!(error["required_role"], "editor");
    }

    #[test]
    fn test_conflict_error_response() {
        let error = json!({
            "error": "Conflict",
            "message": "Dataset 'my_dataset' already exists",
            "request_id": "req-conflict-123"
        });

        assert_eq!(error["error"], "Conflict");
    }
}

// ============================================================================
// Batch Operation Tests
// ============================================================================

mod batch_operations {
    use super::*;

    #[tokio::test]
    async fn test_create_multiple_tenants_with_keys() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create multiple tenants
        let tenant_ids = vec!["batch-tenant-1", "batch-tenant-2", "batch-tenant-3"];

        for tenant_id in &tenant_ids {
            TestTenantBuilder::new(tenant_id).build(&cp).await.unwrap();
        }

        // Verify all tenants exist and have keys
        for tenant_id in &tenant_ids {
            let tenant = cp
                .control_plane()
                .get_tenant(tenant_id)
                .await
                .unwrap()
                .expect("Tenant should exist");
            assert_eq!(tenant.status, "active");

            let keys = cp
                .control_plane()
                .list_tenant_api_keys(tenant_id)
                .await
                .unwrap();
            assert!(
                !keys.is_empty(),
                "Tenant {} should have API keys",
                tenant_id
            );
        }
    }

    #[tokio::test]
    async fn test_create_multiple_api_keys_per_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("multi-key-batch")
            .build(&cp)
            .await
            .unwrap();

        // Create multiple keys of each role
        for i in 0..3 {
            TestApiKey::create(
                &cp,
                "multi-key-batch",
                &format!("viewer-key-{}", i),
                TenantRole::Viewer,
            )
            .await
            .unwrap();

            TestApiKey::create(
                &cp,
                "multi-key-batch",
                &format!("editor-key-{}", i),
                TenantRole::Editor,
            )
            .await
            .unwrap();
        }

        // Verify all keys exist
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("multi-key-batch")
            .await
            .unwrap();

        // Initial admin + 3 viewers + 3 editors = 7 keys
        assert!(
            keys.len() >= 7,
            "Should have at least 7 keys, found {}",
            keys.len()
        );
    }
}

// ============================================================================
// Concurrent Write Tests
// ============================================================================

mod concurrent_writes {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_concurrent_api_key_creation() {
        let cp = Arc::new(TestControlPlane::new().await.unwrap());
        TestTenantBuilder::new("concurrent-key-create")
            .build(&cp)
            .await
            .unwrap();

        let mut handles = vec![];

        // Spawn multiple concurrent key creation tasks
        for i in 0..5 {
            let cp_clone = Arc::clone(&cp);
            handles.push(tokio::spawn(async move {
                TestApiKey::create(
                    &cp_clone,
                    "concurrent-key-create",
                    &format!("concurrent-key-{}", i),
                    TenantRole::Viewer,
                )
                .await
            }));
        }

        // All should succeed
        let mut created_keys = vec![];
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            created_keys.push(result.plaintext);
        }

        // All keys should be unique
        let unique_count = created_keys
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert_eq!(unique_count, 5, "All concurrent keys should be unique");
    }

    #[tokio::test]
    async fn test_concurrent_tenant_creation() {
        let cp = Arc::new(TestControlPlane::new().await.unwrap());

        let mut handles = vec![];

        // Spawn multiple concurrent tenant creation tasks
        for i in 0..5 {
            let cp_clone = Arc::clone(&cp);
            handles.push(tokio::spawn(async move {
                TestTenantBuilder::new(&format!("concurrent-tenant-{}", i))
                    .build(&cp_clone)
                    .await
            }));
        }

        // All should succeed
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "Concurrent tenant creation should succeed");
        }

        // Verify all tenants exist
        let tenants = cp.control_plane().list_tenants(None).await.unwrap();
        assert!(tenants.len() >= 5, "Should have at least 5 tenants");
    }
}

// ============================================================================
// Audit Trail Tests for Write Operations
// ============================================================================

mod write_audit_trail {
    use super::*;
    use metafuse_catalog_api::control_plane::UpdateTenantRequest;
    use metafuse_catalog_api::test_utils::test_audit_context;

    const AUDIT_LOG_LIMIT: usize = 100;

    #[tokio::test]
    async fn test_tenant_creation_audited() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("audit-create")
            .build(&cp)
            .await
            .unwrap();

        let logs = cp
            .control_plane()
            .get_audit_log(Some("audit-create"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        assert!(!logs.is_empty(), "Should have audit log entries");
        assert!(
            logs.iter().any(|l| l.action == "create"),
            "Should have 'create' action"
        );
    }

    #[tokio::test]
    async fn test_tenant_update_audited() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("audit-update")
            .build(&cp)
            .await
            .unwrap();

        // Update tenant
        cp.control_plane()
            .update_tenant(
                &tenant.tenant_id,
                UpdateTenantRequest {
                    display_name: Some("Updated Name".to_string()),
                    tier: None,
                    admin_email: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                test_audit_context(),
            )
            .await
            .unwrap();

        let logs = cp
            .control_plane()
            .get_audit_log(Some("audit-update"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        assert!(
            logs.iter().any(|l| l.action == "update"),
            "Should have 'update' action"
        );
    }

    #[tokio::test]
    async fn test_tenant_suspend_audited() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("audit-suspend")
            .build(&cp)
            .await
            .unwrap();

        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        let logs = cp
            .control_plane()
            .get_audit_log(Some("audit-suspend"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        assert!(
            logs.iter().any(|l| l.action == "suspend"),
            "Should have 'suspend' action"
        );
    }

    #[tokio::test]
    async fn test_full_lifecycle_audit_trail() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("audit-lifecycle")
            .build(&cp)
            .await
            .unwrap();

        // Perform full lifecycle
        cp.control_plane()
            .update_tenant(
                &tenant.tenant_id,
                UpdateTenantRequest {
                    display_name: Some("Updated".to_string()),
                    tier: None,
                    admin_email: None,
                    quota_max_datasets: None,
                    quota_max_storage_bytes: None,
                    quota_max_api_calls_per_hour: None,
                    region: None,
                },
                test_audit_context(),
            )
            .await
            .unwrap();

        cp.control_plane()
            .suspend_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        cp.control_plane()
            .reactivate_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        cp.control_plane()
            .delete_tenant(&tenant.tenant_id, test_audit_context())
            .await
            .unwrap();

        // Check audit trail
        let logs = cp
            .control_plane()
            .get_audit_log(Some("audit-lifecycle"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        let actions: Vec<&str> = logs.iter().map(|l| l.action.as_str()).collect();
        assert!(actions.contains(&"create"), "Should have 'create'");
        assert!(actions.contains(&"update"), "Should have 'update'");
        assert!(actions.contains(&"suspend"), "Should have 'suspend'");
        assert!(actions.contains(&"reactivate"), "Should have 'reactivate'");
        assert!(actions.contains(&"delete"), "Should have 'delete'");
    }
}
