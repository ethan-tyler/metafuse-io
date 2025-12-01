//! Tenant Resolution End-to-End Tests
//!
//! Tests the full tenant resolution middleware chain including:
//! - API key resolution
//! - Header resolution (when enabled)
//! - Combined API key + header resolution
//! - Permission guards (require_tenant, require_write, require_admin)
//! - Error handling and edge cases
//!
//! Run with: `cargo test -p metafuse-catalog-api --features "api-keys,test-utils" --test tenant_resolution_e2e_tests`

// This test module requires both api-keys and test-utils features
#![cfg(all(feature = "api-keys", feature = "test-utils"))]

use axum::{
    body::Body,
    extract::Extension,
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use metafuse_catalog_api::control_plane::{ControlPlane, TenantRole};
use metafuse_catalog_api::tenant_resolver::{
    require_admin_permission, require_tenant_middleware, require_write_permission,
    tenant_resolver_middleware, ResolvedTenant, TenantResolverConfig, TenantSource,
    TENANT_ID_HEADER,
};
use metafuse_catalog_api::test_utils::{TestApiKey, TestControlPlane, TestTenantBuilder};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

// ============================================================================
// Test Handlers
// ============================================================================

/// Handler that returns tenant info if resolved
async fn get_tenant_info(tenant: Option<Extension<ResolvedTenant>>) -> impl IntoResponse {
    match tenant {
        Some(Extension(tenant)) => Json(serde_json::json!({
            "tenant_id": tenant.tenant_id(),
            "role": format!("{}", tenant.effective_role()),
            "source": format!("{:?}", tenant.source()),
            "can_read": tenant.can_read(),
            "can_write": tenant.can_write(),
            "can_delete": tenant.can_delete(),
            "can_manage_keys": tenant.can_manage_keys(),
        }))
        .into_response(),
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "tenant_id": null,
                "message": "No tenant context"
            })),
        )
            .into_response(),
    }
}

/// Handler that requires tenant context
async fn require_tenant_handler(Extension(tenant): Extension<ResolvedTenant>) -> impl IntoResponse {
    Json(serde_json::json!({
        "tenant_id": tenant.tenant_id(),
        "role": format!("{}", tenant.effective_role()),
    }))
}

/// Handler that requires write permission
async fn write_handler(Extension(tenant): Extension<ResolvedTenant>) -> impl IntoResponse {
    Json(serde_json::json!({
        "action": "write",
        "tenant_id": tenant.tenant_id(),
    }))
}

/// Handler that requires admin permission
async fn admin_handler(Extension(tenant): Extension<ResolvedTenant>) -> impl IntoResponse {
    Json(serde_json::json!({
        "action": "admin",
        "tenant_id": tenant.tenant_id(),
    }))
}

// ============================================================================
// Test Router Builders
// ============================================================================

/// Build a basic test router with tenant resolution middleware
fn build_basic_router(control_plane: Arc<ControlPlane>) -> Router {
    Router::new()
        .route("/tenant-info", get(get_tenant_info))
        .layer(middleware::from_fn(tenant_resolver_middleware))
        .layer(Extension(control_plane))
}

/// Build a router with header resolution enabled
fn build_router_with_header_resolution(control_plane: Arc<ControlPlane>) -> Router {
    Router::new()
        .route("/tenant-info", get(get_tenant_info))
        .layer(middleware::from_fn(tenant_resolver_middleware))
        .layer(Extension(TenantResolverConfig::with_header_resolution()))
        .layer(Extension(control_plane))
}

/// Build a router with require_tenant middleware
fn build_router_require_tenant(control_plane: Arc<ControlPlane>) -> Router {
    Router::new()
        .route("/protected", get(require_tenant_handler))
        .layer(middleware::from_fn(require_tenant_middleware))
        .layer(middleware::from_fn(tenant_resolver_middleware))
        .layer(Extension(control_plane))
}

/// Build a router with write permission guard
fn build_router_require_write(control_plane: Arc<ControlPlane>) -> Router {
    Router::new()
        .route("/write", get(write_handler))
        .layer(middleware::from_fn(require_write_permission))
        .layer(middleware::from_fn(tenant_resolver_middleware))
        .layer(Extension(control_plane))
}

/// Build a router with admin permission guard
fn build_router_require_admin(control_plane: Arc<ControlPlane>) -> Router {
    Router::new()
        .route("/admin", get(admin_handler))
        .layer(middleware::from_fn(require_admin_permission))
        .layer(middleware::from_fn(tenant_resolver_middleware))
        .layer(Extension(control_plane))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Make a request with optional auth header and tenant header
async fn make_request(
    router: Router,
    path: &str,
    auth_header: Option<&str>,
    tenant_header: Option<&str>,
) -> (StatusCode, Value) {
    let mut req_builder = Request::builder().uri(path).method("GET");

    if let Some(auth) = auth_header {
        req_builder = req_builder.header(AUTHORIZATION, auth);
    }

    if let Some(tenant) = tenant_header {
        req_builder = req_builder.header(TENANT_ID_HEADER, tenant);
    }

    let request = req_builder.body(Body::empty()).unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).to_string()));

    (status, json)
}

// ============================================================================
// API Key Resolution Tests
// ============================================================================

mod api_key_resolution {
    use super::*;

    #[tokio::test]
    async fn test_resolve_admin_from_api_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("api-key-admin")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "api-key-admin").await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/tenant-info", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tenant_id"], "api-key-admin");
        assert_eq!(json["role"], "admin"); // lowercase from TenantRole::as_str()
        assert_eq!(json["source"], "ApiKey");
        assert_eq!(json["can_read"], true);
        assert_eq!(json["can_write"], true);
        assert_eq!(json["can_delete"], true);
        assert_eq!(json["can_manage_keys"], true);
    }

    #[tokio::test]
    async fn test_resolve_editor_from_api_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("api-key-editor")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::editor(&cp, "api-key-editor").await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/tenant-info", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tenant_id"], "api-key-editor");
        assert_eq!(json["role"], "editor");
        assert_eq!(json["can_write"], true);
        assert_eq!(json["can_delete"], false);
    }

    #[tokio::test]
    async fn test_resolve_viewer_from_api_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("api-key-viewer")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::viewer(&cp, "api-key-viewer").await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/tenant-info", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tenant_id"], "api-key-viewer");
        assert_eq!(json["role"], "viewer");
        assert_eq!(json["can_read"], true);
        assert_eq!(json["can_write"], false);
    }

    #[tokio::test]
    async fn test_invalid_api_key_returns_401() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        let fake_key = format!("mft_{}", "a".repeat(64));
        let (status, json) = make_request(
            router,
            "/tenant-info",
            Some(&format!("Bearer {}", fake_key)),
            None,
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"], "Unauthorized");
    }

    #[tokio::test]
    async fn test_revoked_api_key_returns_401() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("revoked-key-test")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "revoked-key-test").await.unwrap();

        // Revoke the key
        let keys = cp
            .control_plane()
            .list_tenant_api_keys("revoked-key-test")
            .await
            .unwrap();
        let key_to_revoke = keys.iter().find(|k| k.name == "test-admin-key").unwrap();
        cp.control_plane()
            .revoke_tenant_api_key("revoked-key-test", key_to_revoke.id)
            .await
            .unwrap();

        let router = build_basic_router(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/tenant-info", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"], "Unauthorized");
    }

    #[tokio::test]
    async fn test_suspended_tenant_key_returns_401() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("suspended-tenant")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "suspended-tenant").await.unwrap();

        // Suspend the tenant
        cp.control_plane()
            .suspend_tenant(
                &tenant.tenant_id,
                metafuse_catalog_api::test_utils::test_audit_context(),
            )
            .await
            .unwrap();

        let router = build_basic_router(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/tenant-info", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"], "Unauthorized");
    }

    #[tokio::test]
    async fn test_global_api_key_does_not_resolve_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        // Global keys start with "mf_" not "mft_"
        let global_key = format!("mf_{}", "a".repeat(64));
        let (status, json) = make_request(
            router,
            "/tenant-info",
            Some(&format!("Bearer {}", global_key)),
            None,
        )
        .await;

        // Should succeed but without tenant context (global keys don't provide tenant identity)
        assert_eq!(status, StatusCode::OK);
        assert!(json["tenant_id"].is_null());
    }
}

// ============================================================================
// Header Resolution Tests
// ============================================================================

mod header_resolution {
    use super::*;

    #[tokio::test]
    async fn test_header_resolution_when_enabled() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("header-tenant")
            .build(&cp)
            .await
            .unwrap();

        // Use router with header resolution enabled
        let router = build_router_with_header_resolution(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/tenant-info", None, Some("header-tenant")).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tenant_id"], "header-tenant");
        assert_eq!(json["source"], "Header");
        // Header-only grants Viewer role
        assert_eq!(json["role"], "viewer");
        assert_eq!(json["can_read"], true);
        assert_eq!(json["can_write"], false);
    }

    #[tokio::test]
    async fn test_header_resolution_disabled_by_default() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("no-header-tenant")
            .build(&cp)
            .await
            .unwrap();

        // Default router does NOT allow header-only resolution
        let router = build_basic_router(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/tenant-info", None, Some("no-header-tenant")).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("Header-only resolution is disabled"));
    }

    #[tokio::test]
    async fn test_header_resolution_nonexistent_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_router_with_header_resolution(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/tenant-info", None, Some("nonexistent-tenant")).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(json["message"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn test_header_resolution_suspended_tenant() {
        let cp = TestControlPlane::new().await.unwrap();
        let tenant = TestTenantBuilder::new("suspended-header")
            .build(&cp)
            .await
            .unwrap();

        cp.control_plane()
            .suspend_tenant(
                &tenant.tenant_id,
                metafuse_catalog_api::test_utils::test_audit_context(),
            )
            .await
            .unwrap();

        let router = build_router_with_header_resolution(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/tenant-info", None, Some("suspended-header")).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(json["message"].as_str().unwrap().contains("not active"));
    }

    #[tokio::test]
    async fn test_header_resolution_invalid_format() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_router_with_header_resolution(cp.control_plane().clone());

        // Invalid tenant ID format
        let (status, json) = make_request(
            router,
            "/tenant-info",
            None,
            Some("AB"), // Too short and wrong case
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("Invalid tenant ID"));
    }
}

// ============================================================================
// Combined Resolution Tests (API Key + Header)
// ============================================================================

mod combined_resolution {
    use super::*;

    #[tokio::test]
    async fn test_api_key_and_header_match() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("match-tenant")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "match-tenant").await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        // Both API key and header specify the same tenant
        let (status, json) = make_request(
            router,
            "/tenant-info",
            Some(&key.auth_header()),
            Some("match-tenant"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tenant_id"], "match-tenant");
        assert_eq!(json["source"], "Both"); // Both sources used
        assert_eq!(json["role"], "admin"); // Role from API key
    }

    #[tokio::test]
    async fn test_api_key_and_header_mismatch() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("tenant-a").build(&cp).await.unwrap();
        TestTenantBuilder::new("tenant-b").build(&cp).await.unwrap();

        // Key belongs to tenant-a
        let key = TestApiKey::admin(&cp, "tenant-a").await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        // Header specifies tenant-b
        let (status, json) = make_request(
            router,
            "/tenant-info",
            Some(&key.auth_header()),
            Some("tenant-b"),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(json["message"].as_str().unwrap().contains("mismatch"));
    }

    #[tokio::test]
    async fn test_api_key_takes_precedence_over_header() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("precedence-tenant")
            .build(&cp)
            .await
            .unwrap();

        // Create both admin and viewer keys
        let admin_key = TestApiKey::admin(&cp, "precedence-tenant").await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        // Use admin key with matching header
        let (status, json) = make_request(
            router,
            "/tenant-info",
            Some(&admin_key.auth_header()),
            Some("precedence-tenant"),
        )
        .await;

        // Should use Admin role from API key, not Viewer from header
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["role"], "admin");
        assert_eq!(json["can_manage_keys"], true);
    }
}

// ============================================================================
// No Authentication Tests
// ============================================================================

mod no_auth {
    use super::*;

    #[tokio::test]
    async fn test_no_auth_no_header_passes_through() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        // No auth, no header
        let (status, json) = make_request(router, "/tenant-info", None, None).await;

        // Should succeed but without tenant context
        assert_eq!(status, StatusCode::OK);
        assert!(json["tenant_id"].is_null());
        assert_eq!(json["message"], "No tenant context");
    }

    #[tokio::test]
    async fn test_empty_auth_header_ignored() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        let (status, json) = make_request(
            router,
            "/tenant-info",
            Some("Bearer "), // Empty bearer token
            None,
        )
        .await;

        // Should pass through without tenant context
        assert_eq!(status, StatusCode::OK);
        assert!(json["tenant_id"].is_null());
    }

    #[tokio::test]
    async fn test_empty_tenant_header_ignored() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_router_with_header_resolution(cp.control_plane().clone());

        let (status, json) = make_request(
            router,
            "/tenant-info",
            None,
            Some(""), // Empty tenant header
        )
        .await;

        // Empty header should be ignored, no tenant context
        assert_eq!(status, StatusCode::OK);
        assert!(json["tenant_id"].is_null());
    }
}

// ============================================================================
// Permission Guard Tests
// ============================================================================

mod permission_guards {
    use super::*;

    #[tokio::test]
    async fn test_require_tenant_succeeds_with_api_key() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("require-tenant")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::viewer(&cp, "require-tenant").await.unwrap();
        let router = build_router_require_tenant(cp.control_plane().clone());

        let (status, json) =
            make_request(router, "/protected", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tenant_id"], "require-tenant");
    }

    #[tokio::test]
    async fn test_require_tenant_fails_without_auth() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_router_require_tenant(cp.control_plane().clone());

        let (status, json) = make_request(router, "/protected", None, None).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("Tenant context required"));
    }

    #[tokio::test]
    async fn test_require_write_succeeds_with_editor() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("write-editor")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::editor(&cp, "write-editor").await.unwrap();
        let router = build_router_require_write(cp.control_plane().clone());

        let (status, json) = make_request(router, "/write", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["action"], "write");
    }

    #[tokio::test]
    async fn test_require_write_succeeds_with_admin() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("write-admin")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "write-admin").await.unwrap();
        let router = build_router_require_write(cp.control_plane().clone());

        let (status, json) = make_request(router, "/write", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_require_write_fails_with_viewer() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("write-viewer")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::viewer(&cp, "write-viewer").await.unwrap();
        let router = build_router_require_write(cp.control_plane().clone());

        let (status, json) = make_request(router, "/write", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("Write permission required"));
    }

    #[tokio::test]
    async fn test_require_admin_succeeds_with_admin() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("admin-only")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "admin-only").await.unwrap();
        let router = build_router_require_admin(cp.control_plane().clone());

        let (status, json) = make_request(router, "/admin", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["action"], "admin");
    }

    #[tokio::test]
    async fn test_require_admin_fails_with_editor() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("admin-editor")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::editor(&cp, "admin-editor").await.unwrap();
        let router = build_router_require_admin(cp.control_plane().clone());

        let (status, json) = make_request(router, "/admin", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("Admin permission required"));
    }

    #[tokio::test]
    async fn test_require_admin_fails_with_viewer() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("admin-viewer")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::viewer(&cp, "admin-viewer").await.unwrap();
        let router = build_router_require_admin(cp.control_plane().clone());

        let (status, json) = make_request(router, "/admin", Some(&key.auth_header()), None).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_require_write_fails_without_auth() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_router_require_write(cp.control_plane().clone());

        let (status, json) = make_request(router, "/write", None, None).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_require_admin_fails_without_auth() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_router_require_admin(cp.control_plane().clone());

        let (status, json) = make_request(router, "/admin", None, None).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

// ============================================================================
// ResolvedTenant Unit Tests
// ============================================================================

mod resolved_tenant_unit {
    use super::*;

    #[test]
    fn test_for_testing_constructor() {
        let tenant =
            ResolvedTenant::for_testing("test-id", Some(TenantRole::Admin), TenantSource::ApiKey);

        assert_eq!(tenant.tenant_id(), "test-id");
        assert_eq!(tenant.role(), Some(TenantRole::Admin));
        assert_eq!(tenant.source(), TenantSource::ApiKey);
        assert_eq!(tenant.effective_role(), TenantRole::Admin);
    }

    #[test]
    fn test_effective_role_defaults_to_viewer() {
        let tenant = ResolvedTenant::for_testing("test-id", None, TenantSource::Header);

        assert_eq!(tenant.role(), None);
        assert_eq!(tenant.effective_role(), TenantRole::Viewer);
    }

    #[test]
    fn test_display_format() {
        let api_key_tenant =
            ResolvedTenant::for_testing("acme", Some(TenantRole::Admin), TenantSource::ApiKey);
        assert_eq!(format!("{}", api_key_tenant), "acme(api_key)");

        let header_tenant = ResolvedTenant::for_testing("acme", None, TenantSource::Header);
        assert_eq!(format!("{}", header_tenant), "acme(header)");

        let both_tenant =
            ResolvedTenant::for_testing("acme", Some(TenantRole::Editor), TenantSource::Both);
        assert_eq!(format!("{}", both_tenant), "acme(both)");
    }

    #[test]
    fn test_permission_checks_admin() {
        let tenant = ResolvedTenant::for_testing(
            "test-tenant",
            Some(TenantRole::Admin),
            TenantSource::ApiKey,
        );

        assert!(tenant.can_read());
        assert!(tenant.can_write());
        assert!(tenant.can_delete());
        assert!(tenant.can_manage_keys());
    }

    #[test]
    fn test_permission_checks_editor() {
        let tenant = ResolvedTenant::for_testing(
            "test-tenant",
            Some(TenantRole::Editor),
            TenantSource::ApiKey,
        );

        assert!(tenant.can_read());
        assert!(tenant.can_write());
        assert!(!tenant.can_delete());
        assert!(!tenant.can_manage_keys());
    }

    #[test]
    fn test_permission_checks_viewer() {
        let tenant = ResolvedTenant::for_testing(
            "test-tenant",
            Some(TenantRole::Viewer),
            TenantSource::ApiKey,
        );

        assert!(tenant.can_read());
        assert!(!tenant.can_write());
        assert!(!tenant.can_delete());
        assert!(!tenant.can_manage_keys());
    }

    #[test]
    fn test_tenant_source_equality() {
        assert_eq!(TenantSource::ApiKey, TenantSource::ApiKey);
        assert_eq!(TenantSource::Header, TenantSource::Header);
        assert_eq!(TenantSource::Both, TenantSource::Both);
        assert_ne!(TenantSource::ApiKey, TenantSource::Header);
    }
}

// ============================================================================
// Edge Cases and Error Handling Tests
// ============================================================================

mod edge_cases {
    use super::*;

    #[tokio::test]
    async fn test_malformed_bearer_token() {
        let cp = TestControlPlane::new().await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        // Missing "Bearer " prefix
        let (status, json) =
            make_request(router, "/tenant-info", Some("mft_sometoken"), None).await;

        // Without Bearer prefix, not recognized as tenant key
        assert_eq!(status, StatusCode::OK);
        assert!(json["tenant_id"].is_null());
    }

    #[tokio::test]
    async fn test_bearer_with_extra_whitespace() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("whitespace-test")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "whitespace-test").await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        // Extra whitespace around token
        let (status, json) = make_request(
            router,
            "/tenant-info",
            Some(&format!("Bearer   {}  ", key.plaintext)),
            None,
        )
        .await;

        // Should still work (trimmed)
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tenant_id"], "whitespace-test");
    }

    #[tokio::test]
    async fn test_case_sensitive_bearer() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("case-test")
            .build(&cp)
            .await
            .unwrap();

        let key = TestApiKey::admin(&cp, "case-test").await.unwrap();
        let router = build_basic_router(cp.control_plane().clone());

        // Wrong case "bearer" instead of "Bearer"
        let (status, _) = make_request(
            router,
            "/tenant-info",
            Some(&format!("bearer {}", key.plaintext)),
            None,
        )
        .await;

        // Should not recognize as auth header (case sensitive)
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_tenant_header_with_whitespace() {
        let cp = TestControlPlane::new().await.unwrap();
        TestTenantBuilder::new("trim-tenant")
            .build(&cp)
            .await
            .unwrap();

        let router = build_router_with_header_resolution(cp.control_plane().clone());

        // Extra whitespace in header value
        let (status, json) =
            make_request(router, "/tenant-info", None, Some("  trim-tenant  ")).await;

        // Should work (trimmed)
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["tenant_id"], "trim-tenant");
    }

    #[tokio::test]
    async fn test_concurrent_requests_different_tenants() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create multiple tenants
        for i in 0..3 {
            TestTenantBuilder::new(&format!("concurrent-{}", i))
                .build(&cp)
                .await
                .unwrap();
        }

        // Create keys for each (sequentially - they're fast)
        let mut keys = Vec::new();
        for i in 0..3 {
            let key = TestApiKey::admin(&cp, &format!("concurrent-{}", i))
                .await
                .unwrap();
            keys.push(key);
        }

        // Make concurrent requests
        let cp = Arc::new(cp);
        let handles: Vec<_> = keys
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                let cp = Arc::clone(&cp);
                tokio::spawn(async move {
                    let router = build_basic_router(cp.control_plane().clone());
                    let (status, json) =
                        make_request(router, "/tenant-info", Some(&key.auth_header()), None).await;
                    (i, status, json)
                })
            })
            .collect();

        // All should succeed with correct tenant
        for handle in handles {
            let (i, status, json) = handle.await.unwrap();
            assert_eq!(status, StatusCode::OK);
            assert_eq!(json["tenant_id"], format!("concurrent-{}", i));
        }
    }
}

// ============================================================================
// TenantResolverConfig Tests
// ============================================================================

mod resolver_config {
    use super::*;

    #[test]
    fn test_default_config_disables_header_resolution() {
        let config = TenantResolverConfig::default();
        assert!(!config.allow_header_only_resolution);
    }

    #[test]
    fn test_with_header_resolution_enables_it() {
        let config = TenantResolverConfig::with_header_resolution();
        assert!(config.allow_header_only_resolution);
    }
}
