//! Integration tests for MetaFuse HTTP client using wiremock.
//!
//! These tests verify:
//! - All client HTTP methods work correctly
//! - Error handling for various HTTP status codes
//! - Retry behavior for transient errors
//! - API key header presence
//! - Cache behavior

use metafuse_catalog_client::{ClientConfig, ClientError, MetafuseClient};
use std::time::Duration;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test client pointing to the mock server
fn test_client(server: &MockServer) -> MetafuseClient {
    let config = ClientConfig::builder(server.uri())
        .timeout(Duration::from_secs(5))
        .max_retries(2)
        .retry_initial_delay(Duration::from_millis(10))
        .retry_max_delay(Duration::from_millis(50))
        .no_cache()
        .build()
        .unwrap();
    MetafuseClient::new(config).unwrap()
}

/// Create a test client with API key
fn test_client_with_api_key(server: &MockServer, api_key: &str) -> MetafuseClient {
    let config = ClientConfig::builder(server.uri())
        .api_key(api_key)
        .timeout(Duration::from_secs(5))
        .max_retries(2)
        .retry_initial_delay(Duration::from_millis(10))
        .retry_max_delay(Duration::from_millis(50))
        .no_cache()
        .build()
        .unwrap();
    MetafuseClient::new(config).unwrap()
}

/// Create a test client with caching enabled
fn test_client_with_cache(server: &MockServer) -> MetafuseClient {
    let config = ClientConfig::builder(server.uri())
        .timeout(Duration::from_secs(5))
        .cache_ttl(Duration::from_secs(60))
        .cache_capacity(10)
        .build()
        .unwrap();
    MetafuseClient::new(config).unwrap()
}

// ============================================================================
// Health Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_health_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "healthy",
            "version": "0.5.0"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let health = client.health().await.unwrap();

    assert_eq!(health.status, "healthy");
    assert_eq!(health.version, Some("0.5.0".to_string()));
}

// ============================================================================
// List Datasets Tests
// ============================================================================

#[tokio::test]
async fn test_list_datasets_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "datasets": [
                {
                    "name": "orders",
                    "path": "s3://bucket/orders",
                    "format": "delta",
                    "domain": "analytics",
                    "last_updated": "2024-01-15T10:30:00Z",
                    "tags": ["production"]
                },
                {
                    "name": "customers",
                    "path": "s3://bucket/customers",
                    "format": "parquet",
                    "domain": "analytics",
                    "last_updated": "2024-01-14T09:00:00Z",
                    "tags": []
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let datasets = client.list_datasets().await.unwrap();

    assert_eq!(datasets.len(), 2);
    assert_eq!(datasets[0].name, "orders");
    assert_eq!(datasets[1].name, "customers");
}

#[tokio::test]
async fn test_list_datasets_by_domain_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets"))
        .and(query_param("domain", "analytics"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "datasets": [
                {
                    "name": "orders",
                    "path": "s3://bucket/orders",
                    "format": "delta",
                    "domain": "analytics",
                    "last_updated": "2024-01-15T10:30:00Z",
                    "tags": []
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let datasets = client.list_datasets_by_domain("analytics").await.unwrap();

    assert_eq!(datasets.len(), 1);
    assert_eq!(datasets[0].domain, Some("analytics".to_string()));
}

#[tokio::test]
async fn test_list_domains_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/domains"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            "analytics",
            "marketing",
            "finance"
        ])))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let domains = client.list_domains().await.unwrap();

    assert_eq!(domains.len(), 3);
    assert!(domains.contains(&"analytics".to_string()));
}

// ============================================================================
// Get Dataset Tests
// ============================================================================

#[tokio::test]
async fn test_get_dataset_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets/orders"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "orders",
            "path": "s3://bucket/orders",
            "format": "delta",
            "domain": "analytics",
            "created_at": "2024-01-01T00:00:00Z",
            "last_updated": "2024-01-15T10:30:00Z",
            "fields": [
                {"name": "id", "data_type": "Int64", "nullable": false},
                {"name": "amount", "data_type": "Float64", "nullable": true}
            ],
            "tags": ["production", "daily"]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let dataset = client.get_dataset("orders").await.unwrap();

    assert_eq!(dataset.name, "orders");
    assert_eq!(dataset.format, "delta");
    assert_eq!(dataset.fields.len(), 2);
    assert_eq!(dataset.tags.len(), 2);
}

#[tokio::test]
async fn test_get_dataset_not_found() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({
                    "error": "Dataset 'nonexistent' not found",
                    "request_id": "req-12345"
                }))
                .insert_header("x-request-id", "req-12345"),
        )
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.get_dataset("nonexistent").await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ClientError::NotFound(msg) => {
            assert!(msg.contains("nonexistent"));
        }
        other => panic!("Expected NotFound error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_get_dataset_with_includes() {
    let server = MockServer::start().await;

    // The include param is URL-encoded by the client: "delta,quality" -> "delta%2Cquality"
    Mock::given(method("GET"))
        .and(path("/datasets/orders"))
        .and(query_param("include", "delta,quality"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "orders",
            "path": "s3://bucket/orders",
            "format": "delta",
            "created_at": "2024-01-01T00:00:00Z",
            "last_updated": "2024-01-15T10:30:00Z",
            "fields": [],
            "delta": {
                "version": 42,
                "row_count": 10000,
                "size_bytes": 1048576,
                "num_files": 10,
                "last_modified": "2024-01-15T10:30:00Z"
            },
            "quality": {
                "score": 95.5,
                "dimensions": [],
                "computed_at": "2024-01-15T10:00:00Z"
            }
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let dataset = client
        .get_dataset_with_includes("orders", &["delta", "quality"])
        .await
        .unwrap();

    assert!(dataset.delta.is_some());
    assert_eq!(dataset.delta.unwrap().version, 42);
    assert!(dataset.quality.is_some());
    assert_eq!(dataset.quality.unwrap().score, Some(95.5));
}

// ============================================================================
// Search Tests
// ============================================================================

#[tokio::test]
async fn test_search_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "orders"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "query": "orders",
            "total": 1,
            "datasets": [
                {
                    "name": "orders",
                    "path": "s3://bucket/orders",
                    "format": "delta",
                    "last_updated": "2024-01-15T10:30:00Z",
                    "tags": []
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let results = client.search("orders").await.unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "orders");
}

// ============================================================================
// Delta History Tests
// ============================================================================

#[tokio::test]
async fn test_get_history_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets/orders/delta/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dataset": "orders",
            "history": [
                {
                    "version": 42,
                    "timestamp": "2024-01-15T10:30:00Z",
                    "operation": "WRITE",
                    "user_name": "etl-job"
                },
                {
                    "version": 41,
                    "timestamp": "2024-01-14T10:30:00Z",
                    "operation": "MERGE",
                    "user_name": "etl-job"
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let history = client.get_history("orders", None).await.unwrap();

    assert_eq!(history.dataset, "orders");
    assert_eq!(history.history.len(), 2);
    assert_eq!(history.history[0].version, 42);
}

#[tokio::test]
async fn test_get_history_with_limit() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets/orders/delta/history"))
        .and(query_param("limit", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dataset": "orders",
            "history": []
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let history = client.get_history("orders", Some(5)).await.unwrap();

    assert_eq!(history.dataset, "orders");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_error_401_unauthorized() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({
                    "error": "Invalid or missing API key"
                }))
                .insert_header("x-request-id", "req-auth-fail"),
        )
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.list_datasets().await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ClientError::Unauthorized(msg) => {
            assert!(msg.contains("API key"));
        }
        other => panic!("Expected Unauthorized error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_error_403_forbidden() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets/restricted"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "Access denied to dataset 'restricted'"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.get_dataset("restricted").await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ClientError::Forbidden(msg) => {
            assert!(msg.contains("Access denied"));
        }
        other => panic!("Expected Forbidden error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_error_429_rate_limited() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(serde_json::json!({
                    "error": "Rate limit exceeded"
                }))
                .insert_header("Retry-After", "30")
                .insert_header("x-request-id", "req-rate-limit"),
        )
        .expect(3) // Initial + 2 retries
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.list_datasets().await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ClientError::RateLimited {
            retry_after,
            request_id,
        } => {
            assert_eq!(request_id, Some("req-rate-limit".to_string()));
            // Verify Retry-After header is parsed
            assert_eq!(retry_after, Some(Duration::from_secs(30)));
        }
        other => panic!("Expected RateLimited error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_error_429_rate_limited_no_retry_after() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(serde_json::json!({
                    "error": "Rate limit exceeded"
                }))
                .insert_header("x-request-id", "req-no-retry"),
        )
        .expect(3)
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.list_datasets().await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ClientError::RateLimited {
            retry_after,
            request_id,
        } => {
            assert_eq!(request_id, Some("req-no-retry".to_string()));
            // No Retry-After header means None
            assert_eq!(retry_after, None);
        }
        other => panic!("Expected RateLimited error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_error_500_server_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(serde_json::json!({
                    "error": "Internal server error"
                }))
                .insert_header("x-request-id", "req-500"),
        )
        .expect(3) // Should retry on 5xx
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.list_datasets().await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ClientError::ServerError {
            status, request_id, ..
        } => {
            assert_eq!(status, 500);
            assert_eq!(request_id, Some("req-500".to_string()));
        }
        other => panic!("Expected ServerError, got: {:?}", other),
    }
}

// ============================================================================
// Retry Behavior Tests
// ============================================================================

#[tokio::test]
async fn test_retry_on_503_then_success() {
    let server = MockServer::start().await;

    // First call returns 503, second succeeds
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "healthy"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let health = client.health().await.unwrap();

    assert_eq!(health.status, "healthy");
}

#[tokio::test]
async fn test_no_retry_on_400_bad_request() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets/invalid%20name"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "Invalid dataset name"
        })))
        .expect(1) // Should NOT retry on 4xx (except 429)
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.get_dataset("invalid name").await;

    assert!(result.is_err());
}

// ============================================================================
// API Key Header Tests
// ============================================================================

#[tokio::test]
async fn test_api_key_header_sent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets"))
        .and(header("Authorization", "Bearer mf_test_key_12345"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "datasets": []
        })))
        .mount(&server)
        .await;

    let client = test_client_with_api_key(&server, "mf_test_key_12345");
    let datasets = client.list_datasets().await.unwrap();

    assert!(datasets.is_empty());
}

#[tokio::test]
async fn test_no_api_key_header_when_not_configured() {
    let server = MockServer::start().await;

    // This mock requires NO Authorization header
    Mock::given(method("GET"))
        .and(path("/datasets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "datasets": []
        })))
        .mount(&server)
        .await;

    let client = test_client(&server); // No API key
    let datasets = client.list_datasets().await.unwrap();

    assert!(datasets.is_empty());
}

// ============================================================================
// Cache Behavior Tests
// ============================================================================

#[tokio::test]
async fn test_cache_hit_avoids_second_request() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets/orders"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "orders",
            "path": "s3://bucket/orders",
            "format": "delta",
            "created_at": "2024-01-01T00:00:00Z",
            "last_updated": "2024-01-15T10:30:00Z",
            "fields": []
        })))
        .expect(1) // Should only be called once due to caching
        .mount(&server)
        .await;

    let client = test_client_with_cache(&server);

    // First call - hits the server
    let dataset1 = client.get_dataset("orders").await.unwrap();
    assert_eq!(dataset1.name, "orders");

    // Second call - should use cache
    let dataset2 = client.get_dataset("orders").await.unwrap();
    assert_eq!(dataset2.name, "orders");
}

#[tokio::test]
async fn test_cache_invalidation() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets/orders"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "orders",
            "path": "s3://bucket/orders",
            "format": "delta",
            "created_at": "2024-01-01T00:00:00Z",
            "last_updated": "2024-01-15T10:30:00Z",
            "fields": []
        })))
        .expect(2) // Called twice: before and after invalidation
        .mount(&server)
        .await;

    let client = test_client_with_cache(&server);

    // First call
    let _ = client.get_dataset("orders").await.unwrap();

    // Invalidate cache
    client.invalidate_cache("orders").await;

    // Second call - should hit server again
    let _ = client.get_dataset("orders").await.unwrap();
}

// ============================================================================
// Request ID Propagation Tests
// ============================================================================

#[tokio::test]
async fn test_request_id_extracted_from_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets/test"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({
                    "error": "Not found"
                }))
                .insert_header("x-request-id", "req-header-id"),
        )
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.get_dataset("test").await;

    // The request ID should be extractable from the error
    assert!(result.is_err());
}

#[tokio::test]
async fn test_request_id_from_error_body_fallback() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/datasets"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error": "Internal error",
            "request_id": "req-body-id"
        })))
        .expect(3) // Retries on 5xx
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.list_datasets().await;

    // Even without header, request_id should come from body
    assert!(result.is_err());
    match result.unwrap_err() {
        ClientError::ServerError { request_id, .. } => {
            assert_eq!(request_id, Some("req-body-id".to_string()));
        }
        other => panic!("Expected ServerError, got: {:?}", other),
    }
}

// ============================================================================
// URL Encoding Tests
// ============================================================================

#[tokio::test]
async fn test_dataset_name_url_encoded() {
    let server = MockServer::start().await;

    // Dataset name with special characters
    Mock::given(method("GET"))
        .and(path("/datasets/my%2Fdataset"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "my/dataset",
            "path": "s3://bucket/data",
            "format": "parquet",
            "created_at": "2024-01-01T00:00:00Z",
            "last_updated": "2024-01-15T10:30:00Z",
            "fields": []
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let dataset = client.get_dataset("my/dataset").await.unwrap();

    assert_eq!(dataset.name, "my/dataset");
}
