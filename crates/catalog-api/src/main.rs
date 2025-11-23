//! MetaFuse Catalog API Server
//!
//! REST API for querying the MetaFuse catalog.

#[cfg(feature = "metrics")]
mod metrics;

use axum::{
    extract::{Extension, Path, Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use metafuse_catalog_core::validation;
use metafuse_catalog_storage::{backend_from_uri, DynCatalogBackend};
use rusqlite::params_from_iter;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::Instrument;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

/// Request ID for tracking requests through the system
#[derive(Debug, Clone)]
struct RequestId(String);

/// Application state shared across handlers
struct AppState {
    backend: Arc<DynCatalogBackend>,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            backend: Arc::clone(&self.backend),
        }
    }
}

/// Dataset response structure
#[derive(Debug, Serialize, Deserialize)]
struct DatasetResponse {
    id: i64,
    name: String,
    path: String,
    format: String,
    description: Option<String>,
    tenant: Option<String>,
    domain: Option<String>,
    owner: Option<String>,
    created_at: String,
    last_updated: String,
    operational: OperationalMetaResponse,
}

/// Field response structure
#[derive(Debug, Serialize, Deserialize)]
struct FieldResponse {
    name: String,
    data_type: String,
    nullable: bool,
    description: Option<String>,
}

/// Dataset detail response with fields
#[derive(Debug, Serialize, Deserialize)]
struct DatasetDetailResponse {
    #[serde(flatten)]
    dataset: DatasetResponse,
    fields: Vec<FieldResponse>,
    tags: Vec<String>,
    upstream_datasets: Vec<String>,
    downstream_datasets: Vec<String>,
}

/// Operational metadata response
#[derive(Debug, Serialize, Deserialize, Default)]
struct OperationalMetaResponse {
    row_count: Option<i64>,
    size_bytes: Option<i64>,
    partition_keys: Vec<String>,
}
/// Error response with request ID for tracing
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    request_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Get catalog path from environment or use default
    let catalog_path = std::env::var("METAFUSE_CATALOG_PATH")
        .or_else(|_| std::env::var("METAFUSE_CATALOG"))
        .unwrap_or_else(|_| "metafuse_catalog.db".to_string());

    tracing::info!("Using catalog at: {}", catalog_path);

    let backend = backend_from_uri(&catalog_path).map_err(|e| {
        tracing::error!("Failed to create backend: {}", e);
        e
    })?;

    // Check if catalog exists for local backends
    if let Ok(false) = backend.exists().await {
        tracing::warn!("Catalog does not exist, initializing new catalog");
        backend.initialize().await.map_err(|e| {
            tracing::error!("Failed to initialize catalog: {}", e);
            e
        })?;
    }

    let state = AppState {
        backend: Arc::from(backend),
    };

    // Build router with conditional metrics endpoint
    #[cfg_attr(not(feature = "metrics"), allow(unused_mut))]
    let mut app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/datasets", get(list_datasets))
        .route("/api/v1/datasets/:name", get(get_dataset))
        .route("/api/v1/search", get(search_datasets));

    // Add metrics endpoint if metrics feature is enabled
    #[cfg(feature = "metrics")]
    {
        app = app.route("/metrics", get(metrics::metrics_handler));
        tracing::info!("Metrics endpoint enabled at /metrics");
    }

    let app = app
        .layer(middleware::from_fn(request_id_middleware))
        // Add metrics middleware if enabled
        .layer({
            #[cfg(feature = "metrics")]
            {
                middleware::from_fn(metrics::track_metrics)
            }
            #[cfg(not(feature = "metrics"))]
            {
                middleware::from_fn(|req: Request, next: Next| async move { next.run(req).await })
            }
        })
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Get port from environment or use default
    let port = std::env::var("METAFUSE_PORT")
        .or_else(|_| std::env::var("PORT"))
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .map_err(|e| {
            tracing::error!("PORT must be a valid number: {}", e);
            e
        })?;

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("MetaFuse API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Middleware to add request ID to every request and create tracing span
async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let request_id = RequestId(Uuid::new_v4().to_string());
    req.extensions_mut().insert(request_id.clone());

    // Create a span that will correlate all logs for this request
    let span = tracing::info_span!(
        "request",
        request_id = %request_id.0,
        method = %req.method(),
        uri = %req.uri(),
    );

    async move {
        tracing::info!("Request started");
        let mut response = next.run(req).await;
        // Propagate request ID to response headers for client correlation
        if let Ok(value) = HeaderValue::from_str(&request_id.0) {
            response
                .headers_mut()
                .insert(header::HeaderName::from_static("x-request-id"), value);
        }
        tracing::info!(status = %response.status(), "Request completed");
        response
    }
    .instrument(span)
    .await
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "ok"
}

/// List all datasets
async fn list_datasets(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<DatasetResponse>>, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(
        tenant = ?params.get("tenant"),
        domain = ?params.get("domain"),
        "Listing datasets with filters"
    );

    let conn = state
        .backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let mut query = String::from(
        r#"
        SELECT id, name, path, format, description, tenant, domain, owner,
               created_at, last_updated, row_count, size_bytes, partition_keys
        FROM datasets
        WHERE 1=1
        "#,
    );

    let mut bindings: Vec<String> = Vec::new();

    // Validate and apply tenant filter
    if let Some(tenant) = params.get("tenant") {
        validation::validate_identifier(tenant, "tenant")
            .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;
        query.push_str(" AND tenant = ?");
        bindings.push(tenant.clone());
    }

    // Validate and apply domain filter
    if let Some(domain) = params.get("domain") {
        validation::validate_identifier(domain, "domain")
            .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;
        query.push_str(" AND domain = ?");
        bindings.push(domain.clone());
    }

    query.push_str(" ORDER BY last_updated DESC");

    let mut stmt = conn
        .prepare(&query)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let datasets = stmt
        .query_map(params_from_iter(bindings.iter()), |row| {
            let row_count: Option<i64> = row.get(10)?;
            let size_bytes: Option<i64> = row.get(11)?;
            let partition_keys = parse_partition_keys(row.get::<_, Option<String>>(12)?);
            Ok(DatasetResponse {
                id: row.get(0)?,
                name: row.get(1)?,
                path: row.get(2)?,
                format: row.get(3)?,
                description: row.get(4)?,
                tenant: row.get(5)?,
                domain: row.get(6)?,
                owner: row.get(7)?,
                created_at: row.get(8)?,
                last_updated: row.get(9)?,
                operational: OperationalMetaResponse {
                    row_count,
                    size_bytes,
                    partition_keys,
                },
            })
        })
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(count = datasets.len(), "Listed datasets successfully");

    #[cfg(feature = "metrics")]
    metrics::record_catalog_operation("list_datasets", "success");

    Ok(Json(datasets))
}

/// Get a specific dataset by name
async fn get_dataset(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
) -> Result<Json<DatasetDetailResponse>, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(dataset_name = %name, "Getting dataset details");

    // Validate dataset name
    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let conn = state
        .backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get dataset
    let dataset: DatasetResponse = conn
        .query_row(
            r#"
        SELECT id, name, path, format, description, tenant, domain, owner,
               created_at, last_updated, row_count, size_bytes, partition_keys
        FROM datasets
        WHERE name = ?1
        "#,
            [&name],
            |row| {
                let row_count: Option<i64> = row.get(10)?;
                let size_bytes: Option<i64> = row.get(11)?;
                let partition_keys = parse_partition_keys(row.get::<_, Option<String>>(12)?);
                Ok(DatasetResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    path: row.get(2)?,
                    format: row.get(3)?,
                    description: row.get(4)?,
                    tenant: row.get(5)?,
                    domain: row.get(6)?,
                    owner: row.get(7)?,
                    created_at: row.get(8)?,
                    last_updated: row.get(9)?,
                    operational: OperationalMetaResponse {
                        row_count,
                        size_bytes,
                        partition_keys,
                    },
                })
            },
        )
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    // Get fields
    let mut stmt = conn
        .prepare("SELECT name, data_type, nullable, description FROM fields WHERE dataset_id = ?1")
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let fields = stmt
        .query_map([dataset.id], |row| {
            Ok(FieldResponse {
                name: row.get(0)?,
                data_type: row.get(1)?,
                nullable: row.get::<_, i32>(2)? != 0,
                description: row.get(3)?,
            })
        })
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get tags
    let mut stmt = conn
        .prepare("SELECT tag FROM tags WHERE dataset_id = ?1")
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let tags = stmt
        .query_map([dataset.id], |row| row.get::<_, String>(0))
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get upstream datasets
    let mut stmt = conn
        .prepare(
            r#"
            SELECT d.name
            FROM lineage l
            JOIN datasets d ON l.upstream_dataset_id = d.id
            WHERE l.downstream_dataset_id = ?1
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let upstream_datasets = stmt
        .query_map([dataset.id], |row| row.get::<_, String>(0))
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get downstream datasets
    let mut stmt = conn
        .prepare(
            r#"
            SELECT d.name
            FROM lineage l
            JOIN datasets d ON l.downstream_dataset_id = d.id
            WHERE l.upstream_dataset_id = ?1
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let downstream_datasets = stmt
        .query_map([dataset.id], |row| row.get::<_, String>(0))
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(
        dataset_name = %name,
        field_count = fields.len(),
        tag_count = tags.len(),
        upstream_count = upstream_datasets.len(),
        downstream_count = downstream_datasets.len(),
        "Retrieved dataset details successfully"
    );

    #[cfg(feature = "metrics")]
    metrics::record_catalog_operation("get_dataset", "success");

    Ok(Json(DatasetDetailResponse {
        dataset,
        fields,
        tags,
        upstream_datasets,
        downstream_datasets,
    }))
}

/// Search datasets using FTS
async fn search_datasets(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<DatasetResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let query = params
        .get("q")
        .ok_or_else(|| bad_request("Missing 'q' parameter".to_string(), request_id.0.clone()))?;

    tracing::debug!(search_query = %query, "Executing full-text search");

    // Validate FTS query (operators are allowed for powerful search)
    let validated_query = validation::validate_fts_query(query)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let conn = state
        .backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT d.id, d.name, d.path, d.format, d.description, d.tenant, d.domain, d.owner,
                   d.created_at, d.last_updated, d.row_count, d.size_bytes, d.partition_keys
            FROM datasets d
            JOIN dataset_search s ON d.name = s.dataset_name
            WHERE dataset_search MATCH ?1
            ORDER BY bm25(dataset_search)
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let datasets = stmt
        .query_map([&validated_query], |row| {
            let row_count: Option<i64> = row.get(10)?;
            let size_bytes: Option<i64> = row.get(11)?;
            let partition_keys = parse_partition_keys(row.get::<_, Option<String>>(12)?);
            Ok(DatasetResponse {
                id: row.get(0)?,
                name: row.get(1)?,
                path: row.get(2)?,
                format: row.get(3)?,
                description: row.get(4)?,
                tenant: row.get(5)?,
                domain: row.get(6)?,
                owner: row.get(7)?,
                created_at: row.get(8)?,
                last_updated: row.get(9)?,
                operational: OperationalMetaResponse {
                    row_count,
                    size_bytes,
                    partition_keys,
                },
            })
        })
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(
        search_query = %query,
        result_count = datasets.len(),
        "Search completed successfully"
    );

    #[cfg(feature = "metrics")]
    metrics::record_catalog_operation("search_datasets", "success");

    Ok(Json(datasets))
}

/// Helper function to create internal error response
///
/// Logs the detailed error message internally but returns a generic message to the client
/// to avoid leaking implementation details.
fn internal_error(message: String, request_id: String) -> (StatusCode, Json<ErrorResponse>) {
    tracing::error!(error = %message, "Internal server error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: "Internal server error. Please contact support with the request ID.".to_string(),
            request_id,
        }),
    )
}

/// Helper function to create not found error response
///
/// Returns a user-friendly not found message without leaking details about what exists.
fn not_found(message: String, request_id: String) -> (StatusCode, Json<ErrorResponse>) {
    tracing::info!(message = %message, "Resource not found");
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: message,
            request_id,
        }),
    )
}

/// Helper function to create bad request error response
///
/// Validation errors are user-facing and safe to return to the client.
fn bad_request(message: String, request_id: String) -> (StatusCode, Json<ErrorResponse>) {
    tracing::info!(message = %message, "Bad request");
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: message,
            request_id,
        }),
    )
}

fn parse_partition_keys(raw: Option<String>) -> Vec<String> {
    raw.and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default()
}
