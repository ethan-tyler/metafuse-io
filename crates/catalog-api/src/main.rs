//! MetaFuse Catalog API Server
//!
//! REST API for querying the MetaFuse catalog.

#[cfg(feature = "metrics")]
mod metrics;

#[cfg(feature = "rate-limiting")]
mod rate_limiting;

#[cfg(feature = "api-keys")]
mod api_keys;

#[cfg(feature = "audit")]
mod audit;

#[cfg(feature = "usage-analytics")]
mod usage_analytics;

mod health;
mod quality;

#[cfg(feature = "classification")]
mod classification;

// Multi-Tenant Integration
mod multi_tenant;

#[cfg(feature = "api-keys")]
mod control_plane;

#[cfg(feature = "api-keys")]
mod tenant_resolver;

#[cfg(feature = "alerting")]
use metafuse_catalog_api::alerting;

#[cfg(feature = "contracts")]
use metafuse_catalog_api::contracts;

#[cfg(feature = "column-lineage")]
use metafuse_catalog_api::lineage;

use axum::{
    extract::{Extension, Path, Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use metafuse_catalog_core::{migrations, validation};
use metafuse_catalog_delta::DeltaReader;
use metafuse_catalog_storage::{backend_from_uri, DynCatalogBackend};
use rusqlite::params_from_iter;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use tracing::Instrument;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

// Multi-tenant imports
use multi_tenant::{resolve_backend, MultiTenantConfig, MultiTenantResources, TenantBackend};

#[cfg(feature = "api-keys")]
use multi_tenant::{require_delete_permission, require_write_permission};

#[cfg(feature = "api-keys")]
use tenant_resolver::{ResolvedTenant, TenantResolverConfig};

#[cfg(feature = "api-keys")]
use control_plane::{
    AuditContext as ControlPlaneAuditContext, AuditLogEntry, CreateTenantRequest, Tenant,
    TenantApiKey, TenantRole, UpdateTenantRequest,
};

#[cfg(feature = "api-keys")]
use axum::http::HeaderMap;

/// Request ID for tracking requests through the system
#[derive(Debug, Clone)]
struct RequestId(String);

/// Application state shared across handlers
struct AppState {
    backend: Arc<DynCatalogBackend>,
    delta_reader: Arc<DeltaReader>,
    #[cfg(feature = "audit")]
    audit_logger: audit::AuditLogger,
    #[cfg(feature = "usage-analytics")]
    usage_tracker: Arc<usage_analytics::UsageTracker>,
    /// Multi-tenant resources (factory and control plane)
    multi_tenant: MultiTenantResources,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            backend: Arc::clone(&self.backend),
            delta_reader: Arc::clone(&self.delta_reader),
            #[cfg(feature = "audit")]
            audit_logger: self.audit_logger.clone(),
            #[cfg(feature = "usage-analytics")]
            usage_tracker: Arc::clone(&self.usage_tracker),
            multi_tenant: self.multi_tenant.clone(),
        }
    }
}

/// Identity context for audit logging
/// Extracted from request extensions - includes API key identity and client IP
/// Always available to handlers; enrich_event only active with audit feature
#[derive(Debug, Clone, Default)]
struct AuditContext {
    api_key_id: Option<String>,
    client_ip: Option<String>,
}

impl AuditContext {
    /// Create new audit context with optional API key and client IP
    fn new(api_key_id: Option<String>, client_ip: Option<String>) -> Self {
        Self {
            api_key_id,
            client_ip,
        }
    }

    /// Enrich an audit event with identity context
    #[cfg(feature = "audit")]
    fn enrich_event(&self, event: audit::AuditEvent) -> audit::AuditEvent {
        let event = match &self.api_key_id {
            Some(key_id) => event.with_actor(key_id, audit::ActorType::Service),
            None => event.with_actor("anonymous", audit::ActorType::Anonymous),
        };
        match &self.client_ip {
            Some(ip) => event.with_client_ip(ip),
            None => event,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    delta_location: Option<String>,
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

/// Convert RBAC error responses to the standard ErrorResponse type
#[cfg(feature = "api-keys")]
fn rbac_error(
    (status, json): (StatusCode, Json<multi_tenant::RbacErrorResponse>),
) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: json.error.clone(),
            request_id: json.request_id.clone(),
        }),
    )
}

// =============================================================================
// Admin API Types (requires api-keys feature)
// =============================================================================

/// Request to create a new API key for a tenant
#[cfg(feature = "api-keys")]
#[derive(Debug, Deserialize)]
struct AdminCreateApiKeyRequest {
    name: String,
    role: TenantRole,
    #[serde(default)]
    expires_at: Option<String>,
}

/// Response when creating a tenant (includes initial API key)
#[cfg(feature = "api-keys")]
#[derive(Debug, Serialize)]
struct AdminCreateTenantResponse {
    tenant: Tenant,
    /// Initial admin API key - only returned at creation time
    initial_api_key: String,
}

/// Response when creating an API key
#[cfg(feature = "api-keys")]
#[derive(Debug, Serialize)]
struct AdminCreateApiKeyResponse {
    /// The API key - only returned at creation time
    api_key: String,
}

/// Query parameters for audit log
#[cfg(feature = "api-keys")]
#[derive(Debug, Deserialize)]
struct AdminAuditLogQuery {
    tenant_id: Option<String>,
    #[serde(default = "default_audit_limit")]
    limit: usize,
}

#[cfg(feature = "api-keys")]
fn default_audit_limit() -> usize {
    100
}

/// Query parameters for listing tenants
#[cfg(feature = "api-keys")]
#[derive(Debug, Deserialize)]
struct AdminListTenantsQuery {
    status: Option<String>,
}

/// Response for tenant usage endpoint (admin view)
#[cfg(feature = "api-keys")]
#[derive(Debug, Serialize)]
struct TenantUsageResponse {
    tenant_id: String,
    /// Current dataset count
    dataset_count: i64,
    /// Quota limits
    quota_max_datasets: i64,
    quota_max_storage_bytes: i64,
    quota_max_api_calls_per_hour: i64,
    /// Usage percentages (0.0 to 1.0+)
    usage_ratio_datasets: f64,
    /// Human-readable status
    status: String,
}

/// Response for tenant self-service usage endpoint
#[cfg(feature = "api-keys")]
#[derive(Debug, Serialize)]
struct MyUsageResponse {
    /// Current dataset count
    dataset_count: i64,
    /// Quota limit for datasets (0 = unlimited)
    quota_max_datasets: i64,
    /// Usage percentage (0.0 to 1.0+)
    usage_ratio: f64,
    /// Human-readable status: "ok", "warning", "exceeded", "unlimited"
    status: String,
    /// Optional warning message when approaching or exceeding quota
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

// =============================================================================
// Admin Auth Middleware
// =============================================================================

/// Platform admin authorization middleware.
/// Validates the METAFUSE_ADMIN_KEY environment variable.
#[cfg(feature = "api-keys")]
async fn require_admin_auth(
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let admin_key = std::env::var("METAFUSE_ADMIN_KEY").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Admin authentication not configured".to_string(),
                request_id: request_id.0.clone(),
            }),
        )
    })?;

    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing Authorization header".to_string(),
                    request_id: request_id.0.clone(),
                }),
            )
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid Authorization format. Expected: Bearer <token>".to_string(),
                request_id: request_id.0.clone(),
            }),
        )
    })?;

    if token != admin_key {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Invalid admin key".to_string(),
                request_id: request_id.0.clone(),
            }),
        ));
    }

    Ok(next.run(request).await)
}

// =============================================================================
// Request Types for Write Endpoints
// =============================================================================

/// Request to create a new dataset
#[derive(Debug, Deserialize)]
struct CreateDatasetRequest {
    name: String,
    path: String,
    format: String,
    delta_location: Option<String>,
    description: Option<String>,
    tenant: Option<String>,
    domain: Option<String>,
    owner: Option<String>,
    tags: Option<Vec<String>>,
    upstream_datasets: Option<Vec<String>>,
}

/// Request to update an existing dataset
#[derive(Debug, Deserialize)]
struct UpdateDatasetRequest {
    path: Option<String>,
    format: Option<String>,
    delta_location: Option<String>,
    description: Option<String>,
    tenant: Option<String>,
    domain: Option<String>,
    owner: Option<String>,
}

/// Request to create a new owner
#[derive(Debug, Deserialize)]
struct CreateOwnerRequest {
    owner_id: String,
    name: String,
    owner_type: Option<String>,
    email: Option<String>,
    slack_channel: Option<String>,
    contact_info: Option<serde_json::Value>,
}

/// Request to update an existing owner
#[derive(Debug, Deserialize)]
struct UpdateOwnerRequest {
    name: Option<String>,
    owner_type: Option<String>,
    email: Option<String>,
    slack_channel: Option<String>,
    contact_info: Option<serde_json::Value>,
}

/// Request to create a new domain
#[derive(Debug, Deserialize)]
struct CreateDomainRequest {
    name: String,
    display_name: String,
    description: Option<String>,
    owner_id: Option<String>,
}

/// Request to update an existing domain
#[derive(Debug, Deserialize)]
struct UpdateDomainRequest {
    display_name: Option<String>,
    description: Option<String>,
    owner_id: Option<String>,
    is_active: Option<bool>,
}

/// Request to create a lineage edge
#[derive(Debug, Deserialize)]
struct CreateLineageEdgeRequest {
    source_dataset: String,
    target_dataset: String,
}

/// Request to create a governance rule
#[derive(Debug, Deserialize)]
struct CreateGovernanceRuleRequest {
    name: String,
    rule_type: String,
    description: Option<String>,
    config: serde_json::Value,
    priority: Option<i32>,
}

/// Request to update a governance rule
#[derive(Debug, Deserialize)]
struct UpdateGovernanceRuleRequest {
    name: Option<String>,
    rule_type: Option<String>,
    description: Option<String>,
    config: Option<serde_json::Value>,
    priority: Option<i32>,
    is_active: Option<bool>,
}

/// Request to create a quality metric
#[derive(Debug, Deserialize)]
struct CreateQualityMetricRequest {
    completeness_score: Option<f64>,
    freshness_score: Option<f64>,
    file_health_score: Option<f64>,
    overall_score: Option<f64>,
    row_count: Option<i64>,
    file_count: Option<i64>,
    size_bytes: Option<i64>,
    details: Option<serde_json::Value>,
}

/// Request to set freshness configuration
#[derive(Debug, Deserialize)]
struct SetFreshnessConfigRequest {
    expected_interval_secs: i64,
    grace_period_secs: Option<i64>,
    timezone: Option<String>,
    cron_schedule: Option<String>,
    alert_on_stale: Option<bool>,
    alert_channels: Option<Vec<String>>,
}

/// Request to add tags to a dataset
#[derive(Debug, Deserialize)]
struct AddTagsRequest {
    tags: Vec<String>,
}

/// Request to remove tags from a dataset
#[derive(Debug, Deserialize)]
struct RemoveTagsRequest {
    tags: Vec<String>,
}

// =============================================================================
// Response Types for New Endpoints
// =============================================================================

/// Owner response structure
#[derive(Debug, Serialize)]
struct OwnerResponse {
    id: i64,
    owner_id: String,
    name: String,
    owner_type: String,
    email: Option<String>,
    slack_channel: Option<String>,
    contact_info: Option<serde_json::Value>,
    created_at: String,
    updated_at: String,
}

/// Domain response structure
#[derive(Debug, Serialize)]
struct DomainResponse {
    id: i64,
    name: String,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_id: Option<String>,
    is_active: bool,
    dataset_count: i64,
    created_at: String,
    updated_at: String,
}

/// Request to create a glossary term
#[derive(Debug, Deserialize)]
struct CreateGlossaryTermRequest {
    term: String,
    description: Option<String>,
    domain: Option<String>,
    owner_id: Option<String>,
    status: Option<String>,
}

/// Request to update a glossary term
#[derive(Debug, Deserialize)]
struct UpdateGlossaryTermRequest {
    term: Option<String>,
    description: Option<String>,
    domain: Option<String>,
    owner_id: Option<String>,
    status: Option<String>,
}

/// Request to link a term to a dataset or field
#[derive(Debug, Deserialize)]
struct LinkTermRequest {
    dataset_id: Option<i64>,
    field_id: Option<i64>,
}

/// Glossary term response structure
#[derive(Debug, Serialize)]
struct GlossaryTermResponse {
    id: i64,
    term: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_id: Option<String>,
    status: String,
    link_count: i64,
    created_at: String,
    updated_at: String,
}

/// Term link response structure
#[derive(Debug, Serialize)]
struct TermLinkResponse {
    id: i64,
    term_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dataset_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dataset_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field_name: Option<String>,
}

/// Governance rule response structure
#[derive(Debug, Serialize)]
struct GovernanceRuleResponse {
    id: i64,
    name: String,
    rule_type: String,
    description: Option<String>,
    config: serde_json::Value,
    priority: i32,
    is_active: bool,
    created_at: String,
    updated_at: String,
}

/// Quality metric response structure
#[derive(Debug, Serialize)]
struct QualityMetricResponse {
    id: i64,
    dataset_id: i64,
    computed_at: String,
    completeness_score: Option<f64>,
    freshness_score: Option<f64>,
    file_health_score: Option<f64>,
    overall_score: Option<f64>,
    row_count: Option<i64>,
    file_count: Option<i64>,
    size_bytes: Option<i64>,
    details: Option<serde_json::Value>,
}

/// Freshness config response structure
#[derive(Debug, Serialize)]
struct FreshnessConfigResponse {
    id: i64,
    dataset_id: i64,
    expected_interval_secs: i64,
    grace_period_secs: i64,
    timezone: String,
    cron_schedule: Option<String>,
    alert_on_stale: bool,
    alert_channels: Option<Vec<String>>,
    created_at: String,
    updated_at: String,
}

/// Lineage edge response
#[derive(Debug, Serialize)]
struct LineageEdgeResponse {
    id: i64,
    upstream_dataset_id: i64,
    downstream_dataset_id: i64,
    created_at: String,
}

// =============================================================================
// Delta-Delegated Response Types
// =============================================================================

/// Schema response from Delta table
#[derive(Debug, Serialize)]
struct SchemaResponse {
    dataset_name: String,
    delta_version: i64,
    schema: serde_json::Value,
    partition_columns: Vec<String>,
}

/// Schema diff response from Delta table
#[derive(Debug, Serialize)]
struct SchemaDiffResponse {
    dataset_name: String,
    from_version: i64,
    to_version: i64,
    added_columns: Vec<SchemaDiffField>,
    removed_columns: Vec<SchemaDiffField>,
    modified_columns: Vec<SchemaDiffFieldChange>,
}

/// Field info for schema diff response
#[derive(Debug, Serialize)]
struct SchemaDiffField {
    name: String,
    data_type: String,
    nullable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

/// Field change info for schema diff response
#[derive(Debug, Serialize)]
struct SchemaDiffFieldChange {
    name: String,
    old_type: String,
    new_type: String,
    old_nullable: bool,
    new_nullable: bool,
}

/// Stats response from Delta table
#[derive(Debug, Serialize)]
struct StatsResponse {
    dataset_name: String,
    delta_version: i64,
    row_count: i64,
    size_bytes: i64,
    num_files: i64,
    last_modified: Option<String>,
}

/// History response from Delta table
#[derive(Debug, Serialize)]
struct HistoryResponse {
    dataset_name: String,
    versions: Vec<VersionInfo>,
}

/// Version info for history response
#[derive(Debug, Serialize)]
struct VersionInfo {
    version: i64,
    timestamp: String,
    operation: String,
    parameters: HashMap<String, String>,
}

// =============================================================================
// Query Parameter Types
// =============================================================================

/// Query params for schema endpoint
#[derive(Debug, Deserialize)]
struct SchemaQueryParams {
    version: Option<i64>,
}

/// Query params for schema diff endpoint
#[derive(Debug, Deserialize)]
struct SchemaDiffQueryParams {
    from: i64,
    to: i64,
}

/// Query params for history endpoint
#[derive(Debug, Deserialize)]
struct HistoryQueryParams {
    limit: Option<usize>,
}

/// Query params for get_dataset endpoint with optional includes
#[derive(Debug, Deserialize, Default)]
struct DatasetQueryParams {
    /// Comma-separated list of additional data to include: delta,quality,lineage
    include: Option<String>,
}

/// Valid include values
const VALID_INCLUDE_VALUES: &[&str] = &["delta", "quality", "lineage"];

/// Parsed include options
#[derive(Debug, Default)]
struct IncludeOptions {
    delta: bool,
    quality: bool,
    lineage: bool,
}

impl IncludeOptions {
    /// Parse and validate include query parameter
    ///
    /// Returns an error if any unknown include values are provided.
    /// Valid values: delta, quality, lineage
    fn parse(include: &Option<String>) -> Result<Self, String> {
        match include {
            None => Ok(Self::default()),
            Some(s) if s.trim().is_empty() => Ok(Self::default()),
            Some(s) => {
                let parts: Vec<String> = s.split(',').map(|p| p.trim().to_lowercase()).collect();

                // Validate all values are known
                let invalid: Vec<&String> = parts
                    .iter()
                    .filter(|p| !p.is_empty() && !VALID_INCLUDE_VALUES.contains(&p.as_str()))
                    .collect();

                if !invalid.is_empty() {
                    return Err(format!(
                        "Invalid include value(s): {}. Valid values: {}",
                        invalid
                            .iter()
                            .map(|s| format!("'{}'", s))
                            .collect::<Vec<_>>()
                            .join(", "),
                        VALID_INCLUDE_VALUES.join(", ")
                    ));
                }

                Ok(Self {
                    delta: parts.iter().any(|p| p == "delta"),
                    quality: parts.iter().any(|p| p == "quality"),
                    lineage: parts.iter().any(|p| p == "lineage"),
                })
            }
        }
    }
}

// =============================================================================
// Extended Response Types for ?include support
// =============================================================================

/// Delta table info (from live Delta metadata)
#[derive(Debug, Serialize)]
struct DeltaInfo {
    version: i64,
    row_count: i64,
    size_bytes: i64,
    num_files: i64,
    partition_columns: Vec<String>,
    last_modified: Option<String>,
}

/// Quality metrics info (latest computed scores)
#[derive(Debug, Serialize)]
struct QualityInfo {
    overall_score: Option<f64>,
    completeness_score: Option<f64>,
    freshness_score: Option<f64>,
    file_health_score: Option<f64>,
    last_computed: Option<String>,
}

/// Lineage info (upstream and downstream datasets)
#[derive(Debug, Serialize)]
struct LineageInfo {
    upstream: Vec<String>,
    downstream: Vec<String>,
}

/// Extended dataset detail response with optional includes
#[derive(Debug, Serialize)]
struct ExtendedDatasetResponse {
    #[serde(flatten)]
    dataset: DatasetResponse,
    fields: Vec<FieldResponse>,
    tags: Vec<String>,
    upstream_datasets: Vec<String>,
    downstream_datasets: Vec<String>,
    /// Delta table metadata (optional, via ?include=delta)
    #[serde(skip_serializing_if = "Option::is_none")]
    delta: Option<DeltaInfo>,
    /// Quality metrics (optional, via ?include=quality)
    #[serde(skip_serializing_if = "Option::is_none")]
    quality: Option<QualityInfo>,
    /// Lineage info (optional, via ?include=lineage) - separate from upstream/downstream for structured access
    #[serde(skip_serializing_if = "Option::is_none")]
    lineage: Option<LineageInfo>,
}

/// Pagination query params for list endpoints
#[derive(Debug, Deserialize, Default)]
struct PaginationParams {
    /// Maximum number of items to return (default: 100, max: 1000)
    limit: Option<usize>,
    /// Number of items to skip (default: 0)
    offset: Option<usize>,
}

impl PaginationParams {
    fn limit(&self) -> usize {
        self.limit.unwrap_or(100).min(1000)
    }

    fn offset(&self) -> usize {
        self.offset.unwrap_or(0)
    }
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

    // Run migrations if enabled via environment variable
    if std::env::var("METAFUSE_RUN_MIGRATIONS").unwrap_or_default() == "true" {
        tracing::info!("Running schema migrations on startup...");
        let conn = backend.get_connection().await.map_err(|e| {
            tracing::error!("Failed to get connection for migrations: {}", e);
            e
        })?;
        match migrations::run_migrations(&conn) {
            Ok(count) => {
                if count > 0 {
                    tracing::info!("Applied {} migrations", count);
                } else {
                    tracing::info!("No pending migrations");
                }
            }
            Err(e) => {
                tracing::error!("Migration failed: {}", e);
                return Err(e.into());
            }
        }
    }

    // Create DeltaReader with configurable cache settings
    let cache_ttl_secs = std::env::var("METAFUSE_DELTA_CACHE_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300u64); // Default: 5 minutes
    let delta_reader = Arc::new(DeltaReader::new(Duration::from_secs(cache_ttl_secs)));
    tracing::info!(cache_ttl_secs, "Delta reader initialized");

    let backend = Arc::from(backend);

    // Initialize audit logger if feature enabled
    #[cfg(feature = "audit")]
    let audit_logger = {
        let config = audit::AuditConfig::default();
        let (logger, receiver) = audit::AuditLogger::new(&config);
        // Start background worker
        let backend_clone = Arc::clone(&backend);
        tokio::spawn(async move {
            audit::audit_writer_task(receiver, backend_clone, config).await;
        });
        tracing::info!("Audit logging enabled");
        logger
    };

    // Initialize usage tracker if feature enabled
    #[cfg(feature = "usage-analytics")]
    let usage_tracker = {
        let tracker = Arc::new(usage_analytics::UsageTracker::new_default());
        // Start background flush worker
        let tracker_clone = Arc::clone(&tracker);
        let backend_clone = Arc::clone(&backend);
        tokio::spawn(async move {
            usage_analytics::usage_flush_task(tracker_clone, backend_clone).await;
        });
        tracing::info!("Usage analytics enabled");
        tracker
    };

    // Initialize alerting background task if feature enabled
    #[cfg(feature = "alerting")]
    {
        let webhook_client = Arc::new(alerting::WebhookClient::new_default());
        let backend_clone = Arc::clone(&backend);
        tokio::spawn(async move {
            alerting::alert_check_task(webhook_client, backend_clone).await;
        });
        tracing::info!("Alerting background task started");
    }

    // Initialize scheduled quality check background task
    {
        let quality_config = quality::ScheduledQualityCheckConfig::default();
        if quality_config.enabled {
            let delta_reader_clone = Arc::clone(&delta_reader);
            let backend_clone = Arc::clone(&backend);
            tokio::spawn(async move {
                quality::quality_check_task(delta_reader_clone, backend_clone, quality_config)
                    .await;
            });
            tracing::info!("Scheduled quality check background task started");
        }
    }

    // Initialize freshness violation detection background task
    {
        let freshness_config = quality::FreshnessCheckConfig::default();
        if freshness_config.enabled {
            let backend_clone = Arc::clone(&backend);
            tokio::spawn(async move {
                quality::freshness_check_task(backend_clone, freshness_config).await;
            });
            tracing::info!("Freshness violation detection background task started");
        }
    }

    // Initialize schema change detection background task
    #[cfg(feature = "alerting")]
    {
        let schema_config = alerting::SchemaMonitorConfig::default();
        if schema_config.enabled {
            let delta_reader_clone = Arc::clone(&delta_reader);
            let webhook_client = Arc::new(alerting::WebhookClient::new_default());
            let backend_clone = Arc::clone(&backend);
            tokio::spawn(async move {
                alerting::schema_monitor_task(
                    delta_reader_clone,
                    webhook_client,
                    backend_clone,
                    schema_config,
                )
                .await;
            });
            tracing::info!("Schema change detection background task started");
        }
    }

    // Initialize multi-tenant resources
    let mt_config = MultiTenantConfig::from_env();
    mt_config.validate()?;
    let multi_tenant = MultiTenantResources::new(&mt_config).await?;
    if multi_tenant.is_enabled() {
        tracing::info!(
            storage_template = %mt_config.storage_uri_template,
            cache_capacity = mt_config.cache_capacity,
            "Multi-tenant mode enabled"
        );
    }

    let state = AppState {
        backend,
        delta_reader,
        #[cfg(feature = "audit")]
        audit_logger,
        #[cfg(feature = "usage-analytics")]
        usage_tracker,
        multi_tenant,
    };

    // Build router with conditional feature routes
    let app = Router::new()
        // Health check endpoints (Kubernetes-compatible)
        .route("/health", get(health::health_check))
        .route("/ready", get(health::readiness_check))
        .route("/live", get(health::liveness_check))
        // Dataset endpoints
        .route("/api/v1/datasets", get(list_datasets).post(create_dataset))
        .route(
            "/api/v1/datasets/:name",
            get(get_dataset).put(update_dataset).delete(delete_dataset),
        )
        .route("/api/v1/datasets/:name/tags", post(add_tags))
        .route("/api/v1/datasets/:name/tags/remove", post(remove_tags))
        // Delta-delegated endpoints
        .route("/api/v1/datasets/:name/schema", get(get_dataset_schema))
        .route(
            "/api/v1/datasets/:name/schema/diff",
            get(get_dataset_schema_diff),
        )
        .route("/api/v1/datasets/:name/stats", get(get_dataset_stats))
        .route("/api/v1/datasets/:name/history", get(get_dataset_history))
        // Quality metrics endpoints
        .route(
            "/api/v1/datasets/:name/quality",
            get(list_quality_metrics).post(create_quality_metric),
        )
        // Freshness config endpoints
        .route(
            "/api/v1/datasets/:name/freshness",
            get(get_freshness_config).post(set_freshness_config),
        )
        // Owner endpoints
        .route("/api/v1/owners", get(list_owners).post(create_owner))
        .route(
            "/api/v1/owners/:id",
            get(get_owner).put(update_owner).delete(delete_owner),
        )
        // Domain endpoints
        .route("/api/v1/domains", get(list_domains).post(create_domain))
        .route(
            "/api/v1/domains/:name",
            get(get_domain).put(update_domain).delete(delete_domain),
        )
        .route("/api/v1/domains/:name/datasets", get(list_domain_datasets))
        // Glossary endpoints
        .route(
            "/api/v1/glossary",
            get(list_glossary_terms).post(create_glossary_term),
        )
        .route(
            "/api/v1/glossary/:id",
            get(get_glossary_term)
                .put(update_glossary_term)
                .delete(delete_glossary_term),
        )
        .route(
            "/api/v1/glossary/:id/links",
            get(get_term_links).post(link_term).delete(unlink_term),
        )
        // Lineage endpoint
        .route("/api/v1/lineage", post(create_lineage_edge))
        // Governance rules endpoints
        .route(
            "/api/v1/governance/rules",
            get(list_governance_rules).post(create_governance_rule),
        )
        .route(
            "/api/v1/governance/rules/:id",
            get(get_governance_rule)
                .put(update_governance_rule)
                .delete(delete_governance_rule),
        )
        // Search endpoint
        .route("/api/v1/search", get(search_datasets));

    // Add audit endpoint if audit feature is enabled
    #[cfg(feature = "audit")]
    let app = app.route("/api/v1/audit", get(list_audit_logs));

    // Add usage analytics endpoints if usage-analytics feature is enabled
    #[cfg(feature = "usage-analytics")]
    let app = app
        .route("/api/v1/datasets/:name/usage", get(get_dataset_usage))
        .route("/api/v1/analytics/popular", get(get_popular_datasets))
        .route("/api/v1/analytics/stale", get(get_stale_datasets));

    // Quality endpoints (core functionality)
    let app = app
        .route(
            "/api/v1/datasets/:name/quality",
            get(get_dataset_quality).post(compute_dataset_quality),
        )
        .route("/api/v1/quality/unhealthy", get(get_unhealthy_datasets))
        // Quality check management endpoints (v1.7.0)
        .route(
            "/api/v1/datasets/:name/quality/checks",
            get(list_quality_checks).post(create_quality_check),
        )
        .route(
            "/api/v1/datasets/:name/quality/checks/:check_id",
            get(get_quality_check).delete(delete_quality_check),
        )
        .route(
            "/api/v1/datasets/:name/quality/execute",
            post(execute_quality_checks),
        )
        .route(
            "/api/v1/datasets/:name/quality/results",
            get(get_quality_results),
        )
        // Freshness violation endpoints (v1.7.0)
        .route(
            "/api/v1/datasets/:name/freshness/violations",
            get(get_dataset_freshness_violations),
        )
        .route(
            "/api/v1/freshness/violations",
            get(get_all_freshness_violations),
        );

    // Tenant self-service usage endpoint (requires api-keys for auth)
    #[cfg(feature = "api-keys")]
    let app = app.route("/api/v1/usage", get(get_my_usage));

    // Classification endpoints if classification feature is enabled
    #[cfg(feature = "classification")]
    let app = app
        .route(
            "/api/v1/datasets/:name/classifications",
            get(get_dataset_classifications).post(scan_dataset_classifications),
        )
        .route("/api/v1/classifications/pii", get(get_all_pii_columns))
        .route(
            "/api/v1/fields/:id/classification",
            axum::routing::put(set_field_classification),
        );

    // Alerting endpoints (v0.9.0)
    #[cfg(feature = "alerting")]
    let app = app.route("/api/v1/alerts", get(list_alerts));

    // Contract endpoints (v0.9.0)
    #[cfg(feature = "contracts")]
    let app = app
        .route(
            "/api/v1/contracts",
            get(list_contracts).post(create_contract),
        )
        .route(
            "/api/v1/contracts/:name",
            get(get_contract)
                .put(update_contract)
                .delete(delete_contract),
        );

    // Column-level lineage endpoints (v0.10.0)
    #[cfg(feature = "column-lineage")]
    let app = {
        tracing::info!("Column-level lineage API enabled at /api/v1/lineage/*");
        app.route("/api/v1/lineage/parse", post(lineage_parse))
            .route("/api/v1/lineage/edges", post(lineage_record))
            .route(
                "/api/v1/lineage/dataset/:dataset_id/columns/:column/upstream",
                get(lineage_upstream),
            )
            .route(
                "/api/v1/lineage/dataset/:dataset_id/columns/:column/downstream",
                get(lineage_downstream),
            )
            .route(
                "/api/v1/lineage/dataset/:dataset_id/columns/:column/pii-propagation",
                get(lineage_pii_propagation),
            )
            .route(
                "/api/v1/lineage/dataset/:dataset_id",
                axum::routing::delete(lineage_delete_dataset),
            )
            .route(
                "/api/v1/lineage/fields/:field_id/impact",
                get(lineage_field_impact),
            )
    };

    // Add metrics endpoint if metrics feature is enabled
    #[cfg(feature = "metrics")]
    let app = {
        tracing::info!("Metrics endpoint enabled at /metrics");
        app.route("/metrics", get(metrics::metrics_handler))
    };

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
        });

    // Add rate limiting if enabled
    #[cfg(feature = "rate-limiting")]
    let app = {
        let rate_limiter = rate_limiting::create_rate_limiter();
        tracing::info!(
            anonymous_limit = rate_limiter.config().anonymous_limit,
            authenticated_limit = rate_limiter.config().authenticated_limit,
            window_secs = rate_limiter.config().window_secs,
            "Rate limiting enabled"
        );
        app.layer(axum::Extension(rate_limiter))
            .layer(middleware::from_fn(rate_limiting::rate_limit_middleware))
    };

    // Add audit context middleware to extract identity for audit logging
    // Always run to make AuditContext available to handlers
    let app = app.layer(middleware::from_fn(audit_context_middleware));

    // Add admin API routes (requires api-keys feature)
    // These routes are protected by METAFUSE_ADMIN_KEY, NOT tenant API keys
    #[cfg(feature = "api-keys")]
    let app = {
        use axum::routing::delete;

        // Build admin router with dedicated admin auth
        let admin_routes = Router::new()
            .route(
                "/tenants",
                get(admin_list_tenants).post(admin_create_tenant),
            )
            .route(
                "/tenants/:tenant_id",
                get(admin_get_tenant)
                    .put(admin_update_tenant)
                    .delete(admin_delete_tenant),
            )
            .route("/tenants/:tenant_id/suspend", post(admin_suspend_tenant))
            .route(
                "/tenants/:tenant_id/reactivate",
                post(admin_reactivate_tenant),
            )
            .route(
                "/tenants/:tenant_id/api-keys",
                get(admin_list_api_keys).post(admin_create_api_key),
            )
            .route(
                "/tenants/:tenant_id/api-keys/:key_id",
                delete(admin_revoke_api_key),
            )
            .route("/audit-log", get(admin_get_audit_log))
            .route("/tenants/:tenant_id/usage", get(admin_get_tenant_usage))
            .layer(middleware::from_fn(require_admin_auth));

        tracing::info!("Admin API routes enabled at /api/v1/admin/*");

        // Merge admin routes into main app
        app.nest("/api/v1/admin", admin_routes)
    };

    // Add multi-tenant middleware if enabled (requires api-keys feature)
    #[cfg(feature = "api-keys")]
    let app = if mt_config.enabled {
        use multi_tenant::tenant_backend_middleware;
        use tenant_resolver::{require_tenant_middleware, tenant_resolver_middleware};

        let factory = state
            .multi_tenant
            .factory()
            .expect("factory required when enabled")
            .clone();
        let control_plane = state
            .multi_tenant
            .control_plane()
            .expect("control plane required when enabled")
            .clone();
        let resolver_config = TenantResolverConfig::default();

        tracing::info!("Multi-tenant middleware enabled for API routes");

        // Middleware layers applied in reverse order (last added = first executed):
        // 1. tenant_resolver_middleware - Resolves tenant from API key or X-Tenant-ID header
        // 2. tenant_metrics_middleware - Injects TenantMetricsInfo for metrics recording (if enabled)
        // 3. require_tenant_middleware - Rejects requests without valid tenant context (401)
        // 4. tenant_backend_middleware - Gets tenant-specific backend for resolved tenant
        #[cfg(feature = "metrics")]
        let app = {
            let metrics_config = metrics::TenantMetricsConfig::from_env();
            tracing::info!(
                include_tenant_id = metrics_config.include_tenant_id,
                "Tenant metrics configured (cardinality control)"
            );
            app.layer(middleware::from_fn(tenant_backend_middleware))
                .layer(middleware::from_fn(require_tenant_middleware))
                .layer(middleware::from_fn(metrics::tenant_metrics_middleware))
                .layer(middleware::from_fn(tenant_resolver_middleware))
                .layer(Extension(factory))
                .layer(Extension(control_plane))
                .layer(Extension(resolver_config))
                .layer(Extension(metrics_config))
        };

        #[cfg(not(feature = "metrics"))]
        let app = app
            .layer(middleware::from_fn(tenant_backend_middleware))
            .layer(middleware::from_fn(require_tenant_middleware))
            .layer(middleware::from_fn(tenant_resolver_middleware))
            .layer(Extension(factory))
            .layer(Extension(control_plane))
            .layer(Extension(resolver_config));

        app
    } else {
        app
    };

    // Clone multi_tenant for shutdown handler before moving state
    let multi_tenant_for_shutdown = state.multi_tenant.clone();
    let app = app.layer(CorsLayer::permissive()).with_state(state);

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

    // Graceful shutdown with signal handling
    let shutdown = shutdown_signal(multi_tenant_for_shutdown);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Create shutdown signal handler for graceful termination
///
/// Handles SIGINT (Ctrl+C) and SIGTERM signals for graceful shutdown.
/// Background tasks (audit logger, usage tracker) will flush their buffers
/// when their channels are closed during shutdown.
async fn shutdown_signal(multi_tenant: multi_tenant::MultiTenantResources) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }

    // Perform cleanup
    tracing::info!("Initiating graceful shutdown...");

    // Clear multi-tenant caches
    if multi_tenant.is_enabled() {
        multi_tenant.clear_all_caches();
        tracing::info!("Multi-tenant caches cleared");
    }

    // Note: Audit logs and usage stats are flushed by their background tasks
    // when their channels close during the shutdown sequence.
    tracing::info!("Background tasks will flush pending data on exit");
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

/// Middleware to extract audit context (API key identity + client IP)
/// Must run after auth middleware so ApiKeyId is available in extensions
/// Always runs to make AuditContext available to all handlers
async fn audit_context_middleware(mut req: Request, next: Next) -> Response {
    // Extract API key ID if present (set by auth/rate-limiting middleware)
    #[cfg(feature = "rate-limiting")]
    let api_key_id = req
        .extensions()
        .get::<rate_limiting::ApiKeyId>()
        .map(|k| k.id.clone());
    #[cfg(not(feature = "rate-limiting"))]
    let api_key_id: Option<String> = None;

    // Extract client IP from headers (X-Forwarded-For, X-Real-IP) or connection
    let client_ip = extract_client_ip(&req);

    // Create and insert audit context
    let audit_context = AuditContext::new(api_key_id, client_ip);
    req.extensions_mut().insert(audit_context);

    next.run(req).await
}

/// Extract client IP from request headers or connection info
fn extract_client_ip(req: &Request) -> Option<String> {
    // Try X-Forwarded-For first (may contain multiple IPs, take the first)
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }

    // Fallback: could extract from connection info but axum doesn't expose it directly here
    None
}

// =============================================================================
// Admin API Handlers (requires api-keys feature)
// =============================================================================

/// List all tenants
#[cfg(feature = "api-keys")]
async fn admin_list_tenants(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<AdminListTenantsQuery>,
) -> Result<Json<Vec<Tenant>>, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let tenants = control_plane
        .list_tenants(params.status.as_deref())
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    Ok(Json(tenants))
}

/// Create a new tenant
#[cfg(feature = "api-keys")]
async fn admin_create_tenant(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<AdminCreateTenantResponse>), (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let cp_audit = ControlPlaneAuditContext {
        actor: "platform-admin".to_string(),
        request_id: Some(request_id.0.clone()),
        client_ip: audit_ctx.client_ip.clone(),
    };

    let (tenant, initial_api_key) =
        control_plane
            .create_tenant(req, cp_audit)
            .await
            .map_err(|e| {
                if e.to_string().contains("already exists") {
                    (
                        StatusCode::CONFLICT,
                        Json(ErrorResponse {
                            error: e.to_string(),
                            request_id: request_id.0.clone(),
                        }),
                    )
                } else {
                    internal_error(e.to_string(), request_id.0.clone())
                }
            })?;

    Ok((
        StatusCode::CREATED,
        Json(AdminCreateTenantResponse {
            tenant,
            initial_api_key,
        }),
    ))
}

/// Get a specific tenant
#[cfg(feature = "api-keys")]
async fn admin_get_tenant(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Tenant>, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let tenant = control_plane
        .get_tenant(&tenant_id)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Tenant '{}' not found", tenant_id),
                    request_id: request_id.0.clone(),
                }),
            )
        })?;

    Ok(Json(tenant))
}

/// Update a tenant
#[cfg(feature = "api-keys")]
async fn admin_update_tenant(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    Path(tenant_id): Path<String>,
    Json(req): Json<UpdateTenantRequest>,
) -> Result<Json<Tenant>, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let cp_audit = ControlPlaneAuditContext {
        actor: "platform-admin".to_string(),
        request_id: Some(request_id.0.clone()),
        client_ip: audit_ctx.client_ip.clone(),
    };

    let tenant = control_plane
        .update_tenant(&tenant_id, req, cp_audit)
        .await
        .map_err(|e| {
            if e.to_string().contains("not found") {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        request_id: request_id.0.clone(),
                    }),
                )
            } else {
                internal_error(e.to_string(), request_id.0.clone())
            }
        })?;

    Ok(Json(tenant))
}

/// Suspend a tenant
#[cfg(feature = "api-keys")]
async fn admin_suspend_tenant(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Tenant>, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let cp_audit = ControlPlaneAuditContext {
        actor: "platform-admin".to_string(),
        request_id: Some(request_id.0.clone()),
        client_ip: audit_ctx.client_ip.clone(),
    };

    let tenant = control_plane
        .suspend_tenant(&tenant_id, cp_audit)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    Ok(Json(tenant))
}

/// Reactivate a suspended tenant
#[cfg(feature = "api-keys")]
async fn admin_reactivate_tenant(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Tenant>, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let cp_audit = ControlPlaneAuditContext {
        actor: "platform-admin".to_string(),
        request_id: Some(request_id.0.clone()),
        client_ip: audit_ctx.client_ip.clone(),
    };

    let tenant = control_plane
        .reactivate_tenant(&tenant_id, cp_audit)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    Ok(Json(tenant))
}

/// Delete a tenant (soft delete)
#[cfg(feature = "api-keys")]
async fn admin_delete_tenant(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Tenant>, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let cp_audit = ControlPlaneAuditContext {
        actor: "platform-admin".to_string(),
        request_id: Some(request_id.0.clone()),
        client_ip: audit_ctx.client_ip.clone(),
    };

    let tenant = control_plane
        .delete_tenant(&tenant_id, cp_audit)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    Ok(Json(tenant))
}

/// List API keys for a tenant
#[cfg(feature = "api-keys")]
async fn admin_list_api_keys(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<TenantApiKey>>, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let keys = control_plane
        .list_tenant_api_keys(&tenant_id)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    Ok(Json(keys))
}

/// Create a new API key for a tenant
#[cfg(feature = "api-keys")]
async fn admin_create_api_key(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(tenant_id): Path<String>,
    Json(req): Json<AdminCreateApiKeyRequest>,
) -> Result<(StatusCode, Json<AdminCreateApiKeyResponse>), (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let api_key = control_plane
        .create_tenant_api_key(&tenant_id, req.name, req.role, req.expires_at)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    Ok((
        StatusCode::CREATED,
        Json(AdminCreateApiKeyResponse { api_key }),
    ))
}

/// Revoke an API key
#[cfg(feature = "api-keys")]
async fn admin_revoke_api_key(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path((tenant_id, key_id)): Path<(String, i64)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let revoked = control_plane
        .revoke_tenant_api_key(&tenant_id, key_id)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("API key {} not found for tenant {}", key_id, tenant_id),
                request_id: request_id.0.clone(),
            }),
        ))
    }
}

/// Get audit log
#[cfg(feature = "api-keys")]
async fn admin_get_audit_log(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<AdminAuditLogQuery>,
) -> Result<Json<Vec<AuditLogEntry>>, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let logs = control_plane
        .get_audit_log(params.tenant_id.as_deref(), params.limit)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    Ok(Json(logs))
}

/// Get usage statistics for a tenant (admin endpoint)
#[cfg(feature = "api-keys")]
async fn admin_get_tenant_usage(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantUsageResponse>, (StatusCode, Json<ErrorResponse>)> {
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    // Get tenant info
    let tenant = control_plane
        .get_tenant(&tenant_id)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Tenant '{}' not found", tenant_id),
                    request_id: request_id.0.clone(),
                }),
            )
        })?;

    // Get tenant's backend to count datasets
    let factory = state.multi_tenant.factory().ok_or_else(|| {
        internal_error(
            "Tenant factory not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let backend = factory
        .get_backend_by_id(&tenant_id)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Count datasets
    let dataset_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM datasets", [], |row| row.get(0))
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Calculate usage ratio
    let usage_ratio_datasets = if tenant.quota_max_datasets > 0 {
        dataset_count as f64 / tenant.quota_max_datasets as f64
    } else {
        0.0 // Unlimited quota
    };

    // Determine status
    let status = if tenant.quota_max_datasets <= 0 {
        "unlimited".to_string()
    } else if usage_ratio_datasets >= 1.0 {
        "exceeded".to_string()
    } else if usage_ratio_datasets >= 0.8 {
        "warning".to_string()
    } else {
        "ok".to_string()
    };

    tracing::info!(
        tenant_id = %tenant_id,
        dataset_count,
        quota_max = tenant.quota_max_datasets,
        usage_ratio = usage_ratio_datasets,
        "Returning tenant usage stats"
    );

    Ok(Json(TenantUsageResponse {
        tenant_id,
        dataset_count,
        quota_max_datasets: tenant.quota_max_datasets,
        quota_max_storage_bytes: tenant.quota_max_storage_bytes,
        quota_max_api_calls_per_hour: tenant.quota_max_api_calls_per_hour,
        usage_ratio_datasets,
        status,
    }))
}

/// Get my usage statistics (tenant self-service endpoint)
///
/// Returns the authenticated tenant's current usage and quota status.
#[cfg(feature = "api-keys")]
async fn get_my_usage(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    resolved_tenant: Option<Extension<ResolvedTenant>>,
    tenant_backend: Option<Extension<TenantBackend>>,
) -> Result<Json<MyUsageResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Require tenant authentication
    let resolved = resolved_tenant.as_ref().map(|e| &e.0).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Authentication required to view usage".to_string(),
                request_id: request_id.0.clone(),
            }),
        )
    })?;

    let tenant_id = resolved.tenant_id();

    // Get control plane to fetch quota info
    let control_plane = state.multi_tenant.control_plane().ok_or_else(|| {
        internal_error(
            "Control plane not available".to_string(),
            request_id.0.clone(),
        )
    })?;

    let tenant = control_plane
        .get_tenant(tenant_id)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .ok_or_else(|| {
            internal_error(
                format!("Tenant '{}' not found in control plane", tenant_id),
                request_id.0.clone(),
            )
        })?;

    // Get backend to count datasets
    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Count datasets
    let dataset_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM datasets", [], |row| row.get(0))
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let quota_max = tenant.quota_max_datasets;

    // Calculate usage ratio and determine status
    let (usage_ratio, status, warning) = if quota_max <= 0 {
        (0.0, "unlimited".to_string(), None)
    } else {
        let ratio = dataset_count as f64 / quota_max as f64;
        if ratio >= 1.0 {
            (
                ratio,
                "exceeded".to_string(),
                Some(format!(
                    "Dataset quota exceeded: {} of {} datasets used",
                    dataset_count, quota_max
                )),
            )
        } else if ratio >= 0.8 {
            (
                ratio,
                "warning".to_string(),
                Some(format!(
                    "Approaching dataset quota: {} of {} ({:.0}%)",
                    dataset_count,
                    quota_max,
                    ratio * 100.0
                )),
            )
        } else {
            (ratio, "ok".to_string(), None)
        }
    };

    tracing::debug!(
        tenant_id = %tenant_id,
        dataset_count,
        quota_max,
        usage_ratio,
        status = %status,
        "Returning tenant usage"
    );

    Ok(Json(MyUsageResponse {
        dataset_count,
        quota_max_datasets: quota_max,
        usage_ratio,
        status,
        warning,
    }))
}

// =============================================================================
// Dataset Handlers
// =============================================================================

/// List all datasets
async fn list_datasets(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<DatasetResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        filter_tenant = ?params.get("tenant"),
        filter_domain = ?params.get("domain"),
        "Listing datasets with filters"
    );

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let mut query = String::from(
        r#"
        SELECT id, name, path, format, delta_location, description, tenant, domain, owner,
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
            let row_count: Option<i64> = row.get(11)?;
            let size_bytes: Option<i64> = row.get(12)?;
            let partition_keys = parse_partition_keys(row.get::<_, Option<String>>(13)?);
            Ok(DatasetResponse {
                id: row.get(0)?,
                name: row.get(1)?,
                path: row.get(2)?,
                format: row.get(3)?,
                delta_location: row.get(4)?,
                description: row.get(5)?,
                tenant: row.get(6)?,
                domain: row.get(7)?,
                owner: row.get(8)?,
                created_at: row.get(9)?,
                last_updated: row.get(10)?,
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

    // Track search appearances for all returned datasets (non-blocking)
    #[cfg(feature = "usage-analytics")]
    {
        let tracker = state.usage_tracker.clone();
        let dataset_ids: Vec<i64> = datasets.iter().map(|d| d.id).collect();
        tokio::spawn(async move {
            tracker.record_search_appearances(&dataset_ids, None).await;
        });
    }

    Ok(Json(datasets))
}

/// Get a specific dataset by name with optional includes via ?include=delta,quality,lineage
async fn get_dataset(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Query(params): Query<DatasetQueryParams>,
) -> Result<Json<ExtendedDatasetResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate include parameter first
    let includes =
        IncludeOptions::parse(&params.include).map_err(|e| bad_request(e, request_id.0.clone()))?;

    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        dataset_name = %name,
        include_delta = includes.delta,
        include_quality = includes.quality,
        include_lineage = includes.lineage,
        "Getting dataset details"
    );

    // Validate dataset name
    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    // Perform all synchronous database operations in a block to properly scope borrows
    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let (dataset, fields, tags, upstream_datasets, downstream_datasets, quality_info) = {
        let conn = backend
            .get_connection()
            .await
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

        // Get dataset
        let dataset: DatasetResponse = conn
            .query_row(
                r#"
            SELECT id, name, path, format, delta_location, description, tenant, domain, owner,
                   created_at, last_updated, row_count, size_bytes, partition_keys
            FROM datasets
            WHERE name = ?1
            "#,
                [&name],
                |row| {
                    let row_count: Option<i64> = row.get(11)?;
                    let size_bytes: Option<i64> = row.get(12)?;
                    let partition_keys = parse_partition_keys(row.get::<_, Option<String>>(13)?);
                    Ok(DatasetResponse {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        path: row.get(2)?,
                        format: row.get(3)?,
                        delta_location: row.get(4)?,
                        description: row.get(5)?,
                        tenant: row.get(6)?,
                        domain: row.get(7)?,
                        owner: row.get(8)?,
                        created_at: row.get(9)?,
                        last_updated: row.get(10)?,
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
            .prepare(
                "SELECT name, data_type, nullable, description FROM fields WHERE dataset_id = ?1",
            )
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;
        let fields: Vec<FieldResponse> = stmt
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
        drop(stmt);

        // Get tags
        let mut stmt = conn
            .prepare("SELECT tag FROM tags WHERE dataset_id = ?1")
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;
        let tags: Vec<String> = stmt
            .query_map([dataset.id], |row| row.get::<_, String>(0))
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;
        drop(stmt);

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
        let upstream_datasets: Vec<String> = stmt
            .query_map([dataset.id], |row| row.get::<_, String>(0))
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;
        drop(stmt);

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
        let downstream_datasets: Vec<String> = stmt
            .query_map([dataset.id], |row| row.get::<_, String>(0))
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;
        drop(stmt);

        // Fetch quality metrics from current connection (before dropping it)
        let quality_info = if includes.quality {
            conn.query_row(
                r#"
                SELECT overall_score, completeness_score, freshness_score, file_health_score, computed_at
                FROM quality_metrics
                WHERE dataset_id = ?1
                ORDER BY computed_at DESC
                LIMIT 1
                "#,
                [dataset.id],
                |row| {
                    Ok(QualityInfo {
                        overall_score: row.get(0)?,
                        completeness_score: row.get(1)?,
                        freshness_score: row.get(2)?,
                        file_health_score: row.get(3)?,
                        last_computed: row.get(4)?,
                    })
                },
            )
            .ok()
        } else {
            None
        };

        // Return all data - conn and statements are dropped at end of block
        (
            dataset,
            fields,
            tags,
            upstream_datasets,
            downstream_datasets,
            quality_info,
        )
    };

    // Fetch delta info asynchronously if requested
    let delta_info = if includes.delta {
        match &dataset.delta_location {
            Some(loc) => match state.delta_reader.get_metadata_cached(loc).await {
                Ok(meta) => Some(DeltaInfo {
                    version: meta.version,
                    row_count: meta.row_count,
                    size_bytes: meta.size_bytes,
                    num_files: meta.num_files,
                    partition_columns: meta.partition_columns,
                    last_modified: Some(meta.last_modified.to_rfc3339()),
                }),
                Err(e) => {
                    tracing::warn!(error = %e, delta_location = %loc, "Failed to fetch delta metadata");
                    None
                }
            },
            None => {
                return Err(bad_request(
                    format!(
                        "Cannot include delta metadata for dataset '{}': delta_location is not configured",
                        name
                    ),
                    request_id.0.clone(),
                ));
            }
        }
    } else {
        None
    };

    // Build structured lineage if requested
    let lineage_info = if includes.lineage {
        Some(LineageInfo {
            upstream: upstream_datasets.clone(),
            downstream: downstream_datasets.clone(),
        })
    } else {
        None
    };

    tracing::info!(
        dataset_name = %name,
        field_count = fields.len(),
        tag_count = tags.len(),
        upstream_count = upstream_datasets.len(),
        downstream_count = downstream_datasets.len(),
        include_delta = includes.delta,
        include_quality = includes.quality,
        include_lineage = includes.lineage,
        request_id = %request_id.0,
        "Retrieved dataset details successfully"
    );

    #[cfg(feature = "metrics")]
    metrics::record_catalog_operation("get_dataset", "success");

    // Track usage (non-blocking)
    #[cfg(feature = "usage-analytics")]
    {
        let tracker = state.usage_tracker.clone();
        let dataset_id = dataset.id;
        tokio::spawn(async move {
            tracker
                .record_access(dataset_id, None, usage_analytics::AccessType::Read)
                .await;
        });
    }

    Ok(Json(ExtendedDatasetResponse {
        dataset,
        fields,
        tags,
        upstream_datasets,
        downstream_datasets,
        delta: delta_info,
        quality: quality_info,
        lineage: lineage_info,
    }))
}

/// Search datasets using FTS
async fn search_datasets(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<DatasetResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let query = params
        .get("q")
        .ok_or_else(|| bad_request("Missing 'q' parameter".to_string(), request_id.0.clone()))?;

    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, search_query = %query, "Executing full-text search");

    // Validate FTS query (operators are allowed for powerful search)
    let validated_query = validation::validate_fts_query(query)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT d.id, d.name, d.path, d.format, d.delta_location, d.description, d.tenant, d.domain, d.owner,
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
            let row_count: Option<i64> = row.get(11)?;
            let size_bytes: Option<i64> = row.get(12)?;
            let partition_keys = parse_partition_keys(row.get::<_, Option<String>>(13)?);
            Ok(DatasetResponse {
                id: row.get(0)?,
                name: row.get(1)?,
                path: row.get(2)?,
                format: row.get(3)?,
                delta_location: row.get(4)?,
                description: row.get(5)?,
                tenant: row.get(6)?,
                domain: row.get(7)?,
                owner: row.get(8)?,
                created_at: row.get(9)?,
                last_updated: row.get(10)?,
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

    // Track search appearances for all returned datasets (non-blocking)
    #[cfg(feature = "usage-analytics")]
    {
        let tracker = state.usage_tracker.clone();
        let dataset_ids: Vec<i64> = datasets.iter().map(|d| d.id).collect();
        tokio::spawn(async move {
            tracker.record_search_appearances(&dataset_ids, None).await;
        });
    }

    Ok(Json(datasets))
}

// =============================================================================
// Audit Log Endpoint (Phase 3)
// =============================================================================

/// List audit logs with optional filtering
#[cfg(feature = "audit")]
async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(params): Query<audit::AuditQueryParams>,
) -> Result<Json<audit::AuditLogResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        entity_type = ?params.entity_type,
        entity_id = ?params.entity_id,
        action = ?params.action,
        limit = ?params.limit,
        offset = ?params.offset,
        "Querying audit logs"
    );

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Run DB query in blocking task to avoid blocking async runtime
    let req_id = request_id.0.clone();
    let result = tokio::task::spawn_blocking(move || audit::query_audit_logs(&conn, &params))
        .await
        .map_err(|e| internal_error(format!("Task join error: {}", e), req_id.clone()))?
        .map_err(|e| internal_error(e.to_string(), req_id))?;

    tracing::info!(
        total = result.total,
        returned = result.entries.len(),
        "Audit logs query completed"
    );

    Ok(Json(result))
}

// =============================================================================
// Usage Analytics Handlers
// =============================================================================

/// Query parameters for popular datasets endpoint
#[cfg(feature = "usage-analytics")]
#[derive(Debug, Deserialize)]
struct PopularQueryParams {
    #[serde(default = "default_popular_limit")]
    limit: usize,
    #[serde(default = "default_period")]
    period: String,
}

#[cfg(feature = "usage-analytics")]
fn default_popular_limit() -> usize {
    10
}

#[cfg(feature = "usage-analytics")]
fn default_period() -> String {
    "7d".to_string()
}

/// Query parameters for stale datasets endpoint
#[cfg(feature = "usage-analytics")]
#[derive(Debug, Deserialize)]
struct StaleQueryParams {
    #[serde(default = "default_stale_threshold")]
    threshold_days: i64,
}

#[cfg(feature = "usage-analytics")]
fn default_stale_threshold() -> i64 {
    30
}

/// Get usage stats for a specific dataset
#[cfg(feature = "usage-analytics")]
async fn get_dataset_usage(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Query(params): Query<usage_analytics::UsageQueryParams>,
) -> Result<Json<usage_analytics::DatasetUsageResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        dataset_name = %name,
        period = %params.period,
        "Querying dataset usage"
    );

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Run DB queries in blocking task to avoid blocking async runtime
    let req_id = request_id.0.clone();
    let dataset_name_clone = name.clone();
    let period = params.period.clone();

    let result = tokio::task::spawn_blocking(move || {
        // First, look up the dataset to get its ID
        let dataset: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, name FROM datasets WHERE name = ?1",
                [&dataset_name_clone],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        match dataset {
            Some((dataset_id, dataset_name)) => {
                usage_analytics::query_dataset_usage(&conn, dataset_id, &dataset_name, &period)
                    .map_err(|e| e.to_string())
            }
            None => Err(format!("Dataset '{}' not found", dataset_name_clone)),
        }
    })
    .await
    .map_err(|e| internal_error(format!("Task join error: {}", e), req_id.clone()))?
    .map_err(|e| {
        if e.contains("not found") {
            not_found(e, req_id.clone())
        } else {
            internal_error(e, req_id.clone())
        }
    })?;

    tracing::info!(
        dataset_name = %name,
        total_reads = result.total_reads,
        "Dataset usage query completed"
    );

    Ok(Json(result))
}

/// Get most popular datasets by access count
#[cfg(feature = "usage-analytics")]
async fn get_popular_datasets(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(params): Query<PopularQueryParams>,
) -> Result<Json<usage_analytics::PopularDatasetsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        limit = params.limit,
        period = %params.period,
        "Querying popular datasets"
    );

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Run DB query in blocking task to avoid blocking async runtime
    let req_id = request_id.0.clone();
    let period = params.period.clone();
    let limit = params.limit;

    let result = tokio::task::spawn_blocking(move || {
        usage_analytics::query_popular_datasets(&conn, &period, limit)
    })
    .await
    .map_err(|e| internal_error(format!("Task join error: {}", e), req_id.clone()))?
    .map_err(|e| internal_error(e.to_string(), req_id))?;

    tracing::info!(
        count = result.datasets.len(),
        "Popular datasets query completed"
    );

    Ok(Json(result))
}

/// Get stale datasets (no recent access)
#[cfg(feature = "usage-analytics")]
async fn get_stale_datasets(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(params): Query<StaleQueryParams>,
) -> Result<Json<usage_analytics::StaleDatasetsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        threshold_days = params.threshold_days,
        "Querying stale datasets"
    );

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Run DB query in blocking task to avoid blocking async runtime
    let req_id = request_id.0.clone();
    let threshold_days = params.threshold_days;

    let result = tokio::task::spawn_blocking(move || {
        usage_analytics::query_stale_datasets(&conn, threshold_days)
    })
    .await
    .map_err(|e| internal_error(format!("Task join error: {}", e), req_id.clone()))?
    .map_err(|e| internal_error(e.to_string(), req_id))?;

    tracing::info!(
        count = result.datasets.len(),
        "Stale datasets query completed"
    );

    Ok(Json(result))
}

// =============================================================================
// Quality Framework Handlers
// =============================================================================

/// Query parameters for unhealthy datasets endpoint
#[derive(Debug, Deserialize)]
struct UnhealthyQueryParams {
    #[serde(default = "default_unhealthy_threshold")]
    threshold: f64,
}

fn default_unhealthy_threshold() -> f64 {
    0.7
}

/// Get quality scores for a specific dataset
async fn get_dataset_quality(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<quality::QualityResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset_name = %name, "Getting dataset quality");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Look up dataset
    let dataset: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, name FROM datasets WHERE name = ?1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    let (dataset_id, dataset_name) = dataset.ok_or_else(|| {
        not_found(
            format!("Dataset '{}' not found", name),
            request_id.0.clone(),
        )
    })?;

    // Get latest quality scores
    let result = quality::get_latest_quality(&conn, dataset_id, &dataset_name)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    match result {
        Some(quality) => {
            tracing::info!(
                dataset_name = %name,
                overall_score = ?quality.scores.overall_score,
                "Quality scores retrieved"
            );
            Ok(Json(quality))
        }
        None => Err(not_found(
            format!("No quality scores found for dataset '{}'", name),
            request_id.0,
        )),
    }
}

/// Trigger quality computation for a dataset
async fn compute_dataset_quality(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<quality::QualityResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::info!(tenant_id = %tenant_id, dataset_name = %name, "Computing dataset quality");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));

    // First, look up the dataset and get delta_location (sync DB operation)
    let (dataset_id, dataset_name, delta_location) = {
        let conn = backend
            .get_connection()
            .await
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

        let dataset: Option<(i64, String, Option<String>)> = conn
            .query_row(
                "SELECT id, name, delta_location FROM datasets WHERE name = ?1",
                [&name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        let (id, ds_name, loc) = dataset.ok_or_else(|| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

        let loc = loc.ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Dataset '{}' has no delta_location configured for quality computation",
                        name
                    ),
                    request_id: request_id.0.clone(),
                }),
            )
        })?;

        (id, ds_name, loc)
    };

    // Get Delta metadata (async operation)
    let delta_metadata = state
        .delta_reader
        .get_metadata_cached(&delta_location)
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Now compute and store scores (sync DB operations)
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let scores = quality::compute_scores_from_metadata(&conn, dataset_id, &delta_metadata)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Store the scores
    quality::store_quality_scores(&conn, dataset_id, &scores)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Return the response
    let response = quality::QualityResponse {
        dataset_id,
        dataset_name,
        computed_at: chrono::Utc::now().to_rfc3339(),
        scores,
    };

    tracing::info!(
        dataset_name = %name,
        overall_score = ?response.scores.overall_score,
        "Quality scores computed and stored"
    );

    Ok(Json(response))
}

/// Get datasets with quality below threshold
async fn get_unhealthy_datasets(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(params): Query<UnhealthyQueryParams>,
) -> Result<Json<quality::UnhealthyDatasetsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, threshold = params.threshold, "Querying unhealthy datasets");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let result = quality::get_unhealthy_datasets(&conn, params.threshold)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(
        count = result.datasets.len(),
        threshold = params.threshold,
        "Unhealthy datasets query completed"
    );

    Ok(Json(result))
}

// =============================================================================
// Quality Check Management Handlers (v1.7.0)
// =============================================================================

/// Response for quality check list
#[derive(Debug, Serialize)]
struct QualityChecksListResponse {
    dataset_id: i64,
    dataset_name: String,
    checks: Vec<QualityCheckResponse>,
}

/// Individual quality check response
#[derive(Debug, Serialize)]
struct QualityCheckResponse {
    id: String,
    check_type: String,
    check_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    check_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    check_config: Option<String>,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    warn_threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fail_threshold: Option<f64>,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule: Option<String>,
    on_demand: bool,
    created_at: String,
}

/// Response for quality check execution
#[derive(Debug, Serialize)]
struct ExecuteQualityChecksResponse {
    dataset_id: i64,
    dataset_name: String,
    checks_executed: usize,
    results: Vec<quality::QualityCheckExecutionResponse>,
}

/// Response for quality check results history
#[derive(Debug, Serialize)]
struct QualityResultsResponse {
    dataset_id: i64,
    dataset_name: String,
    results: Vec<QualityResultEntry>,
}

/// Individual quality result entry
#[derive(Debug, Serialize)]
struct QualityResultEntry {
    id: String,
    check_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records_checked: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records_failed: Option<i64>,
    executed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_time_ms: Option<i64>,
    execution_mode: String,
}

/// Query params for quality results
#[derive(Debug, Deserialize)]
struct QualityResultsQueryParams {
    #[serde(default = "default_results_limit")]
    limit: i64,
}

fn default_results_limit() -> i64 {
    100
}

/// List quality checks for a dataset
async fn list_quality_checks(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<QualityChecksListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset_name = %name, "Listing quality checks");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Look up dataset
    let dataset: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, name FROM datasets WHERE name = ?1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    let (dataset_id, dataset_name) = dataset.ok_or_else(|| {
        not_found(
            format!("Dataset '{}' not found", name),
            request_id.0.clone(),
        )
    })?;

    // Get quality checks
    let checks = quality::get_quality_checks(&conn, dataset_id)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let check_responses: Vec<QualityCheckResponse> = checks
        .into_iter()
        .map(|c| QualityCheckResponse {
            id: c.id,
            check_type: c.check_type.to_string(),
            check_name: c.check_name,
            check_description: c.check_description,
            check_config: c.check_config,
            severity: c.severity.to_string(),
            warn_threshold: c.warn_threshold,
            fail_threshold: c.fail_threshold,
            enabled: c.enabled,
            schedule: c.schedule,
            on_demand: c.on_demand,
            created_at: c.created_at.to_rfc3339(),
        })
        .collect();

    tracing::info!(
        dataset_name = %name,
        check_count = check_responses.len(),
        "Quality checks listed"
    );

    Ok(Json(QualityChecksListResponse {
        dataset_id,
        dataset_name,
        checks: check_responses,
    }))
}

/// Create a new quality check for a dataset
async fn create_quality_check(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Json(request): Json<quality::CreateQualityCheckRequest>,
) -> Result<(StatusCode, Json<QualityCheckResponse>), (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::info!(tenant_id = %tenant_id, dataset_name = %name, check_name = %request.check_name, "Creating quality check");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Look up dataset
    let dataset_id: i64 = conn
        .query_row("SELECT id FROM datasets WHERE name = ?1", [&name], |row| {
            row.get(0)
        })
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    // Create the quality check
    let check = quality::create_quality_check(
        &conn,
        dataset_id,
        &request,
        audit_ctx.api_key_id.as_deref(),
        Some(tenant_id),
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
                request_id: request_id.0.clone(),
            }),
        )
    })?;

    tracing::info!(
        dataset_name = %name,
        check_id = %check.id,
        check_name = %check.check_name,
        "Quality check created"
    );

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "quality_check",
            &check.id,
            serde_json::json!({
                "id": check.id,
                "dataset_name": name,
                "check_name": check.check_name,
                "check_type": check.check_type.to_string(),
                "severity": check.severity.to_string(),
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_ctx.enrich_event(event));
    }

    Ok((
        StatusCode::CREATED,
        Json(QualityCheckResponse {
            id: check.id,
            check_type: check.check_type.to_string(),
            check_name: check.check_name,
            check_description: check.check_description,
            check_config: check.check_config,
            severity: check.severity.to_string(),
            warn_threshold: check.warn_threshold,
            fail_threshold: check.fail_threshold,
            enabled: check.enabled,
            schedule: check.schedule,
            on_demand: check.on_demand,
            created_at: check.created_at.to_rfc3339(),
        }),
    ))
}

/// Path params for quality check operations
#[derive(Debug, Deserialize)]
struct QualityCheckPathParams {
    name: String,
    check_id: String,
}

/// Get a specific quality check
async fn get_quality_check(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(params): Path<QualityCheckPathParams>,
) -> Result<Json<QualityCheckResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset_name = %params.name, check_id = %params.check_id, "Getting quality check");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get the quality check
    let check = quality::get_quality_check(&conn, &params.check_id)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .ok_or_else(|| {
            not_found(
                format!("Quality check '{}' not found", params.check_id),
                request_id.0.clone(),
            )
        })?;

    Ok(Json(QualityCheckResponse {
        id: check.id,
        check_type: check.check_type.to_string(),
        check_name: check.check_name,
        check_description: check.check_description,
        check_config: check.check_config,
        severity: check.severity.to_string(),
        warn_threshold: check.warn_threshold,
        fail_threshold: check.fail_threshold,
        enabled: check.enabled,
        schedule: check.schedule,
        on_demand: check.on_demand,
        created_at: check.created_at.to_rfc3339(),
    }))
}

/// Delete a quality check
async fn delete_quality_check(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(params): Path<QualityCheckPathParams>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::info!(tenant_id = %tenant_id, dataset_name = %params.name, check_id = %params.check_id, "Deleting quality check");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let deleted = quality::delete_quality_check(&conn, &params.check_id)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if deleted {
        tracing::info!(check_id = %params.check_id, "Quality check deleted");

        // Emit audit event (non-blocking)
        #[cfg(feature = "audit")]
        {
            let event = audit::AuditEvent::delete(
                "quality_check",
                &params.check_id,
                serde_json::json!({
                    "check_id": params.check_id,
                    "dataset_name": params.name,
                }),
                &request_id.0,
            );
            state.audit_logger.log(audit_ctx.enrich_event(event));
        }

        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(not_found(
            format!("Quality check '{}' not found", params.check_id),
            request_id.0,
        ))
    }
}

/// Execute quality checks for a dataset on-demand
async fn execute_quality_checks(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<ExecuteQualityChecksResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::info!(tenant_id = %tenant_id, dataset_name = %name, "Executing quality checks on-demand");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));

    // Phase 1: Fetch all data from DB (sync)
    let (dataset_id, dataset_name, delta_location, on_demand_checks, freshness_configs) = {
        let conn = backend
            .get_connection()
            .await
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

        // Look up dataset and delta_location
        let dataset: Option<(i64, String, Option<String>)> = conn
            .query_row(
                "SELECT id, name, delta_location FROM datasets WHERE name = ?1",
                [&name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        let (dataset_id, dataset_name, delta_location) = dataset.ok_or_else(|| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

        // Get enabled quality checks that support on-demand execution
        let checks = quality::get_quality_checks(&conn, dataset_id)
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

        let on_demand_checks: Vec<_> = checks.into_iter().filter(|c| c.on_demand).collect();

        // Pre-fetch freshness configs for all checks
        let freshness_configs: HashMap<i64, (i64, i64)> = conn
            .query_row(
                "SELECT expected_interval_secs, grace_period_secs FROM freshness_config WHERE dataset_id = ?1",
                [dataset_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok()
            .map(|config| {
                let mut map = HashMap::new();
                map.insert(dataset_id, config);
                map
            })
            .unwrap_or_default();

        (
            dataset_id,
            dataset_name,
            delta_location,
            on_demand_checks,
            freshness_configs,
        )
    }; // conn dropped here

    if on_demand_checks.is_empty() {
        return Ok(Json(ExecuteQualityChecksResponse {
            dataset_id,
            dataset_name,
            checks_executed: 0,
            results: vec![],
        }));
    }

    // Phase 2: Get Delta metadata if needed (async, no DB connection)
    let delta_metadata = if let Some(ref loc) = delta_location {
        Some(
            state
                .delta_reader
                .get_metadata_cached(loc)
                .await
                .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?,
        )
    } else {
        None
    };

    // Phase 3: Execute checks and build results (no DB during check execution)
    let executor = quality::QualityCheckExecutor::new(Arc::clone(&state.delta_reader));
    let mut check_results = Vec::new();

    for check in &on_demand_checks {
        let start = std::time::Instant::now();
        let result_id = uuid::Uuid::new_v4().to_string();

        // Execute check based on type using pre-fetched data
        let (score, details, records_checked, records_failed, status) = match check.check_type {
            metafuse_catalog_core::QualityCheckType::Completeness => {
                if let Some(ref metadata) = delta_metadata {
                    let row_count = metadata.row_count;
                    let column_count = metadata.schema.fields.len() as i64;

                    if row_count == 0 || column_count == 0 {
                        (
                            1.0,
                            Some(r#"{"status":"empty_table"}"#.to_string()),
                            0,
                            0,
                            metafuse_catalog_core::QualityCheckStatus::Pass,
                        )
                    } else {
                        let total_nulls: i64 = metadata
                            .column_stats
                            .iter()
                            .filter_map(|s| s.null_count)
                            .sum();
                        let total_cells = row_count * column_count;
                        let null_ratio = total_nulls as f64 / total_cells as f64;
                        let score = (1.0 - null_ratio).clamp(0.0, 1.0);
                        let details = serde_json::json!({
                            "row_count": row_count,
                            "column_count": column_count,
                            "total_cells": total_cells,
                            "null_cells": total_nulls,
                            "null_ratio": null_ratio,
                        });
                        let status = executor.determine_status_from_score(score, check);
                        (
                            score,
                            Some(details.to_string()),
                            total_cells,
                            total_nulls,
                            status,
                        )
                    }
                } else {
                    (
                        1.0,
                        Some(r#"{"status":"no_delta_metadata"}"#.to_string()),
                        0,
                        0,
                        metafuse_catalog_core::QualityCheckStatus::Pass,
                    )
                }
            }
            metafuse_catalog_core::QualityCheckType::Freshness => {
                if let Some((expected_interval, grace_period)) = freshness_configs.get(&dataset_id)
                {
                    let last_modified = delta_metadata
                        .as_ref()
                        .map(|m| m.last_modified)
                        .unwrap_or_else(chrono::Utc::now);

                    let now = chrono::Utc::now();
                    let staleness_secs = (now - last_modified).num_seconds();
                    let threshold_secs = expected_interval + grace_period;

                    let score = if staleness_secs <= threshold_secs {
                        1.0
                    } else {
                        let extra_staleness = staleness_secs - threshold_secs;
                        let periods_overdue = extra_staleness as f64 / *expected_interval as f64;
                        (1.0 / (1.0 + periods_overdue)).clamp(0.0, 1.0)
                    };

                    let details = serde_json::json!({
                        "last_modified": last_modified.to_rfc3339(),
                        "staleness_secs": staleness_secs,
                        "expected_interval_secs": expected_interval,
                        "grace_period_secs": grace_period,
                        "threshold_secs": threshold_secs,
                    });
                    let failed = if score < 1.0 { 1 } else { 0 };
                    let status = executor.determine_status_from_score(score, check);
                    (score, Some(details.to_string()), 1, failed, status)
                } else {
                    (
                        1.0,
                        Some(r#"{"status":"no_freshness_config"}"#.to_string()),
                        0,
                        0,
                        metafuse_catalog_core::QualityCheckStatus::Skipped,
                    )
                }
            }
            _ => {
                // Uniqueness and Custom checks require external execution
                let details = serde_json::json!({
                    "status": "requires_external_execution",
                    "message": "This check type requires external data scanning",
                    "check_config": check.check_config,
                });
                (
                    1.0,
                    Some(details.to_string()),
                    0,
                    0,
                    metafuse_catalog_core::QualityCheckStatus::Skipped,
                )
            }
        };

        let execution_time_ms = start.elapsed().as_millis() as i64;

        check_results.push(metafuse_catalog_core::QualityCheckResult {
            id: result_id,
            check_id: check.id.clone(),
            dataset_id,
            status,
            score: Some(score),
            details,
            error_message: None,
            records_checked: Some(records_checked),
            records_failed: Some(records_failed),
            executed_at: chrono::Utc::now(),
            execution_time_ms: Some(execution_time_ms),
            execution_mode: metafuse_catalog_core::QualityCheckExecutionMode::OnDemand,
            delta_version: delta_metadata.as_ref().map(|m| m.version),
        });
    }

    // Phase 4: Store results (new connection)
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let mut results = Vec::new();
    for (result, check) in check_results.iter().zip(on_demand_checks.iter()) {
        quality::store_quality_check_result(&conn, result)
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

        results.push(quality::QualityCheckExecutionResponse {
            check_id: result.check_id.clone(),
            check_name: check.check_name.clone(),
            dataset_id: result.dataset_id,
            status: result.status.to_string(),
            score: result.score,
            details: result.details.clone(),
            records_checked: result.records_checked,
            records_failed: result.records_failed,
            execution_time_ms: result.execution_time_ms.unwrap_or(0),
            executed_at: result.executed_at.to_rfc3339(),
        });
    }

    tracing::info!(
        dataset_name = %name,
        checks_executed = results.len(),
        "Quality checks executed"
    );

    Ok(Json(ExecuteQualityChecksResponse {
        dataset_id,
        dataset_name,
        checks_executed: results.len(),
        results,
    }))
}

/// Get quality check results history for a dataset
async fn get_quality_results(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Query(params): Query<QualityResultsQueryParams>,
) -> Result<Json<QualityResultsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset_name = %name, limit = params.limit, "Getting quality results");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Look up dataset
    let dataset: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, name FROM datasets WHERE name = ?1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    let (dataset_id, dataset_name) = dataset.ok_or_else(|| {
        not_found(
            format!("Dataset '{}' not found", name),
            request_id.0.clone(),
        )
    })?;

    // Get quality results
    let results = quality::get_quality_check_results(&conn, dataset_id, Some(params.limit))
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let result_entries: Vec<QualityResultEntry> = results
        .into_iter()
        .map(|r| QualityResultEntry {
            id: r.id,
            check_id: r.check_id,
            status: r.status.to_string(),
            score: r.score,
            details: r.details,
            error_message: r.error_message,
            records_checked: r.records_checked,
            records_failed: r.records_failed,
            executed_at: r.executed_at.to_rfc3339(),
            execution_time_ms: r.execution_time_ms,
            execution_mode: r.execution_mode.to_string(),
        })
        .collect();

    tracing::info!(
        dataset_name = %name,
        result_count = result_entries.len(),
        "Quality results retrieved"
    );

    Ok(Json(QualityResultsResponse {
        dataset_id,
        dataset_name,
        results: result_entries,
    }))
}

// =============================================================================
// Freshness Violation Handlers (v1.7.0)
// =============================================================================

/// Query parameters for freshness violations
#[derive(Debug, Deserialize)]
struct FreshnessViolationsQuery {
    /// Limit results (default 50)
    #[serde(default = "default_violation_limit")]
    limit: i64,
    /// Include resolved violations (default false)
    #[serde(default)]
    include_resolved: bool,
}

fn default_violation_limit() -> i64 {
    50
}

/// Response for freshness violations
#[derive(Debug, Serialize)]
struct FreshnessViolationsResponse {
    dataset_id: Option<i64>,
    dataset_name: Option<String>,
    violations: Vec<FreshnessViolationEntry>,
    total_count: usize,
}

/// A single freshness violation entry
#[derive(Debug, Serialize)]
struct FreshnessViolationEntry {
    id: String,
    dataset_id: i64,
    expected_by: String,
    detected_at: String,
    resolved_at: Option<String>,
    sla: String,
    grace_period_minutes: Option<i32>,
    hours_overdue: Option<f64>,
    last_updated_at: Option<String>,
    alert_sent: bool,
    status: String,
}

impl From<metafuse_catalog_core::FreshnessViolation> for FreshnessViolationEntry {
    fn from(v: metafuse_catalog_core::FreshnessViolation) -> Self {
        let status = if v.resolved_at.is_some() {
            "resolved"
        } else {
            "open"
        };
        Self {
            id: v.id,
            dataset_id: v.dataset_id,
            expected_by: v.expected_by.to_rfc3339(),
            detected_at: v.detected_at.to_rfc3339(),
            resolved_at: v.resolved_at.map(|t| t.to_rfc3339()),
            sla: v.sla,
            grace_period_minutes: v.grace_period_minutes,
            hours_overdue: v.hours_overdue,
            last_updated_at: v.last_updated_at.map(|t| t.to_rfc3339()),
            alert_sent: v.alert_sent,
            status: status.to_string(),
        }
    }
}

/// Get freshness violations for a specific dataset
async fn get_dataset_freshness_violations(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Query(params): Query<FreshnessViolationsQuery>,
) -> Result<Json<FreshnessViolationsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        dataset_name = %name,
        limit = params.limit,
        include_resolved = params.include_resolved,
        "Getting dataset freshness violations"
    );

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Look up dataset
    let dataset: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, name FROM datasets WHERE name = ?1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    let (dataset_id, dataset_name) = dataset.ok_or_else(|| {
        not_found(
            format!("Dataset '{}' not found", name),
            request_id.0.clone(),
        )
    })?;

    // Get violations based on params
    let violations = if params.include_resolved {
        quality::get_dataset_violations(&conn, dataset_id, params.limit)
    } else {
        quality::get_open_violations(&conn, Some(dataset_id))
    }
    .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let total_count = violations.len();
    let entries: Vec<FreshnessViolationEntry> = violations.into_iter().map(Into::into).collect();

    tracing::info!(
        dataset_name = %name,
        violation_count = total_count,
        "Freshness violations retrieved"
    );

    Ok(Json(FreshnessViolationsResponse {
        dataset_id: Some(dataset_id),
        dataset_name: Some(dataset_name),
        violations: entries,
        total_count,
    }))
}

/// Query parameters for all violations endpoint
#[derive(Debug, Deserialize)]
struct AllViolationsQuery {
    /// Limit results (default 50, max 200)
    #[serde(default = "default_violation_limit")]
    limit: i64,
    /// Offset for pagination
    #[serde(default)]
    offset: i64,
}

/// Get all open freshness violations across all datasets
async fn get_all_freshness_violations(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(params): Query<AllViolationsQuery>,
) -> Result<Json<FreshnessViolationsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    // Cap limit at 200 to prevent unbounded responses
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    tracing::debug!(
        tenant_id = %tenant_id,
        limit,
        offset,
        "Getting all open freshness violations"
    );

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get all open violations with pagination
    let violations = quality::get_open_violations_paginated(&conn, limit, offset)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let total_count = violations.len();
    let entries: Vec<FreshnessViolationEntry> = violations.into_iter().map(Into::into).collect();

    tracing::info!(
        violation_count = total_count,
        "All open freshness violations retrieved"
    );

    Ok(Json(FreshnessViolationsResponse {
        dataset_id: None,
        dataset_name: None,
        violations: entries,
        total_count,
    }))
}

// =============================================================================
// Classification Handlers
// =============================================================================

/// Get classifications for a dataset's columns
#[cfg(feature = "classification")]
async fn get_dataset_classifications(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<classification::DatasetClassificationsResponse>, (StatusCode, Json<ErrorResponse>)>
{
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset_name = %name, "Getting dataset classifications");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Run DB queries in blocking task to avoid blocking async runtime
    let req_id = request_id.0.clone();
    let dataset_name_clone = name.clone();

    let response = tokio::task::spawn_blocking(move || {
        // Look up dataset
        let dataset: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, name FROM datasets WHERE name = ?1",
                [&dataset_name_clone],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        let (dataset_id, dataset_name) = match dataset {
            Some(d) => d,
            None => return Err(format!("Dataset '{}' not found", dataset_name_clone)),
        };

        let classifications = classification::get_dataset_classifications(&conn, dataset_id)
            .map_err(|e| e.to_string())?;

        let pii_count = classifications
            .iter()
            .filter(|c| c.classification == classification::Classification::Pii)
            .count();
        let unclassified_count = classifications
            .iter()
            .filter(|c| c.classification == classification::Classification::Unknown)
            .count();

        Ok(classification::DatasetClassificationsResponse {
            dataset_id,
            dataset_name,
            classifications,
            pii_count,
            unclassified_count,
        })
    })
    .await
    .map_err(|e| internal_error(format!("Task join error: {}", e), req_id.clone()))?
    .map_err(|e: String| {
        if e.contains("not found") {
            not_found(e, req_id.clone())
        } else {
            internal_error(e, req_id.clone())
        }
    })?;

    tracing::info!(
        dataset_name = %name,
        pii_count = response.pii_count,
        "Dataset classifications retrieved"
    );

    Ok(Json(response))
}

/// Scan a dataset for classifications
#[cfg(feature = "classification")]
async fn scan_dataset_classifications(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<classification::DatasetClassificationsResponse>, (StatusCode, Json<ErrorResponse>)>
{
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::info!(tenant_id = %tenant_id, dataset_name = %name, "Scanning dataset for classifications");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Run heavy classification work in blocking task
    let req_id = request_id.0.clone();
    let dataset_name_clone = name.clone();

    let (response, fields_scanned) = tokio::task::spawn_blocking(move || {
        // Look up dataset
        let dataset: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, name FROM datasets WHERE name = ?1",
                [&dataset_name_clone],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        let (dataset_id, dataset_name) = match dataset {
            Some(d) => d,
            None => return Err(format!("Dataset '{}' not found", dataset_name_clone)),
        };

        // Load classification engine
        let engine =
            classification::ClassificationEngine::load_from_db(&conn).map_err(|e| e.to_string())?;

        // Get fields for this dataset
        let mut stmt = conn
            .prepare("SELECT id, name, data_type FROM fields WHERE dataset_id = ?1")
            .map_err(|e| e.to_string())?;

        let fields: Vec<(i64, String, String)> = stmt
            .query_map([dataset_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;

        let fields_count = fields.len();

        // Scan and store classifications
        let mut pii_count = 0;
        let mut unclassified_count = 0;

        for (field_id, field_name, data_type) in &fields {
            let result = engine.classify_column(field_name, data_type);

            if result.classification == classification::Classification::Pii {
                pii_count += 1;
            } else if result.classification == classification::Classification::Unknown {
                unclassified_count += 1;
            }

            classification::store_classification(&conn, *field_id, &result)
                .map_err(|e| e.to_string())?;
        }

        // Get updated classifications
        let classifications = classification::get_dataset_classifications(&conn, dataset_id)
            .map_err(|e| e.to_string())?;

        let response = classification::DatasetClassificationsResponse {
            dataset_id,
            dataset_name,
            classifications,
            pii_count,
            unclassified_count,
        };

        Ok((response, fields_count))
    })
    .await
    .map_err(|e| internal_error(format!("Task join error: {}", e), req_id.clone()))?
    .map_err(|e: String| {
        if e.contains("not found") {
            not_found(e, req_id.clone())
        } else {
            internal_error(e, req_id.clone())
        }
    })?;

    tracing::info!(
        dataset_name = %name,
        pii_count = response.pii_count,
        fields_scanned,
        "Dataset classification scan completed"
    );

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "classification_scan",
            &name,
            serde_json::json!({
                "dataset_name": name,
                "dataset_id": response.dataset_id,
                "pii_count": response.pii_count,
                "fields_scanned": fields_scanned,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_ctx.enrich_event(event));
    }

    Ok(Json(response))
}

/// Get all PII columns across all datasets
#[cfg(feature = "classification")]
async fn get_all_pii_columns(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
) -> Result<Json<classification::PiiColumnsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, "Getting all PII columns");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Run DB query in blocking task
    let req_id = request_id.0.clone();
    let response = tokio::task::spawn_blocking(move || {
        let columns = classification::get_pii_columns(&conn)?;
        let verified_count = columns.iter().filter(|c| c.verified).count();

        Ok::<_, rusqlite::Error>(classification::PiiColumnsResponse {
            total_pii_columns: columns.len(),
            verified_count,
            columns,
        })
    })
    .await
    .map_err(|e| internal_error(format!("Task join error: {}", e), req_id.clone()))?
    .map_err(|e| internal_error(e.to_string(), req_id))?;

    tracing::info!(
        total_pii = response.total_pii_columns,
        verified = response.verified_count,
        "PII columns query completed"
    );

    Ok(Json(response))
}

/// Set a manual classification for a field
#[cfg(feature = "classification")]
async fn set_field_classification(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(field_id): Path<i64>,
    Json(req): Json<classification::SetClassificationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::info!(tenant_id = %tenant_id, field_id, classification = %req.classification, "Setting manual classification");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Run DB operations in blocking task
    let req_id = request_id.0.clone();
    let classification_str = req.classification.clone();
    let category = req.category.clone();

    tokio::task::spawn_blocking(move || {
        // Verify field exists
        let exists: bool = conn
            .query_row("SELECT 1 FROM fields WHERE id = ?1", [field_id], |_| {
                Ok(true)
            })
            .unwrap_or(false);

        if !exists {
            return Err(format!("Field {} not found", field_id));
        }

        let classification_type = classification::Classification::parse(&classification_str);

        // For now, use a placeholder user - in production this would come from auth
        classification::set_manual_classification(
            &conn,
            field_id,
            classification_type,
            category.as_deref(),
            "api_user",
        )
        .map_err(|e| e.to_string())?;

        Ok(())
    })
    .await
    .map_err(|e| internal_error(format!("Task join error: {}", e), req_id.clone()))?
    .map_err(|e: String| {
        if e.contains("not found") {
            not_found(e, req_id.clone())
        } else {
            internal_error(e, req_id.clone())
        }
    })?;

    tracing::info!(field_id, "Manual classification set");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "field_classification",
            field_id.to_string(),
            serde_json::json!({}), // old values not tracked for simplicity
            serde_json::json!({
                "field_id": field_id,
                "classification": req.classification,
                "category": req.category,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_ctx.enrich_event(event));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "field_id": field_id,
        "classification": req.classification
    })))
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

/// Helper function to create quota exceeded error response (HTTP 403)
#[cfg(feature = "quota-enforcement")]
fn quota_exceeded(message: String, request_id: String) -> (StatusCode, Json<ErrorResponse>) {
    tracing::warn!(message = %message, "Quota exceeded");
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: message,
            request_id,
        }),
    )
}

/// Result of quota check including soft limit warning state
#[cfg(feature = "quota-enforcement")]
struct QuotaCheckResult {
    /// Whether a soft limit warning should be returned
    warning: Option<String>,
}

/// Check dataset quota for a tenant.
///
/// Returns Ok(QuotaCheckResult) if the tenant is within their quota (or in dry-run mode).
/// Returns Err with 403 if quota is exceeded and enforcement is enabled.
///
/// # Dry-run mode
///
/// When METAFUSE_QUOTA_DRY_RUN=true (default), quota violations are logged but not enforced.
/// This allows safe production rollout with metering before enforcement.
#[cfg(feature = "quota-enforcement")]
fn check_dataset_quota(
    conn: &rusqlite::Connection,
    tenant: &control_plane::Tenant,
    request_id: &str,
) -> Result<QuotaCheckResult, (StatusCode, Json<ErrorResponse>)> {
    let quota_max = tenant.quota_max_datasets;
    let tenant_id = &tenant.tenant_id;

    // Defensive check: treat 0 or negative as unlimited
    // Note: The database has a CHECK constraint (quota_max_datasets > 0) that prevents
    // storing invalid values. This check is defensive programming for edge cases like
    // manual database modifications or future schema changes.
    if quota_max <= 0 {
        #[cfg(feature = "metrics")]
        metrics::record_quota_check_ok(tenant_id, "datasets");
        return Ok(QuotaCheckResult { warning: None });
    }

    // Count current datasets
    let current_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM datasets", [], |row| row.get(0))
        .map_err(|e| internal_error(e.to_string(), request_id.to_string()))?;

    let dry_run = std::env::var("METAFUSE_QUOTA_DRY_RUN")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true); // Default to dry-run mode for safe rollout

    // Calculate usage ratio for metrics and soft limit warning
    let usage_ratio = current_count as f64 / quota_max as f64;
    let usage_percent = usage_ratio * 100.0;
    let soft_limit_threshold = 80.0;

    // Update quota usage ratio metric
    #[cfg(feature = "metrics")]
    metrics::update_quota_usage_ratio(tenant_id, "datasets", usage_ratio);

    // Check if at hard limit
    if current_count >= quota_max {
        let msg = format!(
            "Dataset quota exceeded: {} of {} datasets used",
            current_count, quota_max
        );

        #[cfg(feature = "metrics")]
        metrics::record_quota_exceeded(tenant_id, "datasets");

        if dry_run {
            tracing::warn!(
                tenant_id = %tenant_id,
                current = current_count,
                quota = quota_max,
                "Quota exceeded (dry-run mode - not enforced)"
            );

            #[cfg(feature = "metrics")]
            metrics::record_quota_dry_run_allowed(tenant_id, "datasets");

            // In dry-run mode, return warning but allow operation
            return Ok(QuotaCheckResult {
                warning: Some(format!("Quota exceeded (dry-run): {}", msg)),
            });
        }

        #[cfg(feature = "metrics")]
        metrics::record_quota_blocked(tenant_id, "datasets");

        return Err(quota_exceeded(msg, request_id.to_string()));
    }

    // Soft limit warning at 80%
    let warning = if usage_percent >= soft_limit_threshold {
        #[cfg(feature = "metrics")]
        metrics::record_quota_warning(tenant_id, "datasets");

        Some(format!(
            "Approaching dataset quota: {} of {} ({:.0}%)",
            current_count, quota_max, usage_percent
        ))
    } else {
        #[cfg(feature = "metrics")]
        metrics::record_quota_check_ok(tenant_id, "datasets");

        None
    };

    Ok(QuotaCheckResult { warning })
}

fn parse_partition_keys(raw: Option<String>) -> Vec<String> {
    raw.and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default()
}

// =============================================================================
// Dataset Write Handlers
// =============================================================================

/// Create a new dataset
async fn create_dataset(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Json(req): Json<CreateDatasetRequest>,
) -> Result<(StatusCode, Json<DatasetResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, name = %req.name, "Creating dataset");

    // Validate inputs
    validation::validate_dataset_name(&req.name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Check dataset quota before creation
    #[cfg(feature = "quota-enforcement")]
    let _quota_warning = {
        // Get tenant from control plane to check quota
        if let Some(control_plane) = state.multi_tenant.control_plane() {
            if let Ok(Some(tenant)) = control_plane.get_tenant(tenant_id).await {
                let result = check_dataset_quota(&conn, &tenant, &request_id.0)?;
                if let Some(ref warning) = result.warning {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        warning = %warning,
                        "Quota warning for dataset creation"
                    );
                }
                result.warning
            } else {
                tracing::debug!(tenant_id = %tenant_id, "Tenant not found in control plane, skipping quota check");
                None
            }
        } else {
            tracing::debug!("Control plane not configured, skipping quota check");
            None
        }
    };

    // Check if dataset already exists
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM datasets WHERE name = ?1",
            [&req.name],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if exists {
        return Err(bad_request(
            format!("Dataset '{}' already exists", req.name),
            request_id.0.clone(),
        ));
    }

    // Use transaction for multi-step write
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Insert dataset
    tx.execute(
        r#"
        INSERT INTO datasets (name, path, format, delta_location, description, tenant, domain, owner, created_at, last_updated)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'), datetime('now'))
        "#,
        rusqlite::params![
            req.name,
            req.path,
            req.format,
            req.delta_location,
            req.description,
            req.tenant,
            req.domain,
            req.owner,
        ],
    )
    .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let dataset_id = tx.last_insert_rowid();

    // Insert tags if provided
    if let Some(tags) = &req.tags {
        for tag in tags {
            tx.execute(
                "INSERT INTO tags (dataset_id, tag) VALUES (?1, ?2)",
                rusqlite::params![dataset_id, tag],
            )
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;
        }
    }

    // Insert lineage if provided
    if let Some(upstream) = &req.upstream_datasets {
        for upstream_name in upstream {
            let upstream_id: Result<i64, _> = tx.query_row(
                "SELECT id FROM datasets WHERE name = ?1",
                [upstream_name],
                |row| row.get(0),
            );
            if let Ok(uid) = upstream_id {
                tx.execute(
                    "INSERT OR IGNORE INTO lineage (upstream_dataset_id, downstream_dataset_id, created_at) VALUES (?1, ?2, datetime('now'))",
                    rusqlite::params![uid, dataset_id],
                )
                .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;
            }
        }
    }

    // Fetch the created dataset (still within transaction)
    let dataset: DatasetResponse = tx
        .query_row(
            r#"
            SELECT id, name, path, format, delta_location, description, tenant, domain, owner,
                   created_at, last_updated, row_count, size_bytes, partition_keys
            FROM datasets WHERE id = ?1
            "#,
            [dataset_id],
            |row| {
                let row_count: Option<i64> = row.get(11)?;
                let size_bytes: Option<i64> = row.get(12)?;
                let partition_keys = parse_partition_keys(row.get::<_, Option<String>>(13)?);
                Ok(DatasetResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    path: row.get(2)?,
                    format: row.get(3)?,
                    delta_location: row.get(4)?,
                    description: row.get(5)?,
                    tenant: row.get(6)?,
                    domain: row.get(7)?,
                    owner: row.get(8)?,
                    created_at: row.get(9)?,
                    last_updated: row.get(10)?,
                    operational: OperationalMetaResponse {
                        row_count,
                        size_bytes,
                        partition_keys,
                    },
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Commit transaction
    tx.commit()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(name = %req.name, id = dataset_id, "Dataset created successfully");

    #[cfg(feature = "metrics")]
    metrics::record_catalog_operation("create_dataset", "success");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "dataset",
            &dataset.name,
            serde_json::json!({
                "id": dataset.id,
                "name": dataset.name,
                "path": dataset.path,
                "format": dataset.format,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    // Auto-classification trigger (opt-in via METAFUSE_CLASSIFICATION_AUTO_SCAN)
    #[cfg(feature = "classification")]
    {
        let auto_scan_enabled = std::env::var("METAFUSE_CLASSIFICATION_AUTO_SCAN")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        if auto_scan_enabled {
            let dataset_id = dataset.id;
            let dataset_name = dataset.name.clone();
            let backend = state.backend.clone();

            tokio::spawn(async move {
                if let Err(e) = auto_classify_dataset(&backend, dataset_id).await {
                    tracing::warn!(
                        dataset_id,
                        dataset_name = %dataset_name,
                        error = %e,
                        "Auto-classification failed"
                    );
                }
            });
        }
    }

    Ok((StatusCode::CREATED, Json(dataset)))
}

/// Auto-classify a dataset's fields (background task)
#[cfg(feature = "classification")]
async fn auto_classify_dataset(
    backend: &Arc<DynCatalogBackend>,
    dataset_id: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::classification::{Classification, ClassificationEngine};

    let conn = backend.get_connection().await?;

    // Load classification engine with rules
    let engine = ClassificationEngine::load_from_db(&conn)?;

    // Get fields for this dataset
    let mut stmt = conn.prepare(
        r#"
        SELECT id, name, data_type
        FROM fields
        WHERE dataset_id = ?1
        "#,
    )?;

    let fields: Vec<(i64, String, String)> = stmt
        .query_map([dataset_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

    if fields.is_empty() {
        tracing::debug!(dataset_id, "No fields to classify");
        return Ok(());
    }

    let mut classified_count = 0;
    let mut pii_count = 0;

    for (field_id, field_name, data_type) in fields {
        let classification = engine.classify_column(&field_name, &data_type);

        // Store classification
        classification::store_classification(&conn, field_id, &classification)?;

        classified_count += 1;
        if classification.classification != Classification::Unknown
            && classification.classification != Classification::Public
        {
            pii_count += 1;
        }
    }

    tracing::info!(
        dataset_id,
        classified_count,
        pii_count,
        "Auto-classification completed"
    );

    Ok(())
}

/// Update an existing dataset
async fn update_dataset(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(name): Path<String>,
    Json(req): Json<UpdateDatasetRequest>,
) -> Result<Json<DatasetResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, name = %name, "Updating dataset");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get the dataset ID first
    let dataset_id: i64 = conn
        .query_row("SELECT id FROM datasets WHERE name = ?1", [&name], |row| {
            row.get(0)
        })
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    // Build dynamic update query and execute in a block to drop non-Send types before await
    let delta_location_to_invalidate: Option<String> = {
        let mut updates = vec!["last_updated = datetime('now')".to_string()];
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        if let Some(path) = &req.path {
            updates.push(format!("path = ?{}", params.len() + 1));
            params.push(Box::new(path.clone()));
        }
        if let Some(format) = &req.format {
            updates.push(format!("format = ?{}", params.len() + 1));
            params.push(Box::new(format.clone()));
        }
        if let Some(delta_location) = &req.delta_location {
            updates.push(format!("delta_location = ?{}", params.len() + 1));
            params.push(Box::new(delta_location.clone()));
        }
        if let Some(description) = &req.description {
            updates.push(format!("description = ?{}", params.len() + 1));
            params.push(Box::new(description.clone()));
        }
        if let Some(tenant) = &req.tenant {
            updates.push(format!("tenant = ?{}", params.len() + 1));
            params.push(Box::new(tenant.clone()));
        }
        if let Some(domain) = &req.domain {
            updates.push(format!("domain = ?{}", params.len() + 1));
            params.push(Box::new(domain.clone()));
        }
        if let Some(owner) = &req.owner {
            updates.push(format!("owner = ?{}", params.len() + 1));
            params.push(Box::new(owner.clone()));
        }

        let sql = format!(
            "UPDATE datasets SET {} WHERE id = ?{}",
            updates.join(", "),
            params.len() + 1
        );
        params.push(Box::new(dataset_id));

        let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        conn.execute(&sql, params_refs.as_slice())
            .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

        // Capture delta_location for cache invalidation if it was updated
        if req.delta_location.is_some() {
            conn.query_row::<String, _, _>(
                "SELECT delta_location FROM datasets WHERE id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .ok()
        } else {
            None
        }
    };

    // Now that non-Send types are dropped, we can await
    if let Some(loc) = delta_location_to_invalidate {
        state.delta_reader.invalidate_cache(&loc).await;
    }

    // Fetch updated dataset
    let dataset: DatasetResponse = conn
        .query_row(
            r#"
            SELECT id, name, path, format, delta_location, description, tenant, domain, owner,
                   created_at, last_updated, row_count, size_bytes, partition_keys
            FROM datasets WHERE id = ?1
            "#,
            [dataset_id],
            |row| {
                let row_count: Option<i64> = row.get(11)?;
                let size_bytes: Option<i64> = row.get(12)?;
                let partition_keys = parse_partition_keys(row.get::<_, Option<String>>(13)?);
                Ok(DatasetResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    path: row.get(2)?,
                    format: row.get(3)?,
                    delta_location: row.get(4)?,
                    description: row.get(5)?,
                    tenant: row.get(6)?,
                    domain: row.get(7)?,
                    owner: row.get(8)?,
                    created_at: row.get(9)?,
                    last_updated: row.get(10)?,
                    operational: OperationalMetaResponse {
                        row_count,
                        size_bytes,
                        partition_keys,
                    },
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Resolve any open freshness violations for this dataset (data was updated)
    match quality::resolve_freshness_violations(&conn, dataset_id, chrono::Utc::now()) {
        Ok(resolved) if resolved > 0 => {
            tracing::info!(
                dataset_id,
                resolved_count = resolved,
                "Auto-resolved freshness violations on dataset update"
            );
        }
        Err(e) => {
            tracing::warn!(
                dataset_id,
                error = %e,
                "Failed to resolve freshness violations on dataset update"
            );
        }
        _ => {}
    }

    // Evaluate data contracts on update (v0.9.0)
    //
    // FAIL-OPEN BEHAVIOR: Contract evaluation requires delta_location to be set.
    // For non-Delta datasets (CSV, Parquet, etc.), we skip contract evaluation
    // entirely rather than blocking the update. This ensures backwards compatibility
    // and allows gradual contract adoption. Operators can enforce Delta-only ingestion
    // at the organizational level if strict contract enforcement is required.
    #[cfg(feature = "contracts")]
    {
        let has_delta: bool = dataset.delta_location.is_some();

        if has_delta {
            let ctx = contracts::DatasetContext {
                id: dataset_id,
                name: dataset.name.clone(),
                tenant_id: Some(tenant_id.to_string()),
            };

            let evaluator = contracts::ContractEvaluator::new(&conn);
            match evaluator.evaluate_for_dataset(&ctx) {
                Ok(results) => {
                    for result in results {
                        if !result.passed {
                            tracing::warn!(
                                dataset_name = %dataset.name,
                                contract_name = %result.contract_name,
                                violations = ?result.violations,
                                "Contract violation detected"
                            );

                            // Get the contract to determine enforcement action
                            if let Ok(Some(contract)) =
                                contracts::get_contract(&conn, &result.contract_name)
                            {
                                let action =
                                    evaluator.determine_enforcement(&contract, &result.violations);

                                match action {
                                    contracts::EnforcementAction::Block(violations) => {
                                        // Return error to block the update
                                        return Err(bad_request(
                                            format!(
                                                "Contract '{}' violated: {}",
                                                contract.name,
                                                violations.join("; ")
                                            ),
                                            request_id.0.clone(),
                                        ));
                                    }
                                    contracts::EnforcementAction::Alert(violations) => {
                                        // Send alert asynchronously
                                        #[cfg(feature = "alerting")]
                                        {
                                            let payload =
                                                alerting::AlertPayload::contract_violation(
                                                    &dataset.name,
                                                    dataset_id,
                                                    &contract.name,
                                                    &violations,
                                                );

                                            // Send to contract's alert channels
                                            for channel in &contract.alert_channels {
                                                let client = alerting::WebhookClient::new_default();
                                                let url = channel.clone();
                                                let payload_clone = payload.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) =
                                                        client.send(&url, &payload_clone).await
                                                    {
                                                        tracing::warn!(
                                                            error = %e,
                                                            url = %url,
                                                            "Failed to send contract violation alert"
                                                        );
                                                    }
                                                });
                                            }
                                        }
                                    }
                                    contracts::EnforcementAction::Warn(violations) => {
                                        tracing::warn!(
                                            dataset_name = %dataset.name,
                                            contract_name = %contract.name,
                                            violations = ?violations,
                                            "Contract violation (warn mode)"
                                        );
                                    }
                                    contracts::EnforcementAction::Allow => {}
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    // Fail open - log error but don't block the update
                    tracing::warn!(
                        dataset_id,
                        error = %e,
                        "Failed to evaluate contracts, failing open"
                    );
                }
            }
        } else {
            tracing::debug!(
                dataset_id,
                "Skipping contract evaluation - no delta_location"
            );
        }
    }

    tracing::info!(name = %name, "Dataset updated successfully");

    #[cfg(feature = "metrics")]
    metrics::record_catalog_operation("update_dataset", "success");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "dataset",
            &name,
            serde_json::json!({}), // old values not tracked for simplicity
            serde_json::json!({
                "id": dataset.id,
                "name": dataset.name,
                "path": dataset.path,
                "format": dataset.format,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(Json(dataset))
}

/// Delete a dataset
async fn delete_dataset(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check delete permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_delete_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, name = %name, "Deleting dataset");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get delta_location before deleting to invalidate cache
    if let Ok(loc) = conn.query_row::<String, _, _>(
        "SELECT delta_location FROM datasets WHERE name = ?1",
        [&name],
        |row| row.get(0),
    ) {
        state.delta_reader.invalidate_cache(&loc).await;
    }

    let rows = conn
        .execute("DELETE FROM datasets WHERE name = ?1", [&name])
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if rows == 0 {
        return Err(not_found(
            format!("Dataset '{}' not found", name),
            request_id.0.clone(),
        ));
    }

    tracing::info!(name = %name, "Dataset deleted successfully");

    #[cfg(feature = "metrics")]
    metrics::record_catalog_operation("delete_dataset", "success");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::delete(
            "dataset",
            &name,
            serde_json::json!({ "name": name }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Add tags to a dataset
async fn add_tags(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(name): Path<String>,
    Json(req): Json<AddTagsRequest>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, name = %name, tags = ?req.tags, "Adding tags to dataset");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let dataset_id: i64 = conn
        .query_row("SELECT id FROM datasets WHERE name = ?1", [&name], |row| {
            row.get(0)
        })
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    for tag in &req.tags {
        conn.execute(
            "INSERT OR IGNORE INTO tags (dataset_id, tag) VALUES (?1, ?2)",
            rusqlite::params![dataset_id, tag],
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;
    }

    // Get all tags for the dataset
    let mut stmt = conn
        .prepare("SELECT tag FROM tags WHERE dataset_id = ?1")
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let tags = stmt
        .query_map([dataset_id], |row| row.get::<_, String>(0))
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(name = %name, added = req.tags.len(), "Tags added successfully");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "dataset_tags",
            &name,
            serde_json::json!({}),
            serde_json::json!({
                "action": "add",
                "tags": req.tags,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(Json(tags))
}

/// Remove tags from a dataset
async fn remove_tags(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(name): Path<String>,
    Json(req): Json<RemoveTagsRequest>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, name = %name, tags = ?req.tags, "Removing tags from dataset");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let dataset_id: i64 = conn
        .query_row("SELECT id FROM datasets WHERE name = ?1", [&name], |row| {
            row.get(0)
        })
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    for tag in &req.tags {
        conn.execute(
            "DELETE FROM tags WHERE dataset_id = ?1 AND tag = ?2",
            rusqlite::params![dataset_id, tag],
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;
    }

    // Get remaining tags
    let mut stmt = conn
        .prepare("SELECT tag FROM tags WHERE dataset_id = ?1")
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let tags = stmt
        .query_map([dataset_id], |row| row.get::<_, String>(0))
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(name = %name, removed = req.tags.len(), "Tags removed successfully");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "dataset_tags",
            &name,
            serde_json::json!({
                "action": "remove",
                "tags": req.tags,
            }),
            serde_json::json!({}),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(Json(tags))
}

// =============================================================================
// Owner Handlers
// =============================================================================

/// Create a new owner
async fn create_owner(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Json(req): Json<CreateOwnerRequest>,
) -> Result<(StatusCode, Json<OwnerResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, owner_id = %req.owner_id, "Creating owner");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let owner_type = req.owner_type.as_deref().unwrap_or("user");
    let contact_info_json = req.contact_info.as_ref().map(|v| v.to_string());

    conn.execute(
        r#"
        INSERT INTO owners (owner_id, name, owner_type, email, slack_channel, contact_info, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'), datetime('now'))
        "#,
        rusqlite::params![
            req.owner_id,
            req.name,
            owner_type,
            req.email,
            req.slack_channel,
            contact_info_json,
        ],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint failed") {
            bad_request(
                format!("Owner '{}' already exists", req.owner_id),
                request_id.0.clone(),
            )
        } else {
            internal_error(e.to_string(), request_id.0.clone())
        }
    })?;

    let id = conn.last_insert_rowid();

    let owner = OwnerResponse {
        id,
        owner_id: req.owner_id,
        name: req.name,
        owner_type: owner_type.to_string(),
        email: req.email,
        slack_channel: req.slack_channel,
        contact_info: req.contact_info,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    tracing::info!(owner_id = %owner.owner_id, "Owner created successfully");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "owner",
            &owner.owner_id,
            serde_json::json!({
                "id": owner.id,
                "owner_id": owner.owner_id,
                "name": owner.name,
                "owner_type": owner.owner_type,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok((StatusCode::CREATED, Json(owner)))
}

/// List all owners
async fn list_owners(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<Vec<OwnerResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        limit = pagination.limit(),
        offset = pagination.offset(),
        "Listing owners"
    );

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, owner_id, name, owner_type, email, slack_channel, contact_info, created_at, updated_at
            FROM owners ORDER BY name LIMIT ?1 OFFSET ?2
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let owners = stmt
        .query_map(
            rusqlite::params![pagination.limit() as i64, pagination.offset() as i64],
            |row| {
                let contact_info: Option<String> = row.get(6)?;
                Ok(OwnerResponse {
                    id: row.get(0)?,
                    owner_id: row.get(1)?,
                    name: row.get(2)?,
                    owner_type: row.get(3)?,
                    email: row.get(4)?,
                    slack_channel: row.get(5)?,
                    contact_info: contact_info.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(count = owners.len(), "Listed owners successfully");

    Ok(Json(owners))
}

/// Get an owner by ID
async fn get_owner(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(id): Path<String>,
) -> Result<Json<OwnerResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, owner_id = %id, "Getting owner");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let owner = conn
        .query_row(
            r#"
            SELECT id, owner_id, name, owner_type, email, slack_channel, contact_info, created_at, updated_at
            FROM owners WHERE owner_id = ?1
            "#,
            [&id],
            |row| {
                let contact_info: Option<String> = row.get(6)?;
                Ok(OwnerResponse {
                    id: row.get(0)?,
                    owner_id: row.get(1)?,
                    name: row.get(2)?,
                    owner_type: row.get(3)?,
                    email: row.get(4)?,
                    slack_channel: row.get(5)?,
                    contact_info: contact_info.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .map_err(|_| not_found(format!("Owner '{}' not found", id), request_id.0.clone()))?;

    Ok(Json(owner))
}

/// Update an owner
async fn update_owner(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateOwnerRequest>,
) -> Result<Json<OwnerResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, owner_id = %id, "Updating owner");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Build dynamic update query
    let mut updates = vec!["updated_at = datetime('now')".to_string()];
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

    if let Some(name) = &req.name {
        updates.push(format!("name = ?{}", params.len() + 1));
        params.push(Box::new(name.clone()));
    }
    if let Some(owner_type) = &req.owner_type {
        updates.push(format!("owner_type = ?{}", params.len() + 1));
        params.push(Box::new(owner_type.clone()));
    }
    if let Some(email) = &req.email {
        updates.push(format!("email = ?{}", params.len() + 1));
        params.push(Box::new(email.clone()));
    }
    if let Some(slack_channel) = &req.slack_channel {
        updates.push(format!("slack_channel = ?{}", params.len() + 1));
        params.push(Box::new(slack_channel.clone()));
    }
    if let Some(contact_info) = &req.contact_info {
        updates.push(format!("contact_info = ?{}", params.len() + 1));
        params.push(Box::new(contact_info.to_string()));
    }

    let sql = format!(
        "UPDATE owners SET {} WHERE owner_id = ?{}",
        updates.join(", "),
        params.len() + 1
    );
    params.push(Box::new(id.clone()));

    let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let rows = conn
        .execute(&sql, params_refs.as_slice())
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if rows == 0 {
        return Err(not_found(
            format!("Owner '{}' not found", id),
            request_id.0.clone(),
        ));
    }

    // Fetch updated owner
    let owner = conn
        .query_row(
            r#"
            SELECT id, owner_id, name, owner_type, email, slack_channel, contact_info, created_at, updated_at
            FROM owners WHERE owner_id = ?1
            "#,
            [&id],
            |row| {
                let contact_info: Option<String> = row.get(6)?;
                Ok(OwnerResponse {
                    id: row.get(0)?,
                    owner_id: row.get(1)?,
                    name: row.get(2)?,
                    owner_type: row.get(3)?,
                    email: row.get(4)?,
                    slack_channel: row.get(5)?,
                    contact_info: contact_info.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(owner_id = %id, "Owner updated successfully");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "owner",
            &id,
            serde_json::json!({}), // old values not tracked for simplicity
            serde_json::json!({
                "id": owner.id,
                "owner_id": owner.owner_id,
                "name": owner.name,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(Json(owner))
}

/// Delete an owner
async fn delete_owner(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check delete permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_delete_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, owner_id = %id, "Deleting owner");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let rows = conn
        .execute("DELETE FROM owners WHERE owner_id = ?1", [&id])
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if rows == 0 {
        return Err(not_found(
            format!("Owner '{}' not found", id),
            request_id.0.clone(),
        ));
    }

    tracing::info!(owner_id = %id, "Owner deleted successfully");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::delete(
            "owner",
            &id,
            serde_json::json!({ "owner_id": id }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Domain Handlers
// =============================================================================

/// List all domains
async fn list_domains(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<DomainResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, "Listing domains");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    let mut stmt = conn
        .prepare(
            r#"
            SELECT d.id, d.name, d.display_name, d.description, d.owner_id,
                   d.is_active, d.created_at, d.updated_at,
                   (SELECT COUNT(*) FROM datasets WHERE domain = d.name) as dataset_count
            FROM domains d
            WHERE d.is_active = 1
            ORDER BY d.name
            LIMIT ?1 OFFSET ?2
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let domains: Vec<DomainResponse> = stmt
        .query_map([limit as i64, offset as i64], |row| {
            Ok(DomainResponse {
                id: row.get(0)?,
                name: row.get(1)?,
                display_name: row.get(2)?,
                description: row.get(3)?,
                owner_id: row.get(4)?,
                is_active: row.get::<_, i32>(5)? == 1,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
                dataset_count: row.get(8)?,
            })
        })
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(domains))
}

/// Create a new domain
async fn create_domain(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Json(req): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<DomainResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, name = %req.name, "Creating domain");

    // Validate domain name (lowercase alphanumeric with hyphens/underscores)
    if !req
        .name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(bad_request(
            "Domain name must be lowercase alphanumeric with hyphens or underscores".to_string(),
            request_id.0.clone(),
        ));
    }

    if req.name.is_empty() || req.name.len() > 64 {
        return Err(bad_request(
            "Domain name must be 1-64 characters".to_string(),
            request_id.0.clone(),
        ));
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Insert domain
    conn.execute(
        r#"
        INSERT INTO domains (name, display_name, description, owner_id, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, datetime('now'), datetime('now'))
        "#,
        rusqlite::params![req.name, req.display_name, req.description, req.owner_id],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint failed") {
            bad_request(
                format!("Domain '{}' already exists", req.name),
                request_id.0.clone(),
            )
        } else {
            internal_error(e.to_string(), request_id.0.clone())
        }
    })?;

    // Fetch the created domain
    let domain: DomainResponse = conn
        .query_row(
            r#"
            SELECT id, name, display_name, description, owner_id, is_active, created_at, updated_at
            FROM domains WHERE name = ?1
            "#,
            [&req.name],
            |row| {
                Ok(DomainResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    display_name: row.get(2)?,
                    description: row.get(3)?,
                    owner_id: row.get(4)?,
                    is_active: row.get::<_, i32>(5)? == 1,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    dataset_count: 0,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(name = %req.name, id = domain.id, "Domain created successfully");

    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "domain",
            &domain.name,
            serde_json::json!({
                "id": domain.id,
                "name": domain.name,
                "display_name": domain.display_name,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok((StatusCode::CREATED, Json(domain)))
}

/// Get a domain by name
async fn get_domain(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<DomainResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, name = %name, "Getting domain");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let domain: DomainResponse = conn
        .query_row(
            r#"
            SELECT d.id, d.name, d.display_name, d.description, d.owner_id,
                   d.is_active, d.created_at, d.updated_at,
                   (SELECT COUNT(*) FROM datasets WHERE domain = d.name) as dataset_count
            FROM domains d
            WHERE d.name = ?1
            "#,
            [&name],
            |row| {
                Ok(DomainResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    display_name: row.get(2)?,
                    description: row.get(3)?,
                    owner_id: row.get(4)?,
                    is_active: row.get::<_, i32>(5)? == 1,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    dataset_count: row.get(8)?,
                })
            },
        )
        .map_err(|_| not_found(format!("Domain '{}' not found", name), request_id.0.clone()))?;

    Ok(Json(domain))
}

/// Update a domain
async fn update_domain(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(name): Path<String>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<DomainResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, name = %name, "Updating domain");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Build dynamic update query
    let mut updates = vec!["updated_at = datetime('now')".to_string()];
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

    if let Some(display_name) = &req.display_name {
        updates.push(format!("display_name = ?{}", params.len() + 1));
        params.push(Box::new(display_name.clone()));
    }
    if let Some(description) = &req.description {
        updates.push(format!("description = ?{}", params.len() + 1));
        params.push(Box::new(description.clone()));
    }
    if let Some(owner_id) = &req.owner_id {
        updates.push(format!("owner_id = ?{}", params.len() + 1));
        params.push(Box::new(owner_id.clone()));
    }
    if let Some(is_active) = req.is_active {
        updates.push(format!("is_active = ?{}", params.len() + 1));
        params.push(Box::new(if is_active { 1i32 } else { 0i32 }));
    }

    params.push(Box::new(name.clone()));
    let sql = format!(
        "UPDATE domains SET {} WHERE name = ?{}",
        updates.join(", "),
        params.len()
    );

    let rows_updated = conn
        .execute(&sql, params_from_iter(params.iter().map(|p| p.as_ref())))
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if rows_updated == 0 {
        return Err(not_found(
            format!("Domain '{}' not found", name),
            request_id.0.clone(),
        ));
    }

    // Fetch updated domain
    let domain: DomainResponse = conn
        .query_row(
            r#"
            SELECT d.id, d.name, d.display_name, d.description, d.owner_id,
                   d.is_active, d.created_at, d.updated_at,
                   (SELECT COUNT(*) FROM datasets WHERE domain = d.name) as dataset_count
            FROM domains d
            WHERE d.name = ?1
            "#,
            [&name],
            |row| {
                Ok(DomainResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    display_name: row.get(2)?,
                    description: row.get(3)?,
                    owner_id: row.get(4)?,
                    is_active: row.get::<_, i32>(5)? == 1,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    dataset_count: row.get(8)?,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(name = %name, "Domain updated successfully");

    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "domain",
            &domain.name,
            serde_json::json!({}),
            serde_json::json!({
                "display_name": domain.display_name,
                "description": domain.description,
                "owner_id": domain.owner_id,
                "is_active": domain.is_active,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(Json(domain))
}

/// Delete (soft delete) a domain
async fn delete_domain(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check delete permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_delete_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, name = %name, "Deleting domain");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Check for datasets in this domain (warning only, soft delete still proceeds)
    let dataset_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM datasets WHERE domain = ?1",
            [&name],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if dataset_count > 0 {
        tracing::warn!(
            domain = %name,
            dataset_count,
            "Soft-deleting domain with existing datasets"
        );
    }

    // Soft delete - set is_active = 0
    let rows_updated = conn
        .execute(
            "UPDATE domains SET is_active = 0, updated_at = datetime('now') WHERE name = ?1 AND is_active = 1",
            [&name],
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if rows_updated == 0 {
        return Err(not_found(
            format!("Domain '{}' not found", name),
            request_id.0.clone(),
        ));
    }

    tracing::info!(name = %name, dataset_count, "Domain deleted (soft delete)");

    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::delete(
            "domain",
            &name,
            serde_json::json!({"name": name}),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(StatusCode::NO_CONTENT)
}

/// List datasets in a domain
async fn list_domain_datasets(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<DatasetResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, domain = %name, "Listing datasets in domain");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Verify domain exists
    let domain_exists: bool = conn
        .query_row(
            "SELECT 1 FROM domains WHERE name = ?1 AND is_active = 1",
            [&name],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !domain_exists {
        return Err(not_found(
            format!("Domain '{}' not found", name),
            request_id.0.clone(),
        ));
    }

    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, name, path, format, delta_location, description, tenant, domain, owner,
                   created_at, last_updated, row_count, size_bytes, partition_keys
            FROM datasets
            WHERE domain = ?1
            ORDER BY name
            LIMIT ?2 OFFSET ?3
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let datasets: Vec<DatasetResponse> = stmt
        .query_map(
            rusqlite::params![name, limit as i64, offset as i64],
            |row| {
                let row_count: Option<i64> = row.get(11)?;
                let size_bytes: Option<i64> = row.get(12)?;
                let partition_keys = parse_partition_keys(row.get::<_, Option<String>>(13)?);
                Ok(DatasetResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    path: row.get(2)?,
                    format: row.get(3)?,
                    delta_location: row.get(4)?,
                    description: row.get(5)?,
                    tenant: row.get(6)?,
                    domain: row.get(7)?,
                    owner: row.get(8)?,
                    created_at: row.get(9)?,
                    last_updated: row.get(10)?,
                    operational: OperationalMetaResponse {
                        row_count,
                        size_bytes,
                        partition_keys,
                    },
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(datasets))
}

// =============================================================================
// Glossary Handlers
// =============================================================================

/// List all glossary terms with optional filters
async fn list_glossary_terms(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<GlossaryTermResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, "Listing glossary terms");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                gt.id, gt.term, gt.description, gt.domain, gt.owner_id,
                COALESCE(gt.status, 'draft') as status,
                COALESCE(gt.created_at, datetime('now')) as created_at,
                COALESCE(gt.updated_at, datetime('now')) as updated_at,
                COUNT(tl.id) as link_count
            FROM glossary_terms gt
            LEFT JOIN term_links tl ON gt.id = tl.term_id
            GROUP BY gt.id
            ORDER BY gt.term
            LIMIT ?1 OFFSET ?2
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let terms: Vec<GlossaryTermResponse> = stmt
        .query_map(rusqlite::params![limit as i64, offset as i64], |row| {
            Ok(GlossaryTermResponse {
                id: row.get(0)?,
                term: row.get(1)?,
                description: row.get(2)?,
                domain: row.get(3)?,
                owner_id: row.get(4)?,
                status: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
                link_count: row.get(8)?,
            })
        })
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(terms))
}

/// Create a new glossary term
async fn create_glossary_term(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Json(req): Json<CreateGlossaryTermRequest>,
) -> Result<(StatusCode, Json<GlossaryTermResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, term = %req.term, "Creating glossary term");

    // Validate term
    if req.term.trim().is_empty() {
        return Err(bad_request(
            "Term cannot be empty".to_string(),
            request_id.0.clone(),
        ));
    }

    if req.term.len() > 255 {
        return Err(bad_request(
            "Term must be 255 characters or less".to_string(),
            request_id.0.clone(),
        ));
    }

    // Validate status if provided
    if let Some(ref status) = req.status {
        let valid_statuses = ["draft", "approved", "deprecated"];
        if !valid_statuses.contains(&status.as_str()) {
            return Err(bad_request(
                format!(
                    "Invalid status '{}'. Must be one of: draft, approved, deprecated",
                    status
                ),
                request_id.0.clone(),
            ));
        }
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let status = req.status.unwrap_or_else(|| "draft".to_string());

    conn.execute(
        r#"
        INSERT INTO glossary_terms (term, description, domain, owner_id, status, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'), datetime('now'))
        "#,
        rusqlite::params![req.term, req.description, req.domain, req.owner_id, status],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint failed") {
            bad_request(
                format!("Glossary term '{}' already exists", req.term),
                request_id.0.clone(),
            )
        } else {
            internal_error(e.to_string(), request_id.0.clone())
        }
    })?;

    let id = conn.last_insert_rowid();

    let term_response = GlossaryTermResponse {
        id,
        term: req.term.clone(),
        description: req.description.clone(),
        domain: req.domain.clone(),
        owner_id: req.owner_id.clone(),
        status: status.clone(),
        link_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    tracing::info!(term = %req.term, id, "Glossary term created");

    // Emit audit event
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "glossary_term",
            req.term.clone(),
            serde_json::json!({
                "id": id,
                "term": req.term,
                "domain": req.domain,
                "status": status,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok((StatusCode::CREATED, Json(term_response)))
}

/// Get a glossary term by ID
async fn get_glossary_term(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(id): Path<i64>,
) -> Result<Json<GlossaryTermResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, id, "Getting glossary term");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let term = conn
        .query_row(
            r#"
            SELECT
                gt.id, gt.term, gt.description, gt.domain, gt.owner_id,
                COALESCE(gt.status, 'draft') as status,
                COALESCE(gt.created_at, datetime('now')) as created_at,
                COALESCE(gt.updated_at, datetime('now')) as updated_at,
                COUNT(tl.id) as link_count
            FROM glossary_terms gt
            LEFT JOIN term_links tl ON gt.id = tl.term_id
            WHERE gt.id = ?1
            GROUP BY gt.id
            "#,
            [id],
            |row| {
                Ok(GlossaryTermResponse {
                    id: row.get(0)?,
                    term: row.get(1)?,
                    description: row.get(2)?,
                    domain: row.get(3)?,
                    owner_id: row.get(4)?,
                    status: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    link_count: row.get(8)?,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => not_found(
                format!("Glossary term {} not found", id),
                request_id.0.clone(),
            ),
            _ => internal_error(e.to_string(), request_id.0.clone()),
        })?;

    Ok(Json(term))
}

/// Update a glossary term
async fn update_glossary_term(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateGlossaryTermRequest>,
) -> Result<Json<GlossaryTermResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, id, "Updating glossary term");

    // Validate term if provided
    if let Some(ref term) = req.term {
        if term.trim().is_empty() {
            return Err(bad_request(
                "Term cannot be empty".to_string(),
                request_id.0.clone(),
            ));
        }
    }

    // Validate status if provided
    if let Some(ref status) = req.status {
        let valid_statuses = ["draft", "approved", "deprecated"];
        if !valid_statuses.contains(&status.as_str()) {
            return Err(bad_request(
                format!(
                    "Invalid status '{}'. Must be one of: draft, approved, deprecated",
                    status
                ),
                request_id.0.clone(),
            ));
        }
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Check term exists
    let exists: bool = conn
        .query_row("SELECT 1 FROM glossary_terms WHERE id = ?1", [id], |_| {
            Ok(true)
        })
        .unwrap_or(false);

    if !exists {
        return Err(not_found(
            format!("Glossary term {} not found", id),
            request_id.0.clone(),
        ));
    }

    // Build dynamic update
    let mut updates = vec!["updated_at = datetime('now')"];
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

    if let Some(ref term) = req.term {
        updates.push("term = ?");
        params.push(Box::new(term.clone()));
    }
    if let Some(ref description) = req.description {
        updates.push("description = ?");
        params.push(Box::new(description.clone()));
    }
    if let Some(ref domain) = req.domain {
        updates.push("domain = ?");
        params.push(Box::new(domain.clone()));
    }
    if let Some(ref owner_id) = req.owner_id {
        updates.push("owner_id = ?");
        params.push(Box::new(owner_id.clone()));
    }
    if let Some(ref status) = req.status {
        updates.push("status = ?");
        params.push(Box::new(status.clone()));
    }

    params.push(Box::new(id));

    let sql = format!(
        "UPDATE glossary_terms SET {} WHERE id = ?",
        updates.join(", ")
    );

    conn.execute(
        &sql,
        rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint failed") {
            bad_request(
                "A glossary term with that name already exists".to_string(),
                request_id.0.clone(),
            )
        } else {
            internal_error(e.to_string(), request_id.0.clone())
        }
    })?;

    // Fetch updated term
    let term = conn
        .query_row(
            r#"
            SELECT
                gt.id, gt.term, gt.description, gt.domain, gt.owner_id,
                COALESCE(gt.status, 'draft') as status,
                COALESCE(gt.created_at, datetime('now')) as created_at,
                COALESCE(gt.updated_at, datetime('now')) as updated_at,
                COUNT(tl.id) as link_count
            FROM glossary_terms gt
            LEFT JOIN term_links tl ON gt.id = tl.term_id
            WHERE gt.id = ?1
            GROUP BY gt.id
            "#,
            [id],
            |row| {
                Ok(GlossaryTermResponse {
                    id: row.get(0)?,
                    term: row.get(1)?,
                    description: row.get(2)?,
                    domain: row.get(3)?,
                    owner_id: row.get(4)?,
                    status: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    link_count: row.get(8)?,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(id, term = %term.term, "Glossary term updated");

    // Emit audit event
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "glossary_term",
            term.term.clone(),
            serde_json::json!({ "id": id }),
            serde_json::json!({
                "term": req.term,
                "description": req.description,
                "domain": req.domain,
                "owner_id": req.owner_id,
                "status": req.status,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(Json(term))
}

/// Delete a glossary term
async fn delete_glossary_term(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check delete permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_delete_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, id, "Deleting glossary term");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get term name for audit
    let term_name: Option<String> = conn
        .query_row(
            "SELECT term FROM glossary_terms WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .ok();

    let rows = conn
        .execute("DELETE FROM glossary_terms WHERE id = ?1", [id])
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if rows == 0 {
        return Err(not_found(
            format!("Glossary term {} not found", id),
            request_id.0.clone(),
        ));
    }

    tracing::info!(id, "Glossary term deleted");

    // Emit audit event
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::delete(
            "glossary_term",
            term_name.unwrap_or_else(|| id.to_string()),
            serde_json::json!({ "id": id }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Get links for a glossary term
async fn get_term_links(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<TermLinkResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, term_id = id, "Getting term links");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Verify term exists
    let exists: bool = conn
        .query_row("SELECT 1 FROM glossary_terms WHERE id = ?1", [id], |_| {
            Ok(true)
        })
        .unwrap_or(false);

    if !exists {
        return Err(not_found(
            format!("Glossary term {} not found", id),
            request_id.0.clone(),
        ));
    }

    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                tl.id, tl.term_id, tl.dataset_id, tl.field_id,
                d.name as dataset_name, f.name as field_name
            FROM term_links tl
            LEFT JOIN datasets d ON tl.dataset_id = d.id
            LEFT JOIN fields f ON tl.field_id = f.id
            WHERE tl.term_id = ?1
            ORDER BY tl.id
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let links: Vec<TermLinkResponse> = stmt
        .query_map([id], |row| {
            Ok(TermLinkResponse {
                id: row.get(0)?,
                term_id: row.get(1)?,
                dataset_id: row.get(2)?,
                field_id: row.get(3)?,
                dataset_name: row.get(4)?,
                field_name: row.get(5)?,
            })
        })
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(links))
}

/// Link a term to a dataset or field
async fn link_term(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(id): Path<i64>,
    Json(req): Json<LinkTermRequest>,
) -> Result<(StatusCode, Json<TermLinkResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, term_id = id, ?req.dataset_id, ?req.field_id, "Linking term");

    // Validate - must provide exactly one of dataset_id or field_id
    match (&req.dataset_id, &req.field_id) {
        (None, None) => {
            return Err(bad_request(
                "Must provide either dataset_id or field_id".to_string(),
                request_id.0.clone(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(bad_request(
                "Must provide only one of dataset_id or field_id, not both".to_string(),
                request_id.0.clone(),
            ));
        }
        _ => {}
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Verify term exists
    let term_name: String = conn
        .query_row(
            "SELECT term FROM glossary_terms WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .map_err(|_| {
            not_found(
                format!("Glossary term {} not found", id),
                request_id.0.clone(),
            )
        })?;

    // Verify dataset/field exists
    if let Some(dataset_id) = req.dataset_id {
        let exists: bool = conn
            .query_row("SELECT 1 FROM datasets WHERE id = ?1", [dataset_id], |_| {
                Ok(true)
            })
            .unwrap_or(false);
        if !exists {
            return Err(not_found(
                format!("Dataset {} not found", dataset_id),
                request_id.0.clone(),
            ));
        }
    }

    if let Some(field_id) = req.field_id {
        let exists: bool = conn
            .query_row("SELECT 1 FROM fields WHERE id = ?1", [field_id], |_| {
                Ok(true)
            })
            .unwrap_or(false);
        if !exists {
            return Err(not_found(
                format!("Field {} not found", field_id),
                request_id.0.clone(),
            ));
        }
    }

    conn.execute(
        "INSERT OR IGNORE INTO term_links (term_id, dataset_id, field_id) VALUES (?1, ?2, ?3)",
        rusqlite::params![id, req.dataset_id, req.field_id],
    )
    .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let link_id = conn.last_insert_rowid();

    // Get the link with names
    let link = conn
        .query_row(
            r#"
            SELECT
                tl.id, tl.term_id, tl.dataset_id, tl.field_id,
                d.name as dataset_name, f.name as field_name
            FROM term_links tl
            LEFT JOIN datasets d ON tl.dataset_id = d.id
            LEFT JOIN fields f ON tl.field_id = f.id
            WHERE tl.id = ?1
            "#,
            [link_id],
            |row| {
                Ok(TermLinkResponse {
                    id: row.get(0)?,
                    term_id: row.get(1)?,
                    dataset_id: row.get(2)?,
                    field_id: row.get(3)?,
                    dataset_name: row.get(4)?,
                    field_name: row.get(5)?,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(term_id = id, link_id, "Term linked");

    // Emit audit event
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "term_link",
            term_name,
            serde_json::json!({
                "term_id": id,
                "link_id": link_id,
                "dataset_id": req.dataset_id,
                "field_id": req.field_id,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok((StatusCode::CREATED, Json(link)))
}

/// Unlink a term from datasets/fields
async fn unlink_term(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(id): Path<i64>,
    Json(req): Json<LinkTermRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check delete permission in multi-tenant mode (unlinking is a delete-style operation)
    #[cfg(feature = "api-keys")]
    require_delete_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, term_id = id, ?req.dataset_id, ?req.field_id, "Unlinking term");

    // Validate - must provide exactly one of dataset_id or field_id
    match (&req.dataset_id, &req.field_id) {
        (None, None) => {
            return Err(bad_request(
                "Must provide either dataset_id or field_id".to_string(),
                request_id.0.clone(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(bad_request(
                "Must provide only one of dataset_id or field_id, not both".to_string(),
                request_id.0.clone(),
            ));
        }
        _ => {}
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Verify term exists and get name for audit
    let term_name: String = conn
        .query_row(
            "SELECT term FROM glossary_terms WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .map_err(|_| {
            not_found(
                format!("Glossary term {} not found", id),
                request_id.0.clone(),
            )
        })?;

    let rows = if let Some(dataset_id) = req.dataset_id {
        conn.execute(
            "DELETE FROM term_links WHERE term_id = ?1 AND dataset_id = ?2",
            rusqlite::params![id, dataset_id],
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
    } else if let Some(field_id) = req.field_id {
        conn.execute(
            "DELETE FROM term_links WHERE term_id = ?1 AND field_id = ?2",
            rusqlite::params![id, field_id],
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
    } else {
        0
    };

    if rows == 0 {
        return Err(not_found(
            "Link not found".to_string(),
            request_id.0.clone(),
        ));
    }

    tracing::info!(term_id = id, "Term unlinked");

    // Emit audit event
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::delete(
            "term_link",
            term_name,
            serde_json::json!({
                "term_id": id,
                "dataset_id": req.dataset_id,
                "field_id": req.field_id,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Lineage Handlers
// =============================================================================

/// Create a lineage edge between two datasets
async fn create_lineage_edge(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Json(req): Json<CreateLineageEdgeRequest>,
) -> Result<(StatusCode, Json<LineageEdgeResponse>), (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        source = %req.source_dataset,
        target = %req.target_dataset,
        "Creating lineage edge"
    );

    validation::validate_dataset_name(&req.source_dataset)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;
    validation::validate_dataset_name(&req.target_dataset)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get source dataset ID
    let source_id: i64 = conn
        .query_row(
            "SELECT id FROM datasets WHERE name = ?1",
            [&req.source_dataset],
            |row| row.get(0),
        )
        .map_err(|_| {
            not_found(
                format!("Source dataset '{}' not found", req.source_dataset),
                request_id.0.clone(),
            )
        })?;

    // Get target dataset ID
    let target_id: i64 = conn
        .query_row(
            "SELECT id FROM datasets WHERE name = ?1",
            [&req.target_dataset],
            |row| row.get(0),
        )
        .map_err(|_| {
            not_found(
                format!("Target dataset '{}' not found", req.target_dataset),
                request_id.0.clone(),
            )
        })?;

    // Insert lineage edge
    conn.execute(
        "INSERT OR IGNORE INTO lineage (upstream_dataset_id, downstream_dataset_id, created_at) VALUES (?1, ?2, datetime('now'))",
        rusqlite::params![source_id, target_id],
    )
    .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get the lineage edge
    let edge = conn
        .query_row(
            "SELECT id, upstream_dataset_id, downstream_dataset_id, created_at FROM lineage WHERE upstream_dataset_id = ?1 AND downstream_dataset_id = ?2",
            rusqlite::params![source_id, target_id],
            |row| {
                Ok(LineageEdgeResponse {
                    id: row.get(0)?,
                    upstream_dataset_id: row.get(1)?,
                    downstream_dataset_id: row.get(2)?,
                    created_at: row.get(3)?,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(
        source = %req.source_dataset,
        target = %req.target_dataset,
        "Lineage edge created successfully"
    );

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "lineage_edge",
            format!("{}:{}", req.source_dataset, req.target_dataset),
            serde_json::json!({
                "id": edge.id,
                "source_dataset": req.source_dataset,
                "target_dataset": req.target_dataset,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok((StatusCode::CREATED, Json(edge)))
}

// =============================================================================
// Governance Rules Handlers
// =============================================================================

/// Create a governance rule
async fn create_governance_rule(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Json(req): Json<CreateGovernanceRuleRequest>,
) -> Result<(StatusCode, Json<GovernanceRuleResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, name = %req.name, "Creating governance rule");

    // Validate rule type
    validation::validate_rule_type(&req.rule_type)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let priority = req.priority.unwrap_or(100);

    conn.execute(
        r#"
        INSERT INTO governance_rules (name, rule_type, description, config, priority, is_active, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 1, datetime('now'), datetime('now'))
        "#,
        rusqlite::params![
            req.name,
            req.rule_type,
            req.description,
            req.config.to_string(),
            priority,
        ],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint failed") {
            bad_request(
                format!("Governance rule '{}' already exists", req.name),
                request_id.0.clone(),
            )
        } else {
            internal_error(e.to_string(), request_id.0.clone())
        }
    })?;

    let id = conn.last_insert_rowid();

    let rule = GovernanceRuleResponse {
        id,
        name: req.name,
        rule_type: req.rule_type,
        description: req.description,
        config: req.config,
        priority,
        is_active: true,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    tracing::info!(name = %rule.name, "Governance rule created successfully");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "governance_rule",
            &rule.name,
            serde_json::json!({
                "id": rule.id,
                "name": rule.name,
                "rule_type": rule.rule_type,
                "priority": rule.priority,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok((StatusCode::CREATED, Json(rule)))
}

/// List all governance rules
async fn list_governance_rules(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<Vec<GovernanceRuleResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        limit = pagination.limit(),
        offset = pagination.offset(),
        "Listing governance rules"
    );

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, name, rule_type, description, config, priority, is_active, created_at, updated_at
            FROM governance_rules ORDER BY priority, name LIMIT ?1 OFFSET ?2
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let rules = stmt
        .query_map(
            rusqlite::params![pagination.limit() as i64, pagination.offset() as i64],
            |row| {
                let config_str: String = row.get(4)?;
                Ok(GovernanceRuleResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    rule_type: row.get(2)?,
                    description: row.get(3)?,
                    config: serde_json::from_str(&config_str).unwrap_or(serde_json::Value::Null),
                    priority: row.get(5)?,
                    is_active: row.get::<_, i32>(6)? != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(count = rules.len(), "Listed governance rules successfully");

    Ok(Json(rules))
}

/// Get a governance rule by ID
async fn get_governance_rule(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(id): Path<i64>,
) -> Result<Json<GovernanceRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, id = %id, "Getting governance rule");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let rule = conn
        .query_row(
            r#"
            SELECT id, name, rule_type, description, config, priority, is_active, created_at, updated_at
            FROM governance_rules WHERE id = ?1
            "#,
            [id],
            |row| {
                let config_str: String = row.get(4)?;
                Ok(GovernanceRuleResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    rule_type: row.get(2)?,
                    description: row.get(3)?,
                    config: serde_json::from_str(&config_str).unwrap_or(serde_json::Value::Null),
                    priority: row.get(5)?,
                    is_active: row.get::<_, i32>(6)? != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .map_err(|_| {
            not_found(
                format!("Governance rule '{}' not found", id),
                request_id.0.clone(),
            )
        })?;

    Ok(Json(rule))
}

/// Update a governance rule
async fn update_governance_rule(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateGovernanceRuleRequest>,
) -> Result<Json<GovernanceRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, id = %id, "Updating governance rule");

    // Validate rule type if provided
    if let Some(ref rule_type) = req.rule_type {
        validation::validate_rule_type(rule_type)
            .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let mut updates = vec!["updated_at = datetime('now')".to_string()];
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

    if let Some(name) = &req.name {
        updates.push(format!("name = ?{}", params.len() + 1));
        params.push(Box::new(name.clone()));
    }
    if let Some(rule_type) = &req.rule_type {
        updates.push(format!("rule_type = ?{}", params.len() + 1));
        params.push(Box::new(rule_type.clone()));
    }
    if let Some(description) = &req.description {
        updates.push(format!("description = ?{}", params.len() + 1));
        params.push(Box::new(description.clone()));
    }
    if let Some(config) = &req.config {
        updates.push(format!("config = ?{}", params.len() + 1));
        params.push(Box::new(config.to_string()));
    }
    if let Some(priority) = &req.priority {
        updates.push(format!("priority = ?{}", params.len() + 1));
        params.push(Box::new(*priority));
    }
    if let Some(is_active) = &req.is_active {
        updates.push(format!("is_active = ?{}", params.len() + 1));
        params.push(Box::new(if *is_active { 1i32 } else { 0i32 }));
    }

    let sql = format!(
        "UPDATE governance_rules SET {} WHERE id = ?{}",
        updates.join(", "),
        params.len() + 1
    );
    params.push(Box::new(id));

    let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let rows = conn
        .execute(&sql, params_refs.as_slice())
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if rows == 0 {
        return Err(not_found(
            format!("Governance rule '{}' not found", id),
            request_id.0.clone(),
        ));
    }

    // Fetch updated rule
    let rule = conn
        .query_row(
            r#"
            SELECT id, name, rule_type, description, config, priority, is_active, created_at, updated_at
            FROM governance_rules WHERE id = ?1
            "#,
            [id],
            |row| {
                let config_str: String = row.get(4)?;
                Ok(GovernanceRuleResponse {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    rule_type: row.get(2)?,
                    description: row.get(3)?,
                    config: serde_json::from_str(&config_str).unwrap_or(serde_json::Value::Null),
                    priority: row.get(5)?,
                    is_active: row.get::<_, i32>(6)? != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(id = %id, "Governance rule updated successfully");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "governance_rule",
            id.to_string(),
            serde_json::json!({}),
            serde_json::json!({
                "id": rule.id,
                "name": rule.name,
                "rule_type": rule.rule_type,
                "is_active": rule.is_active,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(Json(rule))
}

/// Delete a governance rule
async fn delete_governance_rule(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check delete permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_delete_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(rbac_error)?;

    #[cfg(feature = "api-keys")]
    let tenant_id = resolved_tenant
        .as_ref()
        .map(|e| e.0.tenant_id())
        .or_else(|| tenant_backend.as_ref().map(|e| e.0.tenant_id()))
        .unwrap_or("default");
    #[cfg(not(feature = "api-keys"))]
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    tracing::debug!(tenant_id = %tenant_id, id = %id, "Deleting governance rule");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let rows = conn
        .execute("DELETE FROM governance_rules WHERE id = ?1", [id])
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if rows == 0 {
        return Err(not_found(
            format!("Governance rule '{}' not found", id),
            request_id.0.clone(),
        ));
    }

    tracing::info!(id = %id, "Governance rule deleted successfully");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::delete(
            "governance_rule",
            id.to_string(),
            serde_json::json!({ "id": id }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Quality Metrics Handlers
// =============================================================================

/// Create a quality metric for a dataset
async fn create_quality_metric(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Json(req): Json<CreateQualityMetricRequest>,
) -> Result<(StatusCode, Json<QualityMetricResponse>), (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset = %name, "Creating quality metric");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    // Validate score values (must be 0.0 to 1.0)
    if let Some(score) = req.completeness_score {
        validation::validate_score(score, "completeness_score")
            .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;
    }
    if let Some(score) = req.freshness_score {
        validation::validate_score(score, "freshness_score")
            .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;
    }
    if let Some(score) = req.file_health_score {
        validation::validate_score(score, "file_health_score")
            .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;
    }
    if let Some(score) = req.overall_score {
        validation::validate_score(score, "overall_score")
            .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let dataset_id: i64 = conn
        .query_row("SELECT id FROM datasets WHERE name = ?1", [&name], |row| {
            row.get(0)
        })
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    let details_json = req.details.as_ref().map(|v| v.to_string());

    conn.execute(
        r#"
        INSERT INTO quality_metrics (dataset_id, computed_at, completeness_score, freshness_score, file_health_score, overall_score, row_count, file_count, size_bytes, details)
        VALUES (?1, datetime('now'), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        rusqlite::params![
            dataset_id,
            req.completeness_score,
            req.freshness_score,
            req.file_health_score,
            req.overall_score,
            req.row_count,
            req.file_count,
            req.size_bytes,
            details_json,
        ],
    )
    .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let id = conn.last_insert_rowid();

    let metric = QualityMetricResponse {
        id,
        dataset_id,
        computed_at: chrono::Utc::now().to_rfc3339(),
        completeness_score: req.completeness_score,
        freshness_score: req.freshness_score,
        file_health_score: req.file_health_score,
        overall_score: req.overall_score,
        row_count: req.row_count,
        file_count: req.file_count,
        size_bytes: req.size_bytes,
        details: req.details,
    };

    tracing::info!(dataset = %name, "Quality metric created successfully");

    Ok((StatusCode::CREATED, Json(metric)))
}

/// List quality metrics for a dataset
async fn list_quality_metrics(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<Vec<QualityMetricResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset = %name, "Listing quality metrics");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let dataset_id: i64 = conn
        .query_row("SELECT id FROM datasets WHERE name = ?1", [&name], |row| {
            row.get(0)
        })
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, dataset_id, computed_at, completeness_score, freshness_score, file_health_score, overall_score, row_count, file_count, size_bytes, details
            FROM quality_metrics WHERE dataset_id = ?1 ORDER BY computed_at DESC
            "#,
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let metrics = stmt
        .query_map([dataset_id], |row| {
            let details_str: Option<String> = row.get(10)?;
            Ok(QualityMetricResponse {
                id: row.get(0)?,
                dataset_id: row.get(1)?,
                computed_at: row.get(2)?,
                completeness_score: row.get(3)?,
                freshness_score: row.get(4)?,
                file_health_score: row.get(5)?,
                overall_score: row.get(6)?,
                row_count: row.get(7)?,
                file_count: row.get(8)?,
                size_bytes: row.get(9)?,
                details: details_str.and_then(|s| serde_json::from_str(&s).ok()),
            })
        })
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(dataset = %name, count = metrics.len(), "Listed quality metrics successfully");

    Ok(Json(metrics))
}

// =============================================================================
// Freshness Config Handlers
// =============================================================================

/// Set freshness configuration for a dataset
async fn set_freshness_config(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_context): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Json(req): Json<SetFreshnessConfigRequest>,
) -> Result<Json<FreshnessConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset = %name, "Setting freshness config");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let dataset_id: i64 = conn
        .query_row("SELECT id FROM datasets WHERE name = ?1", [&name], |row| {
            row.get(0)
        })
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    let grace_period_secs = req.grace_period_secs.unwrap_or(0);
    let timezone = req.timezone.as_deref().unwrap_or("UTC");
    let alert_on_stale = req.alert_on_stale.unwrap_or(true);
    let alert_channels_json = req
        .alert_channels
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    // Upsert freshness config
    conn.execute(
        r#"
        INSERT INTO freshness_config (dataset_id, expected_interval_secs, grace_period_secs, timezone, cron_schedule, alert_on_stale, alert_channels, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'), datetime('now'))
        ON CONFLICT(dataset_id) DO UPDATE SET
            expected_interval_secs = ?2,
            grace_period_secs = ?3,
            timezone = ?4,
            cron_schedule = ?5,
            alert_on_stale = ?6,
            alert_channels = ?7,
            updated_at = datetime('now')
        "#,
        rusqlite::params![
            dataset_id,
            req.expected_interval_secs,
            grace_period_secs,
            timezone,
            req.cron_schedule,
            if alert_on_stale { 1 } else { 0 },
            alert_channels_json,
        ],
    )
    .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Fetch the config
    let config = conn
        .query_row(
            r#"
            SELECT id, dataset_id, expected_interval_secs, grace_period_secs, timezone, cron_schedule, alert_on_stale, alert_channels, created_at, updated_at
            FROM freshness_config WHERE dataset_id = ?1
            "#,
            [dataset_id],
            |row| {
                let alert_channels_str: Option<String> = row.get(7)?;
                Ok(FreshnessConfigResponse {
                    id: row.get(0)?,
                    dataset_id: row.get(1)?,
                    expected_interval_secs: row.get(2)?,
                    grace_period_secs: row.get(3)?,
                    timezone: row.get(4)?,
                    cron_schedule: row.get(5)?,
                    alert_on_stale: row.get::<_, i32>(6)? != 0,
                    alert_channels: alert_channels_str.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            },
        )
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    tracing::info!(dataset = %name, "Freshness config set successfully");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "freshness_config",
            &name,
            serde_json::json!({}),
            serde_json::json!({
                "dataset": name,
                "expected_interval_secs": config.expected_interval_secs,
                "grace_period_secs": config.grace_period_secs,
                "alert_on_stale": config.alert_on_stale,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_context.enrich_event(event));
    }

    Ok(Json(config))
}

/// Get freshness configuration for a dataset
async fn get_freshness_config(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<FreshnessConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset = %name, "Getting freshness config");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let dataset_id: i64 = conn
        .query_row("SELECT id FROM datasets WHERE name = ?1", [&name], |row| {
            row.get(0)
        })
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    let config = conn
        .query_row(
            r#"
            SELECT id, dataset_id, expected_interval_secs, grace_period_secs, timezone, cron_schedule, alert_on_stale, alert_channels, created_at, updated_at
            FROM freshness_config WHERE dataset_id = ?1
            "#,
            [dataset_id],
            |row| {
                let alert_channels_str: Option<String> = row.get(7)?;
                Ok(FreshnessConfigResponse {
                    id: row.get(0)?,
                    dataset_id: row.get(1)?,
                    expected_interval_secs: row.get(2)?,
                    grace_period_secs: row.get(3)?,
                    timezone: row.get(4)?,
                    cron_schedule: row.get(5)?,
                    alert_on_stale: row.get::<_, i32>(6)? != 0,
                    alert_channels: alert_channels_str.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            },
        )
        .map_err(|_| {
            not_found(
                format!("Freshness config not found for dataset '{}'", name),
                request_id.0.clone(),
            )
        })?;

    Ok(Json(config))
}

// =============================================================================
// Delta-Delegated Handlers
// =============================================================================

/// Get schema from Delta table
async fn get_dataset_schema(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Query(params): Query<SchemaQueryParams>,
) -> Result<Json<SchemaResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset = %name, version = ?params.version, "Getting dataset schema from Delta");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get delta_location from dataset
    let delta_location: Option<String> = conn
        .query_row(
            "SELECT delta_location FROM datasets WHERE name = ?1",
            [&name],
            |row| row.get(0),
        )
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    let delta_location = delta_location.ok_or_else(|| {
        bad_request(
            format!("Dataset '{}' does not have a delta_location", name),
            request_id.0.clone(),
        )
    })?;

    // Get schema from Delta
    let schema = state
        .delta_reader
        .get_schema(&delta_location, params.version)
        .await
        .map_err(|e| {
            internal_error(
                format!("Failed to read Delta schema: {}", e),
                request_id.0.clone(),
            )
        })?;

    // Get current version
    let metadata = state
        .delta_reader
        .get_metadata_cached(&delta_location)
        .await
        .map_err(|e| {
            internal_error(
                format!("Failed to read Delta metadata: {}", e),
                request_id.0.clone(),
            )
        })?;

    let response = SchemaResponse {
        dataset_name: name,
        delta_version: params.version.unwrap_or(metadata.version),
        schema: serde_json::to_value(&schema).unwrap_or(serde_json::Value::Null),
        partition_columns: schema.partition_columns,
    };

    Ok(Json(response))
}

/// Get schema diff between two Delta versions
async fn get_dataset_schema_diff(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Query(params): Query<SchemaDiffQueryParams>,
) -> Result<Json<SchemaDiffResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(
        tenant_id = %tenant_id,
        dataset = %name,
        from = params.from,
        to = params.to,
        "Getting schema diff from Delta"
    );

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    // Validate version range
    if params.from >= params.to {
        return Err(bad_request(
            "Parameter 'from' must be less than 'to'".to_string(),
            request_id.0.clone(),
        ));
    }

    // Limit version range to prevent expensive operations
    let max_version_range: i64 = std::env::var("METAFUSE_SCHEMA_DIFF_MAX_VERSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);

    if params.to - params.from > max_version_range {
        return Err(bad_request(
            format!(
                "Version range exceeds maximum of {} versions",
                max_version_range
            ),
            request_id.0.clone(),
        ));
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get delta_location from dataset
    let delta_location: Option<String> = conn
        .query_row(
            "SELECT delta_location FROM datasets WHERE name = ?1",
            [&name],
            |row| row.get(0),
        )
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    let delta_location = delta_location.ok_or_else(|| {
        bad_request(
            format!("Dataset '{}' does not have a delta_location", name),
            request_id.0.clone(),
        )
    })?;

    // Get schema diff from Delta
    let diff = state
        .delta_reader
        .diff_schemas(&delta_location, params.from, params.to)
        .await
        .map_err(|e| {
            internal_error(
                format!("Failed to compute schema diff: {}", e),
                request_id.0.clone(),
            )
        })?;

    // Convert to response types
    let response = SchemaDiffResponse {
        dataset_name: name,
        from_version: diff.from_version,
        to_version: diff.to_version,
        added_columns: diff
            .added_columns
            .into_iter()
            .map(|f| SchemaDiffField {
                name: f.name,
                data_type: f.data_type,
                nullable: f.nullable,
                description: f.description,
            })
            .collect(),
        removed_columns: diff
            .removed_columns
            .into_iter()
            .map(|f| SchemaDiffField {
                name: f.name,
                data_type: f.data_type,
                nullable: f.nullable,
                description: f.description,
            })
            .collect(),
        modified_columns: diff
            .modified_columns
            .into_iter()
            .map(|c| SchemaDiffFieldChange {
                name: c.name,
                old_type: c.old_type,
                new_type: c.new_type,
                old_nullable: c.old_nullable,
                new_nullable: c.new_nullable,
            })
            .collect(),
    };

    Ok(Json(response))
}

/// Get stats from Delta table
async fn get_dataset_stats(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<StatsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset = %name, "Getting dataset stats from Delta");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get delta_location from dataset
    let delta_location: Option<String> = conn
        .query_row(
            "SELECT delta_location FROM datasets WHERE name = ?1",
            [&name],
            |row| row.get(0),
        )
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    let delta_location = delta_location.ok_or_else(|| {
        bad_request(
            format!("Dataset '{}' does not have a delta_location", name),
            request_id.0.clone(),
        )
    })?;

    // Get metadata from Delta (with caching)
    let metadata = state
        .delta_reader
        .get_metadata_cached(&delta_location)
        .await
        .map_err(|e| {
            internal_error(
                format!("Failed to read Delta stats: {}", e),
                request_id.0.clone(),
            )
        })?;

    let response = StatsResponse {
        dataset_name: name,
        delta_version: metadata.version,
        row_count: metadata.row_count,
        size_bytes: metadata.size_bytes,
        num_files: metadata.num_files,
        last_modified: Some(metadata.last_modified.to_rfc3339()),
    };

    Ok(Json(response))
}

/// Get history from Delta table
async fn get_dataset_history(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Query(params): Query<HistoryQueryParams>,
) -> Result<Json<HistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, dataset = %name, limit = ?params.limit, "Getting dataset history from Delta");

    validation::validate_dataset_name(&name)
        .map_err(|e| bad_request(e.to_string(), request_id.0.clone()))?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    // Get delta_location from dataset
    let delta_location: Option<String> = conn
        .query_row(
            "SELECT delta_location FROM datasets WHERE name = ?1",
            [&name],
            |row| row.get(0),
        )
        .map_err(|_| {
            not_found(
                format!("Dataset '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    let delta_location = delta_location.ok_or_else(|| {
        bad_request(
            format!("Dataset '{}' does not have a delta_location", name),
            request_id.0.clone(),
        )
    })?;

    let limit = params.limit.unwrap_or(10);

    // Get history from Delta
    let history = state
        .delta_reader
        .get_history(&delta_location, limit)
        .await
        .map_err(|e| {
            internal_error(
                format!("Failed to read Delta history: {}", e),
                request_id.0.clone(),
            )
        })?;

    let versions: Vec<VersionInfo> = history
        .into_iter()
        .map(|v| VersionInfo {
            version: v.version,
            timestamp: v.timestamp.to_rfc3339(),
            operation: v.operation,
            parameters: v.parameters,
        })
        .collect();

    let response = HistoryResponse {
        dataset_name: name,
        versions,
    };

    Ok(Json(response))
}

// =============================================================================
// Alerting Endpoints (v0.9.0)
// =============================================================================

/// List alert history
///
/// SECURITY: This handler enforces tenant isolation by overriding any
/// tenant_id passed in query params with the resolved tenant from the
/// request context. This prevents cross-tenant data leakage.
#[cfg(feature = "alerting")]
async fn list_alerts(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Query(mut params): Query<alerting::AlertHistoryParams>,
) -> Result<Json<alerting::AlertHistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    // CRITICAL: Enforce tenant isolation by overriding tenant_id from request context
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");

    // Override any user-provided tenant_id with the authenticated tenant
    params.tenant_id = Some(tenant_id.to_string());

    tracing::debug!(tenant_id = %tenant_id, "Listing alert history");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let response = alerting::query_alert_history(&conn, &params)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    Ok(Json(response))
}

// =============================================================================
// Contract Endpoints (v0.9.0)
// =============================================================================

/// List all contracts
#[cfg(feature = "contracts")]
async fn list_contracts(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
) -> Result<Json<Vec<contracts::DataContract>>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, "Listing contracts");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let contracts = contracts::list_contracts(&conn)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    Ok(Json(contracts))
}

/// Create a new contract
#[cfg(feature = "contracts")]
async fn create_contract(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Json(contract): Json<contracts::DataContract>,
) -> Result<Json<ContractCreatedResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, contract_name = %contract.name, "Creating contract");

    // Validate contract input
    let validation_errors = contracts::validate_contract(&contract);
    if !validation_errors.is_empty() {
        let error_messages: Vec<String> = validation_errors
            .iter()
            .map(|e| format!("{}: {}", e.field, e.message))
            .collect();
        return Err(bad_request(
            format!("Validation failed: {}", error_messages.join("; ")),
            request_id.0.clone(),
        ));
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let id = contracts::create_contract(&conn, &contract).map_err(|e| {
        if e.to_string().contains("UNIQUE constraint") {
            bad_request(
                format!("Contract '{}' already exists", contract.name),
                request_id.0.clone(),
            )
        } else {
            internal_error(e.to_string(), request_id.0.clone())
        }
    })?;

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "contract",
            &contract.name,
            serde_json::json!({
                "id": id,
                "name": contract.name,
                "version": contract.version,
                "dataset_pattern": contract.dataset_pattern,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_ctx.enrich_event(event));
    }

    Ok(Json(ContractCreatedResponse {
        id,
        name: contract.name,
        message: "Contract created successfully".to_string(),
    }))
}

#[cfg(feature = "contracts")]
#[derive(Serialize)]
struct ContractCreatedResponse {
    id: i64,
    name: String,
    message: String,
}

/// Get a contract by name
#[cfg(feature = "contracts")]
async fn get_contract(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<contracts::DataContract>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, contract_name = %name, "Getting contract");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let contract = contracts::get_contract(&conn, &name)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?
        .ok_or_else(|| {
            not_found(
                format!("Contract '{}' not found", name),
                request_id.0.clone(),
            )
        })?;

    Ok(Json(contract))
}

/// Update an existing contract
#[cfg(feature = "contracts")]
async fn update_contract(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
    Json(contract): Json<contracts::DataContract>,
) -> Result<Json<ContractUpdatedResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, contract_name = %name, "Updating contract");

    // Validate contract input
    let validation_errors = contracts::validate_contract(&contract);
    if !validation_errors.is_empty() {
        let error_messages: Vec<String> = validation_errors
            .iter()
            .map(|e| format!("{}: {}", e.field, e.message))
            .collect();
        return Err(bad_request(
            format!("Validation failed: {}", error_messages.join("; ")),
            request_id.0.clone(),
        ));
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let updated = contracts::update_contract(&conn, &name, &contract)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if !updated {
        return Err(not_found(
            format!("Contract '{}' not found", name),
            request_id.0.clone(),
        ));
    }

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::update(
            "contract",
            &name,
            serde_json::json!({}), // old values not tracked for simplicity
            serde_json::json!({
                "name": name,
                "version": contract.version,
                "dataset_pattern": contract.dataset_pattern,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_ctx.enrich_event(event));
    }

    Ok(Json(ContractUpdatedResponse {
        name,
        version: contract.version,
        message: "Contract updated successfully".to_string(),
    }))
}

#[cfg(feature = "contracts")]
#[derive(Serialize)]
struct ContractUpdatedResponse {
    name: String,
    version: i32,
    message: String,
}

/// Delete a contract
#[cfg(feature = "contracts")]
async fn delete_contract(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(name): Path<String>,
) -> Result<Json<ContractDeletedResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant_id = tenant_backend
        .as_ref()
        .map(|e| e.0.tenant_id())
        .unwrap_or("default");
    tracing::debug!(tenant_id = %tenant_id, contract_name = %name, "Deleting contract");

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend
        .get_connection()
        .await
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    let deleted = contracts::delete_contract(&conn, &name)
        .map_err(|e| internal_error(e.to_string(), request_id.0.clone()))?;

    if !deleted {
        return Err(not_found(
            format!("Contract '{}' not found", name),
            request_id.0.clone(),
        ));
    }

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::delete(
            "contract",
            &name,
            serde_json::json!({ "name": name }),
            &request_id.0,
        );
        state.audit_logger.log(audit_ctx.enrich_event(event));
    }

    Ok(Json(ContractDeletedResponse {
        name,
        message: "Contract deleted successfully".to_string(),
    }))
}

#[cfg(feature = "contracts")]
#[derive(Serialize)]
struct ContractDeletedResponse {
    name: String,
    message: String,
}

// =============================================================================
// Column-Level Lineage Endpoints (v0.10.0)
// =============================================================================

/// Parse SQL and extract column lineage
#[cfg(feature = "column-lineage")]
async fn lineage_parse(
    Json(request): Json<lineage::ParseLineageRequest>,
) -> Result<Json<lineage::ParseLineageResponse>, (StatusCode, String)> {
    use metafuse_catalog_lineage::ColumnLineageParser;

    let parser = ColumnLineageParser::new();
    match parser.parse_lineage(&request.sql, &request.target_dataset) {
        Ok(result) => Ok(Json(lineage::ParseLineageResponse::from(result))),
        Err(e) => Err((StatusCode::BAD_REQUEST, format!("Parse error: {}", e))),
    }
}

/// Record lineage edges in the database
#[cfg(feature = "column-lineage")]
async fn lineage_record(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(audit_ctx): Extension<AuditContext>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Json(request): Json<lineage::RecordLineageRequest>,
) -> Result<Json<lineage::RecordLineageResponse>, (StatusCode, String)> {
    // Check write permission in multi-tenant mode
    #[cfg(feature = "api-keys")]
    require_write_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(|e| (e.0, e.1.error.clone()))?;

    // Input validation: dataset IDs must be positive
    if request.source_dataset_id <= 0 || request.target_dataset_id <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Dataset IDs must be positive integers".to_string(),
        ));
    }

    // Input validation: limit number of edges per request
    const MAX_EDGES_PER_REQUEST: usize = 1000;
    if request.edges.len() > MAX_EDGES_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Maximum {} edges per request", MAX_EDGES_PER_REQUEST),
        ));
    }

    // Input validation: column names
    for edge in &request.edges {
        if edge.source_column.is_empty() || edge.target_column.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Column names cannot be empty".to_string(),
            ));
        }
        if edge.source_column.len() > 256 || edge.target_column.len() > 256 {
            return Err((
                StatusCode::BAD_REQUEST,
                "Column names cannot exceed 256 characters".to_string(),
            ));
        }
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let conn = backend.get_connection().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database connection error: {}", e),
        )
    })?;

    let mut edges_recorded = 0;
    for edge in &request.edges {
        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type, expression)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                request.source_dataset_id,
                edge.source_column,
                request.target_dataset_id,
                edge.target_column,
                edge.transformation_type,
                edge.expression
            ],
        ).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;
        edges_recorded += 1;
    }

    #[cfg(feature = "metrics")]
    metrics::record_lineage_operation("record", "success");

    // Emit audit event (non-blocking)
    #[cfg(feature = "audit")]
    {
        let event = audit::AuditEvent::create(
            "column_lineage",
            format!(
                "{}:{}",
                request.source_dataset_id, request.target_dataset_id
            ),
            serde_json::json!({
                "source_dataset_id": request.source_dataset_id,
                "target_dataset_id": request.target_dataset_id,
                "edges_recorded": edges_recorded,
            }),
            &request_id.0,
        );
        state.audit_logger.log(audit_ctx.enrich_event(event));
    }

    Ok(Json(lineage::RecordLineageResponse { edges_recorded }))
}

/// Maximum recursion depth for lineage traversal
#[cfg(feature = "column-lineage")]
const MAX_LINEAGE_DEPTH: i32 = 50;

/// Validate and clamp lineage lookup parameters
#[cfg(feature = "column-lineage")]
fn validate_lineage_params(
    dataset_id: i64,
    column: &str,
    params: &lineage::LineageLookupParams,
) -> Result<lineage::LineageLookupParams, (StatusCode, String)> {
    // Dataset ID must be positive
    if dataset_id <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Dataset ID must be a positive integer".to_string(),
        ));
    }

    // Column name validation
    if column.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Column name cannot be empty".to_string(),
        ));
    }
    if column.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Column name cannot exceed 256 characters".to_string(),
        ));
    }

    // Clamp max_depth to prevent excessive recursion
    let clamped_depth = params.max_depth.clamp(1, MAX_LINEAGE_DEPTH);

    Ok(lineage::LineageLookupParams {
        max_depth: clamped_depth,
    })
}

/// Get upstream lineage for a column
#[cfg(feature = "column-lineage")]
async fn lineage_upstream(
    State(state): State<AppState>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path((dataset_id, column)): Path<(i64, String)>,
    Query(params): Query<lineage::LineageLookupParams>,
) -> Result<Json<lineage::LineageLookupResponse>, (StatusCode, String)> {
    // Validate and clamp parameters
    let validated_params = validate_lineage_params(dataset_id, &column, &params)?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let lineage_state = lineage::LineageAppState { backend };

    #[cfg(feature = "metrics")]
    metrics::record_lineage_query("upstream", "success");

    // Track usage (non-blocking)
    #[cfg(feature = "usage-analytics")]
    {
        let tracker = state.usage_tracker.clone();
        tokio::spawn(async move {
            tracker
                .record_access(dataset_id, None, usage_analytics::AccessType::LineageQuery)
                .await;
        });
    }

    lineage::get_upstream_lineage(
        State(lineage_state),
        Path((dataset_id, column)),
        Query(validated_params),
    )
    .await
}

/// Get downstream lineage for a column
#[cfg(feature = "column-lineage")]
async fn lineage_downstream(
    State(state): State<AppState>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path((dataset_id, column)): Path<(i64, String)>,
    Query(params): Query<lineage::LineageLookupParams>,
) -> Result<Json<lineage::LineageLookupResponse>, (StatusCode, String)> {
    // Validate and clamp parameters
    let validated_params = validate_lineage_params(dataset_id, &column, &params)?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let lineage_state = lineage::LineageAppState { backend };

    #[cfg(feature = "metrics")]
    metrics::record_lineage_query("downstream", "success");

    // Track usage (non-blocking)
    #[cfg(feature = "usage-analytics")]
    {
        let tracker = state.usage_tracker.clone();
        tokio::spawn(async move {
            tracker
                .record_access(dataset_id, None, usage_analytics::AccessType::LineageQuery)
                .await;
        });
    }

    lineage::get_downstream_lineage(
        State(lineage_state),
        Path((dataset_id, column)),
        Query(validated_params),
    )
    .await
}

/// Get PII propagation for a column
#[cfg(feature = "column-lineage")]
async fn lineage_pii_propagation(
    State(state): State<AppState>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path((dataset_id, column)): Path<(i64, String)>,
    Query(params): Query<lineage::LineageLookupParams>,
) -> Result<Json<lineage::PiiPropagationResponse>, (StatusCode, String)> {
    // Validate and clamp parameters
    let validated_params = validate_lineage_params(dataset_id, &column, &params)?;

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let lineage_state = lineage::LineageAppState { backend };

    #[cfg(feature = "metrics")]
    metrics::record_lineage_query("pii_propagation", "success");

    // Track usage (non-blocking)
    #[cfg(feature = "usage-analytics")]
    {
        let tracker = state.usage_tracker.clone();
        tokio::spawn(async move {
            tracker
                .record_access(dataset_id, None, usage_analytics::AccessType::LineageQuery)
                .await;
        });
    }

    lineage::get_pii_propagation(
        State(lineage_state),
        Path((dataset_id, column)),
        Query(validated_params),
    )
    .await
}

/// Delete lineage edges for a dataset
#[cfg(feature = "column-lineage")]
async fn lineage_delete_dataset(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    tenant_backend: Option<Extension<TenantBackend>>,
    #[cfg(feature = "api-keys")] resolved_tenant: Option<Extension<ResolvedTenant>>,
    Path(dataset_id): Path<i64>,
) -> Result<Json<lineage::DeleteLineageResponse>, (StatusCode, String)> {
    // Check delete permission in multi-tenant mode (requires Admin role)
    #[cfg(feature = "api-keys")]
    require_delete_permission(resolved_tenant.as_ref().map(|e| &e.0), &request_id.0)
        .map_err(|e| (e.0, e.1.error.clone()))?;

    // Input validation
    if dataset_id <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Dataset ID must be a positive integer".to_string(),
        ));
    }

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let lineage_state = lineage::LineageAppState { backend };

    let result = lineage::delete_dataset_lineage(State(lineage_state), Path(dataset_id)).await;

    #[cfg(feature = "metrics")]
    if result.is_ok() {
        metrics::record_lineage_operation("delete", "success");
    } else {
        metrics::record_lineage_operation("delete", "error");
    }

    result
}

/// Get impact analysis for a field change
#[cfg(feature = "column-lineage")]
async fn lineage_field_impact(
    State(state): State<AppState>,
    tenant_backend: Option<Extension<TenantBackend>>,
    Path(field_id): Path<i64>,
    Query(params): Query<lineage::LineageLookupParams>,
) -> Result<Json<lineage::ImpactAnalysisResponse>, (StatusCode, String)> {
    // Input validation
    if field_id <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Field ID must be a positive integer".to_string(),
        ));
    }

    // Clamp max_depth
    let clamped_depth = params.max_depth.clamp(1, MAX_LINEAGE_DEPTH);
    let validated_params = lineage::LineageLookupParams {
        max_depth: clamped_depth,
    };

    let backend = resolve_backend(&state.backend, tenant_backend.as_ref().map(|e| &e.0));
    let lineage_state = lineage::LineageAppState { backend };

    #[cfg(feature = "metrics")]
    metrics::record_lineage_query("impact_analysis", "success");

    lineage::get_field_impact(
        State(lineage_state),
        Path(field_id),
        Query(validated_params),
    )
    .await
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn test_audit_context_new() {
        let ctx = AuditContext::new(
            Some("api-key-123".to_string()),
            Some("192.168.1.1".to_string()),
        );
        assert_eq!(ctx.api_key_id, Some("api-key-123".to_string()));
        assert_eq!(ctx.client_ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_audit_context_default() {
        let ctx = AuditContext::default();
        assert_eq!(ctx.api_key_id, None);
        assert_eq!(ctx.client_ip, None);
    }

    #[cfg(feature = "audit")]
    mod audit_enrichment_tests {
        use super::*;

        #[test]
        fn test_enrich_event_with_api_key() {
            let ctx = AuditContext::new(Some("api-key-123".to_string()), None);
            let event = audit::AuditEvent::create(
                "dataset",
                "test_dataset",
                serde_json::json!({}),
                "req-123",
            );
            let enriched = ctx.enrich_event(event);
            assert_eq!(enriched.actor, Some("api-key-123".to_string()));
            assert_eq!(enriched.actor_type, audit::ActorType::Service);
        }

        #[test]
        fn test_enrich_event_anonymous() {
            let ctx = AuditContext::new(None, None);
            let event = audit::AuditEvent::create(
                "dataset",
                "test_dataset",
                serde_json::json!({}),
                "req-123",
            );
            let enriched = ctx.enrich_event(event);
            assert_eq!(enriched.actor, Some("anonymous".to_string()));
            assert_eq!(enriched.actor_type, audit::ActorType::Anonymous);
        }

        #[test]
        fn test_enrich_event_with_client_ip() {
            let ctx = AuditContext::new(
                Some("api-key-123".to_string()),
                Some("10.0.0.1".to_string()),
            );
            let event = audit::AuditEvent::create(
                "dataset",
                "test_dataset",
                serde_json::json!({}),
                "req-123",
            );
            let enriched = ctx.enrich_event(event);
            assert_eq!(enriched.client_ip, Some("10.0.0.1".to_string()));
        }
    }

    #[test]
    fn test_extract_client_ip_x_forwarded_for() {
        let req = Request::builder()
            .header(
                "x-forwarded-for",
                "203.0.113.195, 70.41.3.18, 150.172.238.178",
            )
            .body(Body::empty())
            .unwrap();
        let ip = extract_client_ip(&req);
        assert_eq!(ip, Some("203.0.113.195".to_string()));
    }

    #[test]
    fn test_extract_client_ip_x_forwarded_for_single() {
        let req = Request::builder()
            .header("x-forwarded-for", "192.168.1.100")
            .body(Body::empty())
            .unwrap();
        let ip = extract_client_ip(&req);
        assert_eq!(ip, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_client_ip_x_real_ip() {
        let req = Request::builder()
            .header("x-real-ip", "10.0.0.1")
            .body(Body::empty())
            .unwrap();
        let ip = extract_client_ip(&req);
        assert_eq!(ip, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_extract_client_ip_prefers_x_forwarded_for() {
        let req = Request::builder()
            .header("x-forwarded-for", "203.0.113.195")
            .header("x-real-ip", "10.0.0.1")
            .body(Body::empty())
            .unwrap();
        let ip = extract_client_ip(&req);
        assert_eq!(ip, Some("203.0.113.195".to_string()));
    }

    #[test]
    fn test_extract_client_ip_none() {
        let req = Request::builder().body(Body::empty()).unwrap();
        let ip = extract_client_ip(&req);
        assert_eq!(ip, None);
    }

    #[test]
    fn test_extract_client_ip_empty_header() {
        let req = Request::builder()
            .header("x-forwarded-for", "")
            .body(Body::empty())
            .unwrap();
        let ip = extract_client_ip(&req);
        assert_eq!(ip, None);
    }
}
