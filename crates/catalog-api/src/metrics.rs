// Allow dead_code for public API metrics functions that may not all be used
// but are exposed for library consumers to integrate with their monitoring
#![allow(dead_code)]

//! Prometheus metrics for the MetaFuse catalog API
//!
//! This module is only compiled when the `metrics` feature is enabled.
//!
//! ## Global Metrics
//! - `http_requests_total` - Counter for total HTTP requests
//! - `http_request_duration_seconds` - Histogram for request latencies
//! - `catalog_operations_total` - Counter for catalog operations
//! - `catalog_datasets_total` - Gauge for total datasets in catalog
//!
//! ## Multi-Tenant Metrics
//!
//! When multi-tenant mode is enabled, additional tenant-labeled metrics are exposed:
//! - `tenant_http_requests_total` - Counter per tenant
//! - `tenant_http_request_duration_seconds` - Histogram per tenant
//! - `tenant_api_calls_total` - Counter per tenant and tier
//! - `tenant_rate_limit_hits_total` - Counter for rate limit rejections per tenant
//! - `tenant_backend_cache_hits_total` - Counter for backend cache hits/misses
//!
//! ## Connection Pool Metrics
//!
//! - `tenant_connection_wait_seconds` - Histogram for permit wait times
//! - `tenant_active_connections` - Gauge for active connections per tenant
//! - `tenant_connection_timeouts_total` - Counter for acquire timeouts
//! - `tenant_circuit_breaker_state` - Gauge for circuit breaker state (0=closed, 1=open)
//! - `tenant_circuit_breaker_trips_total` - Counter for circuit breaker trips
//!
//! ## Quota Enforcement Metrics
//!
//! - `tenant_quota_checks_total` - Counter for quota checks by result (ok, exceeded, warning)
//! - `tenant_quota_usage_ratio` - Gauge for current quota usage ratio per tenant/resource
//! - `tenant_quota_enforcement_total` - Counter for enforcement actions (blocked, dry_run_allowed)
//!
//! ## Alerting Metrics (v0.9.0)
//!
//! - `alerts_fired_total` - Counter for alerts fired by type and severity
//! - `alerts_delivery_total` - Counter for alert delivery outcomes (delivered, failed)
//! - `webhook_requests_total` - Counter for webhook HTTP requests by status code
//! - `webhook_request_duration_seconds` - Histogram for webhook latency
//! - `alert_check_active` - Gauge indicating if alert check is running (for health monitoring)
//!
//! ## Data Contract Metrics (v0.9.0)
//!
//! - `contracts_checks_total` - Counter for contract validations by result
//! - `contracts_violations_total` - Counter for contract violations by type and action
//!
//! ## Column-Level Lineage Metrics (v0.10.0)
//!
//! - `lineage_operations_total` - Counter for lineage operations (parse, record, delete) by status
//! - `lineage_queries_total` - Counter for lineage queries (upstream, downstream, pii_propagation, impact)
//! - `lineage_query_duration_seconds` - Histogram for lineage query latency
//! - `lineage_edges_total` - Gauge for total lineage edges in the catalog
//! - `lineage_transformations_total` - Counter for lineage edges by transformation type
//!
//! ## Cardinality Control
//!
//! Per-tenant metrics (those with `tenant_id` label) create a new Prometheus time series
//! for each unique tenant. In deployments with a large number of tenants (>1000), this
//! can lead to high memory usage and slow metric queries.
//!
//! By default, quota metrics use "aggregated" as the tenant_id label to prevent
//! cardinality explosion. To enable per-tenant quota metrics, set:
//!
//! ```bash
//! export METAFUSE_TENANT_METRICS_INCLUDE_ID=true
//! ```
//!
//! Additional strategies:
//! - Aggregating metrics at the tier level instead of tenant level
//! - Using metric relabeling to drop high-cardinality labels
//! - Implementing tenant metric rotation for inactive tenants

use axum::{
    extract::{Extension, MatchedPath, Request},
    http::StatusCode,
    middleware::Next,
    response::IntoResponse,
};
use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_gauge_vec, register_histogram_vec, CounterVec,
    Encoder, Gauge, GaugeVec, HistogramVec, TextEncoder,
};
use std::time::Instant;

lazy_static! {
    // ==========================================================================
    // Global Metrics (backward compatible)
    // ==========================================================================

    /// Counter for total HTTP requests by method, path, and status
    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "http_requests_total",
        "Total number of HTTP requests",
        &["method", "path", "status"]
    )
    .unwrap();

    /// Histogram for HTTP request duration in seconds
    pub static ref HTTP_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request latency in seconds",
        &["method", "path"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap();

    /// Counter for catalog operations (emit_dataset, search, etc.)
    pub static ref CATALOG_OPERATIONS_TOTAL: CounterVec = register_counter_vec!(
        "catalog_operations_total",
        "Total number of catalog operations",
        &["operation", "status"]
    )
    .unwrap();

    /// Gauge for total number of datasets in the catalog
    pub static ref CATALOG_DATASETS_TOTAL: Gauge = register_gauge!(
        "catalog_datasets_total",
        "Total number of datasets in the catalog"
    )
    .unwrap();

    // ==========================================================================
    // Multi-Tenant Metrics
    // ==========================================================================

    /// Counter for HTTP requests per tenant
    pub static ref TENANT_HTTP_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "tenant_http_requests_total",
        "Total HTTP requests per tenant",
        &["tenant_id", "method", "path", "status"]
    )
    .unwrap();

    /// Histogram for HTTP request duration per tenant
    pub static ref TENANT_HTTP_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "tenant_http_request_duration_seconds",
        "HTTP request latency per tenant in seconds",
        &["tenant_id", "method", "path"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap();

    /// Counter for API calls per tenant and tier
    pub static ref TENANT_API_CALLS_TOTAL: CounterVec = register_counter_vec!(
        "tenant_api_calls_total",
        "Total API calls per tenant with tier label",
        &["tenant_id", "tier", "operation"]
    )
    .unwrap();

    /// Counter for rate limit hits per tenant
    pub static ref TENANT_RATE_LIMIT_HITS_TOTAL: CounterVec = register_counter_vec!(
        "tenant_rate_limit_hits_total",
        "Rate limit rejections per tenant",
        &["tenant_id", "tier"]
    )
    .unwrap();

    /// Counter for tenant backend cache operations
    pub static ref TENANT_BACKEND_CACHE_TOTAL: CounterVec = register_counter_vec!(
        "tenant_backend_cache_total",
        "Tenant backend cache hits and misses",
        &["result"]  // "hit" or "miss"
    )
    .unwrap();

    /// Gauge for current number of cached tenant backends
    pub static ref TENANT_BACKEND_CACHE_SIZE: Gauge = register_gauge!(
        "tenant_backend_cache_size",
        "Current number of cached tenant backends"
    )
    .unwrap();

    /// Gauge for datasets per tenant
    pub static ref TENANT_DATASETS_TOTAL: GaugeVec = register_gauge_vec!(
        "tenant_datasets_total",
        "Total datasets per tenant",
        &["tenant_id"]
    )
    .unwrap();

    /// Counter for tenant lifecycle events
    pub static ref TENANT_LIFECYCLE_EVENTS_TOTAL: CounterVec = register_counter_vec!(
        "tenant_lifecycle_events_total",
        "Tenant lifecycle events",
        &["event"]  // "created", "suspended", "reactivated", "deleted", "purged"
    )
    .unwrap();

    // ==========================================================================
    // Connection Pool Metrics
    // ==========================================================================

    /// Histogram for connection permit wait times per tenant
    pub static ref TENANT_CONNECTION_WAIT_SECONDS: HistogramVec = register_histogram_vec!(
        "tenant_connection_wait_seconds",
        "Time spent waiting for a connection permit",
        &["tenant_id"],
        vec![0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0]
    )
    .unwrap();

    /// Gauge for active connections per tenant
    pub static ref TENANT_ACTIVE_CONNECTIONS: GaugeVec = register_gauge_vec!(
        "tenant_active_connections",
        "Current number of active connections per tenant",
        &["tenant_id"]
    )
    .unwrap();

    /// Counter for connection acquire timeouts per tenant
    pub static ref TENANT_CONNECTION_TIMEOUTS_TOTAL: CounterVec = register_counter_vec!(
        "tenant_connection_timeouts_total",
        "Total connection acquire timeouts per tenant",
        &["tenant_id"]
    )
    .unwrap();

    /// Gauge for circuit breaker state per tenant (0=closed, 1=open)
    pub static ref TENANT_CIRCUIT_BREAKER_STATE: GaugeVec = register_gauge_vec!(
        "tenant_circuit_breaker_state",
        "Circuit breaker state per tenant (0=closed, 1=open)",
        &["tenant_id"]
    )
    .unwrap();

    /// Counter for circuit breaker trips per tenant
    pub static ref TENANT_CIRCUIT_BREAKER_TRIPS_TOTAL: CounterVec = register_counter_vec!(
        "tenant_circuit_breaker_trips_total",
        "Total circuit breaker trips per tenant",
        &["tenant_id"]
    )
    .unwrap();

    // ==========================================================================
    // Quota Enforcement Metrics
    // ==========================================================================

    /// Counter for quota checks per tenant and result
    pub static ref TENANT_QUOTA_CHECKS_TOTAL: CounterVec = register_counter_vec!(
        "tenant_quota_checks_total",
        "Total quota checks by result (ok, exceeded, warning)",
        &["tenant_id", "resource_type", "result"]  // result: "ok", "exceeded", "warning"
    )
    .unwrap();

    /// Gauge for quota usage percentage per tenant and resource type
    pub static ref TENANT_QUOTA_USAGE_RATIO: GaugeVec = register_gauge_vec!(
        "tenant_quota_usage_ratio",
        "Current quota usage ratio (0.0 to 1.0+) per tenant and resource type",
        &["tenant_id", "resource_type"]  // resource_type: "datasets", "storage_bytes", "api_calls"
    )
    .unwrap();

    /// Counter for quota enforcement actions
    pub static ref TENANT_QUOTA_ENFORCEMENT_TOTAL: CounterVec = register_counter_vec!(
        "tenant_quota_enforcement_total",
        "Quota enforcement actions (blocked vs allowed in dry-run)",
        &["tenant_id", "resource_type", "action"]  // action: "blocked", "dry_run_allowed"
    )
    .unwrap();

    // ==========================================================================
    // Alerting Metrics (v0.9.0)
    // ==========================================================================

    /// Counter for alerts fired by type and severity
    /// Labels: alert_type (freshness, quality, schema, contract), severity (info, warning, critical)
    pub static ref ALERTS_FIRED_TOTAL: CounterVec = register_counter_vec!(
        "alerts_fired_total",
        "Total alerts fired by type and severity",
        &["alert_type", "severity"]
    )
    .unwrap();

    /// Counter for alert delivery outcomes
    /// Labels: status (delivered, failed), alert_type
    pub static ref ALERTS_DELIVERY_TOTAL: CounterVec = register_counter_vec!(
        "alerts_delivery_total",
        "Alert delivery outcomes by status",
        &["status", "alert_type"]
    )
    .unwrap();

    /// Counter for webhook HTTP requests
    /// Labels: status_code (2xx, 4xx, 5xx), alert_type
    pub static ref WEBHOOK_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "webhook_requests_total",
        "Total webhook HTTP requests",
        &["status_code", "alert_type"]
    )
    .unwrap();

    /// Histogram for webhook request duration in seconds
    pub static ref WEBHOOK_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "webhook_request_duration_seconds",
        "Webhook request latency in seconds",
        &["alert_type"],
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap();

    /// Gauge for active alert checks (to detect stuck tasks)
    pub static ref ALERT_CHECK_ACTIVE: Gauge = register_gauge!(
        "alert_check_active",
        "Whether an alert check is currently running (0 or 1)"
    )
    .unwrap();

    // ==========================================================================
    // Data Contract Metrics (v0.9.0)
    // ==========================================================================

    /// Counter for contract checks performed
    /// Labels: result (pass, fail), contract_type (schema, quality, freshness)
    pub static ref CONTRACTS_CHECKS_TOTAL: CounterVec = register_counter_vec!(
        "contracts_checks_total",
        "Total contract validations performed",
        &["result", "contract_type"]
    )
    .unwrap();

    /// Counter for contract violations detected
    /// Labels: contract_type, on_violation (alert, warn, block)
    pub static ref CONTRACTS_VIOLATIONS_TOTAL: CounterVec = register_counter_vec!(
        "contracts_violations_total",
        "Total contract violations detected",
        &["contract_type", "on_violation"]
    )
    .unwrap();

    // ==========================================================================
    // Column-Level Lineage Metrics (v0.10.0)
    // ==========================================================================

    /// Counter for lineage operations (parse, record, delete)
    /// Labels: operation (parse, record, delete), status (success, error)
    pub static ref LINEAGE_OPERATIONS_TOTAL: CounterVec = register_counter_vec!(
        "lineage_operations_total",
        "Total column-level lineage operations",
        &["operation", "status"]
    )
    .unwrap();

    /// Counter for lineage queries
    /// Labels: query_type (upstream, downstream, pii_propagation, impact)
    pub static ref LINEAGE_QUERIES_TOTAL: CounterVec = register_counter_vec!(
        "lineage_queries_total",
        "Total lineage graph queries",
        &["query_type", "status"]
    )
    .unwrap();

    /// Histogram for lineage query duration in seconds
    pub static ref LINEAGE_QUERY_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "lineage_query_duration_seconds",
        "Lineage query latency in seconds",
        &["query_type"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap();

    /// Gauge for total lineage edges in the catalog
    pub static ref LINEAGE_EDGES_TOTAL: Gauge = register_gauge!(
        "lineage_edges_total",
        "Total number of column-level lineage edges in the catalog"
    )
    .unwrap();

    /// Counter for lineage parse results by transformation type
    /// Labels: transformation_type (Direct, Expression, Aggregate, Window, Case, Cast)
    pub static ref LINEAGE_TRANSFORMATIONS_TOTAL: CounterVec = register_counter_vec!(
        "lineage_transformations_total",
        "Lineage edges by transformation type",
        &["transformation_type"]
    )
    .unwrap();
}

// =============================================================================
// Cardinality Configuration
// =============================================================================

/// Configuration for tenant metrics cardinality control.
///
/// Controls whether per-tenant metrics include the actual `tenant_id` label
/// or use an aggregated placeholder to prevent cardinality explosion.
///
/// # Cardinality Warning
///
/// Setting `include_tenant_id = true` will create a new Prometheus time series
/// for each unique tenant. With many tenants (>1000), this can cause:
/// - High memory usage in Prometheus
/// - Slow metric queries
/// - Storage bloat
///
/// Only enable per-tenant labels in environments with:
/// - Small number of tenants
/// - Appropriate metric retention policies
/// - Sufficient Prometheus resources
#[derive(Clone, Debug)]
pub struct TenantMetricsConfig {
    /// When true, include actual tenant_id in metric labels.
    /// When false (default), use "aggregated" placeholder for cardinality safety.
    pub include_tenant_id: bool,
}

impl Default for TenantMetricsConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl TenantMetricsConfig {
    /// Create configuration from environment variables.
    ///
    /// # Environment Variables
    ///
    /// - `METAFUSE_TENANT_METRICS_INCLUDE_ID`: Set to "true" to enable per-tenant labels.
    ///   Default: "false" (tier-level aggregation only)
    pub fn from_env() -> Self {
        Self {
            include_tenant_id: std::env::var("METAFUSE_TENANT_METRICS_INCLUDE_ID")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
        }
    }

    /// Create configuration with per-tenant labels enabled.
    ///
    /// **Warning**: This can cause cardinality explosion with many tenants.
    #[allow(dead_code)]
    pub fn with_tenant_labels() -> Self {
        Self {
            include_tenant_id: true,
        }
    }

    /// Create configuration with tier-level aggregation (no per-tenant labels).
    #[allow(dead_code)]
    pub fn aggregated() -> Self {
        Self {
            include_tenant_id: false,
        }
    }
}

// =============================================================================
// Tenant Metrics Info
// =============================================================================

/// Tenant info extracted from request for metrics.
///
/// Used to label Prometheus metrics with tenant information.
/// The actual tenant_id vs "aggregated" placeholder is controlled by
/// `TenantMetricsConfig`.
#[derive(Clone, Debug)]
pub struct TenantMetricsInfo {
    pub tenant_id: String,
    pub tier: String,
}

impl TenantMetricsInfo {
    /// Create tenant metrics info with cardinality-aware tenant_id.
    ///
    /// If `config.include_tenant_id` is false, uses "aggregated" placeholder
    /// instead of the actual tenant_id to prevent metric cardinality explosion.
    pub fn new(tenant_id: &str, tier: &str, config: &TenantMetricsConfig) -> Self {
        Self {
            tenant_id: if config.include_tenant_id {
                tenant_id.to_string()
            } else {
                "aggregated".to_string()
            },
            tier: tier.to_string(),
        }
    }

    /// Create tenant metrics info with explicit tenant_id (no cardinality control).
    ///
    /// Use this only when you need the actual tenant_id regardless of config.
    #[allow(dead_code)]
    pub fn with_explicit_tenant_id(tenant_id: &str, tier: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            tier: tier.to_string(),
        }
    }
}

// =============================================================================
// Tenant Metrics Injection Middleware
// =============================================================================

/// Middleware to inject `TenantMetricsInfo` into request extensions.
///
/// This middleware extracts tenant information from `ResolvedTenant` (if present)
/// and creates `TenantMetricsInfo` for downstream metrics recording.
///
/// **Must run AFTER** `tenant_resolver_middleware` which populates `ResolvedTenant`.
///
/// # Cardinality Control
///
/// Uses `TenantMetricsConfig` to control whether the actual `tenant_id` or
/// "aggregated" placeholder is used in metrics labels.
///
/// # Example
///
/// ```ignore
/// // In main.rs middleware stack (layers execute in reverse order):
/// app.layer(middleware::from_fn(track_metrics))
///    .layer(middleware::from_fn(tenant_metrics_middleware))  // <-- This middleware
///    .layer(middleware::from_fn(tenant_resolver_middleware))
/// ```
#[cfg(feature = "api-keys")]
pub async fn tenant_metrics_middleware(
    config: Option<Extension<TenantMetricsConfig>>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    use crate::tenant_resolver::ResolvedTenant;

    let metrics_config = config.map(|Extension(c)| c).unwrap_or_default();

    // Extract tenant info from ResolvedTenant if present
    if let Some(resolved) = req.extensions().get::<ResolvedTenant>() {
        let tier_str = resolved
            .tier()
            .map(|t| format!("{:?}", t).to_lowercase())
            .unwrap_or_else(|| "unknown".to_string());

        let metrics_info = TenantMetricsInfo::new(resolved.tenant_id(), &tier_str, &metrics_config);

        tracing::debug!(
            tenant_id = %resolved.tenant_id(),
            tier = %tier_str,
            metrics_tenant_id = %metrics_info.tenant_id,
            "Injected TenantMetricsInfo for metrics recording"
        );

        req.extensions_mut().insert(metrics_info);
    }

    next.run(req).await
}

/// Axum middleware to track HTTP request metrics
///
/// Records both global and tenant-specific metrics when tenant info is available.
pub async fn track_metrics(req: Request, next: Next) -> impl IntoResponse {
    let start = Instant::now();
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // Extract tenant info if present
    let tenant_info = req.extensions().get::<TenantMetricsInfo>().cloned();

    let response = next.run(req).await;
    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    // Record global metrics (always)
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&method, &path, &status])
        .inc();

    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[&method, &path])
        .observe(duration);

    // Record tenant-specific metrics if tenant info is available
    if let Some(info) = tenant_info {
        TENANT_HTTP_REQUESTS_TOTAL
            .with_label_values(&[&info.tenant_id, &method, &path, &status])
            .inc();

        TENANT_HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&[&info.tenant_id, &method, &path])
            .observe(duration);
    }

    response
}

/// Handler for the `/metrics` endpoint
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(_) => (
            StatusCode::OK,
            [("content-type", encoder.format_type())],
            buffer,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to encode metrics: {}", e),
        )
            .into_response(),
    }
}

/// Record a catalog operation metric
pub fn record_catalog_operation(operation: &str, status: &str) {
    CATALOG_OPERATIONS_TOTAL
        .with_label_values(&[operation, status])
        .inc();
}

/// Update the total datasets gauge
#[allow(dead_code)]
pub fn update_datasets_total(count: i64) {
    CATALOG_DATASETS_TOTAL.set(count as f64);
}

// =============================================================================
// Multi-Tenant Metrics Helper Functions
// =============================================================================

/// Record a tenant API call
pub fn record_tenant_api_call(tenant_id: &str, tier: &str, operation: &str) {
    TENANT_API_CALLS_TOTAL
        .with_label_values(&[tenant_id, tier, operation])
        .inc();
}

/// Record a tenant rate limit hit
pub fn record_tenant_rate_limit_hit(tenant_id: &str, tier: &str) {
    TENANT_RATE_LIMIT_HITS_TOTAL
        .with_label_values(&[tenant_id, tier])
        .inc();
}

/// Record a tenant backend cache hit
pub fn record_tenant_backend_cache_hit() {
    TENANT_BACKEND_CACHE_TOTAL.with_label_values(&["hit"]).inc();
}

/// Record a tenant backend cache miss
pub fn record_tenant_backend_cache_miss() {
    TENANT_BACKEND_CACHE_TOTAL
        .with_label_values(&["miss"])
        .inc();
}

/// Update the tenant backend cache size gauge
pub fn update_tenant_backend_cache_size(size: usize) {
    TENANT_BACKEND_CACHE_SIZE.set(size as f64);
}

/// Update the datasets count for a specific tenant
pub fn update_tenant_datasets_total(tenant_id: &str, count: i64) {
    TENANT_DATASETS_TOTAL
        .with_label_values(&[tenant_id])
        .set(count as f64);
}

/// Record a tenant lifecycle event
pub fn record_tenant_lifecycle_event(event: &str) {
    TENANT_LIFECYCLE_EVENTS_TOTAL
        .with_label_values(&[event])
        .inc();
}

/// Convenience function to record tenant creation
pub fn record_tenant_created() {
    record_tenant_lifecycle_event("created");
}

/// Convenience function to record tenant suspension
pub fn record_tenant_suspended() {
    record_tenant_lifecycle_event("suspended");
}

/// Convenience function to record tenant reactivation
pub fn record_tenant_reactivated() {
    record_tenant_lifecycle_event("reactivated");
}

/// Convenience function to record tenant deletion
pub fn record_tenant_deleted() {
    record_tenant_lifecycle_event("deleted");
}

/// Convenience function to record tenant purge
pub fn record_tenant_purged() {
    record_tenant_lifecycle_event("purged");
}

// =============================================================================
// Connection Pool Metrics Helper Functions
// =============================================================================

/// Record time spent waiting for a connection permit
pub fn record_connection_wait_time(tenant_id: &str, duration_secs: f64) {
    TENANT_CONNECTION_WAIT_SECONDS
        .with_label_values(&[tenant_id])
        .observe(duration_secs);
}

/// Update the active connection count for a tenant
pub fn update_active_connections(tenant_id: &str, count: usize) {
    TENANT_ACTIVE_CONNECTIONS
        .with_label_values(&[tenant_id])
        .set(count as f64);
}

/// Record a connection acquire timeout
pub fn record_connection_timeout(tenant_id: &str) {
    TENANT_CONNECTION_TIMEOUTS_TOTAL
        .with_label_values(&[tenant_id])
        .inc();
}

/// Update circuit breaker state for a tenant (false=closed, true=open)
pub fn update_circuit_breaker_state(tenant_id: &str, is_open: bool) {
    TENANT_CIRCUIT_BREAKER_STATE
        .with_label_values(&[tenant_id])
        .set(if is_open { 1.0 } else { 0.0 });
}

/// Record a circuit breaker trip
pub fn record_circuit_breaker_trip(tenant_id: &str) {
    TENANT_CIRCUIT_BREAKER_TRIPS_TOTAL
        .with_label_values(&[tenant_id])
        .inc();
    update_circuit_breaker_state(tenant_id, true);
}

// =============================================================================
// Quota Enforcement Metrics Helper Functions
// =============================================================================

// Thread-local cache for TenantMetricsConfig to avoid repeated env lookups
thread_local! {
    static QUOTA_METRICS_CONFIG: TenantMetricsConfig = TenantMetricsConfig::from_env();
}

/// Get the effective tenant_id for metrics based on cardinality config.
///
/// When `METAFUSE_TENANT_METRICS_INCLUDE_ID=true`, returns the actual tenant_id.
/// Otherwise, returns "aggregated" to prevent cardinality explosion.
fn effective_tenant_id(tenant_id: &str) -> String {
    QUOTA_METRICS_CONFIG.with(|config| {
        if config.include_tenant_id {
            tenant_id.to_string()
        } else {
            "aggregated".to_string()
        }
    })
}

/// Record a quota check result (cardinality-aware)
///
/// Uses `TenantMetricsConfig` to determine whether to use actual tenant_id
/// or "aggregated" placeholder in metric labels.
pub fn record_quota_check(tenant_id: &str, resource_type: &str, result: &str) {
    let effective_id = effective_tenant_id(tenant_id);
    TENANT_QUOTA_CHECKS_TOTAL
        .with_label_values(&[effective_id.as_str(), resource_type, result])
        .inc();
}

/// Update the quota usage ratio for a tenant (cardinality-aware)
///
/// Uses `TenantMetricsConfig` to determine whether to use actual tenant_id
/// or "aggregated" placeholder in metric labels.
pub fn update_quota_usage_ratio(tenant_id: &str, resource_type: &str, ratio: f64) {
    let effective_id = effective_tenant_id(tenant_id);
    TENANT_QUOTA_USAGE_RATIO
        .with_label_values(&[effective_id.as_str(), resource_type])
        .set(ratio);
}

/// Record a quota enforcement action (cardinality-aware)
///
/// Uses `TenantMetricsConfig` to determine whether to use actual tenant_id
/// or "aggregated" placeholder in metric labels.
pub fn record_quota_enforcement(tenant_id: &str, resource_type: &str, action: &str) {
    let effective_id = effective_tenant_id(tenant_id);
    TENANT_QUOTA_ENFORCEMENT_TOTAL
        .with_label_values(&[effective_id.as_str(), resource_type, action])
        .inc();
}

/// Convenience function to record a successful quota check
pub fn record_quota_check_ok(tenant_id: &str, resource_type: &str) {
    record_quota_check(tenant_id, resource_type, "ok");
}

/// Convenience function to record a quota exceeded event
pub fn record_quota_exceeded(tenant_id: &str, resource_type: &str) {
    record_quota_check(tenant_id, resource_type, "exceeded");
}

/// Convenience function to record a quota soft limit warning
pub fn record_quota_warning(tenant_id: &str, resource_type: &str) {
    record_quota_check(tenant_id, resource_type, "warning");
}

/// Convenience function to record a blocked request due to quota
pub fn record_quota_blocked(tenant_id: &str, resource_type: &str) {
    record_quota_enforcement(tenant_id, resource_type, "blocked");
}

/// Convenience function to record a dry-run allowed request (would have been blocked)
pub fn record_quota_dry_run_allowed(tenant_id: &str, resource_type: &str) {
    record_quota_enforcement(tenant_id, resource_type, "dry_run_allowed");
}

// =============================================================================
// Alerting Metrics Helper Functions (v0.9.0)
// =============================================================================

/// Record an alert fired event
pub fn record_alert_fired(alert_type: &str, severity: &str) {
    ALERTS_FIRED_TOTAL
        .with_label_values(&[alert_type, severity])
        .inc();
}

/// Record an alert delivery outcome
pub fn record_alert_delivery(status: &str, alert_type: &str) {
    ALERTS_DELIVERY_TOTAL
        .with_label_values(&[status, alert_type])
        .inc();
}

/// Record a webhook HTTP request outcome
pub fn record_webhook_request(status_code: u16, alert_type: &str) {
    let status_bucket = match status_code {
        200..=299 => "2xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };
    WEBHOOK_REQUESTS_TOTAL
        .with_label_values(&[status_bucket, alert_type])
        .inc();
}

/// Record webhook request duration
pub fn record_webhook_duration(alert_type: &str, duration_secs: f64) {
    WEBHOOK_REQUEST_DURATION_SECONDS
        .with_label_values(&[alert_type])
        .observe(duration_secs);
}

/// Set alert check active state (for detecting stuck tasks)
pub fn set_alert_check_active(active: bool) {
    ALERT_CHECK_ACTIVE.set(if active { 1.0 } else { 0.0 });
}

/// Convenience: record alert fired as freshness warning
pub fn record_freshness_alert_fired(severity: &str) {
    record_alert_fired("freshness", severity);
}

/// Convenience: record successful alert delivery
pub fn record_alert_delivered(alert_type: &str) {
    record_alert_delivery("delivered", alert_type);
}

/// Convenience: record failed alert delivery
pub fn record_alert_delivery_failed(alert_type: &str) {
    record_alert_delivery("failed", alert_type);
}

// =============================================================================
// Data Contract Metrics Helper Functions (v0.9.0)
// =============================================================================

/// Record a contract check result
pub fn record_contract_check(result: &str, contract_type: &str) {
    CONTRACTS_CHECKS_TOTAL
        .with_label_values(&[result, contract_type])
        .inc();
}

/// Record a contract violation
pub fn record_contract_violation(contract_type: &str, on_violation: &str) {
    CONTRACTS_VIOLATIONS_TOTAL
        .with_label_values(&[contract_type, on_violation])
        .inc();
}

/// Convenience: record a passing contract check
pub fn record_contract_pass(contract_type: &str) {
    record_contract_check("pass", contract_type);
}

/// Convenience: record a failing contract check
pub fn record_contract_fail(contract_type: &str) {
    record_contract_check("fail", contract_type);
}

// =============================================================================
// Column-Level Lineage Metrics Helper Functions (v0.10.0)
// =============================================================================

/// Record a lineage operation (parse, record, delete)
pub fn record_lineage_operation(operation: &str, status: &str) {
    LINEAGE_OPERATIONS_TOTAL
        .with_label_values(&[operation, status])
        .inc();
}

/// Record a successful lineage operation
pub fn record_lineage_operation_success(operation: &str) {
    record_lineage_operation(operation, "success");
}

/// Record a failed lineage operation
pub fn record_lineage_operation_error(operation: &str) {
    record_lineage_operation(operation, "error");
}

/// Record a lineage query
pub fn record_lineage_query(query_type: &str, status: &str) {
    LINEAGE_QUERIES_TOTAL
        .with_label_values(&[query_type, status])
        .inc();
}

/// Record lineage query duration
pub fn record_lineage_query_duration(query_type: &str, duration_secs: f64) {
    LINEAGE_QUERY_DURATION_SECONDS
        .with_label_values(&[query_type])
        .observe(duration_secs);
}

/// Update the total lineage edges gauge
pub fn update_lineage_edges_total(count: i64) {
    LINEAGE_EDGES_TOTAL.set(count as f64);
}

/// Record lineage transformation type
pub fn record_lineage_transformation(transformation_type: &str) {
    LINEAGE_TRANSFORMATIONS_TOTAL
        .with_label_values(&[transformation_type])
        .inc();
}

/// Convenience: record successful upstream lineage query
pub fn record_upstream_lineage_query_success() {
    record_lineage_query("upstream", "success");
}

/// Convenience: record successful downstream lineage query
pub fn record_downstream_lineage_query_success() {
    record_lineage_query("downstream", "success");
}

/// Convenience: record successful PII propagation query
pub fn record_pii_propagation_query_success() {
    record_lineage_query("pii_propagation", "success");
}

/// Convenience: record successful impact analysis query
pub fn record_impact_analysis_query_success() {
    record_lineage_query("impact", "success");
}

/// Convenience: record successful lineage parse
pub fn record_lineage_parse_success() {
    record_lineage_operation_success("parse");
}

/// Convenience: record failed lineage parse
pub fn record_lineage_parse_error() {
    record_lineage_operation_error("parse");
}

/// Convenience: record successful lineage record
pub fn record_lineage_record_success() {
    record_lineage_operation_success("record");
}

/// Convenience: record successful lineage delete
pub fn record_lineage_delete_success() {
    record_lineage_operation_success("delete");
}
