//! Prometheus metrics for the MetaFuse catalog API
//!
//! This module is only compiled when the `metrics` feature is enabled.
//!
//! Exposed metrics:
//! - `http_requests_total` - Counter for total HTTP requests
//! - `http_request_duration_seconds` - Histogram for request latencies
//! - `catalog_operations_total` - Counter for catalog operations
//! - `catalog_datasets_total` - Gauge for total datasets in catalog

use axum::{
    extract::{MatchedPath, Request},
    http::StatusCode,
    middleware::Next,
    response::IntoResponse,
};
use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Encoder, Gauge,
    HistogramVec, TextEncoder,
};
use std::time::Instant;

lazy_static! {
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
}

/// Axum middleware to track HTTP request metrics
pub async fn track_metrics(req: Request, next: Next) -> impl IntoResponse {
    let start = Instant::now();
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let response = next.run(req).await;
    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    // Record metrics
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&method, &path, &status])
        .inc();

    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[&method, &path])
        .observe(duration);

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
