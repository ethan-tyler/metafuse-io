//! Health Check Module
//!
//! Provides Kubernetes-compatible health endpoints:
//! - `/health` - Basic health check (returns "ok")
//! - `/ready` - Readiness probe (checks database connectivity)
//! - `/live` - Liveness probe (always returns healthy if the process is running)
//!
//! # Usage
//!
//! Kubernetes probes should be configured as:
//! ```yaml
//! livenessProbe:
//!   httpGet:
//!     path: /live
//!     port: 8080
//!   initialDelaySeconds: 5
//!   periodSeconds: 10
//! readinessProbe:
//!   httpGet:
//!     path: /ready
//!     port: 8080
//!   initialDelaySeconds: 5
//!   periodSeconds: 5
//! ```

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

use crate::AppState;

/// Health check response with detailed status
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<ComponentHealth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Health status enumeration
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    #[allow(dead_code)] // Reserved for partial failure scenarios (e.g., degraded cache)
    Degraded,
    Unhealthy,
}

/// Component health status
#[derive(Debug, Serialize)]
pub struct ComponentHealth {
    pub status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Basic health check - always returns "ok" if the server is running
///
/// This is the simplest health check, suitable for load balancers.
pub async fn health_check() -> &'static str {
    "ok"
}

/// Liveness probe - indicates if the application is running
///
/// This check always succeeds if the server process is alive.
/// Kubernetes uses this to decide if the container should be restarted.
pub async fn liveness_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: HealthStatus::Healthy,
            database: None,
            message: Some("Service is alive".to_string()),
        }),
    )
}

/// Readiness probe - indicates if the application is ready to serve traffic
///
/// This check verifies database connectivity. Kubernetes uses this to decide
/// if traffic should be routed to this pod.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    let start = std::time::Instant::now();

    // Check database connectivity
    let db_health = match check_database_health(&state).await {
        Ok(latency_ms) => ComponentHealth {
            status: HealthStatus::Healthy,
            latency_ms: Some(latency_ms),
            message: None,
        },
        Err(e) => ComponentHealth {
            status: HealthStatus::Unhealthy,
            latency_ms: None,
            message: Some(e),
        },
    };

    let overall_status = db_health.status;
    let status_code = match overall_status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK, // Still serve traffic if degraded
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    let response = HealthResponse {
        status: overall_status,
        database: Some(db_health),
        message: if overall_status == HealthStatus::Healthy {
            Some("Service is ready".to_string())
        } else {
            Some("Service is not ready".to_string())
        },
    };

    tracing::debug!(
        status = ?overall_status,
        latency_ms = start.elapsed().as_millis(),
        "Readiness check completed"
    );

    (status_code, Json(response))
}

/// Check database health by executing a simple query
async fn check_database_health(state: &AppState) -> Result<u64, String> {
    let start = std::time::Instant::now();

    let conn = state
        .backend
        .get_connection()
        .await
        .map_err(|e| format!("Failed to get connection: {}", e))?;

    // Execute a simple query to verify database is responsive
    conn.query_row("SELECT 1", [], |_| Ok(()))
        .map_err(|e| format!("Database query failed: {}", e))?;

    Ok(start.elapsed().as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let result = health_check().await;
        assert_eq!(result, "ok");
    }
}
