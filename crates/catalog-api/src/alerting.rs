//! Alerting Module (v0.9.0)
//!
//! This module provides webhook-based alerting for MetaFuse datasets, including:
//! - Freshness alerts (dataset hasn't updated within expected interval)
//! - Quality alerts (data quality scores below threshold)
//! - Schema alerts (schema drift detected)
//! - Contract alerts (data contract violations)
//!
//! # Architecture
//!
//! Uses a background task pattern similar to `usage_analytics.rs`:
//! - Periodically scans datasets with `freshness_config.alert_on_stale = 1`
//! - Checks if dataset is stale (last_updated + expected_interval + grace > now)
//! - Fires webhooks to configured `alert_channels`
//! - Records alerts in `alert_history` with delivery tracking
//!
//! # Webhook Payload
//!
//! Designed for Servo integration with enhanced context:
//! ```json
//! {
//!   "alert_type": "freshness",
//!   "severity": "warning",
//!   "dataset_name": "orders",
//!   "message": "Dataset 'orders' is stale",
//!   "details": { "staleness_secs": 7200, "expected_interval_secs": 3600 },
//!   "integration_id": "...",
//!   "source_system": "metafuse",
//!   "customer_visible": false,
//!   "timestamp": "2024-01-15T10:30:00Z"
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

#[cfg(feature = "metrics")]
use crate::metrics;

#[cfg(feature = "alerting")]
use rand::Rng;

/// Default alert check interval in seconds
const DEFAULT_CHECK_INTERVAL_SECS: u64 = 60;

/// Maximum webhook delivery attempts before giving up
const MAX_DELIVERY_ATTEMPTS: u32 = 3;

/// Timeout for webhook requests
const WEBHOOK_TIMEOUT_SECS: u64 = 10;

/// Cooldown period before re-alerting same condition (in seconds)
const ALERT_COOLDOWN_SECS: i64 = 3600; // 1 hour

/// Jitter factor for retry delays (±25%)
const JITTER_FACTOR: f64 = 0.25;

/// Redact a webhook URL for safe logging (hide path and query params).
///
/// Example: `https://hooks.example.com/webhook/secret123?token=abc` -> `https://hooks.example.com/***`
#[cfg(feature = "alerting")]
fn redact_url(url: &str) -> String {
    // Find scheme separator
    if let Some(scheme_end) = url.find("://") {
        let after_scheme = &url[scheme_end + 3..];
        // Find first slash after domain (path start)
        if let Some(path_start) = after_scheme.find('/') {
            return format!("{}/***", &url[..scheme_end + 3 + path_start]);
        }
        // No path - URL is just domain
        return format!("{}/***", url);
    }
    // Fallback: couldn't parse, fully redact
    "***".to_string()
}

/// Alert types corresponding to `alert_history.alert_type`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    /// Dataset freshness violation
    Freshness,
    /// Data quality issue
    Quality,
    /// Schema drift detected
    Schema,
    /// Data contract violation
    Contract,
}

impl AlertType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertType::Freshness => "freshness",
            AlertType::Quality => "quality",
            AlertType::Schema => "schema",
            AlertType::Contract => "contract",
        }
    }
}

impl std::fmt::Display for AlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational (no action required)
    Info,
    /// Warning (attention needed)
    Warning,
    /// Critical (immediate action required)
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Webhook payload for Servo integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    /// Type of alert
    pub alert_type: AlertType,
    /// Severity level
    pub severity: Severity,
    /// Dataset name that triggered the alert
    pub dataset_name: String,
    /// Dataset ID (optional, for internal tracking)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<i64>,
    /// Human-readable message
    pub message: String,
    /// Alert-specific context (JSON-serializable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Integration ID for Servo correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration_id: Option<String>,
    /// Source system identifier
    pub source_system: String,
    /// Whether this should be shown to customers
    pub customer_visible: bool,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Alert history ID (for tracking)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_history_id: Option<i64>,
}

impl AlertPayload {
    /// Create a new freshness alert payload
    pub fn freshness(
        dataset_name: &str,
        dataset_id: i64,
        staleness_secs: i64,
        expected_interval_secs: i64,
    ) -> Self {
        let severity = if staleness_secs >= expected_interval_secs * 4 {
            Severity::Critical
        } else if staleness_secs >= expected_interval_secs * 2 {
            Severity::Warning
        } else {
            Severity::Info
        };

        Self {
            alert_type: AlertType::Freshness,
            severity,
            dataset_name: dataset_name.to_string(),
            dataset_id: Some(dataset_id),
            message: format!("Dataset '{}' is stale", dataset_name),
            details: Some(serde_json::json!({
                "staleness_secs": staleness_secs,
                "expected_interval_secs": expected_interval_secs,
            })),
            integration_id: None,
            source_system: "metafuse".to_string(),
            customer_visible: false,
            timestamp: chrono::Utc::now().to_rfc3339(),
            alert_history_id: None,
        }
    }

    /// Create a quality alert payload
    pub fn quality(
        dataset_name: &str,
        dataset_id: i64,
        score: f64,
        threshold: f64,
        metric_type: &str,
    ) -> Self {
        let severity = if score < threshold * 0.5 {
            Severity::Critical
        } else {
            Severity::Warning
        };

        Self {
            alert_type: AlertType::Quality,
            severity,
            dataset_name: dataset_name.to_string(),
            dataset_id: Some(dataset_id),
            message: format!(
                "Dataset '{}' {} score ({:.1}%) below threshold ({:.1}%)",
                dataset_name,
                metric_type,
                score * 100.0,
                threshold * 100.0
            ),
            details: Some(serde_json::json!({
                "metric_type": metric_type,
                "score": score,
                "threshold": threshold,
            })),
            integration_id: None,
            source_system: "metafuse".to_string(),
            customer_visible: false,
            timestamp: chrono::Utc::now().to_rfc3339(),
            alert_history_id: None,
        }
    }

    /// Create a schema change alert payload
    pub fn schema_change(
        dataset_name: &str,
        dataset_id: i64,
        added_columns: &[String],
        removed_columns: &[String],
        changed_columns: &[String],
    ) -> Self {
        let severity = if !removed_columns.is_empty() {
            Severity::Warning
        } else {
            Severity::Info
        };

        Self {
            alert_type: AlertType::Schema,
            severity,
            dataset_name: dataset_name.to_string(),
            dataset_id: Some(dataset_id),
            message: format!("Schema changed for dataset '{}'", dataset_name),
            details: Some(serde_json::json!({
                "added_columns": added_columns,
                "removed_columns": removed_columns,
                "changed_columns": changed_columns,
            })),
            integration_id: None,
            source_system: "metafuse".to_string(),
            customer_visible: false,
            timestamp: chrono::Utc::now().to_rfc3339(),
            alert_history_id: None,
        }
    }

    /// Create a contract violation alert payload
    pub fn contract_violation(
        dataset_name: &str,
        dataset_id: i64,
        contract_name: &str,
        violations: &[String],
    ) -> Self {
        Self {
            alert_type: AlertType::Contract,
            severity: Severity::Warning,
            dataset_name: dataset_name.to_string(),
            dataset_id: Some(dataset_id),
            message: format!(
                "Dataset '{}' violates contract '{}'",
                dataset_name, contract_name
            ),
            details: Some(serde_json::json!({
                "contract_name": contract_name,
                "violations": violations,
            })),
            integration_id: None,
            source_system: "metafuse".to_string(),
            customer_visible: false,
            timestamp: chrono::Utc::now().to_rfc3339(),
            alert_history_id: None,
        }
    }

    /// Set integration ID for Servo correlation
    pub fn with_integration_id(mut self, id: Option<String>) -> Self {
        self.integration_id = id;
        self
    }

    /// Mark as customer visible
    pub fn with_customer_visible(mut self, visible: bool) -> Self {
        self.customer_visible = visible;
        self
    }

    /// Set alert history ID
    pub fn with_alert_history_id(mut self, id: i64) -> Self {
        self.alert_history_id = Some(id);
        self
    }
}

/// Configuration for the alerting system
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// How often to check for stale datasets (seconds)
    pub check_interval_secs: u64,
    /// Cooldown between re-alerting same condition (seconds)
    pub cooldown_secs: i64,
    /// Whether alerting is enabled
    pub enabled: bool,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: DEFAULT_CHECK_INTERVAL_SECS,
            cooldown_secs: ALERT_COOLDOWN_SECS,
            enabled: true,
        }
    }
}

/// Webhook delivery client
#[cfg(feature = "alerting")]
pub struct WebhookClient {
    client: reqwest::Client,
    config: AlertConfig,
}

#[cfg(feature = "alerting")]
impl WebhookClient {
    /// Create a new webhook client
    pub fn new(config: AlertConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(WEBHOOK_TIMEOUT_SECS))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    /// Create with default config
    pub fn new_default() -> Self {
        Self::new(AlertConfig::default())
    }

    /// Send alert payload to a webhook URL
    pub async fn send(&self, url: &str, payload: &AlertPayload) -> Result<(), WebhookError> {
        #[cfg(feature = "metrics")]
        let start = std::time::Instant::now();

        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|e| WebhookError::Network(e.to_string()))?;

        let status_code = response.status().as_u16();

        // Record metrics (variables only computed when feature is enabled)
        #[cfg(feature = "metrics")]
        {
            let alert_type = payload.alert_type.as_str();
            let duration = start.elapsed().as_secs_f64();
            metrics::record_webhook_request(status_code, alert_type);
            metrics::record_webhook_duration(alert_type, duration);
        }

        if response.status().is_success() {
            Ok(())
        } else {
            Err(WebhookError::HttpStatus(
                status_code,
                response.text().await.unwrap_or_default(),
            ))
        }
    }

    /// Send with retry logic and jitter
    ///
    /// Uses exponential backoff with ±25% jitter to prevent thundering herd.
    /// URL is redacted in logs to avoid leaking secrets in paths/query params.
    pub async fn send_with_retry(
        &self,
        url: &str,
        payload: &AlertPayload,
        max_attempts: u32,
    ) -> Result<u32, WebhookError> {
        let mut attempts = 0;
        let mut last_error = None;
        let redacted = redact_url(url);

        while attempts < max_attempts {
            attempts += 1;

            match self.send(url, payload).await {
                Ok(()) => return Ok(attempts),
                Err(e) => {
                    warn!(
                        webhook_url = %redacted,
                        attempt = attempts,
                        max_attempts,
                        error = %e,
                        "Webhook delivery failed, will retry"
                    );
                    last_error = Some(e);

                    if attempts < max_attempts {
                        // Exponential backoff: 100ms, 200ms, 400ms base
                        let base_delay_ms = 100u64 * (1 << (attempts - 1));

                        // Add ±25% jitter to prevent thundering herd
                        let jitter_range = (base_delay_ms as f64 * JITTER_FACTOR) as u64;
                        let jitter = if jitter_range > 0 {
                            let mut rng = rand::thread_rng();
                            rng.gen_range(0..jitter_range * 2) as i64 - jitter_range as i64
                        } else {
                            0
                        };

                        let delay_ms = (base_delay_ms as i64 + jitter).max(10) as u64;
                        let delay = Duration::from_millis(delay_ms);

                        debug!(
                            base_delay_ms,
                            jitter,
                            actual_delay_ms = delay_ms,
                            "Waiting before retry"
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        error!(
            webhook_url = %redacted,
            attempts,
            "Webhook delivery permanently failed after all retries"
        );
        Err(last_error.unwrap_or(WebhookError::MaxRetriesExceeded))
    }

    /// Get config
    pub fn config(&self) -> &AlertConfig {
        &self.config
    }
}

/// Webhook delivery errors
#[derive(Debug)]
pub enum WebhookError {
    /// Network error
    Network(String),
    /// HTTP error status
    HttpStatus(u16, String),
    /// Max retries exceeded
    MaxRetriesExceeded,
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookError::Network(e) => write!(f, "Network error: {}", e),
            WebhookError::HttpStatus(code, body) => {
                write!(f, "HTTP {} error: {}", code, body)
            }
            WebhookError::MaxRetriesExceeded => write!(f, "Max retries exceeded"),
        }
    }
}

impl std::error::Error for WebhookError {}

// =============================================================================
// Database Operations
// =============================================================================

/// Record an alert in alert_history
///
/// The tenant_id parameter enables multi-tenant isolation for alert history.
/// If not provided, alerts are not scoped to a tenant (legacy behavior).
#[allow(clippy::too_many_arguments)]
pub fn record_alert(
    conn: &rusqlite::Connection,
    alert_type: AlertType,
    dataset_id: Option<i64>,
    severity: Severity,
    message: &str,
    details: Option<&str>,
    channels_notified: Option<&str>,
    tenant_id: Option<&str>,
) -> Result<i64, rusqlite::Error> {
    conn.execute(
        r#"
        INSERT INTO alert_history
            (alert_type, dataset_id, severity, message, details, channels_notified, delivery_status, delivery_attempts, created_at, tenant_id)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', 0, datetime('now'), ?7)
        "#,
        rusqlite::params![
            alert_type.as_str(),
            dataset_id,
            severity.as_str(),
            message,
            details,
            channels_notified,
            tenant_id,
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Update alert delivery status
pub fn update_delivery_status(
    conn: &rusqlite::Connection,
    alert_id: i64,
    status: &str,
    attempts: i32,
    error: Option<&str>,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        r#"
        UPDATE alert_history
        SET delivery_status = ?1, delivery_attempts = ?2, delivery_error = ?3
        WHERE id = ?4
        "#,
        rusqlite::params![status, attempts, error, alert_id],
    )?;
    Ok(())
}

/// Mark alert as resolved
pub fn resolve_alert(conn: &rusqlite::Connection, alert_id: i64) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE alert_history SET resolved_at = datetime('now') WHERE id = ?1",
        [alert_id],
    )?;
    Ok(())
}

/// Check if we've alerted recently for this condition (cooldown check)
pub fn has_recent_alert(
    conn: &rusqlite::Connection,
    alert_type: AlertType,
    dataset_id: i64,
    cooldown_secs: i64,
) -> Result<bool, rusqlite::Error> {
    let count: i64 = conn.query_row(
        r#"
        SELECT COUNT(*) FROM alert_history
        WHERE alert_type = ?1
          AND dataset_id = ?2
          AND resolved_at IS NULL
          AND created_at > datetime('now', ?3 || ' seconds')
        "#,
        rusqlite::params![
            alert_type.as_str(),
            dataset_id,
            format!("-{}", cooldown_secs)
        ],
        |row| row.get(0),
    )?;

    Ok(count > 0)
}

/// Dataset info needed for freshness checks
#[derive(Debug)]
pub struct StaleDatasetInfo {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub tenant_id: Option<String>,
    pub last_updated: String,
    pub expected_interval_secs: i64,
    pub grace_period_secs: i64,
    pub alert_channels: Option<String>,
    pub staleness_secs: i64,
}

/// Find datasets that are stale and should be alerted
pub fn find_stale_datasets(
    conn: &rusqlite::Connection,
) -> Result<Vec<StaleDatasetInfo>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        r#"
        SELECT
            d.id,
            d.name,
            d.tenant,
            d.last_updated,
            fc.expected_interval_secs,
            fc.grace_period_secs,
            fc.alert_channels,
            CAST((julianday('now') - julianday(d.last_updated)) * 86400 AS INTEGER) as staleness_secs
        FROM datasets d
        JOIN freshness_config fc ON d.id = fc.dataset_id
        WHERE fc.alert_on_stale = 1
          AND d.last_updated IS NOT NULL
          AND (julianday('now') - julianday(d.last_updated)) * 86400 > (fc.expected_interval_secs + fc.grace_period_secs)
        "#,
    )?;

    let results = stmt
        .query_map([], |row| {
            Ok(StaleDatasetInfo {
                dataset_id: row.get(0)?,
                dataset_name: row.get(1)?,
                tenant_id: row.get(2)?,
                last_updated: row.get(3)?,
                expected_interval_secs: row.get(4)?,
                grace_period_secs: row.get(5)?,
                alert_channels: row.get(6)?,
                staleness_secs: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Info for a quality check failure that needs alerting
#[derive(Debug, Clone)]
pub struct QualityAlertInfo {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub tenant_id: Option<String>,
    pub check_id: String,
    pub check_name: String,
    pub check_type: String,
    pub status: String,
    pub score: Option<f64>,
    pub threshold: Option<f64>,
    pub error_message: Option<String>,
    pub alert_channels: Option<String>,
}

/// Find quality check failures that need alerting
/// Returns recent failed/error results that haven't been alerted recently
pub fn find_quality_failures(
    conn: &rusqlite::Connection,
) -> Result<Vec<QualityAlertInfo>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        r#"
        SELECT
            d.id,
            d.name,
            d.tenant,
            qc.id,
            qc.name,
            qc.check_type,
            qr.status,
            qr.score,
            qc.threshold,
            qr.error_message,
            qc.alert_channels
        FROM quality_results qr
        JOIN quality_checks qc ON qr.check_id = qc.id
        JOIN datasets d ON qc.dataset_id = d.id
        WHERE qr.status IN ('Failed', 'Error')
          AND qc.enabled = 1
          AND qc.alert_channels IS NOT NULL
          AND qr.executed_at > datetime('now', '-1 hour')
        ORDER BY qr.executed_at DESC
        "#,
    )?;

    let results = stmt
        .query_map([], |row| {
            Ok(QualityAlertInfo {
                dataset_id: row.get(0)?,
                dataset_name: row.get(1)?,
                tenant_id: row.get(2)?,
                check_id: row.get(3)?,
                check_name: row.get(4)?,
                check_type: row.get(5)?,
                status: row.get(6)?,
                score: row.get(7)?,
                threshold: row.get(8)?,
                error_message: row.get(9)?,
                alert_channels: row.get(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Info for a freshness violation that needs alerting
#[derive(Debug, Clone)]
pub struct FreshnessViolationAlertInfo {
    pub violation_id: String,
    pub dataset_id: i64,
    pub dataset_name: String,
    pub tenant_id: Option<String>,
    pub expected_by: String,
    pub detected_at: String,
    pub sla: String,
    pub hours_overdue: Option<f64>,
    pub alert_channels: Option<String>,
}

/// Find freshness violations that haven't been alerted yet
pub fn find_unalerted_freshness_violations(
    conn: &rusqlite::Connection,
) -> Result<Vec<FreshnessViolationAlertInfo>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        r#"
        SELECT
            fv.id,
            fv.dataset_id,
            d.name,
            d.tenant,
            fv.expected_by,
            fv.detected_at,
            fv.sla,
            fv.hours_overdue,
            fc.alert_channels
        FROM freshness_violations fv
        JOIN datasets d ON fv.dataset_id = d.id
        LEFT JOIN freshness_config fc ON d.id = fc.dataset_id
        WHERE fv.alert_sent = 0
          AND fv.resolved_at IS NULL
        ORDER BY fv.detected_at ASC
        "#,
    )?;

    let results = stmt
        .query_map([], |row| {
            Ok(FreshnessViolationAlertInfo {
                violation_id: row.get(0)?,
                dataset_id: row.get(1)?,
                dataset_name: row.get(2)?,
                tenant_id: row.get(3)?,
                expected_by: row.get(4)?,
                detected_at: row.get(5)?,
                sla: row.get(6)?,
                hours_overdue: row.get(7)?,
                alert_channels: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Mark a freshness violation as alerted
pub fn mark_freshness_violation_alerted(
    conn: &rusqlite::Connection,
    violation_id: &str,
    alert_id: i64,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE freshness_violations SET alert_sent = 1, alert_id = ?1 WHERE id = ?2",
        rusqlite::params![alert_id.to_string(), violation_id],
    )?;
    Ok(())
}

// =============================================================================
// Background Task
// =============================================================================

/// Background task that periodically checks for freshness alerts
#[cfg(feature = "alerting")]
pub async fn alert_check_task(
    webhook_client: Arc<WebhookClient>,
    backend: Arc<metafuse_catalog_storage::DynCatalogBackend>,
) {
    let interval = Duration::from_secs(webhook_client.config().check_interval_secs);
    let cooldown = webhook_client.config().cooldown_secs;

    info!(
        interval_secs = webhook_client.config().check_interval_secs,
        "Alert check task started"
    );

    loop {
        tokio::time::sleep(interval).await;

        if !webhook_client.config().enabled {
            debug!("Alerting disabled, skipping check");
            continue;
        }

        debug!("Running periodic alert check");

        // Mark alert check as active
        #[cfg(feature = "metrics")]
        metrics::set_alert_check_active(true);

        match backend.get_connection().await {
            Ok(conn) => {
                // Find stale datasets
                let stale_datasets = match find_stale_datasets(&conn) {
                    Ok(datasets) => datasets,
                    Err(e) => {
                        error!(error = %e, "Failed to query stale datasets");
                        continue;
                    }
                };

                for ds in stale_datasets {
                    // Check cooldown
                    let has_recent = match has_recent_alert(
                        &conn,
                        AlertType::Freshness,
                        ds.dataset_id,
                        cooldown,
                    ) {
                        Ok(has) => has,
                        Err(e) => {
                            error!(
                                dataset_id = ds.dataset_id,
                                error = %e,
                                "Failed to check alert cooldown"
                            );
                            continue;
                        }
                    };

                    if has_recent {
                        debug!(
                            dataset_id = ds.dataset_id,
                            dataset_name = ds.dataset_name,
                            "Skipping alert due to cooldown"
                        );
                        continue;
                    }

                    // Create alert payload
                    let payload = AlertPayload::freshness(
                        &ds.dataset_name,
                        ds.dataset_id,
                        ds.staleness_secs,
                        ds.expected_interval_secs,
                    );

                    // Parse alert channels
                    let channels: Vec<String> = ds
                        .alert_channels
                        .as_ref()
                        .and_then(|c| serde_json::from_str(c).ok())
                        .unwrap_or_default();

                    if channels.is_empty() {
                        debug!(
                            dataset_id = ds.dataset_id,
                            "No alert channels configured, skipping"
                        );
                        continue;
                    }

                    // Record alert in history with tenant isolation
                    let alert_id = match record_alert(
                        &conn,
                        AlertType::Freshness,
                        Some(ds.dataset_id),
                        payload.severity,
                        &payload.message,
                        payload.details.as_ref().map(|d| d.to_string()).as_deref(),
                        ds.alert_channels.as_deref(),
                        ds.tenant_id.as_deref(),
                    ) {
                        Ok(id) => {
                            // Record alert fired metric
                            #[cfg(feature = "metrics")]
                            metrics::record_alert_fired(
                                AlertType::Freshness.as_str(),
                                payload.severity.as_str(),
                            );
                            id
                        }
                        Err(e) => {
                            error!(
                                dataset_id = ds.dataset_id,
                                error = %e,
                                "Failed to record alert"
                            );
                            continue;
                        }
                    };

                    let payload = payload.with_alert_history_id(alert_id);

                    // Deliver to all channels
                    let mut delivery_success = true;
                    let mut total_attempts = 0;
                    let mut last_error: Option<String> = None;

                    for channel in &channels {
                        // Strip webhook: prefix if present
                        let url = channel.strip_prefix("webhook:").unwrap_or(channel);
                        let redacted = redact_url(url);

                        match webhook_client
                            .send_with_retry(url, &payload, MAX_DELIVERY_ATTEMPTS)
                            .await
                        {
                            Ok(attempts) => {
                                total_attempts += attempts;
                                info!(
                                    alert_id,
                                    dataset_name = ds.dataset_name,
                                    webhook_url = %redacted,
                                    attempts,
                                    "Alert delivered successfully"
                                );
                            }
                            Err(e) => {
                                total_attempts += MAX_DELIVERY_ATTEMPTS;
                                delivery_success = false;
                                last_error = Some(e.to_string());
                                error!(
                                    alert_id,
                                    dataset_name = ds.dataset_name,
                                    webhook_url = %redacted,
                                    error = %e,
                                    "Alert delivery failed"
                                );
                            }
                        }
                    }

                    // Update delivery status
                    let status = if delivery_success {
                        "delivered"
                    } else {
                        "failed"
                    };
                    if let Err(e) = update_delivery_status(
                        &conn,
                        alert_id,
                        status,
                        total_attempts as i32,
                        last_error.as_deref(),
                    ) {
                        error!(
                            alert_id,
                            error = %e,
                            "Failed to update delivery status"
                        );
                    }

                    // Record delivery outcome metric
                    #[cfg(feature = "metrics")]
                    {
                        if delivery_success {
                            metrics::record_alert_delivered(AlertType::Freshness.as_str());
                        } else {
                            metrics::record_alert_delivery_failed(AlertType::Freshness.as_str());
                        }
                    }
                }

                // =================================================================
                // Process Quality Check Failures
                // =================================================================
                let quality_failures = match find_quality_failures(&conn) {
                    Ok(failures) => failures,
                    Err(e) => {
                        error!(error = %e, "Failed to query quality failures");
                        vec![]
                    }
                };

                for qf in quality_failures {
                    // Check cooldown - use check_id as part of message to differentiate
                    let has_recent = match has_recent_alert(
                        &conn,
                        AlertType::Quality,
                        qf.dataset_id,
                        cooldown,
                    ) {
                        Ok(has) => has,
                        Err(e) => {
                            error!(
                                dataset_id = qf.dataset_id,
                                check_id = qf.check_id,
                                error = %e,
                                "Failed to check alert cooldown"
                            );
                            continue;
                        }
                    };

                    if has_recent {
                        debug!(
                            dataset_id = qf.dataset_id,
                            check_name = qf.check_name,
                            "Skipping quality alert due to cooldown"
                        );
                        continue;
                    }

                    // Create quality alert payload
                    let score = qf.score.unwrap_or(0.0);
                    let threshold = qf.threshold.unwrap_or(0.9);
                    let payload = AlertPayload::quality(
                        &qf.dataset_name,
                        qf.dataset_id,
                        score,
                        threshold,
                        &qf.check_type,
                    );

                    // Parse alert channels
                    let channels: Vec<String> = qf
                        .alert_channels
                        .as_ref()
                        .and_then(|c| serde_json::from_str(c).ok())
                        .unwrap_or_default();

                    if channels.is_empty() {
                        debug!(
                            dataset_id = qf.dataset_id,
                            check_name = qf.check_name,
                            "No alert channels configured, skipping"
                        );
                        continue;
                    }

                    // Record alert
                    let alert_id = match record_alert(
                        &conn,
                        AlertType::Quality,
                        Some(qf.dataset_id),
                        payload.severity,
                        &payload.message,
                        payload.details.as_ref().map(|d| d.to_string()).as_deref(),
                        qf.alert_channels.as_deref(),
                        qf.tenant_id.as_deref(),
                    ) {
                        Ok(id) => {
                            #[cfg(feature = "metrics")]
                            metrics::record_alert_fired(
                                AlertType::Quality.as_str(),
                                payload.severity.as_str(),
                            );
                            id
                        }
                        Err(e) => {
                            error!(
                                dataset_id = qf.dataset_id,
                                check_name = qf.check_name,
                                error = %e,
                                "Failed to record quality alert"
                            );
                            continue;
                        }
                    };

                    let payload = payload.with_alert_history_id(alert_id);

                    // Deliver to channels
                    let mut delivery_success = true;
                    let mut total_attempts = 0;
                    let mut last_error: Option<String> = None;

                    for channel in &channels {
                        let url = channel.strip_prefix("webhook:").unwrap_or(channel);
                        let redacted = redact_url(url);

                        match webhook_client
                            .send_with_retry(url, &payload, MAX_DELIVERY_ATTEMPTS)
                            .await
                        {
                            Ok(attempts) => {
                                total_attempts += attempts;
                                info!(
                                    alert_id,
                                    check_name = qf.check_name,
                                    dataset_name = qf.dataset_name,
                                    webhook_url = %redacted,
                                    attempts,
                                    "Quality alert delivered successfully"
                                );
                            }
                            Err(e) => {
                                total_attempts += MAX_DELIVERY_ATTEMPTS;
                                delivery_success = false;
                                last_error = Some(e.to_string());
                                error!(
                                    alert_id,
                                    check_name = qf.check_name,
                                    webhook_url = %redacted,
                                    error = %e,
                                    "Quality alert delivery failed"
                                );
                            }
                        }
                    }

                    // Update delivery status
                    let status = if delivery_success {
                        "delivered"
                    } else {
                        "failed"
                    };
                    if let Err(e) = update_delivery_status(
                        &conn,
                        alert_id,
                        status,
                        total_attempts as i32,
                        last_error.as_deref(),
                    ) {
                        error!(alert_id, error = %e, "Failed to update delivery status");
                    }

                    #[cfg(feature = "metrics")]
                    {
                        if delivery_success {
                            metrics::record_alert_delivered(AlertType::Quality.as_str());
                        } else {
                            metrics::record_alert_delivery_failed(AlertType::Quality.as_str());
                        }
                    }
                }

                // =================================================================
                // Process Freshness Violations (from freshness_violations table)
                // =================================================================
                let violations = match find_unalerted_freshness_violations(&conn) {
                    Ok(v) => v,
                    Err(e) => {
                        error!(error = %e, "Failed to query freshness violations");
                        vec![]
                    }
                };

                for violation in violations {
                    // Calculate staleness from expected_by
                    let staleness_secs = violation
                        .hours_overdue
                        .map(|h| (h * 3600.0) as i64)
                        .unwrap_or(0);

                    // Create freshness alert payload
                    let payload = AlertPayload::freshness(
                        &violation.dataset_name,
                        violation.dataset_id,
                        staleness_secs,
                        3600, // Default expected interval
                    );

                    // Parse alert channels
                    let channels: Vec<String> = violation
                        .alert_channels
                        .as_ref()
                        .and_then(|c| serde_json::from_str(c).ok())
                        .unwrap_or_default();

                    if channels.is_empty() {
                        debug!(
                            violation_id = violation.violation_id,
                            dataset_name = violation.dataset_name,
                            "No alert channels configured for violation, skipping"
                        );
                        // Still mark as alerted to prevent repeated processing
                        let _ = mark_freshness_violation_alerted(&conn, &violation.violation_id, 0);
                        continue;
                    }

                    // Record alert
                    let alert_id = match record_alert(
                        &conn,
                        AlertType::Freshness,
                        Some(violation.dataset_id),
                        payload.severity,
                        &payload.message,
                        payload.details.as_ref().map(|d| d.to_string()).as_deref(),
                        violation.alert_channels.as_deref(),
                        violation.tenant_id.as_deref(),
                    ) {
                        Ok(id) => {
                            #[cfg(feature = "metrics")]
                            metrics::record_alert_fired(
                                AlertType::Freshness.as_str(),
                                payload.severity.as_str(),
                            );
                            id
                        }
                        Err(e) => {
                            error!(
                                violation_id = violation.violation_id,
                                error = %e,
                                "Failed to record freshness violation alert"
                            );
                            continue;
                        }
                    };

                    // Mark violation as alerted
                    if let Err(e) =
                        mark_freshness_violation_alerted(&conn, &violation.violation_id, alert_id)
                    {
                        error!(
                            violation_id = violation.violation_id,
                            error = %e,
                            "Failed to mark violation as alerted"
                        );
                    }

                    let payload = payload.with_alert_history_id(alert_id);

                    // Deliver to channels
                    let mut delivery_success = true;
                    let mut total_attempts = 0;
                    let mut last_error: Option<String> = None;

                    for channel in &channels {
                        let url = channel.strip_prefix("webhook:").unwrap_or(channel);
                        let redacted = redact_url(url);

                        match webhook_client
                            .send_with_retry(url, &payload, MAX_DELIVERY_ATTEMPTS)
                            .await
                        {
                            Ok(attempts) => {
                                total_attempts += attempts;
                                info!(
                                    alert_id,
                                    violation_id = violation.violation_id,
                                    dataset_name = violation.dataset_name,
                                    webhook_url = %redacted,
                                    attempts,
                                    "Freshness violation alert delivered successfully"
                                );
                            }
                            Err(e) => {
                                total_attempts += MAX_DELIVERY_ATTEMPTS;
                                delivery_success = false;
                                last_error = Some(e.to_string());
                                error!(
                                    alert_id,
                                    violation_id = violation.violation_id,
                                    webhook_url = %redacted,
                                    error = %e,
                                    "Freshness violation alert delivery failed"
                                );
                            }
                        }
                    }

                    // Update delivery status
                    let status = if delivery_success {
                        "delivered"
                    } else {
                        "failed"
                    };
                    if let Err(e) = update_delivery_status(
                        &conn,
                        alert_id,
                        status,
                        total_attempts as i32,
                        last_error.as_deref(),
                    ) {
                        error!(alert_id, error = %e, "Failed to update delivery status");
                    }

                    #[cfg(feature = "metrics")]
                    {
                        if delivery_success {
                            metrics::record_alert_delivered(AlertType::Freshness.as_str());
                        } else {
                            metrics::record_alert_delivery_failed(AlertType::Freshness.as_str());
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to get connection for alert check");
            }
        }

        // Mark alert check as complete
        #[cfg(feature = "metrics")]
        metrics::set_alert_check_active(false);
    }
}

// =============================================================================
// API Types
// =============================================================================

/// Query parameters for alert history endpoint with pagination
#[derive(Debug, Clone, Deserialize)]
pub struct AlertHistoryParams {
    /// Filter by tenant ID (for multi-tenant isolation)
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Filter by alert type (freshness, quality, schema, contract)
    #[serde(default)]
    pub alert_type: Option<String>,
    /// Filter by dataset ID
    #[serde(default)]
    pub dataset_id: Option<i64>,
    /// Filter by severity (info, warning, critical)
    #[serde(default)]
    pub severity: Option<String>,
    /// Filter by delivery status (pending, delivered, failed)
    #[serde(default)]
    pub delivery_status: Option<String>,
    /// Include resolved alerts (default: false, show only active)
    #[serde(default)]
    pub include_resolved: bool,
    /// Pagination: number of results to skip
    #[serde(default)]
    pub offset: i64,
    /// Pagination: maximum results to return (default: 100, max: 1000)
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    100
}

fn max_limit() -> i64 {
    1000
}

/// Alert history entry for API responses
#[derive(Debug, Clone, Serialize)]
pub struct AlertHistoryEntry {
    pub id: i64,
    pub alert_type: String,
    pub dataset_id: Option<i64>,
    pub tenant_id: Option<String>,
    pub severity: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub delivery_status: String,
    pub delivery_attempts: i32,
    pub delivery_error: Option<String>,
    pub created_at: String,
    pub resolved_at: Option<String>,
}

/// Response for alert history endpoint with pagination metadata
#[derive(Debug, Clone, Serialize)]
pub struct AlertHistoryResponse {
    /// Alert entries for current page
    pub alerts: Vec<AlertHistoryEntry>,
    /// Total count of matching alerts (for pagination)
    pub total: i64,
    /// Current offset
    pub offset: i64,
    /// Current limit
    pub limit: i64,
    /// Whether there are more results beyond this page
    pub has_more: bool,
}

/// Query alert history with pagination and filtering
///
/// Supports multi-tenant isolation via optional tenant_id filter.
/// If tenant_id is provided, only alerts for that tenant are returned.
pub fn query_alert_history(
    conn: &rusqlite::Connection,
    params: &AlertHistoryParams,
) -> Result<AlertHistoryResponse, rusqlite::Error> {
    // Enforce limit bounds
    let limit = params.limit.min(max_limit()).max(1);
    let offset = params.offset.max(0);

    // Build WHERE clause for reuse in count and data queries
    let mut where_clause = String::from("WHERE 1=1");
    let mut bind_values: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    // Tenant isolation filter (CRITICAL for multi-tenant security)
    if let Some(ref tenant_id) = params.tenant_id {
        where_clause.push_str(" AND tenant_id = ?");
        bind_values.push(Box::new(tenant_id.clone()));
    }

    if let Some(ref alert_type) = params.alert_type {
        where_clause.push_str(" AND alert_type = ?");
        bind_values.push(Box::new(alert_type.clone()));
    }

    if let Some(dataset_id) = params.dataset_id {
        where_clause.push_str(" AND dataset_id = ?");
        bind_values.push(Box::new(dataset_id));
    }

    if let Some(ref severity) = params.severity {
        where_clause.push_str(" AND severity = ?");
        bind_values.push(Box::new(severity.clone()));
    }

    if let Some(ref delivery_status) = params.delivery_status {
        where_clause.push_str(" AND delivery_status = ?");
        bind_values.push(Box::new(delivery_status.clone()));
    }

    if !params.include_resolved {
        where_clause.push_str(" AND resolved_at IS NULL");
    }

    // Count total matching alerts for pagination
    let count_sql = format!("SELECT COUNT(*) FROM alert_history {}", where_clause);
    let count_params: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();
    let total: i64 = conn.query_row(&count_sql, count_params.as_slice(), |row| row.get(0))?;

    // Fetch paginated results
    let data_sql = format!(
        r#"SELECT id, alert_type, dataset_id, tenant_id, severity, message, details,
                  delivery_status, delivery_attempts, delivery_error, created_at, resolved_at
           FROM alert_history
           {}
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?"#,
        where_clause
    );

    // Add limit and offset to bind values
    bind_values.push(Box::new(limit));
    bind_values.push(Box::new(offset));

    let mut stmt = conn.prepare(&data_sql)?;
    let params_refs: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();

    let alerts: Vec<AlertHistoryEntry> = stmt
        .query_map(params_refs.as_slice(), |row| {
            let details_str: Option<String> = row.get(6)?;
            let details = details_str.and_then(|s| serde_json::from_str(&s).ok());

            Ok(AlertHistoryEntry {
                id: row.get(0)?,
                alert_type: row.get(1)?,
                dataset_id: row.get(2)?,
                tenant_id: row.get(3)?,
                severity: row.get(4)?,
                message: row.get(5)?,
                details,
                delivery_status: row.get(7)?,
                delivery_attempts: row.get(8)?,
                delivery_error: row.get(9)?,
                created_at: row.get(10)?,
                resolved_at: row.get(11)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let has_more = offset + (alerts.len() as i64) < total;

    Ok(AlertHistoryResponse {
        alerts,
        total,
        offset,
        limit,
        has_more,
    })
}

// =============================================================================
// Schema Change Detection (v0.11.0)
// =============================================================================

/// Configuration for schema change monitoring
#[derive(Debug, Clone)]
pub struct SchemaMonitorConfig {
    /// How often to check for schema changes (seconds)
    pub check_interval_secs: u64,
    /// Whether schema monitoring is enabled
    pub enabled: bool,
    /// Cooldown between re-alerting same dataset (seconds)
    pub cooldown_secs: i64,
}

impl Default for SchemaMonitorConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 300, // Check every 5 minutes
            enabled: true,
            cooldown_secs: ALERT_COOLDOWN_SECS,
        }
    }
}

/// Information about a dataset that needs schema monitoring
#[derive(Debug, Clone)]
pub struct SchemaMonitorTarget {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub tenant_id: Option<String>,
    pub delta_location: String,
    pub alert_channels: Option<String>,
}

/// Find datasets with delta_location that need schema monitoring
pub fn find_datasets_for_schema_check(
    conn: &rusqlite::Connection,
) -> Result<Vec<SchemaMonitorTarget>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        r#"
        SELECT
            d.id,
            d.name,
            d.tenant,
            d.delta_location,
            fc.alert_channels
        FROM datasets d
        LEFT JOIN freshness_config fc ON d.id = fc.dataset_id
        WHERE d.delta_location IS NOT NULL
          AND d.delta_location != ''
        "#,
    )?;

    let results = stmt
        .query_map([], |row| {
            Ok(SchemaMonitorTarget {
                dataset_id: row.get(0)?,
                dataset_name: row.get(1)?,
                tenant_id: row.get(2)?,
                delta_location: row.get(3)?,
                alert_channels: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Schema of a field from the catalog's fields table
#[derive(Debug, Clone)]
pub struct CatalogField {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
}

/// Get the current schema for a dataset from the fields table
pub fn get_catalog_schema(
    conn: &rusqlite::Connection,
    dataset_id: i64,
) -> Result<Vec<CatalogField>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT name, data_type, nullable FROM fields WHERE dataset_id = ?1 ORDER BY name",
    )?;

    let fields = stmt
        .query_map([dataset_id], |row| {
            Ok(CatalogField {
                name: row.get(0)?,
                data_type: row.get(1)?,
                nullable: row.get::<_, i32>(2)? != 0,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(fields)
}

/// Information about a detected schema change
#[derive(Debug, Clone)]
pub struct SchemaChangeInfo {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub tenant_id: Option<String>,
    pub alert_channels: Option<String>,
    pub added_columns: Vec<String>,
    pub removed_columns: Vec<String>,
    pub modified_columns: Vec<String>,
    pub is_breaking: bool,
}

impl SchemaChangeInfo {
    /// Check if there are any changes
    pub fn has_changes(&self) -> bool {
        !self.added_columns.is_empty()
            || !self.removed_columns.is_empty()
            || !self.modified_columns.is_empty()
    }
}

/// Update the catalog's fields table to match the Delta schema
///
/// This syncs the schema by:
/// 1. Deleting fields that no longer exist
/// 2. Adding new fields
/// 3. Updating fields that changed type/nullability
pub fn sync_catalog_schema(
    conn: &rusqlite::Connection,
    dataset_id: i64,
    delta_fields: &[metafuse_catalog_delta::Field],
) -> Result<(), rusqlite::Error> {
    // Get current catalog fields
    let current_fields = get_catalog_schema(conn, dataset_id)?;
    let current_map: std::collections::HashMap<_, _> =
        current_fields.iter().map(|f| (f.name.clone(), f)).collect();

    let delta_map: std::collections::HashMap<_, _> =
        delta_fields.iter().map(|f| (f.name.clone(), f)).collect();

    // Delete removed fields
    for field in &current_fields {
        if !delta_map.contains_key(&field.name) {
            conn.execute(
                "DELETE FROM fields WHERE dataset_id = ?1 AND name = ?2",
                rusqlite::params![dataset_id, field.name],
            )?;
        }
    }

    // Add or update fields
    for delta_field in delta_fields {
        if let Some(current) = current_map.get(&delta_field.name) {
            // Update if changed
            if current.data_type != delta_field.data_type
                || current.nullable != delta_field.nullable
            {
                conn.execute(
                    "UPDATE fields SET data_type = ?1, nullable = ?2 WHERE dataset_id = ?3 AND name = ?4",
                    rusqlite::params![
                        delta_field.data_type,
                        delta_field.nullable,
                        dataset_id,
                        delta_field.name
                    ],
                )?;
            }
        } else {
            // Insert new field
            conn.execute(
                "INSERT INTO fields (dataset_id, name, data_type, nullable) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    dataset_id,
                    delta_field.name,
                    delta_field.data_type,
                    delta_field.nullable
                ],
            )?;
        }
    }

    Ok(())
}

/// Compare Delta schema with catalog schema and detect changes
pub fn detect_schema_changes(
    catalog_fields: &[CatalogField],
    delta_fields: &[metafuse_catalog_delta::Field],
    target: &SchemaMonitorTarget,
) -> SchemaChangeInfo {
    let catalog_map: std::collections::HashMap<_, _> =
        catalog_fields.iter().map(|f| (f.name.clone(), f)).collect();

    let delta_map: std::collections::HashMap<_, _> =
        delta_fields.iter().map(|f| (f.name.clone(), f)).collect();

    // Find added columns (in Delta but not in catalog)
    let added_columns: Vec<String> = delta_fields
        .iter()
        .filter(|f| !catalog_map.contains_key(&f.name))
        .map(|f| f.name.clone())
        .collect();

    // Find removed columns (in catalog but not in Delta)
    let removed_columns: Vec<String> = catalog_fields
        .iter()
        .filter(|f| !delta_map.contains_key(&f.name))
        .map(|f| f.name.clone())
        .collect();

    // Find modified columns (type or nullability changed)
    let modified_columns: Vec<String> = catalog_fields
        .iter()
        .filter_map(|cf| {
            delta_map.get(&cf.name).and_then(|df| {
                if cf.data_type != df.data_type || cf.nullable != df.nullable {
                    Some(format!(
                        "{} ({} -> {})",
                        cf.name, cf.data_type, df.data_type
                    ))
                } else {
                    None
                }
            })
        })
        .collect();

    // Breaking changes: columns removed or types changed in incompatible ways
    let is_breaking = !removed_columns.is_empty() || !modified_columns.is_empty();

    SchemaChangeInfo {
        dataset_id: target.dataset_id,
        dataset_name: target.dataset_name.clone(),
        tenant_id: target.tenant_id.clone(),
        alert_channels: target.alert_channels.clone(),
        added_columns,
        removed_columns,
        modified_columns,
        is_breaking,
    }
}

/// Background task that monitors Delta tables for schema changes
///
/// This task:
/// 1. Periodically queries datasets with delta_location
/// 2. Compares current Delta schema with catalog schema (fields table)
/// 3. Detects changes (added, removed, modified columns)
/// 4. Fires schema change alerts
/// 5. Updates catalog to reflect new schema
#[cfg(feature = "alerting")]
pub async fn schema_monitor_task(
    delta_reader: Arc<metafuse_catalog_delta::DeltaReader>,
    webhook_client: Arc<WebhookClient>,
    backend: Arc<metafuse_catalog_storage::DynCatalogBackend>,
    config: SchemaMonitorConfig,
) {
    let interval = Duration::from_secs(config.check_interval_secs);

    info!(
        interval_secs = config.check_interval_secs,
        "Schema monitor task started"
    );

    loop {
        tokio::time::sleep(interval).await;

        if !config.enabled {
            debug!("Schema monitoring disabled, skipping");
            continue;
        }

        debug!("Running schema change detection");

        // Phase 1: Get datasets to monitor
        let targets = match backend.get_connection().await {
            Ok(conn) => match find_datasets_for_schema_check(&conn) {
                Ok(t) => t,
                Err(e) => {
                    error!(error = %e, "Failed to query datasets for schema check");
                    continue;
                }
            },
            Err(e) => {
                warn!(error = %e, "Failed to get connection for schema check");
                continue;
            }
        };

        if targets.is_empty() {
            debug!("No datasets with delta_location to monitor");
            continue;
        }

        debug!(
            count = targets.len(),
            "Checking datasets for schema changes"
        );

        // Phase 2: Check each dataset for schema changes
        for target in targets {
            // Get current Delta schema
            let delta_schema = match delta_reader.get_schema(&target.delta_location, None).await {
                Ok(schema) => schema,
                Err(e) => {
                    debug!(
                        dataset_id = target.dataset_id,
                        dataset_name = %target.dataset_name,
                        error = %e,
                        "Failed to get Delta schema, skipping"
                    );
                    continue;
                }
            };

            // Get catalog schema and compare
            let conn = match backend.get_connection().await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "Failed to get connection");
                    continue;
                }
            };

            let catalog_fields = match get_catalog_schema(&conn, target.dataset_id) {
                Ok(f) => f,
                Err(e) => {
                    error!(
                        dataset_id = target.dataset_id,
                        error = %e,
                        "Failed to get catalog schema"
                    );
                    continue;
                }
            };

            // If catalog has no fields, this is initial sync, not a change
            if catalog_fields.is_empty() {
                debug!(
                    dataset_id = target.dataset_id,
                    dataset_name = %target.dataset_name,
                    "No catalog schema yet, syncing initial schema"
                );
                if let Err(e) = sync_catalog_schema(&conn, target.dataset_id, &delta_schema.fields)
                {
                    error!(
                        dataset_id = target.dataset_id,
                        error = %e,
                        "Failed to sync initial schema"
                    );
                }
                continue;
            }

            // Detect changes
            let changes = detect_schema_changes(&catalog_fields, &delta_schema.fields, &target);

            if !changes.has_changes() {
                continue;
            }

            info!(
                dataset_id = target.dataset_id,
                dataset_name = %target.dataset_name,
                added = ?changes.added_columns,
                removed = ?changes.removed_columns,
                modified = ?changes.modified_columns,
                is_breaking = changes.is_breaking,
                "Schema change detected"
            );

            // Check cooldown
            let has_recent = match has_recent_alert(
                &conn,
                AlertType::Schema,
                target.dataset_id,
                config.cooldown_secs,
            ) {
                Ok(has) => has,
                Err(e) => {
                    error!(error = %e, "Failed to check alert cooldown");
                    false
                }
            };

            if has_recent {
                debug!(
                    dataset_id = target.dataset_id,
                    "Skipping schema alert due to cooldown"
                );
                // Still sync schema even if we don't alert
                let _ = sync_catalog_schema(&conn, target.dataset_id, &delta_schema.fields);
                continue;
            }

            // Create alert payload
            let payload = AlertPayload::schema_change(
                &changes.dataset_name,
                changes.dataset_id,
                &changes.added_columns,
                &changes.removed_columns,
                &changes.modified_columns,
            );

            // Parse alert channels
            let channels: Vec<String> = changes
                .alert_channels
                .as_ref()
                .and_then(|c| serde_json::from_str(c).ok())
                .unwrap_or_default();

            // Record alert even if no channels configured
            let alert_id = match record_alert(
                &conn,
                AlertType::Schema,
                Some(changes.dataset_id),
                payload.severity,
                &payload.message,
                payload.details.as_ref().map(|d| d.to_string()).as_deref(),
                changes.alert_channels.as_deref(),
                changes.tenant_id.as_deref(),
            ) {
                Ok(id) => {
                    #[cfg(feature = "metrics")]
                    metrics::record_alert_fired(
                        AlertType::Schema.as_str(),
                        payload.severity.as_str(),
                    );
                    id
                }
                Err(e) => {
                    error!(
                        dataset_id = changes.dataset_id,
                        error = %e,
                        "Failed to record schema change alert"
                    );
                    // Still sync schema
                    let _ = sync_catalog_schema(&conn, target.dataset_id, &delta_schema.fields);
                    continue;
                }
            };

            // Deliver to webhook channels if configured
            if !channels.is_empty() {
                let payload = payload.with_alert_history_id(alert_id);
                let mut delivery_success = true;
                let mut total_attempts = 0;
                let mut last_error: Option<String> = None;

                for channel in &channels {
                    let url = channel.strip_prefix("webhook:").unwrap_or(channel);
                    let redacted = redact_url(url);

                    match webhook_client
                        .send_with_retry(url, &payload, MAX_DELIVERY_ATTEMPTS)
                        .await
                    {
                        Ok(attempts) => {
                            total_attempts += attempts;
                            info!(
                                alert_id,
                                dataset_name = %changes.dataset_name,
                                webhook_url = %redacted,
                                attempts,
                                "Schema change alert delivered successfully"
                            );
                        }
                        Err(e) => {
                            total_attempts += MAX_DELIVERY_ATTEMPTS;
                            delivery_success = false;
                            last_error = Some(e.to_string());
                            error!(
                                alert_id,
                                dataset_name = %changes.dataset_name,
                                webhook_url = %redacted,
                                error = %e,
                                "Schema change alert delivery failed"
                            );
                        }
                    }
                }

                // Update delivery status
                let status = if delivery_success {
                    "delivered"
                } else {
                    "failed"
                };
                if let Err(e) = update_delivery_status(
                    &conn,
                    alert_id,
                    status,
                    total_attempts as i32,
                    last_error.as_deref(),
                ) {
                    error!(alert_id, error = %e, "Failed to update delivery status");
                }

                #[cfg(feature = "metrics")]
                {
                    if delivery_success {
                        metrics::record_alert_delivered(AlertType::Schema.as_str());
                    } else {
                        metrics::record_alert_delivery_failed(AlertType::Schema.as_str());
                    }
                }
            }

            // Sync catalog schema to reflect changes
            if let Err(e) = sync_catalog_schema(&conn, target.dataset_id, &delta_schema.fields) {
                error!(
                    dataset_id = target.dataset_id,
                    error = %e,
                    "Failed to sync schema after change detection"
                );
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_type_as_str() {
        assert_eq!(AlertType::Freshness.as_str(), "freshness");
        assert_eq!(AlertType::Quality.as_str(), "quality");
        assert_eq!(AlertType::Schema.as_str(), "schema");
        assert_eq!(AlertType::Contract.as_str(), "contract");
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(Severity::Info.as_str(), "info");
        assert_eq!(Severity::Warning.as_str(), "warning");
        assert_eq!(Severity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_alert_config_default() {
        let config = AlertConfig::default();
        assert_eq!(config.check_interval_secs, DEFAULT_CHECK_INTERVAL_SECS);
        assert_eq!(config.cooldown_secs, ALERT_COOLDOWN_SECS);
        assert!(config.enabled);
    }

    #[test]
    fn test_freshness_payload_creation() {
        let payload = AlertPayload::freshness("orders", 1, 7200, 3600);

        assert_eq!(payload.alert_type, AlertType::Freshness);
        assert_eq!(payload.severity, Severity::Warning); // 2x expected
        assert_eq!(payload.dataset_name, "orders");
        assert_eq!(payload.dataset_id, Some(1));
        assert!(payload.message.contains("stale"));
        assert_eq!(payload.source_system, "metafuse");
        assert!(!payload.customer_visible);
    }

    #[test]
    fn test_freshness_severity_escalation() {
        // Just over threshold = Info
        let info = AlertPayload::freshness("test", 1, 3700, 3600);
        assert_eq!(info.severity, Severity::Info);

        // 2x threshold = Warning
        let warning = AlertPayload::freshness("test", 1, 7300, 3600);
        assert_eq!(warning.severity, Severity::Warning);

        // 4x+ threshold = Critical
        let critical = AlertPayload::freshness("test", 1, 14500, 3600);
        assert_eq!(critical.severity, Severity::Critical);
    }

    #[test]
    fn test_quality_payload_creation() {
        let payload = AlertPayload::quality("orders", 1, 0.75, 0.95, "completeness");

        assert_eq!(payload.alert_type, AlertType::Quality);
        assert_eq!(payload.severity, Severity::Warning);
        assert!(payload.message.contains("completeness"));
        assert!(payload.message.contains("75.0%"));
    }

    #[test]
    fn test_schema_change_payload() {
        let payload = AlertPayload::schema_change(
            "orders",
            1,
            &["new_col".to_string()],
            &["old_col".to_string()],
            &[],
        );

        assert_eq!(payload.alert_type, AlertType::Schema);
        assert_eq!(payload.severity, Severity::Warning); // Has removed columns
    }

    #[test]
    fn test_contract_violation_payload() {
        let payload = AlertPayload::contract_violation(
            "orders",
            1,
            "orders_contract",
            &["Missing required column: order_id".to_string()],
        );

        assert_eq!(payload.alert_type, AlertType::Contract);
        assert!(payload.message.contains("orders_contract"));
    }

    #[test]
    fn test_payload_builder_methods() {
        let payload = AlertPayload::freshness("test", 1, 7200, 3600)
            .with_integration_id(Some("int-123".to_string()))
            .with_customer_visible(true)
            .with_alert_history_id(42);

        assert_eq!(payload.integration_id, Some("int-123".to_string()));
        assert!(payload.customer_visible);
        assert_eq!(payload.alert_history_id, Some(42));
    }

    #[test]
    fn test_payload_serialization() {
        let payload = AlertPayload::freshness("orders", 1, 7200, 3600);
        let json = serde_json::to_string(&payload).unwrap();

        assert!(json.contains("\"alert_type\":\"freshness\""));
        assert!(json.contains("\"severity\":\"warning\""));
        assert!(json.contains("\"source_system\":\"metafuse\""));
    }

    #[test]
    fn test_record_alert() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        let alert_id = record_alert(
            &conn,
            AlertType::Freshness,
            None, // No FK reference to avoid constraint failure in tests
            Severity::Warning,
            "Test alert",
            Some(r#"{"test": true}"#),
            Some(r#"["webhook:https://example.com"]"#),
            Some("test-tenant"),
        )
        .unwrap();

        assert!(alert_id > 0);

        // Verify in database
        let (alert_type, severity, status, tenant_id): (String, String, String, Option<String>) =
            conn.query_row(
                "SELECT alert_type, severity, delivery_status, tenant_id FROM alert_history WHERE id = ?1",
                [alert_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        assert_eq!(alert_type, "freshness");
        assert_eq!(severity, "warning");
        assert_eq!(status, "pending");
        assert_eq!(tenant_id, Some("test-tenant".to_string()));
    }

    #[test]
    fn test_update_delivery_status() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        let alert_id = record_alert(
            &conn,
            AlertType::Quality,
            None,
            Severity::Critical,
            "Quality alert",
            None,
            None,
            None,
        )
        .unwrap();

        update_delivery_status(&conn, alert_id, "delivered", 2, None).unwrap();

        let (status, attempts): (String, i32) = conn
            .query_row(
                "SELECT delivery_status, delivery_attempts FROM alert_history WHERE id = ?1",
                [alert_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(status, "delivered");
        assert_eq!(attempts, 2);
    }

    #[test]
    fn test_has_recent_alert() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Create a dataset for FK reference
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated) VALUES ('test_ds', '/test', 'delta', datetime('now'), datetime('now'))",
            [],
        ).unwrap();
        let dataset_id: i64 = conn.last_insert_rowid();

        // No alerts yet
        assert!(!has_recent_alert(&conn, AlertType::Freshness, dataset_id, 3600).unwrap());

        // Record an unresolved alert
        record_alert(
            &conn,
            AlertType::Freshness,
            Some(dataset_id),
            Severity::Warning,
            "Test",
            None,
            None,
            None,
        )
        .unwrap();

        // Now should have recent alert
        assert!(has_recent_alert(&conn, AlertType::Freshness, dataset_id, 3600).unwrap());

        // Different dataset should not have recent alert (non-existent ID is fine for check)
        assert!(!has_recent_alert(&conn, AlertType::Freshness, 99999, 3600).unwrap());

        // Different alert type should not match
        assert!(!has_recent_alert(&conn, AlertType::Quality, dataset_id, 3600).unwrap());
    }

    #[test]
    fn test_resolve_alert() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        let alert_id = record_alert(
            &conn,
            AlertType::Freshness,
            None, // No FK reference needed for this test
            Severity::Warning,
            "Test",
            None,
            None,
            None,
        )
        .unwrap();

        // Initially unresolved
        let resolved: Option<String> = conn
            .query_row(
                "SELECT resolved_at FROM alert_history WHERE id = ?1",
                [alert_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(resolved.is_none());

        // Resolve it
        resolve_alert(&conn, alert_id).unwrap();

        // Now should be resolved
        let resolved: Option<String> = conn
            .query_row(
                "SELECT resolved_at FROM alert_history WHERE id = ?1",
                [alert_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(resolved.is_some());
    }

    #[test]
    fn test_query_alert_history() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Create datasets for FK references
        conn.execute(
            "INSERT INTO datasets (name, path, format, tenant, created_at, last_updated) VALUES ('ds1', '/test1', 'delta', 'tenant-a', datetime('now'), datetime('now'))",
            [],
        ).unwrap();
        let ds1_id: i64 = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO datasets (name, path, format, tenant, created_at, last_updated) VALUES ('ds2', '/test2', 'delta', 'tenant-b', datetime('now'), datetime('now'))",
            [],
        ).unwrap();
        let ds2_id: i64 = conn.last_insert_rowid();

        // Record some alerts with tenant_id
        record_alert(
            &conn,
            AlertType::Freshness,
            Some(ds1_id),
            Severity::Warning,
            "Alert 1",
            None,
            None,
            Some("tenant-a"),
        )
        .unwrap();

        record_alert(
            &conn,
            AlertType::Quality,
            Some(ds2_id),
            Severity::Critical,
            "Alert 2",
            None,
            None,
            Some("tenant-b"),
        )
        .unwrap();

        // Query all (no tenant filter)
        let params = AlertHistoryParams {
            tenant_id: None,
            alert_type: None,
            dataset_id: None,
            severity: None,
            delivery_status: None,
            include_resolved: false,
            offset: 0,
            limit: 100,
        };
        let result = query_alert_history(&conn, &params).unwrap();
        assert_eq!(result.alerts.len(), 2);
        assert_eq!(result.total, 2);
        assert!(!result.has_more);

        // Query by tenant (tenant isolation)
        let params = AlertHistoryParams {
            tenant_id: Some("tenant-a".to_string()),
            alert_type: None,
            dataset_id: None,
            severity: None,
            delivery_status: None,
            include_resolved: false,
            offset: 0,
            limit: 100,
        };
        let result = query_alert_history(&conn, &params).unwrap();
        assert_eq!(result.alerts.len(), 1);
        assert_eq!(result.alerts[0].tenant_id, Some("tenant-a".to_string()));

        // Query by type
        let params = AlertHistoryParams {
            tenant_id: None,
            alert_type: Some("freshness".to_string()),
            dataset_id: None,
            severity: None,
            delivery_status: None,
            include_resolved: false,
            offset: 0,
            limit: 100,
        };
        let result = query_alert_history(&conn, &params).unwrap();
        assert_eq!(result.alerts.len(), 1);
        assert_eq!(result.alerts[0].alert_type, "freshness");

        // Query by dataset
        let params = AlertHistoryParams {
            tenant_id: None,
            alert_type: None,
            dataset_id: Some(ds2_id),
            severity: None,
            delivery_status: None,
            include_resolved: false,
            offset: 0,
            limit: 100,
        };
        let result = query_alert_history(&conn, &params).unwrap();
        assert_eq!(result.alerts.len(), 1);
        assert_eq!(result.alerts[0].dataset_id, Some(ds2_id));

        // Test pagination
        let params = AlertHistoryParams {
            tenant_id: None,
            alert_type: None,
            dataset_id: None,
            severity: None,
            delivery_status: None,
            include_resolved: false,
            offset: 0,
            limit: 1,
        };
        let result = query_alert_history(&conn, &params).unwrap();
        assert_eq!(result.alerts.len(), 1);
        assert_eq!(result.total, 2);
        assert!(result.has_more);
        assert_eq!(result.offset, 0);
        assert_eq!(result.limit, 1);

        // Test pagination offset
        let params = AlertHistoryParams {
            tenant_id: None,
            alert_type: None,
            dataset_id: None,
            severity: None,
            delivery_status: None,
            include_resolved: false,
            offset: 1,
            limit: 100,
        };
        let result = query_alert_history(&conn, &params).unwrap();
        assert_eq!(result.alerts.len(), 1);
        assert_eq!(result.total, 2);
        assert!(!result.has_more);

        // Test severity filter
        let params = AlertHistoryParams {
            tenant_id: None,
            alert_type: None,
            dataset_id: None,
            severity: Some("critical".to_string()),
            delivery_status: None,
            include_resolved: false,
            offset: 0,
            limit: 100,
        };
        let result = query_alert_history(&conn, &params).unwrap();
        assert_eq!(result.alerts.len(), 1);
        assert_eq!(result.alerts[0].severity, "critical");
    }

    #[test]
    #[cfg(feature = "alerting")]
    fn test_redact_url_with_path() {
        let url = "https://hooks.example.com/webhook/secret123?token=abc";
        let redacted = super::redact_url(url);
        assert_eq!(redacted, "https://hooks.example.com/***");
    }

    #[test]
    #[cfg(feature = "alerting")]
    fn test_redact_url_no_path() {
        let url = "https://hooks.example.com";
        let redacted = super::redact_url(url);
        assert_eq!(redacted, "https://hooks.example.com/***");
    }

    #[test]
    #[cfg(feature = "alerting")]
    fn test_redact_url_with_port() {
        let url = "https://hooks.example.com:8443/webhook";
        let redacted = super::redact_url(url);
        assert_eq!(redacted, "https://hooks.example.com:8443/***");
    }

    #[test]
    #[cfg(feature = "alerting")]
    fn test_redact_url_invalid() {
        let url = "not-a-url";
        let redacted = super::redact_url(url);
        assert_eq!(redacted, "***");
    }
}
