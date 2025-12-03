// Infrastructure for quality framework - async QualityCalculator not yet wired to handlers
#![allow(dead_code)]

//! Quality Framework Module
//!
//! This module provides data quality computation and tracking for MetaFuse datasets:
//! - **Completeness Score**: Based on null counts from Delta column statistics
//! - **Freshness Score**: Based on last_modified vs configured SLA
//! - **File Health Score**: Based on small file ratio and file size distribution
//! - **Overall Score**: Weighted combination of the above
//!
//! # Architecture
//!
//! Quality scores are computed on-demand from Delta metadata and stored in the
//! `quality_metrics` table. Each computation creates a new row (history is preserved).
//!
//! Partial failures are handled gracefully - if one score can't be computed,
//! the others are still calculated and returned.

use serde::Serialize;
use tracing::{debug, info, warn};

/// Minimum file size in bytes considered "healthy" (128 MB)
const SMALL_FILE_THRESHOLD_BYTES: i64 = 128 * 1024 * 1024;

/// Default weight for completeness in overall score
const WEIGHT_COMPLETENESS: f64 = 0.4;

/// Default weight for freshness in overall score
const WEIGHT_FRESHNESS: f64 = 0.4;

/// Default weight for file health in overall score
const WEIGHT_FILE_HEALTH: f64 = 0.2;

/// Quality scores computed from Delta metadata
#[derive(Debug, Clone, Serialize)]
pub struct QualityScores {
    /// Completeness score (0.0-1.0): 1.0 - (null_cells / total_cells)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completeness_score: Option<f64>,

    /// Freshness score (0.0-1.0): Based on SLA from freshness_config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness_score: Option<f64>,

    /// File health score (0.0-1.0): Based on small file ratio
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_health_score: Option<f64>,

    /// Overall quality score (weighted average)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overall_score: Option<f64>,

    /// Detailed breakdown of quality metrics
    pub details: QualityDetails,
}

/// Detailed quality metrics
#[derive(Debug, Clone, Serialize, Default)]
pub struct QualityDetails {
    /// Total number of rows
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<i64>,

    /// Total number of files
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_count: Option<i64>,

    /// Total size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,

    /// Number of small files (below threshold)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub small_file_count: Option<i64>,

    /// Average file size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_file_size: Option<i64>,

    /// Total null cell count across all columns
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_null_count: Option<i64>,

    /// Expected freshness interval in seconds (from SLA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness_sla_secs: Option<i64>,

    /// Actual staleness in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staleness_secs: Option<i64>,

    /// Last modification timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

/// Response for quality endpoint
#[derive(Debug, Clone, Serialize)]
pub struct QualityResponse {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub computed_at: String,
    #[serde(flatten)]
    pub scores: QualityScores,
}

/// Response for unhealthy datasets endpoint
#[derive(Debug, Clone, Serialize)]
pub struct UnhealthyDatasetsResponse {
    pub threshold: f64,
    pub datasets: Vec<UnhealthyDatasetEntry>,
}

/// Entry in unhealthy datasets list
#[derive(Debug, Clone, Serialize)]
pub struct UnhealthyDatasetEntry {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub overall_score: f64,
    pub completeness_score: Option<f64>,
    pub freshness_score: Option<f64>,
    pub file_health_score: Option<f64>,
    pub computed_at: String,
}

/// Quality calculator using Delta metadata
pub struct QualityCalculator {
    delta_reader: std::sync::Arc<metafuse_catalog_delta::DeltaReader>,
}

impl QualityCalculator {
    /// Create a new quality calculator
    pub fn new(delta_reader: std::sync::Arc<metafuse_catalog_delta::DeltaReader>) -> Self {
        Self { delta_reader }
    }

    /// Compute quality scores for a dataset
    ///
    /// Partial failures are handled gracefully - each score is computed independently.
    pub async fn compute(
        &self,
        conn: &rusqlite::Connection,
        dataset_id: i64,
        delta_location: &str,
    ) -> Result<QualityScores, QualityError> {
        debug!(dataset_id, delta_location, "Computing quality scores");

        // Get Delta metadata
        let metadata = self
            .delta_reader
            .get_metadata_cached(delta_location)
            .await
            .map_err(|e| QualityError::DeltaError(e.to_string()))?;

        // Initialize details
        let mut details = QualityDetails {
            row_count: Some(metadata.row_count),
            file_count: Some(metadata.num_files),
            size_bytes: Some(metadata.size_bytes),
            last_modified: Some(metadata.last_modified.to_rfc3339()),
            ..Default::default()
        };

        // Compute each score independently
        let completeness = self.compute_completeness(&metadata, &mut details);
        let freshness = self
            .compute_freshness(conn, dataset_id, &metadata, &mut details)
            .ok();
        let file_health = self.compute_file_health(&metadata, &mut details);

        // Compute overall (requires at least one score)
        let available_scores: Vec<(f64, f64)> = [
            (completeness, WEIGHT_COMPLETENESS),
            (freshness, WEIGHT_FRESHNESS),
            (file_health, WEIGHT_FILE_HEALTH),
        ]
        .iter()
        .filter_map(|(s, w)| s.map(|score| (score, *w)))
        .collect();

        let overall = if available_scores.is_empty() {
            None
        } else {
            let total_weight: f64 = available_scores.iter().map(|(_, w)| w).sum();
            let weighted_sum: f64 = available_scores.iter().map(|(s, w)| s * w).sum();
            Some(clamp_score(weighted_sum / total_weight))
        };

        let scores = QualityScores {
            completeness_score: completeness,
            freshness_score: freshness,
            file_health_score: file_health,
            overall_score: overall,
            details,
        };

        info!(
            dataset_id,
            overall = ?overall,
            completeness = ?completeness,
            freshness = ?freshness,
            file_health = ?file_health,
            "Quality scores computed"
        );

        Ok(scores)
    }

    /// Compute completeness score from null counts
    ///
    /// Score = 1.0 - (total_nulls / (row_count * column_count))
    /// Empty tables return 1.0 (vacuously complete)
    fn compute_completeness(
        &self,
        metadata: &metafuse_catalog_delta::DeltaMetadata,
        details: &mut QualityDetails,
    ) -> Option<f64> {
        let row_count = metadata.row_count;
        let column_count = metadata.schema.fields.len() as i64;

        if row_count == 0 || column_count == 0 {
            // Empty table is vacuously complete
            return Some(1.0);
        }

        // Sum null counts from column stats
        let total_nulls: i64 = metadata
            .column_stats
            .iter()
            .filter_map(|s| s.null_count)
            .sum();

        details.total_null_count = Some(total_nulls);

        let total_cells = row_count * column_count;
        let null_ratio = total_nulls as f64 / total_cells as f64;
        let score = 1.0 - null_ratio;

        Some(clamp_score(score))
    }

    /// Compute freshness score based on SLA configuration
    ///
    /// Score degrades from 1.0 towards 0.0 as staleness increases beyond SLA.
    fn compute_freshness(
        &self,
        conn: &rusqlite::Connection,
        dataset_id: i64,
        metadata: &metafuse_catalog_delta::DeltaMetadata,
        details: &mut QualityDetails,
    ) -> Result<f64, QualityError> {
        // Get freshness config for this dataset
        let config: Option<(i64, i64)> = conn
            .query_row(
                "SELECT expected_interval_secs, grace_period_secs FROM freshness_config WHERE dataset_id = ?1",
                [dataset_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        let (expected_interval, grace_period) = config.ok_or(QualityError::NoFreshnessConfig)?;

        details.freshness_sla_secs = Some(expected_interval);

        // Calculate staleness
        let last_modified = metadata.last_modified;
        let now = chrono::Utc::now();
        let staleness_secs = (now - last_modified).num_seconds();
        details.staleness_secs = Some(staleness_secs);

        // Calculate score
        // 1.0 if within SLA + grace, degrades towards 0.0 as staleness increases
        let threshold_secs = expected_interval + grace_period;

        let score = if staleness_secs <= threshold_secs {
            1.0
        } else {
            // Degrade linearly: halve the score for each additional SLA period of staleness
            let extra_staleness = staleness_secs - threshold_secs;
            let periods_overdue = extra_staleness as f64 / expected_interval as f64;
            1.0 / (1.0 + periods_overdue)
        };

        Ok(clamp_score(score))
    }

    /// Compute file health score based on small file ratio
    ///
    /// Small files (< 128MB) indicate potential performance issues.
    /// Score = 1.0 - (small_file_ratio * 0.5)
    fn compute_file_health(
        &self,
        metadata: &metafuse_catalog_delta::DeltaMetadata,
        details: &mut QualityDetails,
    ) -> Option<f64> {
        let num_files = metadata.num_files;

        if num_files == 0 {
            return Some(1.0);
        }

        let avg_file_size = metadata.size_bytes / num_files;
        details.avg_file_size = Some(avg_file_size);

        // Count small files
        let small_file_count = if avg_file_size < SMALL_FILE_THRESHOLD_BYTES {
            // If average is below threshold, estimate based on ratio
            // This is an approximation since we don't have individual file sizes
            let estimated_small = (SMALL_FILE_THRESHOLD_BYTES as f64 / avg_file_size as f64)
                .min(num_files as f64) as i64;
            estimated_small.min(num_files)
        } else {
            0
        };

        details.small_file_count = Some(small_file_count);

        let small_file_ratio = small_file_count as f64 / num_files as f64;

        // Score: 1.0 for no small files, down to 0.5 for all small files
        let score = 1.0 - (small_file_ratio * 0.5);

        Some(clamp_score(score))
    }
}

/// Compute quality scores from pre-fetched Delta metadata (synchronous)
///
/// This function takes already-fetched DeltaMetadata and performs synchronous
/// DB operations for freshness config lookup. Use this when the Delta metadata
/// is already available to avoid passing &Connection across async boundaries.
pub fn compute_scores_from_metadata(
    conn: &rusqlite::Connection,
    dataset_id: i64,
    metadata: &metafuse_catalog_delta::DeltaMetadata,
) -> Result<QualityScores, QualityError> {
    tracing::debug!(dataset_id, "Computing quality scores from metadata");

    // Initialize details
    let mut details = QualityDetails {
        row_count: Some(metadata.row_count),
        file_count: Some(metadata.num_files),
        size_bytes: Some(metadata.size_bytes),
        last_modified: Some(metadata.last_modified.to_rfc3339()),
        ..Default::default()
    };

    // Compute each score independently
    let completeness = compute_completeness_sync(metadata, &mut details);
    let freshness = compute_freshness_sync(conn, dataset_id, metadata, &mut details).ok();
    let file_health = compute_file_health_sync(metadata, &mut details);

    // Compute overall (requires at least one score)
    let available_scores: Vec<(f64, f64)> = [
        (completeness, WEIGHT_COMPLETENESS),
        (freshness, WEIGHT_FRESHNESS),
        (file_health, WEIGHT_FILE_HEALTH),
    ]
    .iter()
    .filter_map(|(s, w)| s.map(|score| (score, *w)))
    .collect();

    let overall = if available_scores.is_empty() {
        None
    } else {
        let total_weight: f64 = available_scores.iter().map(|(_, w)| w).sum();
        let weighted_sum: f64 = available_scores.iter().map(|(s, w)| s * w).sum();
        Some(clamp_score(weighted_sum / total_weight))
    };

    tracing::info!(
        dataset_id,
        overall = ?overall,
        completeness = ?completeness,
        freshness = ?freshness,
        file_health = ?file_health,
        "Quality scores computed"
    );

    Ok(QualityScores {
        completeness_score: completeness,
        freshness_score: freshness,
        file_health_score: file_health,
        overall_score: overall,
        details,
    })
}

/// Compute completeness score from null counts (standalone function)
fn compute_completeness_sync(
    metadata: &metafuse_catalog_delta::DeltaMetadata,
    details: &mut QualityDetails,
) -> Option<f64> {
    let row_count = metadata.row_count;
    let column_count = metadata.schema.fields.len() as i64;

    if row_count == 0 || column_count == 0 {
        return Some(1.0);
    }

    let total_nulls: i64 = metadata
        .column_stats
        .iter()
        .filter_map(|s| s.null_count)
        .sum();

    details.total_null_count = Some(total_nulls);

    let total_cells = row_count * column_count;
    let null_ratio = total_nulls as f64 / total_cells as f64;
    Some(clamp_score(1.0 - null_ratio))
}

/// Compute freshness score based on SLA configuration (standalone function)
fn compute_freshness_sync(
    conn: &rusqlite::Connection,
    dataset_id: i64,
    metadata: &metafuse_catalog_delta::DeltaMetadata,
    details: &mut QualityDetails,
) -> Result<f64, QualityError> {
    let config: Option<(i64, i64)> = conn
        .query_row(
            "SELECT expected_interval_secs, grace_period_secs FROM freshness_config WHERE dataset_id = ?1",
            [dataset_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    let (expected_interval, grace_period) = config.ok_or(QualityError::NoFreshnessConfig)?;

    details.freshness_sla_secs = Some(expected_interval);

    let last_modified = metadata.last_modified;
    let now = chrono::Utc::now();
    let staleness_secs = (now - last_modified).num_seconds();
    details.staleness_secs = Some(staleness_secs);

    let threshold_secs = expected_interval + grace_period;
    let score = if staleness_secs <= threshold_secs {
        1.0
    } else {
        let extra_staleness = staleness_secs - threshold_secs;
        let periods_overdue = extra_staleness as f64 / expected_interval as f64;
        1.0 / (1.0 + periods_overdue)
    };

    Ok(clamp_score(score))
}

/// Compute file health score based on small file ratio (standalone function)
fn compute_file_health_sync(
    metadata: &metafuse_catalog_delta::DeltaMetadata,
    details: &mut QualityDetails,
) -> Option<f64> {
    let num_files = metadata.num_files;

    if num_files == 0 {
        return Some(1.0);
    }

    let avg_file_size = metadata.size_bytes / num_files;
    details.avg_file_size = Some(avg_file_size);

    let small_file_count = if avg_file_size < SMALL_FILE_THRESHOLD_BYTES {
        let estimated_small =
            (SMALL_FILE_THRESHOLD_BYTES as f64 / avg_file_size as f64).min(num_files as f64) as i64;
        estimated_small.min(num_files)
    } else {
        0
    };

    details.small_file_count = Some(small_file_count);

    let small_file_ratio = small_file_count as f64 / num_files as f64;
    Some(clamp_score(1.0 - (small_file_ratio * 0.5)))
}

/// Clamp a score to valid range [0.0, 1.0]
fn clamp_score(score: f64) -> f64 {
    if score.is_nan() || score.is_infinite() {
        warn!(score, "Invalid score value, clamping to 0.0");
        return 0.0;
    }
    score.clamp(0.0, 1.0)
}

/// Quality computation errors
#[derive(Debug, Clone)]
pub enum QualityError {
    /// Delta table error
    DeltaError(String),
    /// No freshness configuration for dataset
    NoFreshnessConfig,
    /// No last modified timestamp available
    NoLastModified,
    /// Database error
    DatabaseError(String),
    /// All score calculations failed
    AllCalculationsFailed,
}

impl std::fmt::Display for QualityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QualityError::DeltaError(e) => write!(f, "Delta error: {}", e),
            QualityError::NoFreshnessConfig => write!(f, "No freshness configuration"),
            QualityError::NoLastModified => write!(f, "No last modified timestamp"),
            QualityError::DatabaseError(e) => write!(f, "Database error: {}", e),
            QualityError::AllCalculationsFailed => write!(f, "All quality calculations failed"),
        }
    }
}

impl std::error::Error for QualityError {}

// =============================================================================
// Database Operations
// =============================================================================

/// Store quality scores in the database
pub fn store_quality_scores(
    conn: &rusqlite::Connection,
    dataset_id: i64,
    scores: &QualityScores,
) -> Result<i64, rusqlite::Error> {
    let details_json = serde_json::to_string(&scores.details).ok();

    conn.execute(
        r#"
        INSERT INTO quality_metrics (
            dataset_id, computed_at,
            completeness_score, freshness_score, file_health_score, overall_score,
            row_count, file_count, size_bytes, small_file_count, avg_file_size, details
        ) VALUES (
            ?1, datetime('now'),
            ?2, ?3, ?4, ?5,
            ?6, ?7, ?8, ?9, ?10, ?11
        )
        "#,
        rusqlite::params![
            dataset_id,
            scores.completeness_score,
            scores.freshness_score,
            scores.file_health_score,
            scores.overall_score,
            scores.details.row_count,
            scores.details.file_count,
            scores.details.size_bytes,
            scores.details.small_file_count,
            scores.details.avg_file_size,
            details_json,
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Get the latest quality scores for a dataset
pub fn get_latest_quality(
    conn: &rusqlite::Connection,
    dataset_id: i64,
    dataset_name: &str,
) -> Result<Option<QualityResponse>, rusqlite::Error> {
    let result = conn.query_row(
        r#"
        SELECT
            completeness_score, freshness_score, file_health_score, overall_score,
            row_count, file_count, size_bytes, small_file_count, avg_file_size,
            computed_at
        FROM quality_metrics
        WHERE dataset_id = ?1
        ORDER BY computed_at DESC
        LIMIT 1
        "#,
        [dataset_id],
        |row| {
            Ok(QualityResponse {
                dataset_id,
                dataset_name: dataset_name.to_string(),
                computed_at: row.get(9)?,
                scores: QualityScores {
                    completeness_score: row.get(0)?,
                    freshness_score: row.get(1)?,
                    file_health_score: row.get(2)?,
                    overall_score: row.get(3)?,
                    details: QualityDetails {
                        row_count: row.get(4)?,
                        file_count: row.get(5)?,
                        size_bytes: row.get(6)?,
                        small_file_count: row.get(7)?,
                        avg_file_size: row.get(8)?,
                        ..Default::default()
                    },
                },
            })
        },
    );

    match result {
        Ok(r) => Ok(Some(r)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Get datasets with overall quality below threshold
pub fn get_unhealthy_datasets(
    conn: &rusqlite::Connection,
    threshold: f64,
) -> Result<UnhealthyDatasetsResponse, rusqlite::Error> {
    let mut stmt = conn.prepare(
        r#"
        SELECT
            d.id, d.name,
            q.overall_score, q.completeness_score, q.freshness_score, q.file_health_score,
            q.computed_at
        FROM datasets d
        JOIN quality_metrics q ON q.dataset_id = d.id
        WHERE q.id = (
            SELECT id FROM quality_metrics WHERE dataset_id = d.id ORDER BY computed_at DESC LIMIT 1
        )
        AND q.overall_score < ?1
        ORDER BY q.overall_score ASC
        "#,
    )?;

    let datasets: Vec<UnhealthyDatasetEntry> = stmt
        .query_map([threshold], |row| {
            Ok(UnhealthyDatasetEntry {
                dataset_id: row.get(0)?,
                dataset_name: row.get(1)?,
                overall_score: row.get(2)?,
                completeness_score: row.get(3)?,
                freshness_score: row.get(4)?,
                file_health_score: row.get(5)?,
                computed_at: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(UnhealthyDatasetsResponse {
        threshold,
        datasets,
    })
}

// =============================================================================
// Quality Check Executor (v1.7.0)
// =============================================================================

use metafuse_catalog_core::{
    QualityCheck, QualityCheckExecutionMode, QualityCheckResult, QualityCheckSeverity,
    QualityCheckStatus, QualityCheckType,
};

/// Request to create a new quality check
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CreateQualityCheckRequest {
    pub check_type: String,
    pub check_name: String,
    #[serde(default)]
    pub check_description: Option<String>,
    #[serde(default)]
    pub check_config: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub warn_threshold: Option<f64>,
    #[serde(default)]
    pub fail_threshold: Option<f64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub schedule: Option<String>,
    #[serde(default = "default_true")]
    pub on_demand: bool,
}

fn default_severity() -> String {
    "warning".to_string()
}

fn default_true() -> bool {
    true
}

/// Response from quality check execution
#[derive(Debug, Clone, Serialize)]
pub struct QualityCheckExecutionResponse {
    pub check_id: String,
    pub check_name: String,
    pub dataset_id: i64,
    pub status: String,
    pub score: Option<f64>,
    pub details: Option<String>,
    pub records_checked: Option<i64>,
    pub records_failed: Option<i64>,
    pub execution_time_ms: i64,
    pub executed_at: String,
}

/// Executor for quality checks
pub struct QualityCheckExecutor {
    delta_reader: std::sync::Arc<metafuse_catalog_delta::DeltaReader>,
}

impl QualityCheckExecutor {
    /// Create a new quality check executor
    pub fn new(delta_reader: std::sync::Arc<metafuse_catalog_delta::DeltaReader>) -> Self {
        Self { delta_reader }
    }

    /// Execute a single quality check
    pub async fn execute_check(
        &self,
        conn: &rusqlite::Connection,
        check: &QualityCheck,
        delta_location: Option<&str>,
        mode: QualityCheckExecutionMode,
    ) -> Result<QualityCheckResult, QualityError> {
        let start = std::time::Instant::now();
        let result_id = uuid::Uuid::new_v4().to_string();

        info!(
            check_id = %check.id,
            check_type = %check.check_type,
            check_name = %check.check_name,
            "Executing quality check"
        );

        let result = match check.check_type {
            QualityCheckType::Completeness => {
                self.execute_completeness_check(conn, check, delta_location)
                    .await
            }
            QualityCheckType::Freshness => {
                self.execute_freshness_check(conn, check, delta_location)
                    .await
            }
            QualityCheckType::Validity => {
                // Validity checks require custom SQL in check_config
                self.execute_custom_check(conn, check).await
            }
            QualityCheckType::Uniqueness => {
                self.execute_uniqueness_check(conn, check, delta_location)
                    .await
            }
            QualityCheckType::Custom => self.execute_custom_check(conn, check).await,
        };

        let execution_time_ms = start.elapsed().as_millis() as i64;

        match result {
            Ok((score, details, records_checked, records_failed)) => {
                let status = self.determine_status_from_score(score, check);
                Ok(QualityCheckResult {
                    id: result_id,
                    check_id: check.id.clone(),
                    dataset_id: check.dataset_id,
                    status,
                    score: Some(score),
                    details,
                    error_message: None,
                    records_checked: Some(records_checked),
                    records_failed: Some(records_failed),
                    executed_at: chrono::Utc::now(),
                    execution_time_ms: Some(execution_time_ms),
                    execution_mode: mode,
                    delta_version: None,
                })
            }
            Err(e) => Ok(QualityCheckResult {
                id: result_id,
                check_id: check.id.clone(),
                dataset_id: check.dataset_id,
                status: QualityCheckStatus::Error,
                score: None,
                details: None,
                error_message: Some(e.to_string()),
                records_checked: None,
                records_failed: None,
                executed_at: chrono::Utc::now(),
                execution_time_ms: Some(execution_time_ms),
                execution_mode: mode,
                delta_version: None,
            }),
        }
    }

    /// Execute a completeness check (null count analysis)
    async fn execute_completeness_check(
        &self,
        conn: &rusqlite::Connection,
        check: &QualityCheck,
        delta_location: Option<&str>,
    ) -> Result<(f64, Option<String>, i64, i64), QualityError> {
        // Get Delta metadata if available
        if let Some(location) = delta_location {
            let metadata = self
                .delta_reader
                .get_metadata_cached(location)
                .await
                .map_err(|e| QualityError::DeltaError(e.to_string()))?;

            let row_count = metadata.row_count;
            let column_count = metadata.schema.fields.len() as i64;

            if row_count == 0 || column_count == 0 {
                return Ok((1.0, Some(r#"{"status":"empty_table"}"#.to_string()), 0, 0));
            }

            let total_nulls: i64 = metadata
                .column_stats
                .iter()
                .filter_map(|s| s.null_count)
                .sum();

            let total_cells = row_count * column_count;
            let null_ratio = total_nulls as f64 / total_cells as f64;
            let score = clamp_score(1.0 - null_ratio);

            let details = serde_json::json!({
                "row_count": row_count,
                "column_count": column_count,
                "total_cells": total_cells,
                "null_cells": total_nulls,
                "null_ratio": null_ratio,
            });

            Ok((score, Some(details.to_string()), total_cells, total_nulls))
        } else {
            // Fall back to stored field count
            let field_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM fields WHERE dataset_id = ?1",
                    [check.dataset_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);

            let row_count: Option<i64> = conn
                .query_row(
                    "SELECT row_count FROM datasets WHERE id = ?1",
                    [check.dataset_id],
                    |row| row.get(0),
                )
                .ok()
                .flatten();

            match row_count {
                Some(rows) if rows > 0 && field_count > 0 => {
                    // Without Delta stats, assume 100% completeness
                    Ok((
                        1.0,
                        Some(r#"{"status":"no_null_stats"}"#.to_string()),
                        rows * field_count,
                        0,
                    ))
                }
                _ => Ok((1.0, Some(r#"{"status":"no_data"}"#.to_string()), 0, 0)),
            }
        }
    }

    /// Execute a freshness check
    async fn execute_freshness_check(
        &self,
        conn: &rusqlite::Connection,
        check: &QualityCheck,
        delta_location: Option<&str>,
    ) -> Result<(f64, Option<String>, i64, i64), QualityError> {
        // Get freshness config
        let config: Option<(i64, i64)> = conn
            .query_row(
                "SELECT expected_interval_secs, grace_period_secs FROM freshness_config WHERE dataset_id = ?1",
                [check.dataset_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        let (expected_interval, grace_period) = config.ok_or(QualityError::NoFreshnessConfig)?;

        // Get last modified
        let last_modified = if let Some(location) = delta_location {
            let metadata = self
                .delta_reader
                .get_metadata_cached(location)
                .await
                .map_err(|e| QualityError::DeltaError(e.to_string()))?;
            metadata.last_modified
        } else {
            // Fall back to dataset's last_updated
            let last_updated: String = conn
                .query_row(
                    "SELECT last_updated FROM datasets WHERE id = ?1",
                    [check.dataset_id],
                    |row| row.get(0),
                )
                .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

            chrono::DateTime::parse_from_rfc3339(&last_updated)
                .map_err(|_| QualityError::NoLastModified)?
                .with_timezone(&chrono::Utc)
        };

        let now = chrono::Utc::now();
        let staleness_secs = (now - last_modified).num_seconds();
        let threshold_secs = expected_interval + grace_period;

        let score = if staleness_secs <= threshold_secs {
            1.0
        } else {
            let extra_staleness = staleness_secs - threshold_secs;
            let periods_overdue = extra_staleness as f64 / expected_interval as f64;
            clamp_score(1.0 / (1.0 + periods_overdue))
        };

        let details = serde_json::json!({
            "last_modified": last_modified.to_rfc3339(),
            "staleness_secs": staleness_secs,
            "expected_interval_secs": expected_interval,
            "grace_period_secs": grace_period,
            "threshold_secs": threshold_secs,
        });

        // Freshness is a pass/fail - 1 check, 0 or 1 failed
        let failed = if score < 1.0 { 1 } else { 0 };
        Ok((score, Some(details.to_string()), 1, failed))
    }

    /// Execute a uniqueness check
    async fn execute_uniqueness_check(
        &self,
        _conn: &rusqlite::Connection,
        check: &QualityCheck,
        _delta_location: Option<&str>,
    ) -> Result<(f64, Option<String>, i64, i64), QualityError> {
        // Uniqueness checks require data scanning which we don't do in the catalog
        // Return a placeholder result indicating the check needs external execution
        let details = serde_json::json!({
            "status": "requires_external_execution",
            "message": "Uniqueness checks require external data scanning",
            "check_config": check.check_config,
        });
        Ok((1.0, Some(details.to_string()), 0, 0))
    }

    /// Execute a custom SQL-based check
    async fn execute_custom_check(
        &self,
        _conn: &rusqlite::Connection,
        check: &QualityCheck,
    ) -> Result<(f64, Option<String>, i64, i64), QualityError> {
        // Custom checks require external execution (e.g., via DataFusion)
        let details = serde_json::json!({
            "status": "requires_external_execution",
            "message": "Custom checks require external SQL execution",
            "check_config": check.check_config,
        });
        Ok((1.0, Some(details.to_string()), 0, 0))
    }

    /// Determine status based on score and thresholds
    pub fn determine_status_from_score(
        &self,
        score: f64,
        check: &QualityCheck,
    ) -> QualityCheckStatus {
        if let Some(fail_threshold) = check.fail_threshold {
            if score < fail_threshold {
                return QualityCheckStatus::Fail;
            }
        }
        if let Some(warn_threshold) = check.warn_threshold {
            if score < warn_threshold {
                return QualityCheckStatus::Warn;
            }
        }
        QualityCheckStatus::Pass
    }
}

// =============================================================================
// Quality Check Database Operations
// =============================================================================

/// Create a new quality check
pub fn create_quality_check(
    conn: &rusqlite::Connection,
    dataset_id: i64,
    request: &CreateQualityCheckRequest,
    created_by: Option<&str>,
    tenant_id: Option<&str>,
) -> Result<QualityCheck, QualityError> {
    let check_id = uuid::Uuid::new_v4().to_string();
    let check_type: QualityCheckType =
        request
            .check_type
            .parse()
            .map_err(|e: metafuse_catalog_core::CatalogError| {
                QualityError::DatabaseError(e.to_string())
            })?;
    let severity: QualityCheckSeverity =
        request
            .severity
            .parse()
            .map_err(|e: metafuse_catalog_core::CatalogError| {
                QualityError::DatabaseError(e.to_string())
            })?;

    conn.execute(
        r#"
        INSERT INTO quality_checks (
            id, dataset_id, check_type, check_name, check_description, check_config,
            severity, warn_threshold, fail_threshold, enabled, schedule, on_demand,
            created_at, updated_at, created_by, tenant_id
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
            datetime('now'), datetime('now'), ?13, ?14
        )
        "#,
        rusqlite::params![
            check_id,
            dataset_id,
            check_type.to_string(),
            request.check_name,
            request.check_description,
            request.check_config,
            severity.to_string(),
            request.warn_threshold,
            request.fail_threshold,
            request.enabled,
            request.schedule,
            request.on_demand,
            created_by,
            tenant_id,
        ],
    )
    .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let now = chrono::Utc::now();
    Ok(QualityCheck {
        id: check_id,
        dataset_id,
        check_type,
        check_name: request.check_name.clone(),
        check_description: request.check_description.clone(),
        check_config: request.check_config.clone(),
        severity,
        warn_threshold: request.warn_threshold,
        fail_threshold: request.fail_threshold,
        enabled: request.enabled,
        schedule: request.schedule.clone(),
        on_demand: request.on_demand,
        created_at: now,
        updated_at: now,
        created_by: created_by.map(String::from),
        tenant_id: tenant_id.map(String::from),
    })
}

/// Get all quality checks for a dataset
pub fn get_quality_checks(
    conn: &rusqlite::Connection,
    dataset_id: i64,
) -> Result<Vec<QualityCheck>, QualityError> {
    let mut stmt = conn
        .prepare(
            r#"
        SELECT id, dataset_id, check_type, check_name, check_description, check_config,
               severity, warn_threshold, fail_threshold, enabled, schedule, on_demand,
               created_at, updated_at, created_by, tenant_id
        FROM quality_checks
        WHERE dataset_id = ?1 AND enabled = 1
        ORDER BY created_at
        "#,
        )
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let checks = stmt
        .query_map([dataset_id], |row| {
            let check_type_str: String = row.get(2)?;
            let severity_str: String = row.get(6)?;
            let created_at_str: String = row.get(12)?;
            let updated_at_str: String = row.get(13)?;

            Ok(QualityCheck {
                id: row.get(0)?,
                dataset_id: row.get(1)?,
                check_type: check_type_str.parse().unwrap_or(QualityCheckType::Custom),
                check_name: row.get(3)?,
                check_description: row.get(4)?,
                check_config: row.get(5)?,
                severity: severity_str
                    .parse()
                    .unwrap_or(QualityCheckSeverity::Warning),
                warn_threshold: row.get(7)?,
                fail_threshold: row.get(8)?,
                enabled: row.get(9)?,
                schedule: row.get(10)?,
                on_demand: row.get(11)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                created_by: row.get(14)?,
                tenant_id: row.get(15)?,
            })
        })
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(checks)
}

/// Get a quality check by ID
pub fn get_quality_check(
    conn: &rusqlite::Connection,
    check_id: &str,
) -> Result<Option<QualityCheck>, QualityError> {
    let result = conn.query_row(
        r#"
        SELECT id, dataset_id, check_type, check_name, check_description, check_config,
               severity, warn_threshold, fail_threshold, enabled, schedule, on_demand,
               created_at, updated_at, created_by, tenant_id
        FROM quality_checks
        WHERE id = ?1
        "#,
        [check_id],
        |row| {
            let check_type_str: String = row.get(2)?;
            let severity_str: String = row.get(6)?;
            let created_at_str: String = row.get(12)?;
            let updated_at_str: String = row.get(13)?;

            Ok(QualityCheck {
                id: row.get(0)?,
                dataset_id: row.get(1)?,
                check_type: check_type_str.parse().unwrap_or(QualityCheckType::Custom),
                check_name: row.get(3)?,
                check_description: row.get(4)?,
                check_config: row.get(5)?,
                severity: severity_str
                    .parse()
                    .unwrap_or(QualityCheckSeverity::Warning),
                warn_threshold: row.get(7)?,
                fail_threshold: row.get(8)?,
                enabled: row.get(9)?,
                schedule: row.get(10)?,
                on_demand: row.get(11)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                created_by: row.get(14)?,
                tenant_id: row.get(15)?,
            })
        },
    );

    match result {
        Ok(check) => Ok(Some(check)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(QualityError::DatabaseError(e.to_string())),
    }
}

/// Store a quality check result
pub fn store_quality_check_result(
    conn: &rusqlite::Connection,
    result: &QualityCheckResult,
) -> Result<(), QualityError> {
    conn.execute(
        r#"
        INSERT INTO quality_results (
            id, check_id, dataset_id, status, score, details, error_message,
            records_checked, records_failed, executed_at, execution_time_ms,
            execution_mode, delta_version
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
        )
        "#,
        rusqlite::params![
            result.id,
            result.check_id,
            result.dataset_id,
            result.status.to_string(),
            result.score,
            result.details,
            result.error_message,
            result.records_checked,
            result.records_failed,
            result.executed_at.to_rfc3339(),
            result.execution_time_ms,
            result.execution_mode.to_string(),
            result.delta_version,
        ],
    )
    .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(())
}

/// Get quality check results for a dataset
pub fn get_quality_check_results(
    conn: &rusqlite::Connection,
    dataset_id: i64,
    limit: Option<i64>,
) -> Result<Vec<QualityCheckResult>, QualityError> {
    let limit = limit.unwrap_or(100);

    let mut stmt = conn
        .prepare(
            r#"
        SELECT id, check_id, dataset_id, status, score, details, error_message,
               records_checked, records_failed, executed_at, execution_time_ms,
               execution_mode, delta_version
        FROM quality_results
        WHERE dataset_id = ?1
        ORDER BY executed_at DESC
        LIMIT ?2
        "#,
        )
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let results = stmt
        .query_map([dataset_id, limit], |row| {
            let status_str: String = row.get(3)?;
            let executed_at_str: String = row.get(9)?;
            let mode_str: String = row.get(11)?;

            Ok(QualityCheckResult {
                id: row.get(0)?,
                check_id: row.get(1)?,
                dataset_id: row.get(2)?,
                status: status_str.parse().unwrap_or(QualityCheckStatus::Error),
                score: row.get(4)?,
                details: row.get(5)?,
                error_message: row.get(6)?,
                records_checked: row.get(7)?,
                records_failed: row.get(8)?,
                executed_at: chrono::DateTime::parse_from_rfc3339(&executed_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                execution_time_ms: row.get(10)?,
                execution_mode: if mode_str == "scheduled" {
                    QualityCheckExecutionMode::Scheduled
                } else {
                    QualityCheckExecutionMode::OnDemand
                },
                delta_version: row.get(12)?,
            })
        })
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(results)
}

/// Delete a quality check
pub fn delete_quality_check(
    conn: &rusqlite::Connection,
    check_id: &str,
) -> Result<bool, QualityError> {
    let rows = conn
        .execute("DELETE FROM quality_checks WHERE id = ?1", [check_id])
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(rows > 0)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp_score_valid() {
        assert_eq!(clamp_score(0.5), 0.5);
        assert_eq!(clamp_score(0.0), 0.0);
        assert_eq!(clamp_score(1.0), 1.0);
    }

    #[test]
    fn test_clamp_score_out_of_range() {
        assert_eq!(clamp_score(1.5), 1.0);
        assert_eq!(clamp_score(-0.5), 0.0);
    }

    #[test]
    fn test_clamp_score_nan_inf() {
        assert_eq!(clamp_score(f64::NAN), 0.0);
        assert_eq!(clamp_score(f64::INFINITY), 0.0);
        assert_eq!(clamp_score(f64::NEG_INFINITY), 0.0);
    }

    #[test]
    fn test_quality_error_display() {
        let err = QualityError::DeltaError("test".to_string());
        assert!(err.to_string().contains("Delta error"));

        let err = QualityError::NoFreshnessConfig;
        assert!(err.to_string().contains("freshness"));
    }

    #[test]
    fn test_quality_details_default() {
        let details = QualityDetails::default();
        assert!(details.row_count.is_none());
        assert!(details.file_count.is_none());
        assert!(details.size_bytes.is_none());
    }

    #[test]
    fn test_store_and_get_quality() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();

        // Initialize schema
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Insert a dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('test_ds', '/test', 'delta', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();

        let dataset_id: i64 = conn
            .query_row(
                "SELECT id FROM datasets WHERE name = 'test_ds'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        // Store quality scores
        let scores = QualityScores {
            completeness_score: Some(0.95),
            freshness_score: Some(1.0),
            file_health_score: Some(0.8),
            overall_score: Some(0.92),
            details: QualityDetails {
                row_count: Some(1000),
                file_count: Some(10),
                size_bytes: Some(1024 * 1024 * 1024),
                small_file_count: Some(2),
                avg_file_size: Some(100 * 1024 * 1024),
                ..Default::default()
            },
        };

        let id = store_quality_scores(&conn, dataset_id, &scores).unwrap();
        assert!(id > 0);

        // Get latest quality
        let result = get_latest_quality(&conn, dataset_id, "test_ds").unwrap();
        assert!(result.is_some());

        let quality = result.unwrap();
        assert_eq!(quality.dataset_id, dataset_id);
        assert_eq!(quality.scores.completeness_score, Some(0.95));
        assert_eq!(quality.scores.overall_score, Some(0.92));
    }

    #[test]
    fn test_get_unhealthy_datasets() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();

        // Initialize schema
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Insert datasets
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('healthy_ds', '/healthy', 'delta', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('unhealthy_ds', '/unhealthy', 'delta', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();

        let healthy_id: i64 = conn
            .query_row(
                "SELECT id FROM datasets WHERE name = 'healthy_ds'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let unhealthy_id: i64 = conn
            .query_row(
                "SELECT id FROM datasets WHERE name = 'unhealthy_ds'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        // Store quality scores
        let healthy_scores = QualityScores {
            completeness_score: Some(0.95),
            freshness_score: Some(1.0),
            file_health_score: Some(0.9),
            overall_score: Some(0.95),
            details: QualityDetails::default(),
        };

        let unhealthy_scores = QualityScores {
            completeness_score: Some(0.5),
            freshness_score: Some(0.3),
            file_health_score: Some(0.6),
            overall_score: Some(0.45),
            details: QualityDetails::default(),
        };

        store_quality_scores(&conn, healthy_id, &healthy_scores).unwrap();
        store_quality_scores(&conn, unhealthy_id, &unhealthy_scores).unwrap();

        // Get unhealthy datasets (threshold 0.7)
        let result = get_unhealthy_datasets(&conn, 0.7).unwrap();

        assert_eq!(result.threshold, 0.7);
        assert_eq!(result.datasets.len(), 1);
        assert_eq!(result.datasets[0].dataset_name, "unhealthy_ds");
        assert_eq!(result.datasets[0].overall_score, 0.45);
    }

    #[test]
    fn test_get_latest_quality_not_found() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();

        // Initialize schema
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Query non-existent dataset
        let result = get_latest_quality(&conn, 9999, "nonexistent").unwrap();
        assert!(result.is_none());
    }
}

// =============================================================================
// Background Scheduled Quality Check Task
// =============================================================================

use std::time::Duration;

/// Default interval for scheduled quality check runs (60 seconds)
const DEFAULT_SCHEDULED_CHECK_INTERVAL_SECS: u64 = 60;

/// Configuration for the scheduled quality check background task
#[derive(Debug, Clone)]
pub struct ScheduledQualityCheckConfig {
    /// How often to check for due quality checks (seconds)
    pub check_interval_secs: u64,
    /// Minimum interval between executions of the same check (seconds)
    /// Prevents re-running a check too frequently even if schedule allows
    pub min_execution_interval_secs: i64,
    /// Whether scheduled execution is enabled
    pub enabled: bool,
}

impl Default for ScheduledQualityCheckConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: DEFAULT_SCHEDULED_CHECK_INTERVAL_SECS,
            min_execution_interval_secs: 300, // 5 minutes minimum between runs
            enabled: true,
        }
    }
}

/// Information about a scheduled quality check that is due for execution
#[derive(Debug, Clone)]
pub struct DueQualityCheck {
    pub check: QualityCheck,
    pub dataset_id: i64,
    pub dataset_name: String,
    pub delta_location: Option<String>,
    pub last_executed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Find scheduled quality checks that are due for execution
///
/// A check is due if:
/// 1. It has a schedule (not NULL)
/// 2. It's enabled
/// 3. It hasn't been executed within min_execution_interval_secs
pub fn find_due_quality_checks(
    conn: &rusqlite::Connection,
    min_interval_secs: i64,
) -> Result<Vec<DueQualityCheck>, QualityError> {
    // Query checks with their last execution time
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                qc.id, qc.dataset_id, qc.check_type, qc.check_name, qc.check_description,
                qc.check_config, qc.severity, qc.warn_threshold, qc.fail_threshold,
                qc.enabled, qc.schedule, qc.on_demand, qc.created_at, qc.updated_at,
                qc.created_by, qc.tenant_id,
                d.name as dataset_name, d.delta_location,
                (SELECT MAX(executed_at) FROM quality_results WHERE check_id = qc.id) as last_executed
            FROM quality_checks qc
            JOIN datasets d ON d.id = qc.dataset_id
            WHERE qc.enabled = 1
              AND qc.schedule IS NOT NULL
              AND (
                  -- Never executed, or executed more than min_interval_secs ago
                  (SELECT MAX(executed_at) FROM quality_results WHERE check_id = qc.id) IS NULL
                  OR (julianday('now') - julianday((SELECT MAX(executed_at) FROM quality_results WHERE check_id = qc.id))) * 86400 > ?1
              )
            ORDER BY last_executed ASC NULLS FIRST
            LIMIT 100
            "#,
        )
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let due_checks = stmt
        .query_map([min_interval_secs], |row| {
            let check_type_str: String = row.get(2)?;
            let severity_str: String = row.get(6)?;
            let created_at_str: String = row.get(12)?;
            let updated_at_str: String = row.get(13)?;
            let last_executed_str: Option<String> = row.get(18)?;

            let check = QualityCheck {
                id: row.get(0)?,
                dataset_id: row.get(1)?,
                check_type: check_type_str.parse().unwrap_or(QualityCheckType::Custom),
                check_name: row.get(3)?,
                check_description: row.get(4)?,
                check_config: row.get(5)?,
                severity: severity_str
                    .parse()
                    .unwrap_or(QualityCheckSeverity::Warning),
                warn_threshold: row.get(7)?,
                fail_threshold: row.get(8)?,
                enabled: row.get(9)?,
                schedule: row.get(10)?,
                on_demand: row.get(11)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                created_by: row.get(14)?,
                tenant_id: row.get(15)?,
            };

            let last_executed_at = last_executed_str.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            });

            Ok(DueQualityCheck {
                check,
                dataset_id: row.get(1)?,
                dataset_name: row.get(16)?,
                delta_location: row.get(17)?,
                last_executed_at,
            })
        })
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(due_checks)
}

/// Background task that periodically executes scheduled quality checks
///
/// This task:
/// 1. Runs every `check_interval_secs` seconds
/// 2. Queries for quality checks that are due for execution
/// 3. Executes each check using pre-fetched data (no connection held across await)
/// 4. Stores results and optionally triggers alerts
pub async fn quality_check_task(
    delta_reader: std::sync::Arc<metafuse_catalog_delta::DeltaReader>,
    backend: std::sync::Arc<metafuse_catalog_storage::DynCatalogBackend>,
    config: ScheduledQualityCheckConfig,
) {
    let interval = Duration::from_secs(config.check_interval_secs);

    info!(
        interval_secs = config.check_interval_secs,
        min_execution_interval_secs = config.min_execution_interval_secs,
        "Scheduled quality check task started"
    );

    loop {
        tokio::time::sleep(interval).await;

        if !config.enabled {
            debug!("Scheduled quality checks disabled, skipping");
            continue;
        }

        debug!("Running scheduled quality check scan");

        // Phase 1: Get connection and find due checks
        let due_checks = match backend.get_connection().await {
            Ok(conn) => match find_due_quality_checks(&conn, config.min_execution_interval_secs) {
                Ok(checks) => checks,
                Err(e) => {
                    warn!(error = %e, "Failed to query due quality checks");
                    continue;
                }
            },
            Err(e) => {
                warn!(error = %e, "Failed to get database connection for quality check scan");
                continue;
            }
        };

        if due_checks.is_empty() {
            debug!("No scheduled quality checks due");
            continue;
        }

        info!(
            count = due_checks.len(),
            "Found scheduled quality checks due for execution"
        );

        // Process each due check
        for due_check in due_checks {
            // Phase 2: Pre-fetch freshness config if needed
            let freshness_config = if due_check.check.check_type == QualityCheckType::Freshness {
                match backend.get_connection().await {
                    Ok(conn) => conn
                        .query_row(
                            "SELECT expected_interval_secs, grace_period_secs FROM freshness_config WHERE dataset_id = ?1",
                            [due_check.dataset_id],
                            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                        )
                        .ok(),
                    Err(_) => None,
                }
            } else {
                None
            };

            // Phase 3: Get Delta metadata if available (async, no connection)
            let delta_metadata = if let Some(ref loc) = due_check.delta_location {
                match delta_reader.get_metadata_cached(loc).await {
                    Ok(metadata) => Some(metadata),
                    Err(e) => {
                        debug!(
                            check_id = %due_check.check.id,
                            error = %e,
                            "Failed to get Delta metadata for scheduled check"
                        );
                        None
                    }
                }
            } else {
                None
            };

            // Phase 4: Execute check
            let start = std::time::Instant::now();
            let result_id = uuid::Uuid::new_v4().to_string();

            let (score, details, records_checked, records_failed, status) =
                execute_check_sync(&due_check, &delta_metadata, &freshness_config);

            let execution_time_ms = start.elapsed().as_millis() as i64;

            let result = QualityCheckResult {
                id: result_id,
                check_id: due_check.check.id.clone(),
                dataset_id: due_check.dataset_id,
                status,
                score: Some(score),
                details,
                error_message: None,
                records_checked: Some(records_checked),
                records_failed: Some(records_failed),
                executed_at: chrono::Utc::now(),
                execution_time_ms: Some(execution_time_ms),
                execution_mode: QualityCheckExecutionMode::Scheduled,
                delta_version: delta_metadata.as_ref().map(|m| m.version),
            };

            // Phase 5: Store result (new connection)
            match backend.get_connection().await {
                Ok(conn) => {
                    if let Err(e) = store_quality_check_result(&conn, &result) {
                        warn!(
                            check_id = %due_check.check.id,
                            error = %e,
                            "Failed to store scheduled check result"
                        );
                    } else {
                        info!(
                            check_id = %due_check.check.id,
                            check_name = %due_check.check.check_name,
                            dataset_name = %due_check.dataset_name,
                            status = %result.status,
                            score = ?result.score,
                            execution_time_ms,
                            "Scheduled quality check executed"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        check_id = %due_check.check.id,
                        error = %e,
                        "Failed to get connection to store scheduled check result"
                    );
                }
            }
        }
    }
}

/// Execute a quality check synchronously using pre-fetched data
fn execute_check_sync(
    due_check: &DueQualityCheck,
    delta_metadata: &Option<metafuse_catalog_delta::DeltaMetadata>,
    freshness_config: &Option<(i64, i64)>,
) -> (f64, Option<String>, i64, i64, QualityCheckStatus) {
    match due_check.check.check_type {
        QualityCheckType::Completeness => {
            if let Some(ref metadata) = delta_metadata {
                let row_count = metadata.row_count;
                let column_count = metadata.schema.fields.len() as i64;

                if row_count == 0 || column_count == 0 {
                    (
                        1.0,
                        Some(r#"{"status":"empty_table"}"#.to_string()),
                        0,
                        0,
                        QualityCheckStatus::Pass,
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
                    let status = determine_status_sync(score, &due_check.check);
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
                    QualityCheckStatus::Skipped,
                )
            }
        }
        QualityCheckType::Freshness => {
            if let Some((expected_interval, grace_period)) = freshness_config {
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
                let status = determine_status_sync(score, &due_check.check);
                (score, Some(details.to_string()), 1, failed, status)
            } else {
                (
                    1.0,
                    Some(r#"{"status":"no_freshness_config"}"#.to_string()),
                    0,
                    0,
                    QualityCheckStatus::Skipped,
                )
            }
        }
        _ => {
            // Uniqueness and Custom checks require external execution
            let details = serde_json::json!({
                "status": "requires_external_execution",
                "message": "This check type requires external data scanning",
                "check_config": due_check.check.check_config,
            });
            (
                1.0,
                Some(details.to_string()),
                0,
                0,
                QualityCheckStatus::Skipped,
            )
        }
    }
}

/// Determine status based on score and thresholds (standalone function)
fn determine_status_sync(score: f64, check: &QualityCheck) -> QualityCheckStatus {
    if let Some(fail_threshold) = check.fail_threshold {
        if score < fail_threshold {
            return QualityCheckStatus::Fail;
        }
    }
    if let Some(warn_threshold) = check.warn_threshold {
        if score < warn_threshold {
            return QualityCheckStatus::Warn;
        }
    }
    QualityCheckStatus::Pass
}

// =============================================================================
// Freshness Violation Detection
// =============================================================================

use metafuse_catalog_core::FreshnessViolation;

/// Information about a dataset that may be violating its freshness SLA
#[derive(Debug, Clone)]
pub struct FreshnessCheckTarget {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub tenant_id: Option<String>,
    pub delta_location: Option<String>,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    pub expected_interval_secs: i64,
    pub grace_period_secs: i64,
    pub alert_on_stale: bool,
}

/// Detect freshness violations for all datasets with freshness config
///
/// Returns newly detected violations (not already open for the same dataset)
pub fn detect_freshness_violations(
    conn: &rusqlite::Connection,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<FreshnessViolation>, QualityError> {
    // Find datasets that are stale but don't have an open violation
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                d.id,
                d.name,
                d.tenant,
                d.last_updated,
                d.delta_location,
                fc.expected_interval_secs,
                fc.grace_period_secs,
                fc.alert_on_stale
            FROM datasets d
            JOIN freshness_config fc ON d.id = fc.dataset_id
            WHERE d.last_updated IS NOT NULL
              AND (julianday(?1) - julianday(d.last_updated)) * 86400 > (fc.expected_interval_secs + fc.grace_period_secs)
              AND NOT EXISTS (
                  SELECT 1 FROM freshness_violations fv
                  WHERE fv.dataset_id = d.id AND fv.resolved_at IS NULL
              )
            "#,
        )
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let stale_datasets = stmt
        .query_map([now.to_rfc3339()], |row| {
            let last_updated_str: Option<String> = row.get(3)?;
            let last_updated = last_updated_str.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            });

            Ok(FreshnessCheckTarget {
                dataset_id: row.get(0)?,
                dataset_name: row.get(1)?,
                tenant_id: row.get(2)?,
                delta_location: row.get(4)?,
                last_updated,
                expected_interval_secs: row.get(5)?,
                grace_period_secs: row.get(6)?,
                alert_on_stale: row.get::<_, i32>(7)? != 0,
            })
        })
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let mut violations = Vec::new();

    for target in stale_datasets {
        let last_updated = target.last_updated.unwrap_or(now);

        // Calculate when the data should have been updated
        let expected_by = last_updated
            + chrono::Duration::seconds(target.expected_interval_secs + target.grace_period_secs);

        let hours_overdue = (now - expected_by).num_seconds() as f64 / 3600.0;

        // Determine SLA label
        let sla = if target.expected_interval_secs <= 3600 {
            "hourly"
        } else if target.expected_interval_secs <= 86400 {
            "daily"
        } else if target.expected_interval_secs <= 604800 {
            "weekly"
        } else {
            "custom"
        };

        let violation = FreshnessViolation {
            id: uuid::Uuid::new_v4().to_string(),
            dataset_id: target.dataset_id,
            expected_by,
            detected_at: now,
            resolved_at: None,
            sla: sla.to_string(),
            grace_period_minutes: Some((target.grace_period_secs / 60) as i32),
            hours_overdue: Some(hours_overdue.max(0.0)),
            last_updated_at: target.last_updated,
            alert_sent: false,
            alert_id: None,
            tenant_id: target.tenant_id,
        };

        violations.push(violation);
    }

    Ok(violations)
}

/// Record a freshness violation in the database
pub fn record_freshness_violation(
    conn: &rusqlite::Connection,
    violation: &FreshnessViolation,
) -> Result<(), QualityError> {
    conn.execute(
        r#"
        INSERT INTO freshness_violations (
            id, dataset_id, expected_by, detected_at, resolved_at,
            sla, grace_period_minutes, hours_overdue, last_updated_at,
            alert_sent, alert_id, tenant_id
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
        )
        "#,
        rusqlite::params![
            violation.id,
            violation.dataset_id,
            violation.expected_by.to_rfc3339(),
            violation.detected_at.to_rfc3339(),
            violation.resolved_at.map(|dt| dt.to_rfc3339()),
            violation.sla,
            violation.grace_period_minutes,
            violation.hours_overdue,
            violation.last_updated_at.map(|dt| dt.to_rfc3339()),
            violation.alert_sent,
            violation.alert_id,
            violation.tenant_id,
        ],
    )
    .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(())
}

/// Resolve open freshness violations for a dataset (called when data is updated)
pub fn resolve_freshness_violations(
    conn: &rusqlite::Connection,
    dataset_id: i64,
    resolved_at: chrono::DateTime<chrono::Utc>,
) -> Result<usize, QualityError> {
    let rows = conn
        .execute(
            "UPDATE freshness_violations SET resolved_at = ?1 WHERE dataset_id = ?2 AND resolved_at IS NULL",
            rusqlite::params![resolved_at.to_rfc3339(), dataset_id],
        )
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    if rows > 0 {
        info!(
            dataset_id,
            resolved_count = rows,
            "Resolved freshness violations"
        );
    }

    Ok(rows)
}

/// Get open (unresolved) freshness violations
pub fn get_open_violations(
    conn: &rusqlite::Connection,
    dataset_id: Option<i64>,
) -> Result<Vec<FreshnessViolation>, QualityError> {
    let sql = if dataset_id.is_some() {
        r#"
        SELECT id, dataset_id, expected_by, detected_at, resolved_at,
               sla, grace_period_minutes, hours_overdue, last_updated_at,
               alert_sent, alert_id, tenant_id
        FROM freshness_violations
        WHERE resolved_at IS NULL AND dataset_id = ?1
        ORDER BY detected_at DESC
        "#
    } else {
        r#"
        SELECT id, dataset_id, expected_by, detected_at, resolved_at,
               sla, grace_period_minutes, hours_overdue, last_updated_at,
               alert_sent, alert_id, tenant_id
        FROM freshness_violations
        WHERE resolved_at IS NULL
        ORDER BY detected_at DESC
        LIMIT 100
        "#
    };

    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let query_result = if let Some(ds_id) = dataset_id {
        stmt.query_map([ds_id], map_violation_row)
    } else {
        stmt.query_map([], map_violation_row)
    };

    let violations = query_result
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(violations)
}

/// Get open (unresolved) freshness violations with pagination
pub fn get_open_violations_paginated(
    conn: &rusqlite::Connection,
    limit: i64,
    offset: i64,
) -> Result<Vec<FreshnessViolation>, QualityError> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, dataset_id, expected_by, detected_at, resolved_at,
                   sla, grace_period_minutes, hours_overdue, last_updated_at,
                   alert_sent, alert_id, tenant_id
            FROM freshness_violations
            WHERE resolved_at IS NULL
            ORDER BY detected_at DESC
            LIMIT ?1 OFFSET ?2
            "#,
        )
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let violations = stmt
        .query_map([limit, offset], map_violation_row)
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(violations)
}

/// Get violations for a dataset (with history)
pub fn get_dataset_violations(
    conn: &rusqlite::Connection,
    dataset_id: i64,
    limit: i64,
) -> Result<Vec<FreshnessViolation>, QualityError> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, dataset_id, expected_by, detected_at, resolved_at,
                   sla, grace_period_minutes, hours_overdue, last_updated_at,
                   alert_sent, alert_id, tenant_id
            FROM freshness_violations
            WHERE dataset_id = ?1
            ORDER BY detected_at DESC
            LIMIT ?2
            "#,
        )
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let violations = stmt
        .query_map([dataset_id, limit], map_violation_row)
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(violations)
}

/// Get violations that need alerting (unalerted)
pub fn get_unalerted_violations(
    conn: &rusqlite::Connection,
) -> Result<Vec<FreshnessViolation>, QualityError> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, dataset_id, expected_by, detected_at, resolved_at,
                   sla, grace_period_minutes, hours_overdue, last_updated_at,
                   alert_sent, alert_id, tenant_id
            FROM freshness_violations
            WHERE alert_sent = 0 AND resolved_at IS NULL
            ORDER BY detected_at ASC
            LIMIT 50
            "#,
        )
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    let violations = stmt
        .query_map([], map_violation_row)
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(violations)
}

/// Mark a violation as alerted
pub fn mark_violation_alerted(
    conn: &rusqlite::Connection,
    violation_id: &str,
    alert_id: Option<&str>,
) -> Result<(), QualityError> {
    conn.execute(
        "UPDATE freshness_violations SET alert_sent = 1, alert_id = ?1 WHERE id = ?2",
        rusqlite::params![alert_id, violation_id],
    )
    .map_err(|e| QualityError::DatabaseError(e.to_string()))?;

    Ok(())
}

/// Helper function to map a database row to FreshnessViolation
fn map_violation_row(row: &rusqlite::Row<'_>) -> Result<FreshnessViolation, rusqlite::Error> {
    let expected_by_str: String = row.get(2)?;
    let detected_at_str: String = row.get(3)?;
    let resolved_at_str: Option<String> = row.get(4)?;
    let last_updated_str: Option<String> = row.get(8)?;

    Ok(FreshnessViolation {
        id: row.get(0)?,
        dataset_id: row.get(1)?,
        expected_by: chrono::DateTime::parse_from_rfc3339(&expected_by_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now()),
        detected_at: chrono::DateTime::parse_from_rfc3339(&detected_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now()),
        resolved_at: resolved_at_str.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        }),
        sla: row.get(5)?,
        grace_period_minutes: row.get(6)?,
        hours_overdue: row.get(7)?,
        last_updated_at: last_updated_str.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        }),
        alert_sent: row.get::<_, i32>(9)? != 0,
        alert_id: row.get(10)?,
        tenant_id: row.get(11)?,
    })
}

/// Background task for freshness violation detection
///
/// Runs periodically to:
/// 1. Detect new freshness violations
/// 2. Record them in the database
/// 3. Queue them for alerting
pub async fn freshness_check_task(
    backend: std::sync::Arc<metafuse_catalog_storage::DynCatalogBackend>,
    config: FreshnessCheckConfig,
) {
    let interval = Duration::from_secs(config.check_interval_secs);

    info!(
        interval_secs = config.check_interval_secs,
        "Freshness violation detection task started"
    );

    loop {
        tokio::time::sleep(interval).await;

        if !config.enabled {
            debug!("Freshness violation detection disabled, skipping");
            continue;
        }

        debug!("Running freshness violation detection");

        match backend.get_connection().await {
            Ok(conn) => {
                let now = chrono::Utc::now();

                // Detect violations
                let violations = match detect_freshness_violations(&conn, now) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "Failed to detect freshness violations");
                        continue;
                    }
                };

                if violations.is_empty() {
                    debug!("No new freshness violations detected");
                    continue;
                }

                info!(
                    count = violations.len(),
                    "New freshness violations detected"
                );

                // Record each violation
                for violation in &violations {
                    if let Err(e) = record_freshness_violation(&conn, violation) {
                        warn!(
                            dataset_id = violation.dataset_id,
                            error = %e,
                            "Failed to record freshness violation"
                        );
                    } else {
                        info!(
                            dataset_id = violation.dataset_id,
                            sla = %violation.sla,
                            hours_overdue = ?violation.hours_overdue,
                            "Freshness violation recorded"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to get connection for freshness check");
            }
        }
    }
}

/// Configuration for freshness violation detection
#[derive(Debug, Clone)]
pub struct FreshnessCheckConfig {
    /// How often to check for freshness violations (seconds)
    pub check_interval_secs: u64,
    /// Whether freshness detection is enabled
    pub enabled: bool,
}

impl Default for FreshnessCheckConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 60, // Check every minute
            enabled: true,
        }
    }
}
