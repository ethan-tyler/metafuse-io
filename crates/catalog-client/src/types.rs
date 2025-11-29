//! Response types for the MetaFuse API.
//!
//! These types mirror the API response structures and are used for
//! deserialization of JSON responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Summary information about a dataset (from list endpoints).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSummary {
    /// Unique name of the dataset
    pub name: String,
    /// Storage path
    pub path: String,
    /// Format (parquet, delta, iceberg, csv)
    pub format: String,
    /// Business domain
    pub domain: Option<String>,
    /// Owner/responsible party
    pub owner: Option<String>,
    /// Brief description
    pub description: Option<String>,
    /// Row count (if known)
    pub row_count: Option<i64>,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Full dataset metadata (from get endpoints).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// Unique name of the dataset
    pub name: String,
    /// Storage path
    pub path: String,
    /// Format (parquet, delta, iceberg, csv)
    pub format: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Tenant identifier
    pub tenant: Option<String>,
    /// Business domain
    pub domain: Option<String>,
    /// Owner/responsible party
    pub owner: Option<String>,
    /// When the dataset was first registered
    pub created_at: DateTime<Utc>,
    /// When the dataset metadata was last updated
    pub last_updated: DateTime<Utc>,
    /// Schema fields
    #[serde(default)]
    pub fields: Vec<Field>,
    /// Upstream dataset names (lineage)
    #[serde(default)]
    pub upstream_datasets: Vec<String>,
    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
    /// Row count (if known)
    pub row_count: Option<i64>,
    /// Size in bytes (if known)
    pub size_bytes: Option<i64>,
    /// Partition columns
    #[serde(default)]
    pub partition_keys: Vec<String>,
    /// Delta table location (if applicable)
    pub delta_location: Option<String>,
    /// Delta metadata (when requested via include=delta)
    pub delta: Option<DeltaInfo>,
    /// Quality metrics (when requested via include=quality)
    pub quality: Option<QualityInfo>,
    /// Classification info (when requested via include=classification)
    pub classification: Option<ClassificationInfo>,
}

/// Field/column metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    /// Field name
    pub name: String,
    /// Data type (Arrow format)
    pub data_type: String,
    /// Whether the field allows nulls
    pub nullable: bool,
    /// Human-readable description
    pub description: Option<String>,
}

/// Delta Lake metadata included in dataset response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaInfo {
    /// Current Delta version
    pub version: i64,
    /// Total row count
    pub row_count: i64,
    /// Size in bytes
    pub size_bytes: i64,
    /// Number of active files
    pub num_files: i64,
    /// Last modification timestamp
    pub last_modified: DateTime<Utc>,
    /// Partition columns
    #[serde(default)]
    pub partition_columns: Vec<String>,
    /// Column-level statistics
    #[serde(default)]
    pub column_stats: Vec<ColumnStats>,
}

/// Column-level statistics from Delta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnStats {
    /// Column name
    pub name: String,
    /// Data type
    pub data_type: String,
    /// Whether nullable
    pub nullable: bool,
    /// Null count
    pub null_count: Option<i64>,
    /// Minimum value (as JSON)
    pub min_value: Option<serde_json::Value>,
    /// Maximum value (as JSON)
    pub max_value: Option<serde_json::Value>,
    /// Distinct count (if available)
    pub distinct_count: Option<i64>,
}

/// Quality metrics for a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityInfo {
    /// Overall quality score (0-100)
    pub score: Option<f64>,
    /// Individual dimension scores
    #[serde(default)]
    pub dimensions: Vec<QualityDimension>,
    /// When quality was last computed
    pub computed_at: Option<DateTime<Utc>>,
}

/// A single quality dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityDimension {
    /// Dimension name (completeness, accuracy, etc.)
    pub name: String,
    /// Score for this dimension (0-100)
    pub score: f64,
    /// Weight in overall calculation
    pub weight: f64,
}

/// Classification information for a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationInfo {
    /// Sensitivity level
    pub sensitivity: Option<String>,
    /// Data categories
    #[serde(default)]
    pub categories: Vec<String>,
    /// Compliance frameworks
    #[serde(default)]
    pub compliance: Vec<String>,
}

/// Delta version history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaVersion {
    /// Version number
    pub version: i64,
    /// Timestamp of the commit
    pub timestamp: DateTime<Utc>,
    /// Operation performed (WRITE, DELETE, MERGE, etc.)
    pub operation: String,
    /// User who performed the operation
    pub user_name: Option<String>,
}

/// Delta table history response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaHistory {
    /// Dataset name
    pub dataset: String,
    /// History entries
    pub history: Vec<DeltaVersion>,
}

/// Search results response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    /// Search query
    pub query: String,
    /// Total number of matches
    pub total: usize,
    /// Matching datasets
    pub datasets: Vec<DatasetSummary>,
}

/// List datasets response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDatasetsResponse {
    /// Total count (if available)
    pub total: Option<usize>,
    /// Datasets
    pub datasets: Vec<DatasetSummary>,
}

/// API error response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Error message
    pub error: String,
    /// Error code (if applicable)
    pub code: Option<String>,
    /// Request ID for tracking
    pub request_id: Option<String>,
    /// Additional details
    pub details: Option<serde_json::Value>,
}

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Health status (healthy, degraded, unhealthy)
    pub status: String,
    /// Server version
    pub version: Option<String>,
    /// Additional info
    #[serde(default)]
    pub info: std::collections::HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_summary_deserialize() {
        let json = r#"{
            "name": "test_dataset",
            "path": "s3://bucket/path",
            "format": "delta",
            "domain": "analytics",
            "owner": "team@example.com",
            "description": "Test dataset",
            "row_count": 1000,
            "last_updated": "2024-01-15T10:30:00Z",
            "tags": ["production", "daily"]
        }"#;

        let summary: DatasetSummary = serde_json::from_str(json).unwrap();
        assert_eq!(summary.name, "test_dataset");
        assert_eq!(summary.format, "delta");
        assert_eq!(summary.row_count, Some(1000));
        assert_eq!(summary.tags.len(), 2);
    }

    #[test]
    fn test_api_error_deserialize() {
        let json = r#"{
            "error": "Dataset not found",
            "code": "NOT_FOUND",
            "request_id": "req-12345"
        }"#;

        let error: ApiError = serde_json::from_str(json).unwrap();
        assert_eq!(error.error, "Dataset not found");
        assert_eq!(error.code, Some("NOT_FOUND".to_string()));
        assert_eq!(error.request_id, Some("req-12345".to_string()));
    }
}
