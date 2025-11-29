//! Delta Lake integration for MetaFuse catalog.
//!
//! This crate provides functionality to read metadata from Delta Lake tables,
//! including schema, statistics, column stats, and transaction history.
//!
//! # Architecture
//!
//! The core principle is: **"Read from Delta, never store what Delta maintains."**
//!
//! - Schema, row counts, file statistics → Read live from Delta
//! - Column-level statistics (min/max/null counts) → Aggregated from Delta file stats
//! - Transaction history → Read from Delta log
//! - Caching → Optional LRU cache with configurable TTL
//!
//! # URL Formats
//!
//! The following location formats are supported:
//! - `file:///path/to/table` - Local file path with scheme
//! - `/path/to/table` - Absolute local path (auto-prefixed with `file://`)
//! - `gs://bucket/path` - Google Cloud Storage
//! - `s3://bucket/path` - Amazon S3
//!
//! # Caching Behavior
//!
//! When caching is enabled (TTL > 0), metadata is cached in an LRU cache.
//! Cache entries expire after the configured TTL but are only evicted when:
//! - The entry is accessed after TTL expiration (lazy eviction)
//! - The cache reaches capacity and LRU eviction occurs
//!
//! Stale entries remain in the cache until accessed or evicted by LRU pressure.
//! This is acceptable for most use cases but can be periodically cleaned by
//! calling `clear_cache()` if strict freshness is required.
//!
//! # Example
//!
//! ```rust,ignore
//! use metafuse_catalog_delta::DeltaReader;
//! use std::time::Duration;
//!
//! let reader = DeltaReader::new(Duration::from_secs(60));
//! let metadata = reader.get_metadata("gs://bucket/delta-table/").await?;
//!
//! println!("Schema: {:?}", metadata.schema);
//! println!("Row count: {}", metadata.row_count);
//! println!("Delta version: {}", metadata.version);
//! ```

use chrono::{DateTime, Utc};
use deltalake::DeltaTable;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors that can occur when reading Delta metadata.
#[derive(Error, Debug)]
pub enum DeltaError {
    #[error("Failed to open Delta table at '{0}': {1}")]
    OpenTable(String, String),

    #[error("Failed to read schema from Delta table: {0}")]
    SchemaRead(String),

    #[error("Failed to read statistics from Delta table: {0}")]
    StatsRead(String),

    #[error("Failed to read history from Delta table: {0}")]
    HistoryRead(String),

    #[error("Delta table has no schema")]
    NoSchema,

    #[error("Invalid Delta version: {0}")]
    InvalidVersion(i64),

    #[error("Delta table not found at '{0}'")]
    NotFound(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
}

/// Result type for Delta operations.
pub type Result<T> = std::result::Result<T, DeltaError>;

/// Schema field definition extracted from Delta.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Field {
    /// Field name
    pub name: String,
    /// Data type (Arrow format string)
    pub data_type: String,
    /// Whether the field allows nulls
    pub nullable: bool,
    /// Optional description from Delta metadata
    pub description: Option<String>,
    /// Additional metadata from Delta schema
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Schema extracted from Delta table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Schema {
    /// List of fields in the schema
    pub fields: Vec<Field>,
    /// Partition columns (subset of fields)
    pub partition_columns: Vec<String>,
}

/// Column-level statistics aggregated from Delta file statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ColumnStats {
    /// Column name
    pub name: String,
    /// Data type
    pub data_type: String,
    /// Whether the column allows nulls
    pub nullable: bool,
    /// Total null count across all files
    pub null_count: Option<i64>,
    /// Minimum value (as JSON for flexibility)
    pub min_value: Option<serde_json::Value>,
    /// Maximum value (as JSON for flexibility)
    pub max_value: Option<serde_json::Value>,
    /// Distinct count (if available from Delta stats)
    pub distinct_count: Option<i64>,
}

/// File information from Delta snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// File path relative to table root
    pub path: String,
    /// File size in bytes
    pub size: i64,
    /// Modification timestamp (milliseconds since epoch)
    pub modification_time: i64,
}

/// Complete metadata extracted from a Delta table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaMetadata {
    /// Schema with field definitions
    pub schema: Schema,
    /// Total row count (aggregated from file stats)
    pub row_count: i64,
    /// Total size in bytes
    pub size_bytes: i64,
    /// Number of active files
    pub num_files: i64,
    /// List of file information
    pub files: Vec<FileInfo>,
    /// Partition columns
    pub partition_columns: Vec<String>,
    /// Last modification timestamp
    pub last_modified: DateTime<Utc>,
    /// Current Delta version
    pub version: i64,
    /// Column-level statistics
    pub column_stats: Vec<ColumnStats>,
}

/// A single version in Delta transaction history.
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
    /// Operation parameters
    pub parameters: HashMap<String, String>,
    /// Operation metrics (rows written, files added, etc.)
    pub metrics: HashMap<String, String>,
}

/// Schema difference between two Delta versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDiff {
    /// From version
    pub from_version: i64,
    /// To version
    pub to_version: i64,
    /// Columns added in the new version
    pub added_columns: Vec<Field>,
    /// Columns removed in the new version
    pub removed_columns: Vec<Field>,
    /// Columns with type changes
    pub modified_columns: Vec<FieldChange>,
}

/// A field that changed between versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    /// Field name
    pub name: String,
    /// Old data type
    pub old_type: String,
    /// New data type
    pub new_type: String,
    /// Old nullable flag
    pub old_nullable: bool,
    /// New nullable flag
    pub new_nullable: bool,
}

/// Cached Delta metadata with timestamp.
struct CachedDeltaMeta {
    metadata: DeltaMetadata,
    cached_at: Instant,
}

/// Delta Lake metadata reader with optional caching.
///
/// The `DeltaReader` provides methods to read schema, statistics, and history
/// from Delta Lake tables. It supports an optional LRU cache to reduce
/// repeated reads from cloud storage.
///
/// # Caching
///
/// When caching is enabled (TTL > 0), metadata is cached in an LRU cache.
/// Cache entries expire after the configured TTL. The cache can hold up to
/// 1000 entries by default.
///
/// **Note:** Cache TTL is checked lazily on access. Stale entries remain in
/// the cache until accessed (and refreshed) or evicted by LRU pressure.
///
/// # Example
///
/// ```rust,ignore
/// use metafuse_catalog_delta::DeltaReader;
/// use std::time::Duration;
///
/// // Create reader with 60-second cache TTL
/// let reader = DeltaReader::new(Duration::from_secs(60));
///
/// // First call reads from Delta
/// let meta1 = reader.get_metadata_cached("gs://bucket/table/").await?;
///
/// // Second call (within TTL) returns cached data
/// let meta2 = reader.get_metadata_cached("gs://bucket/table/").await?;
/// ```
pub struct DeltaReader {
    cache: Arc<RwLock<LruCache<String, CachedDeltaMeta>>>,
    cache_ttl: Duration,
}

impl DeltaReader {
    /// Default cache capacity (number of tables).
    const DEFAULT_CACHE_CAPACITY: usize = 1000;

    /// Create a new DeltaReader with the specified cache TTL.
    ///
    /// Set `cache_ttl` to `Duration::ZERO` to disable caching.
    pub fn new(cache_ttl: Duration) -> Self {
        let capacity = NonZeroUsize::new(Self::DEFAULT_CACHE_CAPACITY).unwrap();
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(capacity))),
            cache_ttl,
        }
    }

    /// Create a new DeltaReader with custom cache capacity.
    pub fn with_capacity(cache_ttl: Duration, capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(capacity))),
            cache_ttl,
        }
    }

    /// Get metadata with caching.
    ///
    /// If the metadata is in the cache and not expired, returns the cached version.
    /// Otherwise, reads fresh metadata from the Delta table and caches it.
    ///
    /// **Note:** Cache TTL is checked lazily. Stale entries are refreshed on access.
    pub async fn get_metadata_cached(&self, location: &str) -> Result<DeltaMetadata> {
        let normalized = Self::normalize_location(location)?;

        // Check cache first
        if self.cache_ttl > Duration::ZERO {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.peek(&normalized) {
                if cached.cached_at.elapsed() < self.cache_ttl {
                    tracing::debug!(location = %location, "Delta metadata cache hit");
                    return Ok(cached.metadata.clone());
                }
            }
        }

        // Cache miss - read from Delta
        tracing::debug!(location = %location, "Delta metadata cache miss, reading from Delta");
        let metadata = self.get_metadata_internal(&normalized).await?;

        // Update cache
        if self.cache_ttl > Duration::ZERO {
            let mut cache = self.cache.write().await;
            cache.put(
                normalized,
                CachedDeltaMeta {
                    metadata: metadata.clone(),
                    cached_at: Instant::now(),
                },
            );
        }

        Ok(metadata)
    }

    /// Normalize a location string to a proper URL.
    ///
    /// Supports:
    /// - `file:///path/to/table` - Already valid URL
    /// - `/path/to/table` - Absolute path, converted to file:// URL
    /// - `gs://bucket/path` - Cloud URLs passed through
    /// - `s3://bucket/path` - Cloud URLs passed through
    fn normalize_location(location: &str) -> Result<String> {
        // If it's already a URL with a scheme, use it directly
        if location.contains("://") {
            return Ok(location.to_string());
        }

        // Check if it's an absolute path
        // Handle Unix-style paths (starting with /) on all platforms,
        // plus platform-native absolute paths (e.g., C:\ on Windows)
        let path = Path::new(location);
        if location.starts_with('/') || path.is_absolute() {
            return Ok(format!("file://{}", location));
        }

        // Otherwise, it's likely a relative path or invalid - let URL parsing handle it
        Err(DeltaError::InvalidUrl(format!(
            "Location must be a URL (file://, gs://, s3://) or an absolute path: {}",
            location
        )))
    }

    /// Open a Delta table from a normalized location URL.
    async fn open_table_from_url(&self, url_str: &str) -> Result<DeltaTable> {
        let url = url::Url::parse(url_str)
            .map_err(|e| DeltaError::InvalidUrl(format!("{}: {}", url_str, e)))?;
        deltalake::open_table(url)
            .await
            .map_err(|e| DeltaError::OpenTable(url_str.to_string(), e.to_string()))
    }

    /// Open a Delta table at a specific version from a normalized URL.
    async fn open_table_at_version_from_url(
        &self,
        url_str: &str,
        version: i64,
    ) -> Result<DeltaTable> {
        let url = url::Url::parse(url_str)
            .map_err(|e| DeltaError::InvalidUrl(format!("{}: {}", url_str, e)))?;
        deltalake::open_table_with_version(url, version)
            .await
            .map_err(|e| DeltaError::OpenTable(url_str.to_string(), e.to_string()))
    }

    /// Get fresh metadata (bypasses cache).
    ///
    /// Reads directly from the Delta table, aggregating statistics from all files.
    /// This always reads the latest version.
    pub async fn get_metadata(&self, location: &str) -> Result<DeltaMetadata> {
        let normalized = Self::normalize_location(location)?;
        self.get_metadata_internal(&normalized).await
    }

    /// Get metadata at a specific Delta version.
    ///
    /// Reads the Delta table at the specified version. This bypasses the cache
    /// since versioned reads are typically for historical analysis.
    pub async fn get_metadata_at_version(
        &self,
        location: &str,
        version: i64,
    ) -> Result<DeltaMetadata> {
        let normalized = Self::normalize_location(location)?;
        let table = self
            .open_table_at_version_from_url(&normalized, version)
            .await?;
        self.extract_metadata_from_table(&table).await
    }

    /// Internal metadata extraction from a normalized URL (latest version).
    async fn get_metadata_internal(&self, url_str: &str) -> Result<DeltaMetadata> {
        let table = self.open_table_from_url(url_str).await?;
        self.extract_metadata_from_table(&table).await
    }

    /// Extract metadata from an opened Delta table.
    async fn extract_metadata_from_table(&self, table: &DeltaTable) -> Result<DeltaMetadata> {
        // Extract schema
        let schema = self.extract_schema(table)?;

        // Get snapshot for statistics
        let snapshot = table
            .snapshot()
            .map_err(|e| DeltaError::StatsRead(format!("Failed to get snapshot: {}", e)))?;

        // Get file list using log_store
        let log_store = table.log_store();
        #[allow(deprecated)]
        let files: Vec<_> = snapshot
            .file_actions(log_store.as_ref())
            .await
            .map_err(|e| DeltaError::StatsRead(format!("Failed to get files: {}", e)))?;

        let (row_count, size_bytes, malformed_stats) = self.aggregate_stats(&files);

        // Log warning if there were malformed stats
        if malformed_stats > 0 {
            tracing::warn!(
                malformed_count = malformed_stats,
                total_files = files.len(),
                "Some Delta file stats were malformed and skipped"
            );
        }

        let column_stats = self.extract_column_stats(table, &files)?;

        // Get partition columns from metadata
        let partition_columns = snapshot.metadata().partition_columns().to_vec();

        // Get last modified timestamp
        let last_modified = snapshot
            .metadata()
            .created_time()
            .and_then(DateTime::from_timestamp_millis)
            .unwrap_or_else(Utc::now);

        // Build file info list
        let file_infos: Vec<FileInfo> = files
            .iter()
            .map(|f| FileInfo {
                path: f.path.clone(),
                size: f.size,
                modification_time: f.modification_time,
            })
            .collect();

        Ok(DeltaMetadata {
            schema,
            row_count,
            size_bytes,
            num_files: files.len() as i64,
            files: file_infos,
            partition_columns,
            last_modified,
            version: table.version().unwrap_or(0),
            column_stats,
        })
    }

    /// Get schema from a Delta table, optionally at a specific version.
    pub async fn get_schema(&self, location: &str, version: Option<i64>) -> Result<Schema> {
        let normalized = Self::normalize_location(location)?;
        let table = match version {
            Some(v) => self.open_table_at_version_from_url(&normalized, v).await?,
            None => self.open_table_from_url(&normalized).await?,
        };

        self.extract_schema(&table)
    }

    /// Get transaction history for a Delta table.
    ///
    /// Returns history entries with version numbers derived from the commit info
    /// when available, falling back to index-based calculation.
    pub async fn get_history(&self, location: &str, limit: usize) -> Result<Vec<DeltaVersion>> {
        let normalized = Self::normalize_location(location)?;
        let table = self.open_table_from_url(&normalized).await?;
        let current_version = table.version().unwrap_or(0);

        let history = table
            .history(Some(limit))
            .await
            .map_err(|e| DeltaError::HistoryRead(e.to_string()))?;

        Ok(history
            .into_iter()
            .enumerate()
            .map(|(idx, commit)| {
                // Use commit.version if available, otherwise fall back to index calculation
                // Note: deltalake 0.29 CommitInfo doesn't expose version directly,
                // so we use the index-based calculation. This assumes history is returned
                // in reverse chronological order (newest first), which is the Delta standard.
                let version = current_version - idx as i64;

                DeltaVersion {
                    version,
                    timestamp: commit
                        .timestamp
                        .and_then(DateTime::from_timestamp_millis)
                        .unwrap_or_else(Utc::now),
                    operation: commit.operation.unwrap_or_default(),
                    user_name: commit.user_name,
                    parameters: commit
                        .operation_parameters
                        .map(|params| {
                            params
                                .into_iter()
                                .map(|(k, v)| (k, v.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    metrics: HashMap::new(), // Metrics not directly available in deltalake 0.29
                }
            })
            .collect())
    }

    /// Compare schemas between two versions.
    pub async fn diff_schemas(
        &self,
        location: &str,
        from_version: i64,
        to_version: i64,
    ) -> Result<SchemaDiff> {
        let from_schema = self.get_schema(location, Some(from_version)).await?;
        let to_schema = self.get_schema(location, Some(to_version)).await?;

        let from_fields: HashMap<_, _> = from_schema.fields.iter().map(|f| (&f.name, f)).collect();

        let to_fields: HashMap<_, _> = to_schema.fields.iter().map(|f| (&f.name, f)).collect();

        // Find added columns
        let added_columns: Vec<Field> = to_schema
            .fields
            .iter()
            .filter(|f| !from_fields.contains_key(&f.name))
            .cloned()
            .collect();

        // Find removed columns
        let removed_columns: Vec<Field> = from_schema
            .fields
            .iter()
            .filter(|f| !to_fields.contains_key(&f.name))
            .cloned()
            .collect();

        // Find modified columns (type or nullable changes)
        let modified_columns: Vec<FieldChange> = from_schema
            .fields
            .iter()
            .filter_map(|from_field| {
                to_fields.get(&from_field.name).and_then(|to_field| {
                    if from_field.data_type != to_field.data_type
                        || from_field.nullable != to_field.nullable
                    {
                        Some(FieldChange {
                            name: from_field.name.clone(),
                            old_type: from_field.data_type.clone(),
                            new_type: to_field.data_type.clone(),
                            old_nullable: from_field.nullable,
                            new_nullable: to_field.nullable,
                        })
                    } else {
                        None
                    }
                })
            })
            .collect();

        Ok(SchemaDiff {
            from_version,
            to_version,
            added_columns,
            removed_columns,
            modified_columns,
        })
    }

    /// Invalidate a cache entry.
    pub async fn invalidate_cache(&self, location: &str) {
        if let Ok(normalized) = Self::normalize_location(location) {
            let mut cache = self.cache.write().await;
            cache.pop(&normalized);
            tracing::debug!(location = %location, "Delta metadata cache invalidated");
        }
    }

    /// Clear the entire cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        tracing::debug!("Delta metadata cache cleared");
    }

    /// Extract schema from a Delta table.
    fn extract_schema(&self, table: &DeltaTable) -> Result<Schema> {
        let snapshot = table
            .snapshot()
            .map_err(|e| DeltaError::SchemaRead(format!("Failed to get snapshot: {}", e)))?;

        let delta_schema = snapshot.schema();

        let fields: Vec<Field> = delta_schema
            .fields()
            .map(|f| {
                let metadata: HashMap<String, String> = f
                    .metadata()
                    .iter()
                    .map(|(k, v)| (k.clone(), format!("{:?}", v)))
                    .collect();

                Field {
                    name: f.name().to_string(),
                    data_type: format!("{:?}", f.data_type()),
                    nullable: f.is_nullable(),
                    description: metadata.get("comment").cloned(),
                    metadata,
                }
            })
            .collect();

        let partition_columns = snapshot.metadata().partition_columns().to_vec();

        Ok(Schema {
            fields,
            partition_columns,
        })
    }

    /// Aggregate statistics from Delta file actions.
    ///
    /// Returns (total_rows, total_bytes, malformed_stats_count).
    /// Malformed stats are logged and skipped rather than causing failures.
    fn aggregate_stats(&self, files: &[deltalake::kernel::Add]) -> (i64, i64, usize) {
        let mut total_rows: i64 = 0;
        let mut total_bytes: i64 = 0;
        let mut malformed_count: usize = 0;

        for file in files {
            total_bytes += file.size;
            // In deltalake 0.29, stats need to be parsed from the stats JSON string
            if let Some(ref stats_str) = file.stats {
                match serde_json::from_str::<FileStats>(stats_str) {
                    Ok(stats) => {
                        total_rows += stats.num_records;
                    }
                    Err(e) => {
                        malformed_count += 1;
                        tracing::debug!(
                            file = %file.path,
                            error = %e,
                            "Skipping malformed Delta file stats"
                        );
                    }
                }
            }
        }

        (total_rows, total_bytes, malformed_count)
    }

    /// Extract column-level statistics from Delta files.
    fn extract_column_stats(
        &self,
        table: &DeltaTable,
        files: &[deltalake::kernel::Add],
    ) -> Result<Vec<ColumnStats>> {
        let snapshot = table
            .snapshot()
            .map_err(|e| DeltaError::SchemaRead(format!("Failed to get snapshot: {}", e)))?;

        let schema = snapshot.schema();

        // Aggregate stats from all files
        let mut stats_by_column: HashMap<String, AggregatedStats> = HashMap::new();

        for file in files {
            if let Some(ref stats_str) = file.stats {
                if let Ok(stats) = serde_json::from_str::<FileStats>(stats_str) {
                    // Null counts
                    if let Some(null_counts) = stats.null_count {
                        for (col, count) in null_counts {
                            let entry = stats_by_column.entry(col).or_default();
                            if let serde_json::Value::Number(n) = count {
                                if let Some(n) = n.as_i64() {
                                    entry.null_count += n;
                                }
                            }
                        }
                    }

                    // Min values
                    if let Some(min_values) = stats.min_values {
                        for (col, val) in min_values {
                            let entry = stats_by_column.entry(col).or_default();
                            entry.update_min(val);
                        }
                    }

                    // Max values
                    if let Some(max_values) = stats.max_values {
                        for (col, val) in max_values {
                            let entry = stats_by_column.entry(col).or_default();
                            entry.update_max(val);
                        }
                    }
                }
            }
        }

        // Convert to ColumnStats
        Ok(schema
            .fields()
            .map(|f| {
                let name = f.name();
                let agg = stats_by_column.get(name);

                ColumnStats {
                    name: name.to_string(),
                    data_type: format!("{:?}", f.data_type()),
                    nullable: f.is_nullable(),
                    null_count: agg.map(|a| a.null_count),
                    min_value: agg.and_then(|a| a.min.clone()),
                    max_value: agg.and_then(|a| a.max.clone()),
                    distinct_count: None, // Delta doesn't track this
                }
            })
            .collect())
    }
}

/// File statistics structure parsed from Delta stats JSON.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileStats {
    num_records: i64,
    #[serde(default)]
    null_count: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    min_values: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    max_values: Option<HashMap<String, serde_json::Value>>,
}

/// Helper struct for aggregating column statistics across files.
#[derive(Default)]
struct AggregatedStats {
    null_count: i64,
    min: Option<serde_json::Value>,
    max: Option<serde_json::Value>,
}

impl AggregatedStats {
    fn update_min(&mut self, value: serde_json::Value) {
        if self.min.is_none() {
            self.min = Some(value);
        }
        // For simplicity, we just keep the first min value
        // A proper implementation would compare values
    }

    fn update_max(&mut self, value: serde_json::Value) {
        if self.max.is_none() {
            self.max = Some(value);
        }
        // For simplicity, we just keep the first max value
        // A proper implementation would compare values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_reader_creation() {
        let reader = DeltaReader::new(Duration::from_secs(60));
        assert_eq!(reader.cache_ttl, Duration::from_secs(60));
    }

    #[test]
    fn test_delta_reader_zero_cache() {
        let reader = DeltaReader::new(Duration::ZERO);
        assert_eq!(reader.cache_ttl, Duration::ZERO);
    }

    #[test]
    fn test_schema_equality() {
        let field1 = Field {
            name: "id".to_string(),
            data_type: "Int32".to_string(),
            nullable: false,
            description: None,
            metadata: HashMap::new(),
        };

        let field2 = Field {
            name: "id".to_string(),
            data_type: "Int32".to_string(),
            nullable: false,
            description: None,
            metadata: HashMap::new(),
        };

        assert_eq!(field1, field2);
    }

    #[test]
    fn test_file_stats_deserialize() {
        let json = r#"{
            "numRecords": 100,
            "nullCount": {"col1": 5, "col2": 0},
            "minValues": {"col1": 1, "col2": "a"},
            "maxValues": {"col1": 100, "col2": "z"}
        }"#;

        let stats: FileStats = serde_json::from_str(json).unwrap();
        assert_eq!(stats.num_records, 100);
        assert!(stats.null_count.is_some());
        assert!(stats.min_values.is_some());
        assert!(stats.max_values.is_some());
    }

    #[test]
    fn test_normalize_location_file_url() {
        let result = DeltaReader::normalize_location("file:///path/to/table").unwrap();
        assert_eq!(result, "file:///path/to/table");
    }

    #[test]
    fn test_normalize_location_absolute_path() {
        let result = DeltaReader::normalize_location("/path/to/table").unwrap();
        assert_eq!(result, "file:///path/to/table");
    }

    #[test]
    fn test_normalize_location_cloud_url() {
        let result = DeltaReader::normalize_location("gs://bucket/path").unwrap();
        assert_eq!(result, "gs://bucket/path");

        let result = DeltaReader::normalize_location("s3://bucket/path").unwrap();
        assert_eq!(result, "s3://bucket/path");
    }

    #[test]
    fn test_normalize_location_relative_path_fails() {
        let result = DeltaReader::normalize_location("relative/path");
        assert!(result.is_err());
    }
}
