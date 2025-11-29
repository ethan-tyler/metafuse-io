//! TableProvider implementation for MetaFuse datasets.
//!
//! Provides schema metadata and delegates data scanning to Delta Lake
//! when `delta_location` is configured.
//!
//! # Delta Lake Scanning
//!
//! When a dataset has a `delta_location` configured, the `TableProvider`
//! delegates actual data scanning to Delta Lake. This requires:
//! - DataFusion 50.x (aligned with deltalake 0.29)
//! - A valid Delta table at the configured location
//!
//! If `delta_location` is not set, queries return a clear error indicating
//! the dataset is metadata-only.

use crate::client::MetafuseClient;
use crate::types::Dataset;
use async_trait::async_trait;
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::catalog::Session;
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DataFusionResult};
use datafusion::logical_expr::{Expr, TableType};
use datafusion::physical_plan::ExecutionPlan;
use deltalake::DeltaTable;
use std::any::Any;
use std::sync::Arc;

/// DataFusion TableProvider for a MetaFuse dataset.
///
/// This provider:
/// 1. Exposes the schema from MetaFuse metadata
/// 2. Delegates actual data scanning to Delta Lake when `delta_location` is set
/// 3. Returns a clear error if the dataset has no scannable location
///
/// # Example
///
/// ```rust,ignore
/// use datafusion::prelude::*;
/// use metafuse_catalog_client::datafusion::MetafuseCatalogProvider;
///
/// let ctx = SessionContext::new();
/// let catalog = MetafuseCatalogProvider::new(client);
/// ctx.register_catalog("metafuse", Arc::new(catalog));
///
/// // Query using SQL - domains become schemas, datasets become tables
/// let df = ctx.sql("SELECT * FROM metafuse.analytics.orders LIMIT 10").await?;
/// df.show().await?;
/// ```
pub struct MetafuseTableProvider {
    #[allow(dead_code)]
    client: Arc<MetafuseClient>,
    dataset: Dataset,
    schema: SchemaRef,
    delta_table: Option<DeltaTable>,
}

impl MetafuseTableProvider {
    /// Create a new table provider for the given dataset.
    ///
    /// If the dataset has a `delta_location`, this will open the Delta table
    /// to enable data scanning.
    pub async fn new(client: Arc<MetafuseClient>, dataset: Dataset) -> DataFusionResult<Self> {
        // Convert MetaFuse fields to Arrow schema
        let arrow_fields: Vec<Field> = dataset
            .fields
            .iter()
            .map(|f| {
                let data_type = parse_data_type(&f.data_type);
                Field::new(&f.name, data_type, f.nullable)
            })
            .collect();
        let schema = Arc::new(Schema::new(arrow_fields));

        // Open Delta table if location is configured
        let delta_table = if let Some(ref location) = dataset.delta_location {
            tracing::debug!(
                dataset = %dataset.name,
                location = %location,
                "Opening Delta table for dataset"
            );

            // Parse location as URL
            let url = url::Url::parse(location).map_err(|e| {
                DataFusionError::External(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid delta_location URL '{}': {}", location, e),
                )))
            })?;

            let table = deltalake::open_table(url).await.map_err(|e| {
                DataFusionError::External(Box::new(std::io::Error::other(format!(
                    "Failed to open Delta table at '{}': {}",
                    location, e
                ))))
            })?;

            Some(table)
        } else {
            None
        };

        Ok(Self {
            client,
            dataset,
            schema,
            delta_table,
        })
    }

    /// Returns the underlying dataset metadata.
    pub fn dataset(&self) -> &Dataset {
        &self.dataset
    }

    /// Returns the Delta table location if configured.
    pub fn delta_location(&self) -> Option<&str> {
        self.dataset.delta_location.as_deref()
    }

    /// Returns true if this dataset has a Delta location for scanning.
    pub fn has_delta_location(&self) -> bool {
        self.delta_table.is_some()
    }

    /// Returns true if this table can be scanned.
    pub fn is_scannable(&self) -> bool {
        self.delta_table.is_some()
    }
}

impl std::fmt::Debug for MetafuseTableProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetafuseTableProvider")
            .field("dataset", &self.dataset.name)
            .field("scannable", &self.is_scannable())
            .finish()
    }
}

#[async_trait]
impl TableProvider for MetafuseTableProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        // Use Delta schema if available (more accurate), otherwise use MetaFuse schema
        if let Some(ref delta) = self.delta_table {
            delta.schema()
        } else {
            self.schema.clone()
        }
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        // Delegate to Delta table if available
        let delta = self.delta_table.as_ref().ok_or_else(|| {
            DataFusionError::Plan(format!(
                "Dataset '{}' has no delta_location configured. \
                 This dataset contains metadata only and cannot be scanned. \
                 Set delta_location to enable data access.",
                self.dataset.name
            ))
        })?;

        // Delegate scanning to DeltaTable's TableProvider implementation
        delta.scan(state, projection, filters, limit).await
    }
}

/// Parse a data type string to Arrow DataType.
///
/// Handles common type representations from MetaFuse and Delta.
///
/// # Parameterized Types
///
/// - `decimal(p,s)` or `decimal(p, s)` - Parses precision (p) and scale (s)
/// - `timestamp with time zone` or `timestamptz` - Returns timestamp with UTC timezone
/// - `timestamp without time zone` or `timestamp` - Returns timestamp without timezone
fn parse_data_type(type_str: &str) -> DataType {
    let normalized = type_str.to_lowercase();
    let normalized = normalized.trim();

    match normalized {
        // Boolean
        "bool" | "boolean" => DataType::Boolean,

        // Integer types
        "int8" | "tinyint" | "byte" => DataType::Int8,
        "int16" | "smallint" | "short" => DataType::Int16,
        "int32" | "int" | "integer" => DataType::Int32,
        "int64" | "long" | "bigint" => DataType::Int64,

        // Unsigned integers
        "uint8" => DataType::UInt8,
        "uint16" => DataType::UInt16,
        "uint32" => DataType::UInt32,
        "uint64" => DataType::UInt64,

        // Floating point
        "float16" | "half" => DataType::Float16,
        "float32" | "float" | "real" => DataType::Float32,
        "float64" | "double" => DataType::Float64,

        // String types
        "utf8" | "string" | "text" | "varchar" => DataType::Utf8,
        "largeutf8" | "largestring" => DataType::LargeUtf8,

        // Binary types
        "binary" | "bytes" | "varbinary" => DataType::Binary,
        "largebinary" => DataType::LargeBinary,

        // Date/time types
        "date32" | "date" => DataType::Date32,
        "date64" => DataType::Date64,

        // Timestamp with timezone variants
        "timestamptz" | "timestamp with time zone" => {
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        }

        // Timestamp without timezone
        "timestamp" | "timestamp without time zone" => {
            DataType::Timestamp(TimeUnit::Microsecond, None)
        }

        // Null type
        "null" => DataType::Null,

        // Default to Utf8 for unknown types
        _ => {
            // Check for parameterized types
            if normalized.starts_with("decimal") {
                parse_decimal_type(normalized)
            } else if normalized.starts_with("timestamp") {
                parse_timestamp_type(normalized)
            } else if normalized.starts_with("time") {
                DataType::Time64(TimeUnit::Microsecond)
            } else {
                tracing::warn!(type_str = %type_str, "Unknown data type, defaulting to Utf8");
                DataType::Utf8
            }
        }
    }
}

/// Parse decimal type with precision and scale.
///
/// Supports formats:
/// - `decimal(p,s)` - e.g., `decimal(10,2)`
/// - `decimal(p, s)` - e.g., `decimal(18, 4)`
/// - `decimal` - defaults to (38, 10)
///
/// Returns Decimal128 with parsed or default precision/scale.
fn parse_decimal_type(type_str: &str) -> DataType {
    const DEFAULT_PRECISION: u8 = 38;
    const DEFAULT_SCALE: i8 = 10;

    // Try to extract (precision, scale) from "decimal(p,s)" or "decimal(p, s)"
    if let Some(start) = type_str.find('(') {
        if let Some(end) = type_str.find(')') {
            let params = &type_str[start + 1..end];
            let parts: Vec<&str> = params.split(',').map(|s| s.trim()).collect();

            if parts.len() == 2 {
                if let (Ok(precision), Ok(scale)) = (parts[0].parse::<u8>(), parts[1].parse::<i8>())
                {
                    // Validate bounds (Arrow Decimal128 supports up to 38 digits)
                    let precision = precision.clamp(1, 38);
                    let scale = scale.min(precision as i8);
                    return DataType::Decimal128(precision, scale);
                }
            }
        }
    }

    // Default precision/scale if parsing fails
    DataType::Decimal128(DEFAULT_PRECISION, DEFAULT_SCALE)
}

/// Parse timestamp type with optional timezone.
///
/// Supports formats:
/// - `timestamp` - no timezone
/// - `timestamp with time zone` or `timestamptz` - UTC timezone
/// - `timestamp without time zone` - explicit no timezone
/// - `timestamp[us]` or `timestamp[ms]` - with time unit
/// - `timestamp[us, tz=UTC]` - with time unit and timezone
fn parse_timestamp_type(type_str: &str) -> DataType {
    let has_timezone = type_str.contains("with time zone")
        || type_str.contains("timestamptz")
        || type_str.contains("tz=");

    // Extract timezone if specified as tz=...
    let timezone: Option<Arc<str>> = if has_timezone {
        // Try to extract specific timezone from tz=...
        if let Some(tz_start) = type_str.find("tz=") {
            let tz_part = &type_str[tz_start + 3..];
            // Extract until comma, bracket, or end
            let tz_end = tz_part.find([',', ']', ')']).unwrap_or(tz_part.len());
            let tz = tz_part[..tz_end].trim();
            if !tz.is_empty() {
                Some(tz.into())
            } else {
                Some("UTC".into())
            }
        } else {
            Some("UTC".into())
        }
    } else {
        None
    };

    // Determine time unit (default to microseconds)
    // Check for both [unit] and [unit, patterns
    let time_unit = if type_str.contains("[ns]")
        || type_str.contains("[ns,")
        || type_str.contains("[nanosecond")
    {
        TimeUnit::Nanosecond
    } else if type_str.contains("[ms]")
        || type_str.contains("[ms,")
        || type_str.contains("[millisecond")
    {
        TimeUnit::Millisecond
    } else if type_str.contains("[s]") || type_str.contains("[s,") || type_str.contains("[second") {
        TimeUnit::Second
    } else {
        TimeUnit::Microsecond // Default
    };

    DataType::Timestamp(time_unit, timezone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_data_type_basic() {
        assert_eq!(parse_data_type("Boolean"), DataType::Boolean);
        assert_eq!(parse_data_type("Int32"), DataType::Int32);
        assert_eq!(parse_data_type("Int64"), DataType::Int64);
        assert_eq!(parse_data_type("Float64"), DataType::Float64);
        assert_eq!(parse_data_type("Utf8"), DataType::Utf8);
        assert_eq!(parse_data_type("String"), DataType::Utf8);
    }

    #[test]
    fn test_parse_data_type_aliases() {
        assert_eq!(parse_data_type("integer"), DataType::Int32);
        assert_eq!(parse_data_type("bigint"), DataType::Int64);
        assert_eq!(parse_data_type("double"), DataType::Float64);
        assert_eq!(parse_data_type("varchar"), DataType::Utf8);
    }

    #[test]
    fn test_parse_decimal_with_precision() {
        // decimal(10,2) should parse to Decimal128(10, 2)
        assert_eq!(
            parse_data_type("decimal(10,2)"),
            DataType::Decimal128(10, 2)
        );

        // decimal(18, 4) with spaces should also work
        assert_eq!(
            parse_data_type("decimal(18, 4)"),
            DataType::Decimal128(18, 4)
        );

        // decimal without params should use defaults (38, 10)
        assert_eq!(parse_data_type("decimal"), DataType::Decimal128(38, 10));

        // Out of bounds precision should be clamped
        assert_eq!(
            parse_data_type("decimal(50,5)"),
            DataType::Decimal128(38, 5) // Clamped to max 38
        );

        // Scale larger than precision should be clamped
        assert_eq!(
            parse_data_type("decimal(10,15)"),
            DataType::Decimal128(10, 10) // Scale clamped to precision
        );

        // Invalid formats should fall back to defaults
        assert_eq!(
            parse_data_type("decimal(abc,def)"),
            DataType::Decimal128(38, 10) // Default on parse error
        );
        assert_eq!(
            parse_data_type("decimal(10)"), // Missing scale
            DataType::Decimal128(38, 10)    // Default on malformed input
        );
        assert_eq!(
            parse_data_type("decimal()"), // Empty parens
            DataType::Decimal128(38, 10)
        );
    }

    #[test]
    fn test_parse_timestamp_variants() {
        // Plain timestamp - no timezone
        assert_eq!(
            parse_data_type("timestamp"),
            DataType::Timestamp(TimeUnit::Microsecond, None)
        );

        // timestamp without time zone - explicit no timezone
        assert_eq!(
            parse_data_type("timestamp without time zone"),
            DataType::Timestamp(TimeUnit::Microsecond, None)
        );

        // timestamptz - with timezone (UTC default)
        match parse_data_type("timestamptz") {
            DataType::Timestamp(TimeUnit::Microsecond, Some(tz)) => {
                assert_eq!(tz.as_ref(), "UTC");
            }
            other => panic!("Expected Timestamp with UTC, got {:?}", other),
        }

        // timestamp with time zone - with timezone
        match parse_data_type("timestamp with time zone") {
            DataType::Timestamp(TimeUnit::Microsecond, Some(tz)) => {
                assert_eq!(tz.as_ref(), "UTC");
            }
            other => panic!("Expected Timestamp with UTC, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_timestamp_with_time_unit() {
        // timestamp[ns] - nanosecond precision
        assert_eq!(
            parse_data_type("timestamp[ns]"),
            DataType::Timestamp(TimeUnit::Nanosecond, None)
        );

        // timestamp[ms] - millisecond precision
        assert_eq!(
            parse_data_type("timestamp[ms]"),
            DataType::Timestamp(TimeUnit::Millisecond, None)
        );

        // timestamp[us, tz=America/New_York] - with specific timezone
        // Note: timezone is lowercased during normalization (IANA TZs are case-insensitive)
        match parse_data_type("timestamp[us, tz=America/New_York]") {
            DataType::Timestamp(TimeUnit::Microsecond, Some(tz)) => {
                assert_eq!(tz.as_ref(), "america/new_york");
            }
            other => panic!("Expected Timestamp with timezone, got {:?}", other),
        }

        // timestamp[ns, tz=UTC] - nanoseconds with UTC
        match parse_data_type("timestamp[ns, tz=UTC]") {
            DataType::Timestamp(TimeUnit::Nanosecond, Some(tz)) => {
                assert_eq!(tz.as_ref(), "utc");
            }
            other => panic!("Expected Timestamp[ns] with UTC, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_data_type_unknown() {
        // Unknown types should default to Utf8
        assert_eq!(parse_data_type("unknown_type"), DataType::Utf8);
    }

    #[tokio::test]
    async fn test_metadata_only_dataset_not_scannable() {
        use crate::config::ClientConfig;
        use crate::types::Field;

        // Create a minimal client (won't make HTTP calls for this test)
        let config = ClientConfig::builder("http://localhost:3000")
            .no_cache()
            .build()
            .unwrap();
        let client = Arc::new(crate::client::MetafuseClient::new(config).unwrap());

        // Create a dataset without delta_location
        let dataset = crate::types::Dataset {
            name: "test_metadata_only".to_string(),
            path: "/data/test".to_string(),
            format: "parquet".to_string(),
            description: Some("Test dataset".to_string()),
            tenant: None,
            domain: Some("analytics".to_string()),
            owner: Some("data-team".to_string()),
            created_at: chrono::Utc::now(),
            last_updated: chrono::Utc::now(),
            fields: vec![Field {
                name: "id".to_string(),
                data_type: "Int64".to_string(),
                nullable: false,
                description: None,
            }],
            upstream_datasets: vec![],
            tags: vec![],
            row_count: None,
            size_bytes: None,
            partition_keys: vec![],
            delta_location: None, // No delta location
            delta: None,
            quality: None,
            classification: None,
        };

        // Create the table provider
        let provider = MetafuseTableProvider::new(client, dataset).await.unwrap();

        // Verify it's not scannable
        assert!(!provider.is_scannable());
        assert!(!provider.has_delta_location());

        // Verify scan returns the expected error
        use datafusion::prelude::SessionContext;

        let ctx = SessionContext::new();
        let state = ctx.state();

        let result = provider.scan(&state, None, &[], None).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("test_metadata_only"),
            "Error should mention dataset name"
        );
        assert!(
            err_msg.contains("delta_location"),
            "Error should mention delta_location"
        );
    }
}
