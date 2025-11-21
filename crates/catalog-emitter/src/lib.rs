//! MetaFuse Catalog Emitter
//!
//! DataFusion integration for automatic metadata capture from pipelines.

use chrono::Utc;
use datafusion::arrow::datatypes::SchemaRef;
use metafuse_catalog_core::{
    get_catalog_version, increment_catalog_version, init_sqlite_schema, validation, CatalogError,
    DatasetMeta, FieldMeta, OperationalMeta, Result,
};
use metafuse_catalog_storage::CatalogBackend;
use rusqlite::Connection;
use std::thread;
use std::time::Duration;

/// Emitter API for capturing metadata from DataFusion pipelines
///
/// Use this to automatically register datasets, capture lineage,
/// and track metadata as data flows through your pipeline.
///
/// # Example
/// ```ignore
/// use metafuse_catalog_emitter::Emitter;
/// use metafuse_catalog_storage::LocalSqliteBackend;
/// use metafuse_catalog_core::OperationalMeta;
///
/// let backend = LocalSqliteBackend::new("catalog.db");
/// let emitter = Emitter::new(backend);
///
/// // After writing a dataset with DataFusion:
/// emitter.emit_dataset(
///     "my_dataset",
///     "s3://bucket/path/to/data",
///     "parquet",
///     Some("Description of dataset"),
///     Some("prod-tenant"),
///     Some("analytics"),
///     Some("data-team@company.com"),
///     schema,
///     Some(OperationalMeta {
///         row_count: Some(1_000_000),
///         size_bytes: Some(50_000_000),
///         partition_keys: vec!["year".to_string(), "month".to_string()],
///     }),
///     vec!["upstream_dataset_1".to_string()],
///     vec!["pii".to_string(), "daily".to_string()],
/// )?;
/// ```
pub struct Emitter<B: CatalogBackend> {
    backend: B,
}

impl<B: CatalogBackend> Emitter<B> {
    /// Create a new emitter with the given backend
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Emit metadata for a dataset
    ///
    /// This registers a dataset in the catalog with its schema, lineage, and tags.
    /// Call this after successfully writing a dataset in your pipeline.
    ///
    /// # Arguments
    /// * `name` - Unique name for the dataset
    /// * `path` - Storage path (e.g., "s3://bucket/path" or "gs://bucket/path")
    /// * `format` - Format type ("parquet", "delta", "iceberg", "csv", etc.)
    /// * `description` - Optional human-readable description
    /// * `tenant` - Optional tenant identifier for multi-tenant deployments
    /// * `domain` - Optional business domain ("finance", "marketing", etc.)
    /// * `owner` - Optional owner/responsible party
    /// * `schema` - DataFusion Arrow schema
    /// * `operational` - Optional operational metadata (row count, size, partition keys)
    /// * `upstream_datasets` - List of upstream dataset names this depends on
    /// * `tags` - Tags for categorization and discovery
    #[allow(clippy::too_many_arguments)]
    pub fn emit_dataset(
        &self,
        name: &str,
        path: &str,
        format: &str,
        description: Option<&str>,
        tenant: Option<&str>,
        domain: Option<&str>,
        owner: Option<&str>,
        schema: SchemaRef,
        operational: Option<OperationalMeta>,
        upstream_datasets: Vec<String>,
        tags: Vec<String>,
    ) -> Result<()> {
        // ===== Input Validation =====
        // Validate dataset name
        validation::validate_dataset_name(name)?;

        // Validate tenant if provided
        if let Some(t) = tenant {
            validation::validate_identifier(t, "tenant")?;
        }

        // Validate domain if provided
        if let Some(d) = domain {
            validation::validate_identifier(d, "domain")?;
        }

        // Validate all tags
        for tag in &tags {
            validation::validate_tag(tag)?;
        }

        // Validate all field names from schema
        for field in schema.fields() {
            validation::validate_field_name(field.name())?;
        }

        // Validate upstream dataset names
        for upstream in &upstream_datasets {
            validation::validate_dataset_name(upstream)?;
        }

        // Validate partition keys if present in operational metadata
        if let Some(ref op) = operational {
            for partition_key in &op.partition_keys {
                validation::validate_field_name(partition_key)?;
            }
        }

        // Validate path for traversal attacks (basic check)
        if let Some(file_path) = path.strip_prefix("file://") {
            validation::validate_file_uri_path(file_path)?;
        }
        // ===== End Validation =====

        // Convert Arrow schema to FieldMeta
        let fields = schema
            .fields()
            .iter()
            .map(|f| FieldMeta {
                name: f.name().to_string(),
                data_type: format!("{:?}", f.data_type()),
                nullable: f.is_nullable(),
                description: None,
            })
            .collect();

        let now = Utc::now();

        let dataset = DatasetMeta {
            name: name.to_string(),
            path: path.to_string(),
            format: format.to_string(),
            description: description.map(|s| s.to_string()),
            tenant: tenant.map(|s| s.to_string()),
            domain: domain.map(|s| s.to_string()),
            owner: owner.map(|s| s.to_string()),
            created_at: now,
            last_updated: now,
            fields,
            upstream_datasets,
            tags,
            operational,
        };

        self.write_dataset(&dataset)?;

        Ok(())
    }

    /// Write dataset metadata to the catalog with optimistic concurrency control
    ///
    /// This implements the download-modify-upload pattern with retry logic:
    /// 1. Download catalog from backend (captures current version)
    /// 2. Perform writes in a transaction
    /// 3. Validate catalog version was incremented
    /// 4. Upload modified catalog with version preconditions
    /// 5. If upload fails due to conflict, retry with exponential backoff
    fn write_dataset(&self, dataset: &DatasetMeta) -> Result<()> {
        const MAX_RETRIES: u32 = 3;
        let mut retry_count = 0;

        loop {
            // Download catalog (captures current version and remote metadata)
            let download = self.backend.download()?;
            let expected_version = download.catalog_version;

            tracing::debug!(
                dataset = %dataset.name,
                version = expected_version,
                "Downloaded catalog for write"
            );

            // Open connection to the downloaded catalog
            let mut conn = Connection::open(&download.path)?;
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;
            init_sqlite_schema(&conn)?;

            // Perform all writes in a transaction
            let tx = conn.transaction()?;
            self.write_dataset_tx(&tx, dataset)?;
            tx.commit()?;

            // Verify version was incremented (sanity check)
            let new_version = get_catalog_version(&conn)?;
            if new_version <= expected_version {
                return Err(CatalogError::Other(format!(
                    "Catalog version not incremented: expected > {}, got {}",
                    expected_version, new_version
                )));
            }

            tracing::debug!(
                dataset = %dataset.name,
                old_version = expected_version,
                new_version = new_version,
                "Catalog version incremented"
            );

            // Upload the modified catalog with optimistic locking
            match self.backend.upload(&download) {
                Ok(()) => {
                    tracing::info!(
                        dataset = %dataset.name,
                        version = new_version,
                        "Dataset metadata emitted successfully"
                    );
                    return Ok(());
                }
                Err(CatalogError::ConflictError(msg)) if retry_count < MAX_RETRIES => {
                    retry_count += 1;
                    // Exponential backoff: 100ms, 200ms, 400ms
                    let backoff_ms = 100 * 2_u64.pow(retry_count - 1);
                    tracing::warn!(
                        dataset = %dataset.name,
                        retry = retry_count,
                        max_retries = MAX_RETRIES,
                        backoff_ms = backoff_ms,
                        error = %msg,
                        "Catalog conflict detected, retrying..."
                    );
                    thread::sleep(Duration::from_millis(backoff_ms));
                    // Loop will retry with fresh download
                }
                Err(CatalogError::ConflictError(msg)) => {
                    return Err(CatalogError::ConflictError(format!(
                        "Failed after {} retries: {}",
                        MAX_RETRIES, msg
                    )));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Perform dataset writes within a transaction
    fn write_dataset_tx(&self, tx: &rusqlite::Transaction, dataset: &DatasetMeta) -> Result<()> {
        // Extract operational metadata
        let (row_count, size_bytes, partition_keys_json) = if let Some(ref op) = dataset.operational
        {
            let partition_keys_json = if op.partition_keys.is_empty() {
                None
            } else {
                // Store as JSON array for proper structure and no delimiter issues
                Some(
                    serde_json::to_string(&op.partition_keys)
                        .map_err(|e| CatalogError::SerializationError(e.to_string()))?,
                )
            };
            (op.row_count, op.size_bytes, partition_keys_json)
        } else {
            (None, None, None)
        };

        // Insert or update dataset
        tx.execute(
            r#"
            INSERT INTO datasets (name, path, format, description, tenant, domain, owner, created_at, last_updated, row_count, size_bytes, partition_keys)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(name) DO UPDATE SET
                path = excluded.path,
                format = excluded.format,
                description = excluded.description,
                tenant = excluded.tenant,
                domain = excluded.domain,
                owner = excluded.owner,
                last_updated = excluded.last_updated,
                row_count = excluded.row_count,
                size_bytes = excluded.size_bytes,
                partition_keys = excluded.partition_keys
            "#,
            rusqlite::params![
                dataset.name,
                dataset.path,
                dataset.format,
                dataset.description,
                dataset.tenant,
                dataset.domain,
                dataset.owner,
                dataset.created_at.to_rfc3339(),
                dataset.last_updated.to_rfc3339(),
                row_count,
                size_bytes,
                partition_keys_json,
            ],
        )?;

        // Get dataset ID
        let dataset_id: i64 = tx.query_row(
            "SELECT id FROM datasets WHERE name = ?1",
            [&dataset.name],
            |row| row.get(0),
        )?;

        // Delete existing fields and insert new ones
        tx.execute("DELETE FROM fields WHERE dataset_id = ?1", [dataset_id])?;

        for field in &dataset.fields {
            tx.execute(
                "INSERT INTO fields (dataset_id, name, data_type, nullable, description) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    dataset_id,
                    field.name,
                    field.data_type,
                    field.nullable as i32,
                    field.description,
                ],
            )?;
        }

        // Delete existing lineage and insert new ones
        tx.execute(
            "DELETE FROM lineage WHERE downstream_dataset_id = ?1",
            [dataset_id],
        )?;

        for upstream_name in &dataset.upstream_datasets {
            // Get or skip if upstream doesn't exist
            let upstream_id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM datasets WHERE name = ?1",
                    [upstream_name],
                    |row| row.get(0),
                )
                .ok();

            if let Some(upstream_id) = upstream_id {
                tx.execute(
                    "INSERT OR IGNORE INTO lineage (upstream_dataset_id, downstream_dataset_id, created_at) VALUES (?1, ?2, ?3)",
                    rusqlite::params![
                        upstream_id,
                        dataset_id,
                        Utc::now().to_rfc3339(),
                    ],
                )?;
            }
        }

        // Delete existing tags and insert new ones
        tx.execute("DELETE FROM tags WHERE dataset_id = ?1", [dataset_id])?;

        for tag in &dataset.tags {
            tx.execute(
                "INSERT OR IGNORE INTO tags (dataset_id, tag) VALUES (?1, ?2)",
                rusqlite::params![dataset_id, tag],
            )?;
        }

        // NOTE: FTS index is automatically maintained by triggers on datasets/fields/tags tables.
        // No manual dataset_search insert/delete needed here.

        // Increment catalog version for optimistic concurrency control
        increment_catalog_version(tx)?;

        Ok(())
    }

    /// Get a reference to the backend
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use metafuse_catalog_storage::LocalSqliteBackend;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    #[test]
    fn test_emit_dataset() {
        let temp_file = NamedTempFile::new().unwrap();
        let backend = LocalSqliteBackend::new(temp_file.path());
        let emitter = Emitter::new(backend);

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("value", DataType::Float64, true),
        ]));

        emitter
            .emit_dataset(
                "test_dataset",
                "s3://test-bucket/data",
                "parquet",
                Some("Test dataset for emitter"),
                Some("test-tenant"),
                Some("analytics"),
                Some("test@example.com"),
                schema,
                Some(OperationalMeta {
                    row_count: Some(1000),
                    size_bytes: Some(50000),
                    partition_keys: vec!["date".to_string()],
                }),
                vec![],
                vec!["test".to_string(), "sample".to_string()],
            )
            .unwrap();

        // Verify dataset was written
        let conn = emitter.backend().get_connection().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM datasets", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);

        // Verify fields were written
        let field_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM fields", [], |row| row.get(0))
            .unwrap();
        assert_eq!(field_count, 3);

        // Verify tags were written
        let tag_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM tags", [], |row| row.get(0))
            .unwrap();
        assert_eq!(tag_count, 2);

        // Verify partition keys were written as JSON
        let partition_keys: Option<String> = conn
            .query_row(
                "SELECT partition_keys FROM datasets WHERE name = ?1",
                ["test_dataset"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(partition_keys, Some(r#"["date"]"#.to_string()));
    }

    #[test]
    fn test_emit_dataset_with_lineage() {
        let temp_file = NamedTempFile::new().unwrap();
        let backend = LocalSqliteBackend::new(temp_file.path());
        let emitter = Emitter::new(backend);

        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));

        // Create upstream dataset
        emitter
            .emit_dataset(
                "upstream",
                "s3://bucket/upstream",
                "parquet",
                Some("Upstream dataset"),
                None,
                None,
                None,
                schema.clone(),
                None,
                vec![],
                vec![],
            )
            .unwrap();

        // Create downstream dataset with lineage
        emitter
            .emit_dataset(
                "downstream",
                "s3://bucket/downstream",
                "parquet",
                Some("Downstream dataset"),
                None,
                None,
                None,
                schema,
                None,
                vec!["upstream".to_string()],
                vec![],
            )
            .unwrap();

        // Verify lineage was created
        let conn = emitter.backend().get_connection().unwrap();
        let lineage_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM lineage", [], |row| row.get(0))
            .unwrap();
        assert_eq!(lineage_count, 1);
    }
}
