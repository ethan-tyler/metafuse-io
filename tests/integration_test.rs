// Integration tests for MetaFuse
//
// These tests validate end-to-end workflows:
// - Emit metadata from DataFusion pipelines
// - Query metadata via storage backend
// - Multi-tenant isolation
// - Lineage tracking

use datafusion::arrow::datatypes::{DataType, Field, Schema};
use metafuse_catalog_core::{init_sqlite_schema, OperationalMeta};
use metafuse_catalog_emitter::Emitter;
use metafuse_catalog_storage::{CatalogBackend, LocalSqliteBackend};
use serde_json;
use std::sync::Arc;
use tempfile::TempDir;

/// Helper function to create a test backend with isolated storage
fn create_test_backend() -> (TempDir, LocalSqliteBackend) {
    let temp_dir = TempDir::new().unwrap();
    let catalog_path = temp_dir.path().join("test_catalog.db");
    let backend = LocalSqliteBackend::new(&catalog_path);

    let conn = backend.get_connection().unwrap();
    init_sqlite_schema(&conn).unwrap();
    drop(conn);

    (temp_dir, backend)
}

/// Helper function to create sample Arrow schema
fn create_sample_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("value", DataType::Float64, true),
    ]))
}

#[test]
fn test_emit_and_query_dataset() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    // Emit a dataset
    emitter
        .emit_dataset(
            "test_dataset",
            "/data/test.parquet",
            "parquet",
            Some("Test dataset"),
            Some("test_tenant"),
            Some("test_domain"),
            Some("test@example.com"),
            schema,
            Some(OperationalMeta {
                row_count: Some(100),
                size_bytes: Some(50_000),
                partition_keys: vec![],
            }),
            vec![],
            vec!["test".to_string()],
        )
        .unwrap();

    // Query the dataset
    let conn = backend.get_connection().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT name, path, format, description, tenant, domain, owner, row_count \
             FROM datasets WHERE name = ?1",
        )
        .unwrap();

    let (name, path, format, description, tenant, domain, owner, row_count): (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
    ) = stmt
        .query_row([&"test_dataset"], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        })
        .unwrap();

    assert_eq!(name, "test_dataset");
    assert_eq!(path, "/data/test.parquet");
    assert_eq!(format, "parquet");
    assert_eq!(description, Some("Test dataset".to_string()));
    assert_eq!(tenant, Some("test_tenant".to_string()));
    assert_eq!(domain, Some("test_domain".to_string()));
    assert_eq!(owner, Some("test@example.com".to_string()));
    assert_eq!(row_count, Some(100));
}

#[test]
fn test_lineage_tracking() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    emitter
        .emit_dataset(
            "parent_dataset",
            "/data/parent.parquet",
            "parquet",
            Some("Parent dataset"),
            Some("prod"),
            Some("analytics"),
            Some("team@example.com"),
            schema.clone(),
            None,
            vec![],
            vec![],
        )
        .unwrap();

    emitter
        .emit_dataset(
            "child_dataset",
            "/data/child.parquet",
            "parquet",
            Some("Child dataset"),
            Some("prod"),
            Some("analytics"),
            Some("team@example.com"),
            schema.clone(),
            None,
            vec!["parent_dataset".to_string()],
            vec![],
        )
        .unwrap();

    let conn = backend.get_connection().unwrap();
    let lineage_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM lineage l \
             JOIN datasets u ON l.upstream_dataset_id = u.id \
             JOIN datasets d ON l.downstream_dataset_id = d.id \
             WHERE u.name = 'parent_dataset' AND d.name = 'child_dataset'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(lineage_count, 1);
}

#[test]
fn test_multi_tenant_isolation() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    emitter
        .emit_dataset(
            "dataset_tenant_a",
            "/data/a.parquet",
            "parquet",
            Some("Dataset A"),
            Some("tenant_a"),
            Some("analytics"),
            Some("team_a@example.com"),
            schema.clone(),
            None,
            vec![],
            vec![],
        )
        .unwrap();

    emitter
        .emit_dataset(
            "dataset_tenant_b",
            "/data/b.parquet",
            "parquet",
            Some("Dataset B"),
            Some("tenant_b"),
            Some("analytics"),
            Some("team_b@example.com"),
            schema.clone(),
            None,
            vec![],
            vec![],
        )
        .unwrap();

    let conn = backend.get_connection().unwrap();
    let count_a: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM datasets WHERE tenant = 'tenant_a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let count_b: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM datasets WHERE tenant = 'tenant_b'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(count_a, 1);
    assert_eq!(count_b, 1);
}

#[test]
fn test_upsert_dataset() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    emitter
        .emit_dataset(
            "upsert_dataset",
            "/data/v1.parquet",
            "parquet",
            Some("Version 1"),
            Some("prod"),
            Some("analytics"),
            Some("team@example.com"),
            schema.clone(),
            Some(OperationalMeta {
                row_count: Some(100),
                size_bytes: None,
                partition_keys: vec![],
            }),
            vec![],
            vec!["v1".to_string()],
        )
        .unwrap();

    emitter
        .emit_dataset(
            "upsert_dataset",
            "/data/v2.parquet",
            "parquet",
            Some("Version 2"),
            Some("prod"),
            Some("analytics"),
            Some("team@example.com"),
            schema.clone(),
            Some(OperationalMeta {
                row_count: Some(200),
                size_bytes: None,
                partition_keys: vec![],
            }),
            vec![],
            vec!["v2".to_string()],
        )
        .unwrap();

    let conn = backend.get_connection().unwrap();
    let (path, description, row_count): (String, Option<String>, Option<i64>) = conn
        .query_row(
            "SELECT path, description, row_count FROM datasets WHERE name = 'upsert_dataset'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();

    assert_eq!(path, "/data/v2.parquet");
    assert_eq!(description, Some("Version 2".to_string()));
    assert_eq!(row_count, Some(200));
}

#[test]
fn test_tags() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    emitter
        .emit_dataset(
            "tagged_dataset",
            "/data/tagged.parquet",
            "parquet",
            Some("Tagged dataset"),
            Some("prod"),
            Some("analytics"),
            Some("team@example.com"),
            schema,
            None,
            vec![],
            vec![
                "prod".to_string(),
                "important".to_string(),
                "daily".to_string(),
            ],
        )
        .unwrap();

    let conn = backend.get_connection().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT tag FROM tags t \
             JOIN datasets d ON t.dataset_id = d.id \
             WHERE d.name = ?1 \
             ORDER BY tag",
        )
        .unwrap();

    let tags: Vec<String> = stmt
        .query_map([&"tagged_dataset"], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(tags, vec!["daily", "important", "prod"]);
}

#[test]
fn test_schema_fields() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    emitter
        .emit_dataset(
            "schema_test",
            "/data/schema.parquet",
            "parquet",
            Some("Schema test"),
            None,
            None,
            None,
            schema,
            None,
            vec![],
            vec![],
        )
        .unwrap();

    let conn = backend.get_connection().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT f.name, f.data_type, f.nullable \
             FROM fields f \
             JOIN datasets d ON f.dataset_id = d.id \
             WHERE d.name = ?1 \
             ORDER BY f.name",
        )
        .unwrap();

    let fields: Vec<(String, String, bool)> = stmt
        .query_map([&"schema_test"], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get::<_, i32>(2)? != 0))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], ("id".to_string(), "Int64".to_string(), false));
    assert_eq!(fields[1], ("name".to_string(), "Utf8".to_string(), true));
    assert_eq!(
        fields[2],
        ("value".to_string(), "Float64".to_string(), true)
    );
}

#[test]
fn test_idempotent_emission() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    for _ in 0..3 {
        emitter
            .emit_dataset(
                "idempotent_dataset",
                "/data/idempotent.parquet",
                "parquet",
                Some("Idempotent test"),
                Some("prod"),
                Some("analytics"),
                Some("team@example.com"),
                schema.clone(),
                Some(OperationalMeta {
                    row_count: Some(100),
                    size_bytes: None,
                    partition_keys: vec![],
                }),
                vec![],
                vec!["test".to_string()],
            )
            .unwrap();
    }

    let conn = backend.get_connection().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM datasets WHERE name = 'idempotent_dataset'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(count, 1);
}

#[test]
fn test_fts_search() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    // Emit multiple datasets with searchable content
    emitter
        .emit_dataset(
            "transactions_daily",
            "/data/transactions.parquet",
            "parquet",
            Some("Daily transaction data from payment system"),
            Some("prod"),
            Some("finance"),
            Some("finance@example.com"),
            schema.clone(),
            None,
            vec![],
            vec!["daily".to_string(), "transactions".to_string()],
        )
        .unwrap();

    emitter
        .emit_dataset(
            "users_profile",
            "/data/users.parquet",
            "parquet",
            Some("User profile information"),
            Some("prod"),
            Some("analytics"),
            Some("analytics@example.com"),
            schema.clone(),
            None,
            vec![],
            vec!["users".to_string(), "profile".to_string()],
        )
        .unwrap();

    let conn = backend.get_connection().unwrap();

    // Search for "transactions" should find the transactions dataset
    let mut stmt = conn
        .prepare(
            "SELECT dataset_name FROM dataset_search \
             WHERE dataset_search MATCH ?1",
        )
        .unwrap();

    let results: Vec<String> = stmt
        .query_map(["transactions"], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(results, vec!["transactions_daily"]);

    // Search for "user" should find the users dataset
    let results: Vec<String> = stmt
        .query_map(["user"], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(results, vec!["users_profile"]);

    // Search for "finance" should find transactions (by domain)
    let results: Vec<String> = stmt
        .query_map(["finance"], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(results, vec!["transactions_daily"]);
}

#[test]
fn test_partition_keys() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    // Emit dataset with partition keys
    emitter
        .emit_dataset(
            "partitioned_dataset",
            "/data/partitioned.parquet",
            "parquet",
            Some("Partitioned dataset"),
            Some("prod"),
            Some("analytics"),
            Some("team@example.com"),
            schema,
            Some(OperationalMeta {
                row_count: Some(1_000_000),
                size_bytes: Some(500_000_000),
                partition_keys: vec!["year".to_string(), "month".to_string(), "day".to_string()],
            }),
            vec![],
            vec![],
        )
        .unwrap();

    let conn = backend.get_connection().unwrap();

    // Verify partition keys are stored as JSON
    let partition_keys_json: String = conn
        .query_row(
            "SELECT partition_keys FROM datasets WHERE name = ?1",
            ["partitioned_dataset"],
            |row| row.get(0),
        )
        .unwrap();

    // Parse JSON and verify structure
    let partition_keys: Vec<String> = serde_json::from_str(&partition_keys_json).unwrap();
    assert_eq!(
        partition_keys,
        vec!["year".to_string(), "month".to_string(), "day".to_string()]
    );
}

#[test]
fn test_domain_filtering() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    // Create datasets across different domains
    emitter
        .emit_dataset(
            "finance_dataset_1",
            "/data/finance1.parquet",
            "parquet",
            Some("Finance data 1"),
            Some("prod"),
            Some("finance"),
            Some("finance@example.com"),
            schema.clone(),
            None,
            vec![],
            vec![],
        )
        .unwrap();

    emitter
        .emit_dataset(
            "finance_dataset_2",
            "/data/finance2.parquet",
            "parquet",
            Some("Finance data 2"),
            Some("prod"),
            Some("finance"),
            Some("finance@example.com"),
            schema.clone(),
            None,
            vec![],
            vec![],
        )
        .unwrap();

    emitter
        .emit_dataset(
            "analytics_dataset",
            "/data/analytics.parquet",
            "parquet",
            Some("Analytics data"),
            Some("prod"),
            Some("analytics"),
            Some("analytics@example.com"),
            schema.clone(),
            None,
            vec![],
            vec![],
        )
        .unwrap();

    let conn = backend.get_connection().unwrap();

    // Query datasets by domain
    let finance_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM datasets WHERE domain = 'finance'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    let analytics_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM datasets WHERE domain = 'analytics'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(finance_count, 2);
    assert_eq!(analytics_count, 1);

    // Verify domain names
    let mut stmt = conn
        .prepare("SELECT name FROM datasets WHERE domain = ?1 ORDER BY name")
        .unwrap();

    let finance_datasets: Vec<String> = stmt
        .query_map(["finance"], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(
        finance_datasets,
        vec!["finance_dataset_1", "finance_dataset_2"]
    );
}

#[test]
fn test_operational_metadata() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend.clone());
    let schema = create_sample_schema();

    // Emit dataset with full operational metadata
    emitter
        .emit_dataset(
            "ops_metadata_dataset",
            "/data/ops.parquet",
            "parquet",
            Some("Dataset with operational metadata"),
            Some("prod"),
            Some("analytics"),
            Some("team@example.com"),
            schema,
            Some(OperationalMeta {
                row_count: Some(5_000_000),
                size_bytes: Some(2_500_000_000),
                partition_keys: vec!["region".to_string(), "date".to_string()],
            }),
            vec![],
            vec![],
        )
        .unwrap();

    let conn = backend.get_connection().unwrap();

    // Verify all operational metadata fields
    let (row_count, size_bytes, partition_keys_json): (Option<i64>, Option<i64>, Option<String>) =
        conn.query_row(
            "SELECT row_count, size_bytes, partition_keys FROM datasets WHERE name = ?1",
            ["ops_metadata_dataset"],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();

    assert_eq!(row_count, Some(5_000_000));
    assert_eq!(size_bytes, Some(2_500_000_000));

    let partition_keys: Vec<String> = serde_json::from_str(&partition_keys_json.unwrap()).unwrap();
    assert_eq!(partition_keys, vec!["region", "date"]);
}

// ===== Validation Error Tests =====

#[test]
fn test_validation_reject_invalid_dataset_name() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend);
    let schema = create_sample_schema();

    // Test: Dataset name with spaces (invalid)
    let result = emitter.emit_dataset(
        "invalid dataset name", // Spaces not allowed
        "/data/test.parquet",
        "parquet",
        None,
        None,
        None,
        None,
        schema.clone(),
        None,
        vec![],
        vec![],
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("invalid characters"));

    // Test: Dataset name starting with hyphen (invalid)
    let result = emitter.emit_dataset(
        "-invalid",
        "/data/test.parquet",
        "parquet",
        None,
        None,
        None,
        None,
        schema.clone(),
        None,
        vec![],
        vec![],
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("cannot start or end with hyphen"));

    // Test: Empty dataset name (invalid)
    let result = emitter.emit_dataset(
        "",
        "/data/test.parquet",
        "parquet",
        None,
        None,
        None,
        None,
        schema,
        None,
        vec![],
        vec![],
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}

#[test]
fn test_validation_reject_invalid_tags() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend);
    let schema = create_sample_schema();

    // Test: Tag with spaces (invalid)
    let result = emitter.emit_dataset(
        "test_dataset",
        "/data/test.parquet",
        "parquet",
        None,
        None,
        None,
        None,
        schema.clone(),
        None,
        vec![],
        vec!["invalid tag".to_string()], // Space not allowed
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("invalid characters"));

    // Test: Tag with @ symbol (invalid)
    let result = emitter.emit_dataset(
        "test_dataset",
        "/data/test.parquet",
        "parquet",
        None,
        None,
        None,
        None,
        schema,
        None,
        vec![],
        vec!["tag@value".to_string()], // @ not allowed
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("invalid characters"));
}

#[test]
fn test_validation_reject_invalid_field_names() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend);

    // Create schema with invalid field name (contains hyphen)
    let invalid_schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("invalid-field", DataType::Utf8, true), // Hyphen not allowed
    ]));

    let result = emitter.emit_dataset(
        "test_dataset",
        "/data/test.parquet",
        "parquet",
        None,
        None,
        None,
        None,
        invalid_schema,
        None,
        vec![],
        vec![],
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("invalid characters"));
}

#[test]
fn test_validation_reject_invalid_tenant_domain() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend);
    let schema = create_sample_schema();

    // Test: Tenant with colon (invalid)
    let result = emitter.emit_dataset(
        "test_dataset",
        "/data/test.parquet",
        "parquet",
        None,
        Some("tenant:invalid"), // Colon not allowed in identifiers
        None,
        None,
        schema.clone(),
        None,
        vec![],
        vec![],
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("invalid characters"));

    // Test: Domain with space (invalid)
    let result = emitter.emit_dataset(
        "test_dataset",
        "/data/test.parquet",
        "parquet",
        None,
        None,
        Some("invalid domain"), // Space not allowed
        None,
        schema,
        None,
        vec![],
        vec![],
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("invalid characters"));
}

#[test]
fn test_validation_accept_valid_inputs() {
    let (_temp_dir, backend) = create_test_backend();
    let emitter = Emitter::new(backend);
    let schema = create_sample_schema();

    // All valid inputs should succeed
    let result = emitter.emit_dataset(
        "valid_dataset-name.v2", // Valid: alphanumeric, underscore, hyphen, dot
        "/data/test.parquet",
        "parquet",
        Some("Valid description"),
        Some("prod-tenant"),      // Valid: alphanumeric, hyphen
        Some("analytics_domain"), // Valid: alphanumeric, underscore
        Some("team@example.com"),
        schema,
        Some(OperationalMeta {
            row_count: Some(1000),
            size_bytes: Some(50000),
            partition_keys: vec!["year".to_string(), "month".to_string()],
        }),
        vec!["upstream_dataset".to_string()],
        vec!["env:prod".to_string(), "team-analytics".to_string()], // Valid tags with colon and hyphen
    );
    assert!(result.is_ok());
}
