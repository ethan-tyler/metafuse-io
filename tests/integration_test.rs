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
