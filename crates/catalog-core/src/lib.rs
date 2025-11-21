//! MetaFuse Catalog Core
//!
//! Core types, traits, and SQLite schema for the MetaFuse data catalog.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod validation;

/// Metadata for a dataset in the catalog
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetMeta {
    /// Unique name of the dataset
    pub name: String,
    /// Storage path (e.g., "s3://bucket/path" or "gs://bucket/path")
    pub path: String,
    /// Format of the dataset (e.g., "parquet", "delta", "iceberg", "csv")
    pub format: String,
    /// Optional human-readable description
    pub description: Option<String>,
    /// Tenant identifier for multi-tenant deployments
    pub tenant: Option<String>,
    /// Business domain (e.g., "finance", "marketing", "operations")
    pub domain: Option<String>,
    /// Owner/responsible party
    pub owner: Option<String>,
    /// When the dataset was first registered
    pub created_at: DateTime<Utc>,
    /// When the dataset metadata was last updated
    pub last_updated: DateTime<Utc>,
    /// Schema fields
    pub fields: Vec<FieldMeta>,
    /// Names of upstream datasets this depends on
    pub upstream_datasets: Vec<String>,
    /// Tags for categorization and discovery
    pub tags: Vec<String>,
    /// Operational metadata (row counts, size, partitions)
    pub operational: Option<OperationalMeta>,
}

/// Operational metadata about a dataset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationalMeta {
    /// Approximate number of rows
    pub row_count: Option<i64>,
    /// Size in bytes
    pub size_bytes: Option<i64>,
    /// Partition column names (if partitioned)
    pub partition_keys: Vec<String>,
}

/// Metadata for a field/column in a dataset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMeta {
    /// Name of the field
    pub name: String,
    /// Data type (Arrow/DataFusion type representation)
    pub data_type: String,
    /// Whether the field allows null values
    pub nullable: bool,
    /// Human-readable description of the field
    pub description: Option<String>,
}

/// Errors that can occur in catalog operations
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Dataset not found: {0}")]
    DatasetNotFound(String),

    #[error("Conflict detected: {0}")]
    ConflictError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Other error: {0}")]
    Other(String),
}

// Enable conversion to DataFusionError for seamless integration
impl From<CatalogError> for datafusion::error::DataFusionError {
    fn from(err: CatalogError) -> Self {
        datafusion::error::DataFusionError::External(Box::new(err))
    }
}

/// Result type for catalog operations
pub type Result<T> = std::result::Result<T, CatalogError>;

/// Initialize the SQLite schema for the catalog
///
/// Creates all necessary tables if they don't exist:
/// - `catalog_meta`: Version control for optimistic concurrency
/// - `datasets`: Core dataset registry
/// - `fields`: Column-level metadata
/// - `lineage`: Dataset lineage relationships
/// - `tags`: Dataset tags
/// - `glossary_terms`: Business glossary
/// - `term_links`: Links between datasets and glossary terms
/// - `dataset_search`: FTS5 virtual table for full-text search
pub fn init_sqlite_schema(conn: &rusqlite::Connection) -> Result<()> {
    let ddl = r#"
    -- Version control for optimistic concurrency
    CREATE TABLE IF NOT EXISTS catalog_meta (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      version INTEGER NOT NULL DEFAULT 1,
      last_modified TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    INSERT OR IGNORE INTO catalog_meta (id, version, last_modified)
    VALUES (1, 1, datetime('now'));

    -- Core dataset registry
    CREATE TABLE IF NOT EXISTS datasets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      path TEXT NOT NULL,
      format TEXT NOT NULL,
      description TEXT,
      tenant TEXT,
      domain TEXT,
      owner TEXT,
      created_at TEXT NOT NULL,
      last_updated TEXT NOT NULL,
      row_count INTEGER,
      size_bytes INTEGER,
      partition_keys TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_datasets_tenant ON datasets(tenant);
    CREATE INDEX IF NOT EXISTS idx_datasets_domain ON datasets(domain);
    CREATE INDEX IF NOT EXISTS idx_datasets_owner ON datasets(owner);
    CREATE INDEX IF NOT EXISTS idx_datasets_last_updated ON datasets(last_updated);

    -- Field/column metadata
    CREATE TABLE IF NOT EXISTS fields (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      dataset_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      data_type TEXT NOT NULL,
      nullable INTEGER NOT NULL DEFAULT 1,
      description TEXT,
      FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_fields_dataset_id ON fields(dataset_id);
    CREATE INDEX IF NOT EXISTS idx_fields_name ON fields(name);

    -- Dataset lineage relationships
    CREATE TABLE IF NOT EXISTS lineage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      upstream_dataset_id INTEGER NOT NULL,
      downstream_dataset_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (upstream_dataset_id) REFERENCES datasets(id) ON DELETE CASCADE,
      FOREIGN KEY (downstream_dataset_id) REFERENCES datasets(id) ON DELETE CASCADE,
      UNIQUE(upstream_dataset_id, downstream_dataset_id)
    );

    CREATE INDEX IF NOT EXISTS idx_lineage_upstream ON lineage(upstream_dataset_id);
    CREATE INDEX IF NOT EXISTS idx_lineage_downstream ON lineage(downstream_dataset_id);

    -- Tags for categorization
    CREATE TABLE IF NOT EXISTS tags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      dataset_id INTEGER NOT NULL,
      tag TEXT NOT NULL,
      FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE,
      UNIQUE(dataset_id, tag)
    );

    CREATE INDEX IF NOT EXISTS idx_tags_dataset_id ON tags(dataset_id);
    CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags(tag);

    -- Business glossary
    CREATE TABLE IF NOT EXISTS glossary_terms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      term TEXT UNIQUE NOT NULL,
      description TEXT,
      domain TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_glossary_domain ON glossary_terms(domain);

    -- Links between datasets/fields and glossary terms
    CREATE TABLE IF NOT EXISTS term_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      term_id INTEGER NOT NULL,
      dataset_id INTEGER,
      field_id INTEGER,
      FOREIGN KEY (term_id) REFERENCES glossary_terms(id) ON DELETE CASCADE,
      FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE,
      FOREIGN KEY (field_id) REFERENCES fields(id) ON DELETE CASCADE,
      CHECK ((dataset_id IS NOT NULL AND field_id IS NULL) OR (dataset_id IS NULL AND field_id IS NOT NULL))
    );

    CREATE INDEX IF NOT EXISTS idx_term_links_term ON term_links(term_id);
    CREATE INDEX IF NOT EXISTS idx_term_links_dataset ON term_links(dataset_id);
    CREATE INDEX IF NOT EXISTS idx_term_links_field ON term_links(field_id);

    -- Full-text search virtual table
    CREATE VIRTUAL TABLE IF NOT EXISTS dataset_search USING fts5(
      dataset_name,
      path,
      domain,
      owner,
      description,
      tags,
      field_names
    );

    -- Triggers to maintain FTS index automatically
    -- When a dataset is inserted, add to FTS
    CREATE TRIGGER IF NOT EXISTS dataset_search_insert
    AFTER INSERT ON datasets
    BEGIN
      INSERT INTO dataset_search (dataset_name, path, domain, owner, description, tags, field_names)
      VALUES (
        NEW.name,
        NEW.path,
        NEW.domain,
        NEW.owner,
        NEW.description,
        COALESCE((SELECT GROUP_CONCAT(tag, ' ') FROM (SELECT tag FROM tags WHERE dataset_id = NEW.id ORDER BY tag)), ''),
        COALESCE((SELECT GROUP_CONCAT(name, ' ') FROM (SELECT name FROM fields WHERE dataset_id = NEW.id ORDER BY name)), '')
      );
    END;

    -- When a dataset is updated, refresh FTS entry
    CREATE TRIGGER IF NOT EXISTS dataset_search_update
    AFTER UPDATE ON datasets
    BEGIN
      DELETE FROM dataset_search WHERE dataset_name = OLD.name;
      INSERT INTO dataset_search (dataset_name, path, domain, owner, description, tags, field_names)
      VALUES (
        NEW.name,
        NEW.path,
        NEW.domain,
        NEW.owner,
        NEW.description,
        COALESCE((SELECT GROUP_CONCAT(tag, ' ') FROM (SELECT tag FROM tags WHERE dataset_id = NEW.id ORDER BY tag)), ''),
        COALESCE((SELECT GROUP_CONCAT(name, ' ') FROM (SELECT name FROM fields WHERE dataset_id = NEW.id ORDER BY name)), '')
      );
    END;

    -- When a dataset is deleted, remove from FTS
    CREATE TRIGGER IF NOT EXISTS dataset_search_delete
    AFTER DELETE ON datasets
    BEGIN
      DELETE FROM dataset_search WHERE dataset_name = OLD.name;
    END;

    -- When fields are modified, refresh the parent dataset's FTS entry
    CREATE TRIGGER IF NOT EXISTS dataset_search_fields_update
    AFTER INSERT ON fields
    BEGIN
      DELETE FROM dataset_search WHERE dataset_name = (SELECT name FROM datasets WHERE id = NEW.dataset_id);
      INSERT INTO dataset_search (dataset_name, path, domain, owner, description, tags, field_names)
      SELECT
        d.name,
        d.path,
        d.domain,
        d.owner,
        d.description,
        COALESCE((SELECT GROUP_CONCAT(tag, ' ') FROM (SELECT tag FROM tags WHERE dataset_id = d.id ORDER BY tag)), ''),
        COALESCE((SELECT GROUP_CONCAT(name, ' ') FROM (SELECT name FROM fields WHERE dataset_id = d.id ORDER BY name)), '')
      FROM datasets d WHERE d.id = NEW.dataset_id;
    END;

    CREATE TRIGGER IF NOT EXISTS dataset_search_fields_delete
    AFTER DELETE ON fields
    BEGIN
      DELETE FROM dataset_search WHERE dataset_name = (SELECT name FROM datasets WHERE id = OLD.dataset_id);
      INSERT INTO dataset_search (dataset_name, path, domain, owner, description, tags, field_names)
      SELECT
        d.name,
        d.path,
        d.domain,
        d.owner,
        d.description,
        COALESCE((SELECT GROUP_CONCAT(tag, ' ') FROM (SELECT tag FROM tags WHERE dataset_id = d.id ORDER BY tag)), ''),
        COALESCE((SELECT GROUP_CONCAT(name, ' ') FROM (SELECT name FROM fields WHERE dataset_id = d.id ORDER BY name)), '')
      FROM datasets d WHERE d.id = OLD.dataset_id;
    END;

    -- When tags are modified, refresh the parent dataset's FTS entry
    CREATE TRIGGER IF NOT EXISTS dataset_search_tags_insert
    AFTER INSERT ON tags
    BEGIN
      DELETE FROM dataset_search WHERE dataset_name = (SELECT name FROM datasets WHERE id = NEW.dataset_id);
      INSERT INTO dataset_search (dataset_name, path, domain, owner, description, tags, field_names)
      SELECT
        d.name,
        d.path,
        d.domain,
        d.owner,
        d.description,
        COALESCE((SELECT GROUP_CONCAT(tag, ' ') FROM (SELECT tag FROM tags WHERE dataset_id = d.id ORDER BY tag)), ''),
        COALESCE((SELECT GROUP_CONCAT(name, ' ') FROM (SELECT name FROM fields WHERE dataset_id = d.id ORDER BY name)), '')
      FROM datasets d WHERE d.id = NEW.dataset_id;
    END;

    CREATE TRIGGER IF NOT EXISTS dataset_search_tags_delete
    AFTER DELETE ON tags
    BEGIN
      DELETE FROM dataset_search WHERE dataset_name = (SELECT name FROM datasets WHERE id = OLD.dataset_id);
      INSERT INTO dataset_search (dataset_name, path, domain, owner, description, tags, field_names)
      SELECT
        d.name,
        d.path,
        d.domain,
        d.owner,
        d.description,
        COALESCE((SELECT GROUP_CONCAT(tag, ' ') FROM (SELECT tag FROM tags WHERE dataset_id = d.id ORDER BY tag)), ''),
        COALESCE((SELECT GROUP_CONCAT(name, ' ') FROM (SELECT name FROM fields WHERE dataset_id = d.id ORDER BY name)), '')
      FROM datasets d WHERE d.id = OLD.dataset_id;
    END;
    "#;

    conn.execute_batch(ddl)?;
    Ok(())
}

/// Get the current catalog version for optimistic concurrency control
pub fn get_catalog_version(conn: &rusqlite::Connection) -> Result<i64> {
    let version: i64 =
        conn.query_row("SELECT version FROM catalog_meta WHERE id = 1", [], |row| {
            row.get(0)
        })?;
    Ok(version)
}

/// Increment the catalog version (call after successful write)
pub fn increment_catalog_version(conn: &rusqlite::Connection) -> Result<i64> {
    conn.execute(
        "UPDATE catalog_meta SET version = version + 1, last_modified = datetime('now') WHERE id = 1",
        [],
    )?;
    get_catalog_version(conn)
}

/// Update the catalog version to a specific value (used for optimistic locking validation)
pub fn set_catalog_version(
    conn: &rusqlite::Connection,
    expected_version: i64,
    new_version: i64,
) -> Result<bool> {
    let rows_affected = conn.execute(
        "UPDATE catalog_meta SET version = ?2, last_modified = datetime('now') WHERE id = 1 AND version = ?1",
        [expected_version, new_version],
    )?;
    Ok(rows_affected > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_schema() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_sqlite_schema(&conn).unwrap();

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(tables.contains(&"datasets".to_string()));
        assert!(tables.contains(&"fields".to_string()));
        assert!(tables.contains(&"lineage".to_string()));
        assert!(tables.contains(&"tags".to_string()));
        assert!(tables.contains(&"glossary_terms".to_string()));
    }

    #[test]
    fn test_version_control() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_sqlite_schema(&conn).unwrap();

        let version = get_catalog_version(&conn).unwrap();
        assert_eq!(version, 1);

        let new_version = increment_catalog_version(&conn).unwrap();
        assert_eq!(new_version, 2);
    }

    #[test]
    fn test_fts_triggers() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_sqlite_schema(&conn).unwrap();

        // Insert a dataset - trigger should create FTS entry
        conn.execute(
            "INSERT INTO datasets (name, path, format, description, domain, owner, created_at, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'), datetime('now'))",
            rusqlite::params![
                "test_dataset",
                "/data/test.parquet",
                "parquet",
                "A test dataset",
                "analytics",
                "test@example.com"
            ],
        )
        .unwrap();

        let dataset_id: i64 = conn
            .query_row(
                "SELECT id FROM datasets WHERE name = ?1",
                ["test_dataset"],
                |row| row.get(0),
            )
            .unwrap();

        // Verify FTS entry was created by trigger
        let fts_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM dataset_search WHERE dataset_name = ?1",
                ["test_dataset"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fts_count, 1);

        // Add fields - trigger should update FTS with field_names
        conn.execute(
            "INSERT INTO fields (dataset_id, name, data_type, nullable) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![dataset_id, "id", "Int64", 0],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO fields (dataset_id, name, data_type, nullable) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![dataset_id, "name", "Utf8", 1],
        )
        .unwrap();

        // Verify FTS entry contains field_names
        let field_names: String = conn
            .query_row(
                "SELECT field_names FROM dataset_search WHERE dataset_name = ?1",
                ["test_dataset"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(field_names.contains("id"));
        assert!(field_names.contains("name"));

        // Add tags - trigger should update FTS with tags
        conn.execute(
            "INSERT INTO tags (dataset_id, tag) VALUES (?1, ?2)",
            rusqlite::params![dataset_id, "production"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tags (dataset_id, tag) VALUES (?1, ?2)",
            rusqlite::params![dataset_id, "daily"],
        )
        .unwrap();

        // Verify FTS entry contains tags
        let tags: String = conn
            .query_row(
                "SELECT tags FROM dataset_search WHERE dataset_name = ?1",
                ["test_dataset"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(tags.contains("production"));
        assert!(tags.contains("daily"));

        // Update dataset - trigger should refresh FTS entry
        conn.execute(
            "UPDATE datasets SET description = ?1 WHERE id = ?2",
            rusqlite::params!["Updated description", dataset_id],
        )
        .unwrap();

        let description: String = conn
            .query_row(
                "SELECT description FROM dataset_search WHERE dataset_name = ?1",
                ["test_dataset"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(description, "Updated description");

        // Delete dataset - trigger should remove FTS entry
        conn.execute("DELETE FROM datasets WHERE id = ?1", [dataset_id])
            .unwrap();

        let fts_count_after_delete: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM dataset_search WHERE dataset_name = ?1",
                ["test_dataset"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fts_count_after_delete, 0);
    }
}
