//! MetaFuse Catalog Core
//!
//! Core types, traits, and SQLite schema for the MetaFuse data catalog.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod migrations;
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

// ============================================================================
// Quality Check Types
// ============================================================================

/// Type of quality check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityCheckType {
    /// Check for null/missing values
    Completeness,
    /// Check data conforms to expected patterns
    Validity,
    /// Check for duplicate values
    Uniqueness,
    /// Check data is up-to-date
    Freshness,
    /// User-defined SQL-based check
    Custom,
}

impl std::fmt::Display for QualityCheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QualityCheckType::Completeness => write!(f, "completeness"),
            QualityCheckType::Validity => write!(f, "validity"),
            QualityCheckType::Uniqueness => write!(f, "uniqueness"),
            QualityCheckType::Freshness => write!(f, "freshness"),
            QualityCheckType::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for QualityCheckType {
    type Err = CatalogError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "completeness" => Ok(QualityCheckType::Completeness),
            "validity" => Ok(QualityCheckType::Validity),
            "uniqueness" => Ok(QualityCheckType::Uniqueness),
            "freshness" => Ok(QualityCheckType::Freshness),
            "custom" => Ok(QualityCheckType::Custom),
            _ => Err(CatalogError::ValidationError(format!(
                "Unknown quality check type: {}",
                s
            ))),
        }
    }
}

/// Severity level for quality checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityCheckSeverity {
    /// Informational, no action required
    Info,
    /// Warning, should be investigated
    Warning,
    /// Critical, requires immediate attention
    Critical,
}

impl std::fmt::Display for QualityCheckSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QualityCheckSeverity::Info => write!(f, "info"),
            QualityCheckSeverity::Warning => write!(f, "warning"),
            QualityCheckSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for QualityCheckSeverity {
    type Err = CatalogError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(QualityCheckSeverity::Info),
            "warning" => Ok(QualityCheckSeverity::Warning),
            "critical" => Ok(QualityCheckSeverity::Critical),
            _ => Err(CatalogError::ValidationError(format!(
                "Unknown severity: {}",
                s
            ))),
        }
    }
}

/// A quality check definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCheck {
    /// Unique identifier
    pub id: String,
    /// Dataset this check applies to
    pub dataset_id: i64,
    /// Type of check
    pub check_type: QualityCheckType,
    /// Human-readable name
    pub check_name: String,
    /// Optional description
    pub check_description: Option<String>,
    /// Check-specific configuration (JSON string)
    pub check_config: Option<String>,
    /// Severity level
    pub severity: QualityCheckSeverity,
    /// Score threshold for warning (0.0-1.0)
    pub warn_threshold: Option<f64>,
    /// Score threshold for failure (0.0-1.0)
    pub fail_threshold: Option<f64>,
    /// Whether the check is enabled
    pub enabled: bool,
    /// Cron schedule for periodic execution (None = on-demand only)
    pub schedule: Option<String>,
    /// Whether to allow on-demand execution
    pub on_demand: bool,
    /// When the check was created
    pub created_at: DateTime<Utc>,
    /// When the check was last updated
    pub updated_at: DateTime<Utc>,
    /// Who created the check
    pub created_by: Option<String>,
    /// Tenant identifier (for multi-tenant)
    pub tenant_id: Option<String>,
}

/// Status of a quality check execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityCheckStatus {
    /// Check passed
    Pass,
    /// Check warned (below warn threshold but above fail)
    Warn,
    /// Check failed (below fail threshold)
    Fail,
    /// Check encountered an error during execution
    Error,
    /// Check was skipped
    Skipped,
}

impl std::fmt::Display for QualityCheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QualityCheckStatus::Pass => write!(f, "pass"),
            QualityCheckStatus::Warn => write!(f, "warn"),
            QualityCheckStatus::Fail => write!(f, "fail"),
            QualityCheckStatus::Error => write!(f, "error"),
            QualityCheckStatus::Skipped => write!(f, "skipped"),
        }
    }
}

impl std::str::FromStr for QualityCheckStatus {
    type Err = CatalogError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pass" => Ok(QualityCheckStatus::Pass),
            "warn" => Ok(QualityCheckStatus::Warn),
            "fail" => Ok(QualityCheckStatus::Fail),
            "error" => Ok(QualityCheckStatus::Error),
            "skipped" => Ok(QualityCheckStatus::Skipped),
            _ => Err(CatalogError::ValidationError(format!(
                "Unknown check status: {}",
                s
            ))),
        }
    }
}

/// Execution mode for a quality check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityCheckExecutionMode {
    /// Triggered via API
    OnDemand,
    /// Triggered by background scheduler
    Scheduled,
}

impl std::fmt::Display for QualityCheckExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QualityCheckExecutionMode::OnDemand => write!(f, "on_demand"),
            QualityCheckExecutionMode::Scheduled => write!(f, "scheduled"),
        }
    }
}

/// Result of a quality check execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCheckResult {
    /// Unique identifier
    pub id: String,
    /// Reference to the check definition
    pub check_id: String,
    /// Dataset that was checked
    pub dataset_id: i64,
    /// Status of the check
    pub status: QualityCheckStatus,
    /// Quality score (0.0-1.0), None if error/skipped
    pub score: Option<f64>,
    /// Check-specific details (JSON string)
    pub details: Option<String>,
    /// Error message if status is Error
    pub error_message: Option<String>,
    /// Number of records checked
    pub records_checked: Option<i64>,
    /// Number of records that failed the check
    pub records_failed: Option<i64>,
    /// When the check was executed
    pub executed_at: DateTime<Utc>,
    /// How long the check took (milliseconds)
    pub execution_time_ms: Option<i64>,
    /// How the check was triggered
    pub execution_mode: QualityCheckExecutionMode,
    /// Delta table version at time of check
    pub delta_version: Option<i64>,
}

// ============================================================================
// Freshness Violation Types
// ============================================================================

/// A freshness SLA violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshnessViolation {
    /// Unique identifier
    pub id: String,
    /// Dataset that violated its SLA
    pub dataset_id: i64,
    /// When the data should have been updated
    pub expected_by: DateTime<Utc>,
    /// When the violation was detected
    pub detected_at: DateTime<Utc>,
    /// When the data was finally updated (None if still open)
    pub resolved_at: Option<DateTime<Utc>>,
    /// The SLA that was breached (e.g., "hourly", "daily")
    pub sla: String,
    /// Grace period that was configured (minutes)
    pub grace_period_minutes: Option<i32>,
    /// How many hours past the deadline
    pub hours_overdue: Option<f64>,
    /// Dataset's last_updated at time of detection
    pub last_updated_at: Option<DateTime<Utc>>,
    /// Whether an alert was sent
    pub alert_sent: bool,
    /// Reference to alert_history if alert was sent
    pub alert_id: Option<String>,
    /// Tenant identifier (for multi-tenant)
    pub tenant_id: Option<String>,
}

impl FreshnessViolation {
    /// Check if this violation is still open (unresolved)
    pub fn is_open(&self) -> bool {
        self.resolved_at.is_none()
    }
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
/// - `api_keys`: API key authentication (optional, feature-gated)
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

    -- API key authentication table (always created for schema stability)
    -- Used when 'api-keys' feature is enabled. Creating it unconditionally:
    -- 1. Prevents migration issues when enabling/disabling features
    -- 2. Ensures consistent database schema across deployments
    -- 3. Allows zero-downtime feature enablement
    -- The table is harmless when unused and enables CLI commands regardless of API feature state
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_hash TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      revoked_at TEXT,
      last_used_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
    CREATE INDEX IF NOT EXISTS idx_api_keys_revoked_at ON api_keys(revoked_at);

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

/// Initialize the catalog: base schema + migrations.
///
/// This is the recommended entry point for catalog initialization. It:
/// 1. Creates the base schema (tables, indexes, triggers)
/// 2. Runs any pending migrations to bring the schema up to date
///
/// The function is idempotent - safe to call multiple times.
///
/// # Arguments
///
/// * `conn` - SQLite connection (should be exclusive for initialization)
/// * `run_migrations` - If true, automatically apply pending migrations
///
/// # Returns
///
/// The number of migrations applied (0 if already up to date).
pub fn init_catalog(conn: &rusqlite::Connection, run_migrations_flag: bool) -> Result<usize> {
    // Initialize base schema
    init_sqlite_schema(conn)?;

    // Optionally run migrations
    if run_migrations_flag {
        migrations::run_migrations(conn)
    } else {
        Ok(0)
    }
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
    fn test_init_catalog() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();

        // init_catalog with migrations should work
        let count = init_catalog(&conn, true).unwrap();
        assert!(count > 0); // At least v1.0.0 migration

        // Verify delta_location column was added
        let has_col: bool = conn
            .prepare("PRAGMA table_info(datasets)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .any(|r| r.map(|n| n == "delta_location").unwrap_or(false));
        assert!(has_col);

        // Second call should be idempotent
        let count2 = init_catalog(&conn, true).unwrap();
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_init_catalog_without_migrations() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();

        // init_catalog without migrations should not apply them
        let count = init_catalog(&conn, false).unwrap();
        assert_eq!(count, 0);

        // Base tables should exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(tables.contains(&"datasets".to_string()));

        // But delta_location column should NOT exist (migration not run)
        let has_col: bool = conn
            .prepare("PRAGMA table_info(datasets)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .any(|r| r.map(|n| n == "delta_location").unwrap_or(false));
        assert!(!has_col);
    }

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
        assert!(tables.contains(&"api_keys".to_string()));
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
