//! Migration v1.6.0: Column-Level Lineage.
//!
//! This migration adds support for tracking column-to-column data lineage:
//! - Tracks how source columns are transformed into target columns
//! - Uses hybrid field references (field_id + field_name) for resilience
//! - Enables PII propagation tracking and impact analysis
//!
//! # Schema Design
//!
//! The column_lineage table uses a hybrid approach:
//! - `field_id` references are used when available (preferred)
//! - `field_name` strings are stored as backup for schema evolution resilience
//! - Both source and target can be tracked even if field_id is not available

use super::Migration;

/// Version number: 1_006_000 represents v1.6.0
/// Format: MAJOR * 1_000_000 + MINOR * 1_000 + PATCH
pub const VERSION: i64 = 1_006_000;

/// No additional columns needed (new table)
const ADD_COLUMNS: &[(&str, &str, &str)] = &[];

pub fn migration() -> Migration {
    Migration {
        version: VERSION,
        description: "v1.6.0: Column-Level Lineage",
        sql: SQL,
        add_columns: ADD_COLUMNS,
    }
}

const SQL: &str = r#"
-- ============================================================================
-- MetaFuse v1.6.0 Schema Migration
-- Column-Level Lineage
-- ============================================================================

-- Column-to-column lineage tracking
-- Uses hybrid field references for schema evolution resilience
CREATE TABLE IF NOT EXISTS column_lineage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Source column (the column data comes FROM)
    source_dataset_id INTEGER NOT NULL,
    source_field_id INTEGER,  -- Nullable: may not have field_id for all datasets
    source_field_name TEXT NOT NULL,  -- Always store name for resilience

    -- Target column (the column data flows TO)
    target_dataset_id INTEGER NOT NULL,
    target_field_id INTEGER,  -- Nullable: may not have field_id for all datasets
    target_field_name TEXT NOT NULL,  -- Always store name for resilience

    -- Transformation metadata
    transformation_type TEXT NOT NULL DEFAULT 'Direct',  -- Direct, Expression, Aggregate, Window, Case, Cast
    expression TEXT,  -- The SQL expression (optional)

    -- Tracking
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Foreign keys (soft: allow lineage even if referenced entities are deleted)
    FOREIGN KEY (source_dataset_id) REFERENCES datasets(id) ON DELETE CASCADE,
    FOREIGN KEY (source_field_id) REFERENCES fields(id) ON DELETE SET NULL,
    FOREIGN KEY (target_dataset_id) REFERENCES datasets(id) ON DELETE CASCADE,
    FOREIGN KEY (target_field_id) REFERENCES fields(id) ON DELETE SET NULL
);

-- Index for forward lineage: "Where does this column flow TO?"
CREATE INDEX IF NOT EXISTS idx_column_lineage_source ON column_lineage(source_dataset_id, source_field_name);

-- Index for backward lineage: "Where does this column come FROM?"
CREATE INDEX IF NOT EXISTS idx_column_lineage_target ON column_lineage(target_dataset_id, target_field_name);

-- Index for field_id lookups (when available)
CREATE INDEX IF NOT EXISTS idx_column_lineage_source_field_id ON column_lineage(source_field_id) WHERE source_field_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_column_lineage_target_field_id ON column_lineage(target_field_id) WHERE target_field_id IS NOT NULL;

-- Index for transformation type queries
CREATE INDEX IF NOT EXISTS idx_column_lineage_transformation ON column_lineage(transformation_type);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use rusqlite::Connection;

    #[test]
    fn test_migration_version() {
        assert_eq!(VERSION, 1_006_000);
    }

    #[test]
    fn test_migration_description() {
        let m = migration();
        assert!(m.description.contains("v1.6.0"));
        assert!(m.description.contains("Lineage"));
    }

    #[test]
    fn test_column_lineage_table_created() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify table exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='column_lineage'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "column_lineage table should exist");
    }

    #[test]
    fn test_column_lineage_indexes_created() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify indexes exist
        let index_names = ["idx_column_lineage_source", "idx_column_lineage_target"];

        for index_name in index_names {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1",
                    [index_name],
                    |row| row.get(0),
                )
                .unwrap();

            assert_eq!(count, 1, "{} index should exist", index_name);
        }
    }

    #[test]
    fn test_column_lineage_insert() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create test datasets
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('source_table', '/path/source', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let source_id: i64 = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('target_table', '/path/target', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let target_id: i64 = conn.last_insert_rowid();

        // Insert a lineage edge
        conn.execute(
            "INSERT INTO column_lineage
             (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type, expression)
             VALUES (?1, 'customer_id', ?2, 'cust_id', 'Direct', NULL)",
            [source_id, target_id],
        )
        .unwrap();

        // Verify the insert
        let (src_name, tgt_name, trans_type): (String, String, String) = conn
            .query_row(
                "SELECT source_field_name, target_field_name, transformation_type
                 FROM column_lineage WHERE source_dataset_id = ?1",
                [source_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(src_name, "customer_id");
        assert_eq!(tgt_name, "cust_id");
        assert_eq!(trans_type, "Direct");
    }

    #[test]
    fn test_column_lineage_with_expression() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create test dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('orders', '/path/orders', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let dataset_id: i64 = conn.last_insert_rowid();

        // Insert aggregate lineage edge
        conn.execute(
            "INSERT INTO column_lineage
             (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type, expression)
             VALUES (?1, 'amount', ?1, 'total_amount', 'Aggregate', 'SUM(amount)')",
            [dataset_id],
        )
        .unwrap();

        // Verify the expression was stored
        let expression: Option<String> = conn
            .query_row(
                "SELECT expression FROM column_lineage WHERE transformation_type = 'Aggregate'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(expression, Some("SUM(amount)".to_string()));
    }

    #[test]
    fn test_cascade_delete_on_dataset() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create test dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('temp_table', '/path/temp', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let dataset_id: i64 = conn.last_insert_rowid();

        // Insert lineage edge
        conn.execute(
            "INSERT INTO column_lineage
             (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type)
             VALUES (?1, 'col_a', ?1, 'col_b', 'Direct')",
            [dataset_id],
        )
        .unwrap();

        // Verify lineage exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM column_lineage WHERE source_dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // Delete the dataset
        conn.execute("DELETE FROM datasets WHERE id = ?1", [dataset_id])
            .unwrap();

        // Verify lineage was cascaded
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM column_lineage WHERE source_dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 0,
            "Lineage should be deleted when dataset is deleted"
        );
    }
}
