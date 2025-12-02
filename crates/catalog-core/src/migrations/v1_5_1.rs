//! Migration v1.5.1: Alert History Tenant Backfill & Indexes.
//!
//! This migration completes the tenant isolation work started in v1.5.0:
//! - Backfills tenant_id from associated dataset's tenant
//! - Creates indexes for efficient tenant-scoped queries
//!
//! This is a separate migration because v1.5.0 adds the column via add_columns
//! which runs AFTER the SQL, so we need a subsequent migration to use the column.

use super::Migration;

/// Version number: 1_005_001 represents v1.5.1
/// Format: MAJOR * 1_000_000 + MINOR * 1_000 + PATCH
pub const VERSION: i64 = 1_005_001;

/// No additional columns needed
const ADD_COLUMNS: &[(&str, &str, &str)] = &[];

pub fn migration() -> Migration {
    Migration {
        version: VERSION,
        description: "v1.5.1: Alert History Tenant Backfill & Indexes",
        sql: SQL,
        add_columns: ADD_COLUMNS,
    }
}

const SQL: &str = r#"
-- ============================================================================
-- MetaFuse v1.5.1 Schema Migration
-- Alert History Tenant Backfill & Indexes
-- ============================================================================

-- Backfill tenant_id from associated datasets
-- Uses datasets.tenant which may be NULL for some datasets
UPDATE alert_history
SET tenant_id = (
    SELECT d.tenant
    FROM datasets d
    WHERE d.id = alert_history.dataset_id
)
WHERE dataset_id IS NOT NULL AND tenant_id IS NULL;

-- Create index for tenant-scoped queries
-- This enables efficient filtering by tenant_id
CREATE INDEX IF NOT EXISTS idx_alert_history_tenant ON alert_history(tenant_id);

-- Composite index for common tenant + time queries
CREATE INDEX IF NOT EXISTS idx_alert_history_tenant_created ON alert_history(tenant_id, created_at);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use rusqlite::Connection;

    #[test]
    fn test_migration_version() {
        assert_eq!(VERSION, 1_005_001);
    }

    #[test]
    fn test_migration_description() {
        let m = migration();
        assert!(m.description.contains("v1.5.1"));
        assert!(m.description.contains("Backfill"));
    }

    #[test]
    fn test_tenant_index_created() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify index exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_alert_history_tenant'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "idx_alert_history_tenant index should exist");
    }

    #[test]
    fn test_tenant_composite_index_created() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify composite index exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_alert_history_tenant_created'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(
            count, 1,
            "idx_alert_history_tenant_created index should exist"
        );
    }

    #[test]
    fn test_tenant_backfill() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create a tenant dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, tenant, created_at, last_updated) \
             VALUES ('tenant_dataset', '/path', 'delta', 'test-tenant', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();

        let dataset_id: i64 = conn.last_insert_rowid();

        // Insert an alert without tenant_id (simulating pre-migration data)
        conn.execute(
            "INSERT INTO alert_history (alert_type, dataset_id, severity, message) \
             VALUES ('freshness', ?1, 'warning', 'Test alert')",
            [dataset_id],
        )
        .unwrap();

        // Manually run the backfill (simulating what migration does for fresh data)
        conn.execute(
            "UPDATE alert_history \
             SET tenant_id = (SELECT d.tenant FROM datasets d WHERE d.id = alert_history.dataset_id) \
             WHERE dataset_id IS NOT NULL AND tenant_id IS NULL",
            [],
        )
        .unwrap();

        // Verify tenant_id was backfilled
        let tenant_id: Option<String> = conn
            .query_row(
                "SELECT tenant_id FROM alert_history WHERE dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(
            tenant_id,
            Some("test-tenant".to_string()),
            "tenant_id should be backfilled from dataset"
        );
    }
}
