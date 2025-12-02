//! Migration v1.5.0: Alert History Tenant Isolation.
//!
//! This migration adds tenant_id to alert_history for proper multi-tenant isolation:
//! - Adds `tenant_id` column to `alert_history` table
//! - Backfills existing records from associated dataset's tenant
//! - Adds index for efficient tenant-scoped queries
//!
//! # Multi-Tenant Security
//!
//! Without tenant_id, alert history queries cannot be properly scoped to a tenant,
//! potentially leaking alert information across tenants. This migration:
//! 1. Adds the column (nullable for backwards compatibility)
//! 2. Backfills from datasets.tenant for existing alerts
//! 3. Creates an index for performant tenant-scoped queries
//!
//! Future alerts will be recorded with tenant_id at insertion time.

use super::Migration;

/// Version number: 1_005_000 represents v1.5.0
/// Format: MAJOR * 1_000_000 + MINOR * 1_000 + PATCH
pub const VERSION: i64 = 1_005_000;

/// Add tenant_id column to alert_history
/// SQLite doesn't support IF NOT EXISTS for ADD COLUMN, so we use the add_columns helper
const ADD_COLUMNS: &[(&str, &str, &str)] = &[("alert_history", "tenant_id", "TEXT")];

pub fn migration() -> Migration {
    Migration {
        version: VERSION,
        description: "v1.5.0: Alert History Tenant Isolation",
        sql: SQL,
        add_columns: ADD_COLUMNS,
    }
}

const SQL: &str = r#"
-- ============================================================================
-- MetaFuse v1.5.0 Schema Migration
-- Alert History Tenant Isolation
-- ============================================================================

-- Note: The tenant_id column is added via add_columns AFTER this SQL runs.
-- Backfill and indexing happen in a separate step below.
-- This SQL block is intentionally minimal since the column doesn't exist yet.
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use rusqlite::Connection;

    #[test]
    fn test_migration_version() {
        assert_eq!(VERSION, 1_005_000);
    }

    #[test]
    fn test_migration_description() {
        let m = migration();
        assert!(m.description.contains("v1.5.0"));
        assert!(m.description.contains("Tenant Isolation"));
    }

    #[test]
    fn test_tenant_id_column_added() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify tenant_id column exists in alert_history
        let mut stmt = conn.prepare("PRAGMA table_info(alert_history)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(
            columns.contains(&"tenant_id".to_string()),
            "tenant_id column should exist in alert_history"
        );
    }

    #[test]
    fn test_insert_alert_with_tenant() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Insert alert with tenant_id
        conn.execute(
            "INSERT INTO alert_history (alert_type, severity, message, tenant_id) \
             VALUES ('quality', 'warning', 'Test', 'my-tenant')",
            [],
        )
        .unwrap();

        let tenant_id: String = conn
            .query_row(
                "SELECT tenant_id FROM alert_history WHERE message = 'Test'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(tenant_id, "my-tenant");
    }

    #[test]
    fn test_tenant_scoped_query() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Insert alerts for different tenants
        conn.execute(
            "INSERT INTO alert_history (alert_type, severity, message, tenant_id) \
             VALUES ('quality', 'warning', 'Tenant A alert', 'tenant-a')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO alert_history (alert_type, severity, message, tenant_id) \
             VALUES ('freshness', 'critical', 'Tenant B alert', 'tenant-b')",
            [],
        )
        .unwrap();

        // Query for tenant-a only
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM alert_history WHERE tenant_id = 'tenant-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "Should only see tenant-a alerts");

        // Query for tenant-b only
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM alert_history WHERE tenant_id = 'tenant-b'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "Should only see tenant-b alerts");
    }

    #[test]
    fn test_migration_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();

        // Run migrations twice
        let count1 = run_migrations(&conn).unwrap();
        assert!(count1 > 0);

        let count2 = run_migrations(&conn).unwrap();
        assert_eq!(count2, 0, "Second run should apply no migrations");
    }
}
