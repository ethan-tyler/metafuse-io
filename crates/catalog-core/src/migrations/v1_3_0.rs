//! Migration v1.3.0: Multi-Region Foundation.
//!
//! This migration adds region support to the multi-tenant control plane:
//! - `region` column on `tenants` table for tenant region assignment
//! - Index on region for efficient filtering
//!
//! # Architecture
//!
//! The region field enables multi-region deployments by allowing:
//! - Tenant storage URI resolution with `{region}` placeholder
//! - Region-based routing and data locality
//! - Future cross-region replication support
//!
//! # Backward Compatibility
//!
//! The region column is nullable, so existing tenants continue to work.
//! When region is NULL, the default region from environment is used.

use super::Migration;

/// Version number: 1_003_000 represents v1.3.0
/// Format: MAJOR * 1_000_000 + MINOR * 1_000 + PATCH
pub const VERSION: i64 = 1_003_000;

/// Add region column to tenants table.
/// SQLite doesn't support IF NOT EXISTS for ADD COLUMN, so we use the helper.
const ADD_COLUMNS: &[(&str, &str, &str)] = &[("tenants", "region", "TEXT")];

pub fn migration() -> Migration {
    Migration {
        version: VERSION,
        description: "v1.3.0: Multi-Region Foundation",
        sql: SQL,
        add_columns: ADD_COLUMNS,
    }
}

const SQL: &str = r#"
-- ============================================================================
-- MetaFuse v1.3.0 Schema Migration
-- Multi-Region Foundation
-- ============================================================================
-- Region column is added via add_columns helper (not in SQL)
-- Index can be added in a future migration if query performance requires it
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use rusqlite::Connection;

    #[test]
    fn test_migration_version() {
        assert_eq!(VERSION, 1_003_000);
    }

    #[test]
    fn test_migration_description() {
        let m = migration();
        assert!(m.description.contains("v1.3.0"));
        assert!(m.description.contains("Multi-Region"));
    }

    #[test]
    fn test_region_column_added() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify region column exists
        let mut stmt = conn.prepare("PRAGMA table_info(tenants)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(
            columns.contains(&"region".to_string()),
            "region column should exist in tenants table"
        );
    }

    #[test]
    fn test_tenant_with_region() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create tenant with region
        conn.execute(
            "INSERT INTO tenants (tenant_id, display_name, storage_uri, admin_email, region)
             VALUES ('regional-tenant', 'Regional Corp', 'gs://bucket/tenants/regional/catalog.db', 'admin@regional.com', 'us-east1')",
            [],
        )
        .unwrap();

        // Verify region was stored
        let region: Option<String> = conn
            .query_row(
                "SELECT region FROM tenants WHERE tenant_id = 'regional-tenant'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(region, Some("us-east1".to_string()));
    }

    #[test]
    fn test_tenant_without_region() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create tenant without region (should be NULL)
        conn.execute(
            "INSERT INTO tenants (tenant_id, display_name, storage_uri, admin_email)
             VALUES ('no-region', 'No Region Corp', 'gs://bucket/tenants/no-region/catalog.db', 'admin@noregion.com')",
            [],
        )
        .unwrap();

        // Verify region is NULL
        let region: Option<String> = conn
            .query_row(
                "SELECT region FROM tenants WHERE tenant_id = 'no-region'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(region.is_none(), "region should be NULL by default");
    }

    #[test]
    fn test_query_by_region() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create tenants with different regions
        conn.execute(
            "INSERT INTO tenants (tenant_id, display_name, storage_uri, admin_email, region)
             VALUES ('tenant-us', 'US Tenant', 'gs://bucket/us/catalog.db', 'us@example.com', 'us-east1')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO tenants (tenant_id, display_name, storage_uri, admin_email, region)
             VALUES ('tenant-eu', 'EU Tenant', 'gs://bucket/eu/catalog.db', 'eu@example.com', 'europe-west1')",
            [],
        )
        .unwrap();

        // Query by region
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tenants WHERE region = 'us-east1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "Should find one US tenant");
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
