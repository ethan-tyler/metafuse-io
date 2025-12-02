//! Migration v1.4.0: Alerting & Data Contracts.
//!
//! This migration adds alerting and data contract support for v0.9.0:
//! - `alert_history` table for tracking fired alerts and delivery status
//! - `data_contracts` table for defining schema/quality/freshness contracts
//!
//! # Architecture
//!
//! ## Alerting System
//! The alerting system periodically evaluates conditions (freshness, quality, schema)
//! and dispatches webhooks. Alert history enables:
//! - Deduplication (cooldown windows prevent spam)
//! - Audit trail (who was notified, when)
//! - Delivery tracking (success/failure monitoring)
//!
//! ## Data Contracts
//! Contracts define expectations for datasets:
//! - Schema contracts: required columns, data types
//! - Quality contracts: minimum completeness, freshness scores
//! - Freshness contracts: maximum staleness thresholds
//!
//! # Integration
//!
//! - Servo (orchestration) receives webhook alerts for pipeline retry/notification
//! - Existing `freshness_config.alert_on_stale` is wired to this system
//! - Contract violations trigger alerts automatically

use super::Migration;

/// Version number: 1_004_000 represents v1.4.0
/// Format: MAJOR * 1_000_000 + MINOR * 1_000 + PATCH
pub const VERSION: i64 = 1_004_000;

/// No column additions needed (all columns in CREATE TABLE statements)
const ADD_COLUMNS: &[(&str, &str, &str)] = &[];

pub fn migration() -> Migration {
    Migration {
        version: VERSION,
        description: "v1.4.0: Alerting & Data Contracts",
        sql: SQL,
        add_columns: ADD_COLUMNS,
    }
}

const SQL: &str = r#"
-- ============================================================================
-- MetaFuse v1.4.0 Schema Migration
-- Alerting & Data Contracts
-- ============================================================================

-- Alert history with delivery tracking
-- Stores fired alerts for deduplication, audit, and delivery monitoring
CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Alert identification
    alert_type TEXT NOT NULL,           -- 'freshness', 'quality', 'schema', 'contract'
    dataset_id INTEGER,                 -- Which dataset triggered the alert
    severity TEXT NOT NULL,             -- 'info', 'warning', 'critical'
    message TEXT NOT NULL,              -- Human-readable alert message
    details TEXT,                       -- JSON with alert-specific context
    channels_notified TEXT,             -- JSON array of channels that were notified

    -- Delivery tracking (no DLQ, just visibility)
    delivery_status TEXT DEFAULT 'pending',  -- 'pending', 'delivered', 'failed'
    delivery_attempts INTEGER DEFAULT 0,     -- How many times we tried to deliver
    delivery_error TEXT,                     -- Last error message if failed

    -- Timestamps
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT,                   -- When the alert condition cleared

    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE,
    CHECK (alert_type IN ('freshness', 'quality', 'schema', 'contract')),
    CHECK (severity IN ('info', 'warning', 'critical')),
    CHECK (delivery_status IN ('pending', 'delivered', 'failed'))
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_alert_history_dataset ON alert_history(dataset_id);
CREATE INDEX IF NOT EXISTS idx_alert_history_type ON alert_history(alert_type);
CREATE INDEX IF NOT EXISTS idx_alert_history_created ON alert_history(created_at);
CREATE INDEX IF NOT EXISTS idx_alert_history_delivery ON alert_history(delivery_status);
CREATE INDEX IF NOT EXISTS idx_alert_history_unresolved ON alert_history(resolved_at) WHERE resolved_at IS NULL;

-- Data contracts (dedicated table for pipeline reliability agreements)
-- Contracts define expectations for datasets that trigger alerts on violation
CREATE TABLE IF NOT EXISTS data_contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Contract identification
    name TEXT NOT NULL UNIQUE,          -- Unique contract name (e.g., 'orders_contract')
    dataset_pattern TEXT NOT NULL,      -- Dataset name pattern (* wildcard supported)
    version INTEGER NOT NULL DEFAULT 1, -- Contract version for tracking changes

    -- Contract definitions (JSON)
    schema_contract TEXT,               -- Required columns, types, nullable flags
    quality_contract TEXT,              -- Min completeness, freshness, overall scores
    freshness_contract TEXT,            -- Max staleness, expected interval

    -- Enforcement configuration
    on_violation TEXT NOT NULL DEFAULT 'alert',  -- 'alert', 'warn', 'block'
    alert_channels TEXT,                -- JSON array of webhook URLs
    enabled INTEGER NOT NULL DEFAULT 1, -- Whether contract is active

    -- Metadata
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (on_violation IN ('alert', 'warn', 'block'))
);

-- Indexes for contract lookup
CREATE INDEX IF NOT EXISTS idx_contracts_pattern ON data_contracts(dataset_pattern);
CREATE INDEX IF NOT EXISTS idx_contracts_enabled ON data_contracts(enabled);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use rusqlite::Connection;

    #[test]
    fn test_migration_version() {
        assert_eq!(VERSION, 1_004_000);
    }

    #[test]
    fn test_migration_description() {
        let m = migration();
        assert!(m.description.contains("v1.4.0"));
        assert!(m.description.contains("Alerting"));
        assert!(m.description.contains("Contracts"));
    }

    #[test]
    fn test_alert_history_table_created() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify alert_history table exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='alert_history'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "alert_history table should exist");
    }

    #[test]
    fn test_data_contracts_table_created() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify data_contracts table exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='data_contracts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "data_contracts table should exist");
    }

    #[test]
    fn test_insert_alert_history() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create a dataset first
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated) VALUES ('test_dataset', '/path/to/data', 'delta', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();

        let dataset_id: i64 = conn
            .query_row(
                "SELECT id FROM datasets WHERE name = 'test_dataset'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        // Insert an alert
        conn.execute(
            r#"INSERT INTO alert_history
               (alert_type, dataset_id, severity, message, details, channels_notified, delivery_status)
               VALUES ('freshness', ?1, 'warning', 'Dataset is stale', '{"staleness_secs": 7200}', '["webhook:https://example.com"]', 'pending')"#,
            [dataset_id],
        )
        .unwrap();

        // Verify insert
        let (alert_type, severity, delivery_status): (String, String, String) = conn
            .query_row(
                "SELECT alert_type, severity, delivery_status FROM alert_history WHERE dataset_id = ?1",
                [dataset_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(alert_type, "freshness");
        assert_eq!(severity, "warning");
        assert_eq!(delivery_status, "pending");
    }

    #[test]
    fn test_insert_data_contract() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Insert a contract
        conn.execute(
            r#"INSERT INTO data_contracts
               (name, dataset_pattern, schema_contract, quality_contract, alert_channels)
               VALUES (
                   'orders_contract',
                   'orders*',
                   '{"required_columns": [{"name": "order_id", "data_type": "Int64"}]}',
                   '{"min_completeness": 0.95}',
                   '["webhook:https://example.com/alerts"]'
               )"#,
            [],
        )
        .unwrap();

        // Verify insert
        let (name, pattern, on_violation): (String, String, String) = conn
            .query_row(
                "SELECT name, dataset_pattern, on_violation FROM data_contracts WHERE name = 'orders_contract'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(name, "orders_contract");
        assert_eq!(pattern, "orders*");
        assert_eq!(on_violation, "alert");
    }

    #[test]
    fn test_contract_unique_name() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Insert first contract
        conn.execute(
            "INSERT INTO data_contracts (name, dataset_pattern) VALUES ('unique_contract', 'data*')",
            [],
        )
        .unwrap();

        // Try to insert duplicate (should fail)
        let result = conn.execute(
            "INSERT INTO data_contracts (name, dataset_pattern) VALUES ('unique_contract', 'other*')",
            [],
        );

        assert!(result.is_err(), "Duplicate contract name should fail");
    }

    #[test]
    fn test_alert_type_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Try to insert invalid alert type
        let result = conn.execute(
            "INSERT INTO alert_history (alert_type, severity, message) VALUES ('invalid', 'warning', 'Test')",
            [],
        );

        assert!(
            result.is_err(),
            "Invalid alert_type should fail CHECK constraint"
        );
    }

    #[test]
    fn test_delivery_status_update() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Insert pending alert
        conn.execute(
            "INSERT INTO alert_history (alert_type, severity, message) VALUES ('quality', 'critical', 'Low quality')",
            [],
        )
        .unwrap();

        let id: i64 = conn.last_insert_rowid();

        // Update to delivered
        conn.execute(
            "UPDATE alert_history SET delivery_status = 'delivered', delivery_attempts = 1 WHERE id = ?1",
            [id],
        )
        .unwrap();

        let (status, attempts): (String, i64) = conn
            .query_row(
                "SELECT delivery_status, delivery_attempts FROM alert_history WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(status, "delivered");
        assert_eq!(attempts, 1);
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

    #[test]
    fn test_cascade_delete_alert_history() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated) VALUES ('cascade_test', '/path', 'delta', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();

        let dataset_id: i64 = conn.last_insert_rowid();

        // Create alert for dataset
        conn.execute(
            "INSERT INTO alert_history (alert_type, dataset_id, severity, message) VALUES ('freshness', ?1, 'warning', 'Test')",
            [dataset_id],
        )
        .unwrap();

        // Verify alert exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM alert_history WHERE dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // Delete dataset
        conn.execute("DELETE FROM datasets WHERE id = ?1", [dataset_id])
            .unwrap();

        // Alert should be cascade deleted
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM alert_history WHERE dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "Alert should be cascade deleted with dataset");
    }
}
