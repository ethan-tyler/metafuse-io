//! Migration v1.7.0: Quality Checks & Freshness Violations.
//!
//! This migration adds support for custom quality check definitions,
//! quality check execution results, and freshness violation tracking:
//!
//! - `quality_checks`: Define custom quality checks (completeness, validity, etc.)
//! - `quality_results`: Store results from check executions
//! - `freshness_violations`: Track SLA breaches for freshness monitoring
//!
//! # Quality Check Types
//!
//! - `completeness`: Check for null/missing values
//! - `validity`: Check data conforms to expected patterns
//! - `uniqueness`: Check for duplicate values
//! - `freshness`: Check data is up-to-date (computed from Delta metadata)
//! - `custom`: User-defined SQL-based checks
//!
//! # Execution Modes
//!
//! Quality checks support two execution modes:
//! - **On-demand**: Triggered via API (`POST /datasets/:name/quality/check`)
//! - **Scheduled**: Background task runs checks based on cron schedule

use super::Migration;

/// Version number: 1_007_000 represents v1.7.0
/// Format: MAJOR * 1_000_000 + MINOR * 1_000 + PATCH
pub const VERSION: i64 = 1_007_000;

/// No additional columns needed (new tables only)
const ADD_COLUMNS: &[(&str, &str, &str)] = &[];

pub fn migration() -> Migration {
    Migration {
        version: VERSION,
        description: "v1.7.0: Quality Checks & Freshness Violations",
        sql: SQL,
        add_columns: ADD_COLUMNS,
    }
}

const SQL: &str = r#"
-- ============================================================================
-- MetaFuse v1.7.0 Schema Migration
-- Quality Checks & Freshness Violations
-- ============================================================================

-- Quality check definitions
-- Defines what checks to run on a dataset
CREATE TABLE IF NOT EXISTS quality_checks (
    id TEXT PRIMARY KEY,
    dataset_id INTEGER NOT NULL,

    -- Check definition
    check_type TEXT NOT NULL,  -- 'completeness', 'validity', 'uniqueness', 'freshness', 'custom'
    check_name TEXT NOT NULL,
    check_description TEXT,
    check_config TEXT,  -- JSON: check-specific configuration

    -- Severity and thresholds
    severity TEXT NOT NULL DEFAULT 'warning',  -- 'info', 'warning', 'critical'
    warn_threshold REAL,  -- Score below this = warning (0.0-1.0)
    fail_threshold REAL,  -- Score below this = failure (0.0-1.0)

    -- Execution configuration
    enabled INTEGER NOT NULL DEFAULT 1,
    schedule TEXT,  -- Cron expression for scheduled execution (NULL = on-demand only)
    on_demand INTEGER NOT NULL DEFAULT 1,  -- Allow on-demand execution via API

    -- Timestamps
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT,

    -- Multi-tenant support (optional)
    tenant_id TEXT,

    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

-- Index for finding checks by dataset
CREATE INDEX IF NOT EXISTS idx_quality_checks_dataset ON quality_checks(dataset_id);

-- Index for finding enabled scheduled checks
CREATE INDEX IF NOT EXISTS idx_quality_checks_scheduled ON quality_checks(enabled, schedule)
    WHERE enabled = 1 AND schedule IS NOT NULL;

-- Index for tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_quality_checks_tenant ON quality_checks(tenant_id)
    WHERE tenant_id IS NOT NULL;


-- Quality check execution results
-- Stores the outcome of each check execution
CREATE TABLE IF NOT EXISTS quality_results (
    id TEXT PRIMARY KEY,
    check_id TEXT NOT NULL,
    dataset_id INTEGER NOT NULL,

    -- Result
    status TEXT NOT NULL,  -- 'pass', 'warn', 'fail', 'error', 'skipped'
    score REAL,  -- 0.0 to 1.0 (NULL if error/skipped)

    -- Details
    details TEXT,  -- JSON: check-specific result details
    error_message TEXT,  -- Error message if status = 'error'
    records_checked INTEGER,  -- Number of records evaluated
    records_failed INTEGER,  -- Number of records that failed the check

    -- Execution context
    executed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms INTEGER,  -- How long the check took
    execution_mode TEXT NOT NULL DEFAULT 'on_demand',  -- 'on_demand' or 'scheduled'
    delta_version INTEGER,  -- Delta table version at time of check

    FOREIGN KEY (check_id) REFERENCES quality_checks(id) ON DELETE CASCADE,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

-- Index for finding results by check
CREATE INDEX IF NOT EXISTS idx_quality_results_check ON quality_results(check_id, executed_at DESC);

-- Index for finding results by dataset (most recent first)
CREATE INDEX IF NOT EXISTS idx_quality_results_dataset ON quality_results(dataset_id, executed_at DESC);

-- Index for finding failed/warning results
CREATE INDEX IF NOT EXISTS idx_quality_results_status ON quality_results(status)
    WHERE status IN ('fail', 'warn', 'error');


-- Freshness violations
-- Tracks when datasets breach their freshness SLA
CREATE TABLE IF NOT EXISTS freshness_violations (
    id TEXT PRIMARY KEY,
    dataset_id INTEGER NOT NULL,

    -- Violation details
    expected_by TEXT NOT NULL,  -- When data should have been updated (ISO 8601)
    detected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- When violation was detected
    resolved_at TEXT,  -- When data was finally updated (NULL if still open)

    -- SLA context
    sla TEXT NOT NULL,  -- 'hourly', 'daily', 'weekly', or cron expression
    grace_period_minutes INTEGER,  -- Grace period that was configured
    hours_overdue REAL,  -- How many hours past the SLA deadline

    -- Last known state
    last_updated_at TEXT,  -- Dataset's last_updated at time of detection

    -- Alert tracking
    alert_sent INTEGER NOT NULL DEFAULT 0,  -- Whether an alert was fired
    alert_id TEXT,  -- Reference to alert_history if alert was sent

    -- Multi-tenant support (optional)
    tenant_id TEXT,

    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

-- Index for finding open violations
CREATE INDEX IF NOT EXISTS idx_freshness_violations_open ON freshness_violations(dataset_id, resolved_at)
    WHERE resolved_at IS NULL;

-- Index for finding violations by dataset
CREATE INDEX IF NOT EXISTS idx_freshness_violations_dataset ON freshness_violations(dataset_id, detected_at DESC);

-- Index for finding unalerted violations
CREATE INDEX IF NOT EXISTS idx_freshness_violations_unalerted ON freshness_violations(alert_sent)
    WHERE alert_sent = 0 AND resolved_at IS NULL;

-- Index for tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_freshness_violations_tenant ON freshness_violations(tenant_id)
    WHERE tenant_id IS NOT NULL;
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use rusqlite::Connection;

    #[test]
    fn test_migration_version() {
        assert_eq!(VERSION, 1_007_000);
    }

    #[test]
    fn test_migration_description() {
        let m = migration();
        assert!(m.description.contains("v1.7.0"));
        assert!(m.description.contains("Quality"));
    }

    #[test]
    fn test_quality_checks_table_created() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify table exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='quality_checks'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "quality_checks table should exist");
    }

    #[test]
    fn test_quality_results_table_created() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify table exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='quality_results'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "quality_results table should exist");
    }

    #[test]
    fn test_freshness_violations_table_created() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify table exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='freshness_violations'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "freshness_violations table should exist");
    }

    #[test]
    fn test_quality_check_insert() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create test dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('test_table', '/path/test', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let dataset_id: i64 = conn.last_insert_rowid();

        // Insert a quality check
        conn.execute(
            "INSERT INTO quality_checks (id, dataset_id, check_type, check_name, severity, warn_threshold, fail_threshold)
             VALUES ('check-001', ?1, 'completeness', 'No nulls in customer_id', 'warning', 0.95, 0.80)",
            [dataset_id],
        )
        .unwrap();

        // Verify the insert
        let (check_type, check_name, warn_threshold): (String, String, f64) = conn
            .query_row(
                "SELECT check_type, check_name, warn_threshold FROM quality_checks WHERE id = 'check-001'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(check_type, "completeness");
        assert_eq!(check_name, "No nulls in customer_id");
        assert!((warn_threshold - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_quality_result_insert() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create test dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('test_table', '/path/test', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let dataset_id: i64 = conn.last_insert_rowid();

        // Create quality check
        conn.execute(
            "INSERT INTO quality_checks (id, dataset_id, check_type, check_name)
             VALUES ('check-001', ?1, 'completeness', 'Check nulls')",
            [dataset_id],
        )
        .unwrap();

        // Insert result
        conn.execute(
            "INSERT INTO quality_results (id, check_id, dataset_id, status, score, records_checked, records_failed, execution_time_ms)
             VALUES ('result-001', 'check-001', ?1, 'pass', 0.98, 1000, 20, 150)",
            [dataset_id],
        )
        .unwrap();

        // Verify the insert
        let (status, score, records_checked): (String, f64, i64) = conn
            .query_row(
                "SELECT status, score, records_checked FROM quality_results WHERE id = 'result-001'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(status, "pass");
        assert!((score - 0.98).abs() < 0.001);
        assert_eq!(records_checked, 1000);
    }

    #[test]
    fn test_freshness_violation_insert() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create test dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('daily_sales', '/path/sales', 'delta', datetime('now'), datetime('now', '-2 days'))",
            [],
        )
        .unwrap();
        let dataset_id: i64 = conn.last_insert_rowid();

        // Insert a freshness violation
        conn.execute(
            "INSERT INTO freshness_violations (id, dataset_id, expected_by, sla, hours_overdue, grace_period_minutes)
             VALUES ('violation-001', ?1, datetime('now', '-1 day'), 'daily', 24.0, 60)",
            [dataset_id],
        )
        .unwrap();

        // Verify the insert
        let (sla, hours_overdue): (String, f64) = conn
            .query_row(
                "SELECT sla, hours_overdue FROM freshness_violations WHERE id = 'violation-001'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(sla, "daily");
        assert!((hours_overdue - 24.0).abs() < 0.001);
    }

    #[test]
    fn test_open_violations_query() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create test dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('stale_table', '/path/stale', 'delta', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let dataset_id: i64 = conn.last_insert_rowid();

        // Insert open violation
        conn.execute(
            "INSERT INTO freshness_violations (id, dataset_id, expected_by, sla, hours_overdue)
             VALUES ('open-001', ?1, datetime('now'), 'hourly', 2.0)",
            [dataset_id],
        )
        .unwrap();

        // Insert resolved violation
        conn.execute(
            "INSERT INTO freshness_violations (id, dataset_id, expected_by, sla, hours_overdue, resolved_at)
             VALUES ('resolved-001', ?1, datetime('now', '-1 day'), 'daily', 1.0, datetime('now'))",
            [dataset_id],
        )
        .unwrap();

        // Query open violations
        let open_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM freshness_violations WHERE dataset_id = ?1 AND resolved_at IS NULL",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(open_count, 1, "Should have exactly one open violation");
    }

    #[test]
    fn test_cascade_delete() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Create test dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('temp_dataset', '/path/temp', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let dataset_id: i64 = conn.last_insert_rowid();

        // Create quality check and result
        conn.execute(
            "INSERT INTO quality_checks (id, dataset_id, check_type, check_name)
             VALUES ('check-temp', ?1, 'completeness', 'Temp check')",
            [dataset_id],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO quality_results (id, check_id, dataset_id, status, score)
             VALUES ('result-temp', 'check-temp', ?1, 'pass', 1.0)",
            [dataset_id],
        )
        .unwrap();

        // Create freshness violation
        conn.execute(
            "INSERT INTO freshness_violations (id, dataset_id, expected_by, sla, hours_overdue)
             VALUES ('violation-temp', ?1, datetime('now'), 'daily', 1.0)",
            [dataset_id],
        )
        .unwrap();

        // Verify records exist
        let check_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM quality_checks WHERE dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(check_count, 1);

        // Delete the dataset
        conn.execute("DELETE FROM datasets WHERE id = ?1", [dataset_id])
            .unwrap();

        // Verify cascade deleted all related records
        let check_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM quality_checks WHERE dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(check_count, 0, "Quality checks should be cascade deleted");

        let result_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM quality_results WHERE dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(result_count, 0, "Quality results should be cascade deleted");

        let violation_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM freshness_violations WHERE dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            violation_count, 0,
            "Freshness violations should be cascade deleted"
        );
    }

    #[test]
    fn test_scheduled_checks_index() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Verify index exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_quality_checks_scheduled'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1, "idx_quality_checks_scheduled index should exist");
    }
}
