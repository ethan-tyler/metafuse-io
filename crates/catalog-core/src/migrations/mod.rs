//! Schema migration framework for MetaFuse catalog.
//!
//! This module provides a versioned, idempotent migration system for evolving
//! the SQLite schema. Migrations are forward-only and tracked in a dedicated
//! `schema_migrations` table.
//!
//! # Design Principles
//!
//! 1. **Idempotent**: All migrations use `IF NOT EXISTS` / `IF EXISTS` clauses
//! 2. **Versioned**: Each migration has a unique version number
//! 3. **Forward-only**: No rollback support for simplicity
//! 4. **Atomic**: Each migration runs in a transaction
//! 5. **Traceable**: Migration history is recorded with timestamps
//! 6. **Exclusive**: Advisory lock prevents concurrent migrations
//!
//! # Usage
//!
//! ```rust,ignore
//! use metafuse_catalog_core::migrations::run_migrations;
//!
//! let conn = rusqlite::Connection::open("catalog.db")?;
//! run_migrations(&conn)?;
//! ```
//!
//! # Deployment Best Practices
//!
//! - **Single Actor**: Migrations should be run by a single actor (e.g., CLI or
//!   init script), not by every API instance on startup. Use `init_catalog(conn, false)`
//!   in API servers and run `metafuse migrate run` separately during deployment.
//!
//! - **Multi-Instance Deployments**: The advisory lock prevents concurrent migrations,
//!   but for safety, run migrations as a separate deployment step before scaling up.
//!   Stale locks (>5 minutes) are auto-released to prevent deadlocks on crash/abort.
//!
//! - **SQLite-Specific**: The column addition helpers use `PRAGMA table_info` which
//!   is SQLite-specific. Future database backends would need their own implementations.

use crate::{CatalogError, Result};
use rusqlite::Connection;

mod v1_0_0;
mod v1_1_0;
mod v1_2_0;
mod v1_3_0;

/// Migration version number.
pub type MigrationVersion = i64;

/// A schema migration.
pub struct Migration {
    /// Version number (must be unique and monotonically increasing)
    pub version: MigrationVersion,
    /// Human-readable description
    pub description: &'static str,
    /// SQL to execute (should be idempotent)
    pub sql: &'static str,
    /// Columns to add after SQL execution (table, column, type)
    /// SQLite doesn't support IF NOT EXISTS for ADD COLUMN, so we handle separately
    pub add_columns: &'static [(&'static str, &'static str, &'static str)],
}

/// All available migrations in order.
/// Add new migrations to the end of this array.
pub fn all_migrations() -> Vec<Migration> {
    vec![
        v1_0_0::migration(),
        v1_1_0::migration(),
        v1_2_0::migration(),
        v1_3_0::migration(),
    ]
}

/// Initialize the migrations tracking table with advisory lock support.
fn init_migrations_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        -- Advisory lock table to prevent concurrent migrations
        CREATE TABLE IF NOT EXISTS migration_lock (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            locked_at TEXT,
            locked_by TEXT
        );

        INSERT OR IGNORE INTO migration_lock (id, locked_at, locked_by) VALUES (1, NULL, NULL);
        "#,
    )?;
    Ok(())
}

/// Check if a column exists in a table.
fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .any(|r| r.map(|name| name == column).unwrap_or(false));
    Ok(exists)
}

/// Safely add a column to a table (idempotent - skips if already exists).
fn add_column_if_not_exists(
    conn: &Connection,
    table: &str,
    column: &str,
    column_type: &str,
) -> Result<bool> {
    if column_exists(conn, table, column)? {
        tracing::debug!(table, column, "Column already exists, skipping");
        return Ok(false);
    }

    let sql = format!(
        "ALTER TABLE {} ADD COLUMN {} {}",
        table, column, column_type
    );
    conn.execute(&sql, [])?;
    tracing::info!(table, column, column_type, "Added column");
    Ok(true)
}

/// Acquire the migration advisory lock.
/// Returns true if lock was acquired, false if another process holds it.
fn acquire_migration_lock(conn: &Connection) -> Result<bool> {
    // Try to acquire lock (only if not already locked)
    let rows = conn.execute(
        "UPDATE migration_lock SET locked_at = datetime('now'), locked_by = 'migration'
         WHERE id = 1 AND (locked_at IS NULL OR locked_at < datetime('now', '-5 minutes'))",
        [],
    )?;
    Ok(rows > 0)
}

/// Release the migration advisory lock.
fn release_migration_lock(conn: &Connection) -> Result<()> {
    conn.execute(
        "UPDATE migration_lock SET locked_at = NULL, locked_by = NULL WHERE id = 1",
        [],
    )?;
    Ok(())
}

/// Get the current schema version (highest applied migration).
pub fn get_schema_version(conn: &Connection) -> Result<MigrationVersion> {
    init_migrations_table(conn)?;

    let version: Option<i64> = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .ok()
        .flatten();

    Ok(version.unwrap_or(0))
}

/// Check if a specific migration has been applied.
pub fn is_migration_applied(conn: &Connection, version: MigrationVersion) -> Result<bool> {
    init_migrations_table(conn)?;

    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
        [version],
        |row| row.get(0),
    )?;

    Ok(count > 0)
}

/// Run all pending migrations.
///
/// This function is idempotent - it will only apply migrations that haven't
/// been applied yet. Each migration runs in its own transaction.
///
/// # Concurrency
///
/// Uses an advisory lock to prevent concurrent migrations. If another process
/// holds the lock (and it's not stale), this function will return an error.
/// Stale locks (older than 5 minutes) are automatically released.
///
/// # Returns
///
/// The number of migrations applied.
pub fn run_migrations(conn: &Connection) -> Result<usize> {
    init_migrations_table(conn)?;

    // Acquire advisory lock
    if !acquire_migration_lock(conn)? {
        return Err(CatalogError::Other(
            "Another migration is in progress. Wait and retry.".to_string(),
        ));
    }

    // Ensure we release the lock even on error
    let result = run_migrations_inner(conn);

    // Always release the lock
    if let Err(e) = release_migration_lock(conn) {
        tracing::warn!("Failed to release migration lock: {}", e);
    }

    result
}

/// Internal migration runner (called while holding lock).
fn run_migrations_inner(conn: &Connection) -> Result<usize> {
    let migrations = all_migrations();
    let mut applied_count = 0;

    for migration in migrations {
        if is_migration_applied(conn, migration.version)? {
            tracing::debug!(
                version = migration.version,
                description = migration.description,
                "Migration already applied, skipping"
            );
            continue;
        }

        tracing::info!(
            version = migration.version,
            description = migration.description,
            "Applying migration"
        );

        // Run migration in a transaction
        let tx = conn.unchecked_transaction()?;

        tx.execute_batch(migration.sql).map_err(|e| {
            CatalogError::Other(format!("Migration {} failed: {}", migration.version, e))
        })?;

        // Record the migration
        tx.execute(
            "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?1, ?2, datetime('now'))",
            rusqlite::params![migration.version, migration.description],
        )?;

        tx.commit()?;

        // Apply column additions outside transaction (ALTER TABLE commits implicitly)
        for (table, column, col_type) in migration.add_columns {
            add_column_if_not_exists(conn, table, column, col_type)?;
        }

        tracing::info!(
            version = migration.version,
            "Migration applied successfully"
        );
        applied_count += 1;
    }

    Ok(applied_count)
}

/// Get list of applied migrations with their timestamps.
pub fn get_migration_history(conn: &Connection) -> Result<Vec<(MigrationVersion, String, String)>> {
    init_migrations_table(conn)?;

    let mut stmt = conn.prepare(
        "SELECT version, description, applied_at FROM schema_migrations ORDER BY version",
    )?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(rows)
}

/// Check if the schema needs migration.
pub fn needs_migration(conn: &Connection) -> Result<bool> {
    let current = get_schema_version(conn)?;
    let migrations = all_migrations();
    let latest = migrations.last().map(|m| m.version).unwrap_or(0);
    Ok(current < latest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_migrations_table() {
        let conn = Connection::open_in_memory().unwrap();
        init_migrations_table(&conn).unwrap();

        // Verify table exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_get_schema_version_empty() {
        let conn = Connection::open_in_memory().unwrap();
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, 0);
    }

    #[test]
    fn test_run_migrations() {
        let conn = Connection::open_in_memory().unwrap();

        // Initialize base schema first (migrations extend the base schema)
        crate::init_sqlite_schema(&conn).unwrap();

        // First run should apply migrations
        let count = run_migrations(&conn).unwrap();
        assert!(count > 0);

        // Second run should be idempotent
        let count2 = run_migrations(&conn).unwrap();
        assert_eq!(count2, 0);

        // Verify schema version is set
        let version = get_schema_version(&conn).unwrap();
        assert!(version > 0);
    }

    #[test]
    fn test_migration_history() {
        let conn = Connection::open_in_memory().unwrap();

        // Initialize base schema first
        crate::init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();

        let history = get_migration_history(&conn).unwrap();
        assert!(!history.is_empty());

        // Verify first migration is v1.0.0 (version 1_000_000)
        let (version, description, _) = &history[0];
        assert_eq!(*version, 1_000_000);
        assert!(description.contains("v1.0.0"));
    }

    #[test]
    fn test_needs_migration() {
        let conn = Connection::open_in_memory().unwrap();

        // Initialize base schema first
        crate::init_sqlite_schema(&conn).unwrap();

        // Fresh database needs migration
        assert!(needs_migration(&conn).unwrap());

        // After migration, no more needed
        run_migrations(&conn).unwrap();
        assert!(!needs_migration(&conn).unwrap());
    }

    #[test]
    fn test_column_exists() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();

        // Column 'name' should exist in datasets
        assert!(column_exists(&conn, "datasets", "name").unwrap());

        // Column 'nonexistent' should not exist
        assert!(!column_exists(&conn, "datasets", "nonexistent").unwrap());
    }

    #[test]
    fn test_add_column_if_not_exists() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();

        // Adding new column should succeed
        let added = add_column_if_not_exists(&conn, "datasets", "test_col", "TEXT").unwrap();
        assert!(added);

        // Adding same column again should be idempotent (return false)
        let added2 = add_column_if_not_exists(&conn, "datasets", "test_col", "TEXT").unwrap();
        assert!(!added2);

        // Verify column exists
        assert!(column_exists(&conn, "datasets", "test_col").unwrap());
    }

    #[test]
    fn test_delta_location_column_added() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_sqlite_schema(&conn).unwrap();

        // Before migration, delta_location should not exist
        assert!(!column_exists(&conn, "datasets", "delta_location").unwrap());

        // Run migrations
        run_migrations(&conn).unwrap();

        // After migration, delta_location should exist
        assert!(column_exists(&conn, "datasets", "delta_location").unwrap());
    }

    #[test]
    fn test_advisory_lock() {
        let conn = Connection::open_in_memory().unwrap();
        init_migrations_table(&conn).unwrap();

        // First lock acquisition should succeed
        assert!(acquire_migration_lock(&conn).unwrap());

        // Second lock acquisition should fail (lock is held)
        assert!(!acquire_migration_lock(&conn).unwrap());

        // Release lock
        release_migration_lock(&conn).unwrap();

        // Now should be able to acquire again
        assert!(acquire_migration_lock(&conn).unwrap());
    }
}
