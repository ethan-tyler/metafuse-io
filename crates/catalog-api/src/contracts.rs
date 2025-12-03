//! Data Contracts Module (v0.9.0)
//!
//! This module provides data contract management for MetaFuse datasets, including:
//! - Schema contracts (required columns, data types)
//! - Quality contracts (minimum completeness, freshness scores)
//! - Freshness contracts (maximum staleness thresholds)
//!
//! # Architecture
//!
//! Contracts are stored in the `data_contracts` table and evaluated:
//! - On dataset registration/update
//! - During periodic validation runs
//! - On demand via API
//!
//! Contract violations trigger alerts through the alerting module.
//!
//! # Fail-Open Behavior
//!
//! Contract evaluation requires datasets to have `delta_location` configured.
//! For non-Delta datasets (CSV, Parquet, external tables), contract evaluation
//! is skipped entirely ("fail open") rather than blocking operations. This:
//! - Maintains backwards compatibility with existing non-Delta datasets
//! - Allows gradual adoption of contracts without breaking existing workflows
//! - Enables operators to enforce Delta-only ingestion at the org level if needed
//!
//! Similarly, freshness contracts fail open when staleness metrics are unavailable.

use serde::{Deserialize, Serialize};

// =============================================================================
// Input Validation
// =============================================================================

/// Validation errors for contract input
#[derive(Debug, Clone)]
pub struct ContractValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ContractValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ContractValidationError {}

/// Validate a contract before creation/update
///
/// Returns a list of validation errors (empty if valid).
pub fn validate_contract(contract: &DataContract) -> Vec<ContractValidationError> {
    let mut errors = Vec::new();

    // Validate contract name
    if contract.name.is_empty() {
        errors.push(ContractValidationError {
            field: "name".to_string(),
            message: "Contract name cannot be empty".to_string(),
        });
    } else if contract.name.len() > 128 {
        errors.push(ContractValidationError {
            field: "name".to_string(),
            message: "Contract name cannot exceed 128 characters".to_string(),
        });
    } else if !is_valid_identifier(&contract.name) {
        errors.push(ContractValidationError {
            field: "name".to_string(),
            message: "Contract name must be alphanumeric with underscores (a-z, A-Z, 0-9, _)"
                .to_string(),
        });
    }

    // Validate dataset pattern
    if contract.dataset_pattern.is_empty() {
        errors.push(ContractValidationError {
            field: "dataset_pattern".to_string(),
            message: "Dataset pattern cannot be empty".to_string(),
        });
    } else if contract.dataset_pattern.len() > 256 {
        errors.push(ContractValidationError {
            field: "dataset_pattern".to_string(),
            message: "Dataset pattern cannot exceed 256 characters".to_string(),
        });
    }

    // Validate version
    if contract.version < 1 {
        errors.push(ContractValidationError {
            field: "version".to_string(),
            message: "Version must be >= 1".to_string(),
        });
    }

    // Validate alert channels (webhook URLs)
    for (i, channel) in contract.alert_channels.iter().enumerate() {
        if let Some(err) = validate_webhook_url(channel) {
            errors.push(ContractValidationError {
                field: format!("alert_channels[{}]", i),
                message: err,
            });
        }
    }

    // Validate quality contract
    if let Some(ref qc) = contract.quality_contract {
        if let Some(mc) = qc.min_completeness {
            if !(0.0..=1.0).contains(&mc) {
                errors.push(ContractValidationError {
                    field: "quality_contract.min_completeness".to_string(),
                    message: "min_completeness must be between 0.0 and 1.0".to_string(),
                });
            }
        }
        if let Some(mf) = qc.min_freshness {
            if !(0.0..=1.0).contains(&mf) {
                errors.push(ContractValidationError {
                    field: "quality_contract.min_freshness".to_string(),
                    message: "min_freshness must be between 0.0 and 1.0".to_string(),
                });
            }
        }
        if let Some(mo) = qc.min_overall {
            if !(0.0..=1.0).contains(&mo) {
                errors.push(ContractValidationError {
                    field: "quality_contract.min_overall".to_string(),
                    message: "min_overall must be between 0.0 and 1.0".to_string(),
                });
            }
        }
    }

    // Validate freshness contract
    if let Some(ref fc) = contract.freshness_contract {
        if fc.max_staleness_secs <= 0 {
            errors.push(ContractValidationError {
                field: "freshness_contract.max_staleness_secs".to_string(),
                message: "max_staleness_secs must be positive".to_string(),
            });
        }
        if let Some(interval) = fc.expected_interval_secs {
            if interval <= 0 {
                errors.push(ContractValidationError {
                    field: "freshness_contract.expected_interval_secs".to_string(),
                    message: "expected_interval_secs must be positive".to_string(),
                });
            }
        }
    }

    // Validate schema contract
    if let Some(ref sc) = contract.schema_contract {
        for (i, col) in sc.required_columns.iter().enumerate() {
            if col.name.is_empty() {
                errors.push(ContractValidationError {
                    field: format!("schema_contract.required_columns[{}].name", i),
                    message: "Column name cannot be empty".to_string(),
                });
            }
            if col.data_type.is_empty() {
                errors.push(ContractValidationError {
                    field: format!("schema_contract.required_columns[{}].data_type", i),
                    message: "Column data_type cannot be empty".to_string(),
                });
            }
        }
    }

    errors
}

/// Check if a string is a valid identifier (alphanumeric + underscore)
fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Validate a webhook URL
///
/// Returns None if valid, Some(error_message) if invalid.
pub fn validate_webhook_url(url: &str) -> Option<String> {
    // Strip optional webhook: prefix
    let url = url.strip_prefix("webhook:").unwrap_or(url);

    if url.is_empty() {
        return Some("URL cannot be empty".to_string());
    }

    // Must start with http:// or https://
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Some("URL must start with http:// or https://".to_string());
    }

    // Check for valid URL structure
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or("");

    if after_scheme.is_empty() {
        return Some("URL must have a host".to_string());
    }

    // Check for suspicious characters that might indicate injection
    if url.contains('\n') || url.contains('\r') || url.contains('\0') {
        return Some("URL contains invalid characters".to_string());
    }

    // Length limit
    if url.len() > 2048 {
        return Some("URL cannot exceed 2048 characters".to_string());
    }

    None
}

/// Schema contract definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaContract {
    /// Required columns with types
    #[serde(default)]
    pub required_columns: Vec<RequiredColumn>,
    /// Whether additional columns are allowed
    #[serde(default = "default_true")]
    pub allow_additional_columns: bool,
}

fn default_true() -> bool {
    true
}

/// Required column definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredColumn {
    /// Column name
    pub name: String,
    /// Expected data type (e.g., "Int64", "Utf8", "Float64")
    pub data_type: String,
    /// Whether the column can be nullable
    #[serde(default = "default_true")]
    pub nullable: bool,
}

/// Quality contract definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityContract {
    /// Minimum completeness score (0.0 - 1.0)
    #[serde(default)]
    pub min_completeness: Option<f64>,
    /// Minimum freshness score (0.0 - 1.0)
    #[serde(default)]
    pub min_freshness: Option<f64>,
    /// Minimum overall quality score (0.0 - 1.0)
    #[serde(default)]
    pub min_overall: Option<f64>,
}

/// Freshness contract definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshnessContract {
    /// Maximum staleness in seconds
    pub max_staleness_secs: i64,
    /// Expected update interval in seconds
    #[serde(default)]
    pub expected_interval_secs: Option<i64>,
}

/// Enforcement action on contract violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnViolation {
    /// Send alert but allow operation
    #[default]
    Alert,
    /// Log warning but allow operation
    Warn,
    /// Block the operation
    Block,
}

impl OnViolation {
    pub fn as_str(&self) -> &'static str {
        match self {
            OnViolation::Alert => "alert",
            OnViolation::Warn => "warn",
            OnViolation::Block => "block",
        }
    }
}

/// Full data contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataContract {
    /// Contract ID (from database)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Unique contract name
    pub name: String,
    /// Dataset name pattern (* wildcard supported)
    pub dataset_pattern: String,
    /// Contract version
    #[serde(default = "default_version")]
    pub version: i32,
    /// Schema contract (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_contract: Option<SchemaContract>,
    /// Quality contract (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality_contract: Option<QualityContract>,
    /// Freshness contract (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness_contract: Option<FreshnessContract>,
    /// What to do on violation
    #[serde(default)]
    pub on_violation: OnViolation,
    /// Alert channels (webhook URLs)
    #[serde(default)]
    pub alert_channels: Vec<String>,
    /// Whether contract is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_version() -> i32 {
    1
}

/// Contract validation result
#[derive(Debug, Clone, Serialize)]
pub struct ValidationResult {
    /// Contract name that was validated
    pub contract_name: String,
    /// Dataset that was validated
    pub dataset_name: String,
    /// Whether validation passed
    pub passed: bool,
    /// List of violations (empty if passed)
    pub violations: Vec<String>,
    /// Timestamp of validation
    pub validated_at: String,
}

impl ValidationResult {
    /// Create a passing result
    pub fn pass(contract_name: &str, dataset_name: &str) -> Self {
        Self {
            contract_name: contract_name.to_string(),
            dataset_name: dataset_name.to_string(),
            passed: true,
            violations: vec![],
            validated_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create a failing result
    pub fn fail(contract_name: &str, dataset_name: &str, violations: Vec<String>) -> Self {
        Self {
            contract_name: contract_name.to_string(),
            dataset_name: dataset_name.to_string(),
            passed: false,
            violations,
            validated_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// =============================================================================
// Contract Evaluation Engine
// =============================================================================

/// Context for evaluating contracts against a dataset
#[derive(Debug, Clone)]
pub struct DatasetContext {
    /// Dataset ID
    pub id: i64,
    /// Dataset name
    pub name: String,
    /// Tenant ID (for multi-tenant isolation)
    pub tenant_id: Option<String>,
}

/// Field information from the catalog
#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
}

/// Quality metrics for contract evaluation
#[derive(Debug, Clone, Default)]
pub struct QualityMetrics {
    pub completeness_score: Option<f64>,
    pub freshness_score: Option<f64>,
    pub overall_score: Option<f64>,
    pub staleness_secs: Option<i64>,
}

/// Result of contract enforcement
#[derive(Debug, Clone)]
pub enum EnforcementAction {
    /// Allow the operation
    Allow,
    /// Warn but allow
    Warn(Vec<String>),
    /// Block with violations
    Block(Vec<String>),
    /// Alert and allow
    Alert(Vec<String>),
}

impl EnforcementAction {
    /// Check if the action should block the operation
    pub fn should_block(&self) -> bool {
        matches!(self, EnforcementAction::Block(_))
    }

    /// Get violations if any
    pub fn violations(&self) -> Option<&[String]> {
        match self {
            EnforcementAction::Allow => None,
            EnforcementAction::Warn(v)
            | EnforcementAction::Block(v)
            | EnforcementAction::Alert(v) => Some(v),
        }
    }
}

/// Contract evaluator for validating datasets against contracts
pub struct ContractEvaluator<'a> {
    conn: &'a rusqlite::Connection,
}

impl<'a> ContractEvaluator<'a> {
    /// Create a new contract evaluator
    pub fn new(conn: &'a rusqlite::Connection) -> Self {
        Self { conn }
    }

    /// Evaluate all matching contracts for a dataset
    ///
    /// Returns a list of validation results for each matching contract.
    pub fn evaluate_for_dataset(
        &self,
        ctx: &DatasetContext,
    ) -> Result<Vec<ValidationResult>, rusqlite::Error> {
        let contracts = find_matching_contracts(self.conn, &ctx.name)?;
        let mut results = Vec::new();

        for contract in contracts {
            let result = self.evaluate_contract(&contract, ctx)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Evaluate a single contract against a dataset
    pub fn evaluate_contract(
        &self,
        contract: &DataContract,
        ctx: &DatasetContext,
    ) -> Result<ValidationResult, rusqlite::Error> {
        let mut all_violations = Vec::new();

        // Evaluate schema contract if present
        if let Some(ref schema_contract) = contract.schema_contract {
            let fields = self.get_dataset_fields(ctx.id)?;
            let violations = evaluate_schema_contract(schema_contract, &fields);
            all_violations.extend(violations);
        }

        // Evaluate quality contract if present
        if let Some(ref quality_contract) = contract.quality_contract {
            let metrics = self.get_quality_metrics(ctx.id)?;
            let violations = evaluate_quality_contract(quality_contract, &metrics);
            all_violations.extend(violations);
        }

        // Evaluate freshness contract if present
        if let Some(ref freshness_contract) = contract.freshness_contract {
            let metrics = self.get_quality_metrics(ctx.id)?;
            let violations = evaluate_freshness_contract(freshness_contract, &metrics);
            all_violations.extend(violations);
        }

        if all_violations.is_empty() {
            Ok(ValidationResult::pass(&contract.name, &ctx.name))
        } else {
            Ok(ValidationResult::fail(
                &contract.name,
                &ctx.name,
                all_violations,
            ))
        }
    }

    /// Determine enforcement action based on contract and violations
    pub fn determine_enforcement(
        &self,
        contract: &DataContract,
        violations: &[String],
    ) -> EnforcementAction {
        if violations.is_empty() {
            return EnforcementAction::Allow;
        }

        match contract.on_violation {
            OnViolation::Alert => EnforcementAction::Alert(violations.to_vec()),
            OnViolation::Warn => EnforcementAction::Warn(violations.to_vec()),
            OnViolation::Block => EnforcementAction::Block(violations.to_vec()),
        }
    }

    /// Get fields for a dataset from the catalog
    fn get_dataset_fields(&self, dataset_id: i64) -> Result<Vec<FieldInfo>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT name, data_type, nullable FROM fields WHERE dataset_id = ?1 ORDER BY name",
        )?;

        let fields = stmt
            .query_map([dataset_id], |row| {
                Ok(FieldInfo {
                    name: row.get(0)?,
                    data_type: row.get(1)?,
                    nullable: row.get::<_, i32>(2)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(fields)
    }

    /// Get quality metrics for a dataset
    fn get_quality_metrics(&self, dataset_id: i64) -> Result<QualityMetrics, rusqlite::Error> {
        let result = self.conn.query_row(
            r#"
            SELECT completeness_score, freshness_score, overall_score
            FROM quality_metrics
            WHERE dataset_id = ?1
            ORDER BY computed_at DESC
            LIMIT 1
            "#,
            [dataset_id],
            |row| {
                Ok(QualityMetrics {
                    completeness_score: row.get(0)?,
                    freshness_score: row.get(1)?,
                    overall_score: row.get(2)?,
                    staleness_secs: None, // Will be computed from last_updated if needed
                })
            },
        );

        match result {
            Ok(mut metrics) => {
                // Try to get staleness from dataset's last_updated
                if let Ok(staleness) = self.get_staleness_secs(dataset_id) {
                    metrics.staleness_secs = Some(staleness);
                }
                Ok(metrics)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(QualityMetrics::default()),
            Err(e) => Err(e),
        }
    }

    /// Calculate staleness in seconds from dataset's last_updated
    fn get_staleness_secs(&self, dataset_id: i64) -> Result<i64, rusqlite::Error> {
        let last_updated: String = self.conn.query_row(
            "SELECT last_updated FROM datasets WHERE id = ?1",
            [dataset_id],
            |row| row.get(0),
        )?;

        // Parse timestamp and calculate staleness
        if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&last_updated) {
            let now = chrono::Utc::now();
            let staleness = (now - ts.with_timezone(&chrono::Utc)).num_seconds();
            Ok(staleness.max(0))
        } else {
            // Try simpler formats
            if let Ok(ts) =
                chrono::NaiveDateTime::parse_from_str(&last_updated, "%Y-%m-%d %H:%M:%S")
            {
                let now = chrono::Utc::now().naive_utc();
                let staleness = (now - ts).num_seconds();
                Ok(staleness.max(0))
            } else {
                Ok(0)
            }
        }
    }
}

/// Evaluate schema contract against dataset fields
///
/// Returns a list of violations (empty if contract is satisfied).
pub fn evaluate_schema_contract(contract: &SchemaContract, fields: &[FieldInfo]) -> Vec<String> {
    let mut violations = Vec::new();

    // Build a map of existing fields for quick lookup
    let field_map: std::collections::HashMap<&str, &FieldInfo> =
        fields.iter().map(|f| (f.name.as_str(), f)).collect();

    // Check required columns
    for required in &contract.required_columns {
        match field_map.get(required.name.as_str()) {
            None => {
                violations.push(format!(
                    "Missing required column: '{}' (expected type: {})",
                    required.name, required.data_type
                ));
            }
            Some(field) => {
                // Check type compatibility (case-insensitive)
                if !types_compatible(&field.data_type, &required.data_type) {
                    violations.push(format!(
                        "Column '{}' has type '{}' but contract requires '{}'",
                        required.name, field.data_type, required.data_type
                    ));
                }

                // Check nullable constraint (if required column is non-nullable)
                if !required.nullable && field.nullable {
                    violations.push(format!(
                        "Column '{}' is nullable but contract requires non-nullable",
                        required.name
                    ));
                }
            }
        }
    }

    // Check for additional columns if not allowed
    if !contract.allow_additional_columns {
        let required_names: std::collections::HashSet<&str> = contract
            .required_columns
            .iter()
            .map(|c| c.name.as_str())
            .collect();

        for field in fields {
            if !required_names.contains(field.name.as_str()) {
                violations.push(format!(
                    "Unexpected column '{}' not allowed by contract",
                    field.name
                ));
            }
        }
    }

    violations
}

/// Check if two data types are compatible
///
/// Supports common type aliases and variations.
fn types_compatible(actual: &str, required: &str) -> bool {
    let actual_lower = actual.to_lowercase();
    let required_lower = required.to_lowercase();

    if actual_lower == required_lower {
        return true;
    }

    // Normalize types to canonical forms
    fn normalize(t: &str) -> &'static str {
        match t {
            // Integer types
            "int64" | "bigint" | "long" | "integer" => "int64",
            "int32" | "int" => "int32",
            // String types
            "utf8" | "string" | "text" | "varchar" => "utf8",
            // Float types
            "float64" | "double" | "float" => "float64",
            "float32" => "float32",
            // Boolean
            "bool" | "boolean" => "bool",
            // Timestamp
            "timestamp" | "datetime" | "timestamp[us]" | "timestamp[ns]" => "timestamp",
            // Date
            "date" | "date32" => "date",
            // Keep as-is - return empty to signal no normalization
            _ => "",
        }
    }

    let actual_norm = normalize(&actual_lower);
    let required_norm = normalize(&required_lower);

    // If both normalize to the same non-empty string, they're compatible
    if !actual_norm.is_empty() && !required_norm.is_empty() {
        actual_norm == required_norm
    } else {
        // No normalization possible, check exact match (already done above)
        false
    }
}

/// Evaluate quality contract against metrics
///
/// Returns a list of violations (empty if contract is satisfied).
pub fn evaluate_quality_contract(
    contract: &QualityContract,
    metrics: &QualityMetrics,
) -> Vec<String> {
    let mut violations = Vec::new();

    // Check min_completeness
    if let Some(min_completeness) = contract.min_completeness {
        match metrics.completeness_score {
            Some(score) if score < min_completeness => {
                violations.push(format!(
                    "Completeness score {:.1}% is below required {:.1}%",
                    score * 100.0,
                    min_completeness * 100.0
                ));
            }
            None => {
                violations.push(
                    "Completeness score not available but contract requires min_completeness"
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    // Check min_freshness
    if let Some(min_freshness) = contract.min_freshness {
        match metrics.freshness_score {
            Some(score) if score < min_freshness => {
                violations.push(format!(
                    "Freshness score {:.1}% is below required {:.1}%",
                    score * 100.0,
                    min_freshness * 100.0
                ));
            }
            None => {
                violations.push(
                    "Freshness score not available but contract requires min_freshness".to_string(),
                );
            }
            _ => {}
        }
    }

    // Check min_overall
    if let Some(min_overall) = contract.min_overall {
        match metrics.overall_score {
            Some(score) if score < min_overall => {
                violations.push(format!(
                    "Overall quality score {:.1}% is below required {:.1}%",
                    score * 100.0,
                    min_overall * 100.0
                ));
            }
            None => {
                violations.push(
                    "Overall quality score not available but contract requires min_overall"
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    violations
}

/// Evaluate freshness contract against metrics
///
/// Returns a list of violations (empty if contract is satisfied).
pub fn evaluate_freshness_contract(
    contract: &FreshnessContract,
    metrics: &QualityMetrics,
) -> Vec<String> {
    let mut violations = Vec::new();

    // Check max staleness
    match metrics.staleness_secs {
        Some(staleness) if staleness > contract.max_staleness_secs => {
            let hours = staleness / 3600;
            let max_hours = contract.max_staleness_secs / 3600;
            violations.push(format!(
                "Dataset staleness ({} hours) exceeds max allowed ({} hours)",
                hours, max_hours
            ));
        }
        None => {
            // Can't evaluate - fail open (no violation)
            tracing::debug!(
                "Staleness not available for freshness contract evaluation, failing open"
            );
        }
        _ => {}
    }

    // Check expected interval if specified
    if let Some(expected_interval) = contract.expected_interval_secs {
        if let Some(staleness) = metrics.staleness_secs {
            // Warn if staleness is more than 2x expected interval
            if staleness > expected_interval * 2 {
                let periods_late = staleness / expected_interval;
                violations.push(format!(
                    "Dataset is {} update periods behind expected interval",
                    periods_late
                ));
            }
        }
    }

    violations
}

// =============================================================================
// Database Operations
// =============================================================================

/// Create a new contract
pub fn create_contract(
    conn: &rusqlite::Connection,
    contract: &DataContract,
) -> Result<i64, rusqlite::Error> {
    let schema_json = contract
        .schema_contract
        .as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());
    let quality_json = contract
        .quality_contract
        .as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());
    let freshness_json = contract
        .freshness_contract
        .as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());
    let channels_json = serde_json::to_string(&contract.alert_channels).unwrap_or_default();

    conn.execute(
        r#"
        INSERT INTO data_contracts
            (name, dataset_pattern, version, schema_contract, quality_contract, freshness_contract,
             on_violation, alert_channels, enabled, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'), datetime('now'))
        "#,
        rusqlite::params![
            contract.name,
            contract.dataset_pattern,
            contract.version,
            schema_json,
            quality_json,
            freshness_json,
            contract.on_violation.as_str(),
            channels_json,
            contract.enabled as i32,
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Get contract by name
pub fn get_contract(
    conn: &rusqlite::Connection,
    name: &str,
) -> Result<Option<DataContract>, rusqlite::Error> {
    let result = conn.query_row(
        r#"
        SELECT id, name, dataset_pattern, version, schema_contract, quality_contract,
               freshness_contract, on_violation, alert_channels, enabled
        FROM data_contracts
        WHERE name = ?1
        "#,
        [name],
        |row| {
            let schema_json: Option<String> = row.get(4)?;
            let quality_json: Option<String> = row.get(5)?;
            let freshness_json: Option<String> = row.get(6)?;
            let on_violation_str: String = row.get(7)?;
            let channels_json: Option<String> = row.get(8)?;

            Ok(DataContract {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                dataset_pattern: row.get(2)?,
                version: row.get(3)?,
                schema_contract: schema_json.and_then(|s| serde_json::from_str(&s).ok()),
                quality_contract: quality_json.and_then(|s| serde_json::from_str(&s).ok()),
                freshness_contract: freshness_json.and_then(|s| serde_json::from_str(&s).ok()),
                on_violation: match on_violation_str.as_str() {
                    "warn" => OnViolation::Warn,
                    "block" => OnViolation::Block,
                    _ => OnViolation::Alert,
                },
                alert_channels: channels_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
                enabled: row.get::<_, i32>(9)? != 0,
            })
        },
    );

    match result {
        Ok(contract) => Ok(Some(contract)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// List all contracts
pub fn list_contracts(conn: &rusqlite::Connection) -> Result<Vec<DataContract>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, name, dataset_pattern, version, schema_contract, quality_contract,
               freshness_contract, on_violation, alert_channels, enabled
        FROM data_contracts
        ORDER BY name
        "#,
    )?;

    let contracts = stmt
        .query_map([], |row| {
            let schema_json: Option<String> = row.get(4)?;
            let quality_json: Option<String> = row.get(5)?;
            let freshness_json: Option<String> = row.get(6)?;
            let on_violation_str: String = row.get(7)?;
            let channels_json: Option<String> = row.get(8)?;

            Ok(DataContract {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                dataset_pattern: row.get(2)?,
                version: row.get(3)?,
                schema_contract: schema_json.and_then(|s| serde_json::from_str(&s).ok()),
                quality_contract: quality_json.and_then(|s| serde_json::from_str(&s).ok()),
                freshness_contract: freshness_json.and_then(|s| serde_json::from_str(&s).ok()),
                on_violation: match on_violation_str.as_str() {
                    "warn" => OnViolation::Warn,
                    "block" => OnViolation::Block,
                    _ => OnViolation::Alert,
                },
                alert_channels: channels_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
                enabled: row.get::<_, i32>(9)? != 0,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(contracts)
}

/// Find contracts matching a dataset name
pub fn find_matching_contracts(
    conn: &rusqlite::Connection,
    dataset_name: &str,
) -> Result<Vec<DataContract>, rusqlite::Error> {
    // Get all enabled contracts and filter by pattern
    let all_contracts = list_contracts(conn)?;

    let matching: Vec<DataContract> = all_contracts
        .into_iter()
        .filter(|c| c.enabled && matches_pattern(&c.dataset_pattern, dataset_name))
        .collect();

    Ok(matching)
}

/// Check if a dataset name matches a pattern (supports * wildcard)
fn matches_pattern(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.contains('*') {
        // Convert glob to simple prefix/suffix match
        if let Some(middle) = pattern.strip_prefix('*').and_then(|p| p.strip_suffix('*')) {
            name.contains(middle)
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            name.ends_with(suffix)
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            name.starts_with(prefix)
        } else {
            // Pattern like "foo*bar" - simple contains check for parts
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                name.starts_with(parts[0]) && name.ends_with(parts[1])
            } else {
                pattern == name
            }
        }
    } else {
        pattern == name
    }
}

/// Update an existing contract
///
/// Updates all fields except ID and name. The name is used as the lookup key.
/// Returns true if a contract was updated, false if not found.
pub fn update_contract(
    conn: &rusqlite::Connection,
    name: &str,
    contract: &DataContract,
) -> Result<bool, rusqlite::Error> {
    let schema_json = contract
        .schema_contract
        .as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());
    let quality_json = contract
        .quality_contract
        .as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());
    let freshness_json = contract
        .freshness_contract
        .as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());
    let channels_json = serde_json::to_string(&contract.alert_channels).unwrap_or_default();

    let rows = conn.execute(
        r#"
        UPDATE data_contracts
        SET dataset_pattern = ?1,
            version = ?2,
            schema_contract = ?3,
            quality_contract = ?4,
            freshness_contract = ?5,
            on_violation = ?6,
            alert_channels = ?7,
            enabled = ?8,
            updated_at = datetime('now')
        WHERE name = ?9
        "#,
        rusqlite::params![
            contract.dataset_pattern,
            contract.version,
            schema_json,
            quality_json,
            freshness_json,
            contract.on_violation.as_str(),
            channels_json,
            contract.enabled as i32,
            name,
        ],
    )?;

    Ok(rows > 0)
}

/// Delete a contract
pub fn delete_contract(conn: &rusqlite::Connection, name: &str) -> Result<bool, rusqlite::Error> {
    let rows = conn.execute("DELETE FROM data_contracts WHERE name = ?1", [name])?;
    Ok(rows > 0)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // Validation Tests
    // =============================================================================

    #[test]
    fn test_validate_valid_contract() {
        let contract = DataContract {
            id: None,
            name: "valid_contract".to_string(),
            dataset_pattern: "orders*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec!["https://webhook.example.com/hook".to_string()],
            enabled: true,
        };

        let errors = validate_contract(&contract);
        assert!(
            errors.is_empty(),
            "Valid contract should pass: {:?}",
            errors
        );
    }

    #[test]
    fn test_validate_empty_name() {
        let contract = DataContract {
            id: None,
            name: "".to_string(),
            dataset_pattern: "*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let errors = validate_contract(&contract);
        assert!(!errors.is_empty());
        assert!(errors[0].field == "name");
    }

    #[test]
    fn test_validate_invalid_name() {
        let contract = DataContract {
            id: None,
            name: "invalid-name".to_string(), // Hyphen not allowed
            dataset_pattern: "*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let errors = validate_contract(&contract);
        assert!(!errors.is_empty());
        assert!(errors[0].field == "name");
    }

    #[test]
    fn test_validate_empty_pattern() {
        let contract = DataContract {
            id: None,
            name: "test_contract".to_string(),
            dataset_pattern: "".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let errors = validate_contract(&contract);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.field == "dataset_pattern"));
    }

    #[test]
    fn test_validate_invalid_webhook_url() {
        let contract = DataContract {
            id: None,
            name: "test_contract".to_string(),
            dataset_pattern: "*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec!["not-a-url".to_string()],
            enabled: true,
        };

        let errors = validate_contract(&contract);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.field.contains("alert_channels")));
    }

    #[test]
    fn test_validate_quality_out_of_range() {
        let contract = DataContract {
            id: None,
            name: "test_contract".to_string(),
            dataset_pattern: "*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: Some(QualityContract {
                min_completeness: Some(1.5), // Invalid: > 1.0
                min_freshness: None,
                min_overall: None,
            }),
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let errors = validate_contract(&contract);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.field.contains("min_completeness")));
    }

    #[test]
    fn test_validate_negative_staleness() {
        let contract = DataContract {
            id: None,
            name: "test_contract".to_string(),
            dataset_pattern: "*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: Some(FreshnessContract {
                max_staleness_secs: -100,
                expected_interval_secs: None,
            }),
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let errors = validate_contract(&contract);
        assert!(!errors.is_empty());
        assert!(errors
            .iter()
            .any(|e| e.field.contains("max_staleness_secs")));
    }

    #[test]
    fn test_validate_webhook_url_valid() {
        assert!(validate_webhook_url("https://example.com/webhook").is_none());
        assert!(validate_webhook_url("http://localhost:8080/hook").is_none());
        assert!(validate_webhook_url("webhook:https://example.com/hook").is_none());
    }

    #[test]
    fn test_validate_webhook_url_invalid() {
        assert!(validate_webhook_url("").is_some());
        assert!(validate_webhook_url("ftp://example.com").is_some());
        assert!(validate_webhook_url("not-a-url").is_some());
        assert!(validate_webhook_url("http://").is_some());
    }

    #[test]
    fn test_is_valid_identifier() {
        assert!(is_valid_identifier("valid_name"));
        assert!(is_valid_identifier("Contract123"));
        assert!(is_valid_identifier("a"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("123start")); // Can't start with number
        assert!(!is_valid_identifier("has-hyphen"));
        assert!(!is_valid_identifier("has space"));
    }

    // =============================================================================
    // Original Tests
    // =============================================================================

    #[test]
    fn test_on_violation_default() {
        assert_eq!(OnViolation::default(), OnViolation::Alert);
    }

    #[test]
    fn test_on_violation_as_str() {
        assert_eq!(OnViolation::Alert.as_str(), "alert");
        assert_eq!(OnViolation::Warn.as_str(), "warn");
        assert_eq!(OnViolation::Block.as_str(), "block");
    }

    #[test]
    fn test_validation_result_pass() {
        let result = ValidationResult::pass("test_contract", "orders");
        assert!(result.passed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_validation_result_fail() {
        let result = ValidationResult::fail(
            "test_contract",
            "orders",
            vec!["Missing column: order_id".to_string()],
        );
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn test_pattern_matching() {
        // Exact match
        assert!(matches_pattern("orders", "orders"));
        assert!(!matches_pattern("orders", "customers"));

        // Prefix wildcard
        assert!(matches_pattern("orders*", "orders_raw"));
        assert!(matches_pattern("orders*", "orders"));
        assert!(!matches_pattern("orders*", "raw_orders"));

        // Suffix wildcard
        assert!(matches_pattern("*_raw", "orders_raw"));
        assert!(!matches_pattern("*_raw", "orders_clean"));

        // Both wildcards
        assert!(matches_pattern("*orders*", "raw_orders_clean"));
        assert!(matches_pattern("*orders*", "orders"));

        // Match all
        assert!(matches_pattern("*", "anything"));
    }

    #[test]
    fn test_schema_contract_serialization() {
        let contract = SchemaContract {
            required_columns: vec![RequiredColumn {
                name: "order_id".to_string(),
                data_type: "Int64".to_string(),
                nullable: false,
            }],
            allow_additional_columns: true,
        };

        let json = serde_json::to_string(&contract).unwrap();
        assert!(json.contains("order_id"));
        assert!(json.contains("Int64"));

        let parsed: SchemaContract = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.required_columns.len(), 1);
    }

    #[test]
    fn test_quality_contract_serialization() {
        let contract = QualityContract {
            min_completeness: Some(0.95),
            min_freshness: Some(0.90),
            min_overall: None,
        };

        let json = serde_json::to_string(&contract).unwrap();
        let parsed: QualityContract = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.min_completeness, Some(0.95));
    }

    #[test]
    fn test_data_contract_full() {
        let contract = DataContract {
            id: None,
            name: "orders_contract".to_string(),
            dataset_pattern: "orders*".to_string(),
            version: 1,
            schema_contract: Some(SchemaContract {
                required_columns: vec![],
                allow_additional_columns: true,
            }),
            quality_contract: Some(QualityContract {
                min_completeness: Some(0.95),
                min_freshness: None,
                min_overall: None,
            }),
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec!["webhook:https://example.com".to_string()],
            enabled: true,
        };

        let json = serde_json::to_string(&contract).unwrap();
        assert!(json.contains("orders_contract"));
    }

    #[test]
    fn test_create_and_get_contract() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        let contract = DataContract {
            id: None,
            name: "test_contract".to_string(),
            dataset_pattern: "test*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: Some(QualityContract {
                min_completeness: Some(0.90),
                min_freshness: None,
                min_overall: None,
            }),
            freshness_contract: None,
            on_violation: OnViolation::Warn,
            alert_channels: vec![],
            enabled: true,
        };

        let id = create_contract(&conn, &contract).unwrap();
        assert!(id > 0);

        let retrieved = get_contract(&conn, "test_contract").unwrap().unwrap();
        assert_eq!(retrieved.name, "test_contract");
        assert_eq!(retrieved.dataset_pattern, "test*");
        assert_eq!(retrieved.on_violation, OnViolation::Warn);
    }

    #[test]
    fn test_list_contracts() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Create two contracts
        let c1 = DataContract {
            id: None,
            name: "alpha_contract".to_string(),
            dataset_pattern: "alpha*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let c2 = DataContract {
            id: None,
            name: "beta_contract".to_string(),
            dataset_pattern: "beta*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Block,
            alert_channels: vec![],
            enabled: false,
        };

        create_contract(&conn, &c1).unwrap();
        create_contract(&conn, &c2).unwrap();

        let contracts = list_contracts(&conn).unwrap();
        assert_eq!(contracts.len(), 2);
        assert_eq!(contracts[0].name, "alpha_contract"); // Alphabetically first
    }

    #[test]
    fn test_find_matching_contracts() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Contract that matches orders*
        let c1 = DataContract {
            id: None,
            name: "orders_contract".to_string(),
            dataset_pattern: "orders*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        // Contract that matches *_raw
        let c2 = DataContract {
            id: None,
            name: "raw_contract".to_string(),
            dataset_pattern: "*_raw".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        // Disabled contract
        let c3 = DataContract {
            id: None,
            name: "disabled_contract".to_string(),
            dataset_pattern: "*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: false,
        };

        create_contract(&conn, &c1).unwrap();
        create_contract(&conn, &c2).unwrap();
        create_contract(&conn, &c3).unwrap();

        // orders_raw should match both enabled contracts
        let matching = find_matching_contracts(&conn, "orders_raw").unwrap();
        assert_eq!(matching.len(), 2);

        // orders_clean should only match orders*
        let matching = find_matching_contracts(&conn, "orders_clean").unwrap();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].name, "orders_contract");

        // customers should match none (disabled contract doesn't count)
        let matching = find_matching_contracts(&conn, "customers").unwrap();
        assert_eq!(matching.len(), 0);
    }

    #[test]
    fn test_delete_contract() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        let contract = DataContract {
            id: None,
            name: "to_delete".to_string(),
            dataset_pattern: "*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        create_contract(&conn, &contract).unwrap();
        assert!(get_contract(&conn, "to_delete").unwrap().is_some());

        let deleted = delete_contract(&conn, "to_delete").unwrap();
        assert!(deleted);

        assert!(get_contract(&conn, "to_delete").unwrap().is_none());

        // Deleting again should return false
        let deleted = delete_contract(&conn, "to_delete").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_update_contract() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Create initial contract
        let contract = DataContract {
            id: None,
            name: "to_update".to_string(),
            dataset_pattern: "orders*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        create_contract(&conn, &contract).unwrap();

        // Update it
        let updated_contract = DataContract {
            id: None,
            name: "to_update".to_string(),         // Same name
            dataset_pattern: "sales*".to_string(), // Changed
            version: 2,                            // Bumped version
            schema_contract: None,
            quality_contract: Some(QualityContract {
                min_completeness: Some(0.95),
                min_freshness: None,
                min_overall: None,
            }),
            freshness_contract: None,
            on_violation: OnViolation::Block, // Changed
            alert_channels: vec!["https://webhook.example.com".to_string()],
            enabled: true,
        };

        let updated = update_contract(&conn, "to_update", &updated_contract).unwrap();
        assert!(updated);

        // Verify updates
        let retrieved = get_contract(&conn, "to_update").unwrap().unwrap();
        assert_eq!(retrieved.dataset_pattern, "sales*");
        assert_eq!(retrieved.version, 2);
        assert_eq!(retrieved.on_violation, OnViolation::Block);
        assert!(retrieved.quality_contract.is_some());
        assert_eq!(retrieved.alert_channels.len(), 1);

        // Try to update non-existent contract
        let not_found = update_contract(&conn, "nonexistent", &updated_contract).unwrap();
        assert!(!not_found);
    }

    // =============================================================================
    // Contract Evaluation Tests
    // =============================================================================

    #[test]
    fn test_evaluate_schema_contract_pass() {
        let contract = SchemaContract {
            required_columns: vec![
                RequiredColumn {
                    name: "order_id".to_string(),
                    data_type: "Int64".to_string(),
                    nullable: false,
                },
                RequiredColumn {
                    name: "customer_name".to_string(),
                    data_type: "Utf8".to_string(),
                    nullable: true,
                },
            ],
            allow_additional_columns: true,
        };

        let fields = vec![
            FieldInfo {
                name: "order_id".to_string(),
                data_type: "Int64".to_string(),
                nullable: false,
            },
            FieldInfo {
                name: "customer_name".to_string(),
                data_type: "Utf8".to_string(),
                nullable: true,
            },
            FieldInfo {
                name: "extra_field".to_string(),
                data_type: "Float64".to_string(),
                nullable: true,
            },
        ];

        let violations = evaluate_schema_contract(&contract, &fields);
        assert!(
            violations.is_empty(),
            "Expected no violations: {:?}",
            violations
        );
    }

    #[test]
    fn test_evaluate_schema_contract_missing_column() {
        let contract = SchemaContract {
            required_columns: vec![RequiredColumn {
                name: "order_id".to_string(),
                data_type: "Int64".to_string(),
                nullable: false,
            }],
            allow_additional_columns: true,
        };

        let fields = vec![FieldInfo {
            name: "customer_id".to_string(),
            data_type: "Int64".to_string(),
            nullable: false,
        }];

        let violations = evaluate_schema_contract(&contract, &fields);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("Missing required column"));
        assert!(violations[0].contains("order_id"));
    }

    #[test]
    fn test_evaluate_schema_contract_wrong_type() {
        let contract = SchemaContract {
            required_columns: vec![RequiredColumn {
                name: "amount".to_string(),
                data_type: "Float64".to_string(),
                nullable: true,
            }],
            allow_additional_columns: true,
        };

        let fields = vec![FieldInfo {
            name: "amount".to_string(),
            data_type: "Utf8".to_string(), // Wrong type
            nullable: true,
        }];

        let violations = evaluate_schema_contract(&contract, &fields);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("has type"));
        assert!(violations[0].contains("Utf8"));
    }

    #[test]
    fn test_evaluate_schema_contract_nullable_violation() {
        let contract = SchemaContract {
            required_columns: vec![RequiredColumn {
                name: "order_id".to_string(),
                data_type: "Int64".to_string(),
                nullable: false, // Required non-nullable
            }],
            allow_additional_columns: true,
        };

        let fields = vec![FieldInfo {
            name: "order_id".to_string(),
            data_type: "Int64".to_string(),
            nullable: true, // But field is nullable
        }];

        let violations = evaluate_schema_contract(&contract, &fields);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("nullable"));
    }

    #[test]
    fn test_evaluate_schema_contract_no_additional_columns() {
        let contract = SchemaContract {
            required_columns: vec![RequiredColumn {
                name: "order_id".to_string(),
                data_type: "Int64".to_string(),
                nullable: false,
            }],
            allow_additional_columns: false, // No extra columns allowed
        };

        let fields = vec![
            FieldInfo {
                name: "order_id".to_string(),
                data_type: "Int64".to_string(),
                nullable: false,
            },
            FieldInfo {
                name: "extra_field".to_string(),
                data_type: "Utf8".to_string(),
                nullable: true,
            },
        ];

        let violations = evaluate_schema_contract(&contract, &fields);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("Unexpected column"));
        assert!(violations[0].contains("extra_field"));
    }

    #[test]
    fn test_types_compatible() {
        // Exact match
        assert!(types_compatible("Int64", "Int64"));
        assert!(types_compatible("Utf8", "Utf8"));

        // Case insensitive
        assert!(types_compatible("INT64", "int64"));

        // Common aliases
        assert!(types_compatible("String", "Utf8"));
        assert!(types_compatible("bigint", "Int64"));
        assert!(types_compatible("double", "Float64"));
        assert!(types_compatible("boolean", "bool"));
        assert!(types_compatible("timestamp[us]", "timestamp"));

        // Incompatible
        assert!(!types_compatible("Int64", "Utf8"));
        assert!(!types_compatible("Float64", "Int64"));
    }

    #[test]
    fn test_evaluate_quality_contract_pass() {
        let contract = QualityContract {
            min_completeness: Some(0.90),
            min_freshness: Some(0.80),
            min_overall: Some(0.85),
        };

        let metrics = QualityMetrics {
            completeness_score: Some(0.95),
            freshness_score: Some(0.90),
            overall_score: Some(0.92),
            staleness_secs: None,
        };

        let violations = evaluate_quality_contract(&contract, &metrics);
        assert!(
            violations.is_empty(),
            "Expected no violations: {:?}",
            violations
        );
    }

    #[test]
    fn test_evaluate_quality_contract_completeness_violation() {
        let contract = QualityContract {
            min_completeness: Some(0.95),
            min_freshness: None,
            min_overall: None,
        };

        let metrics = QualityMetrics {
            completeness_score: Some(0.85), // Below threshold
            freshness_score: None,
            overall_score: None,
            staleness_secs: None,
        };

        let violations = evaluate_quality_contract(&contract, &metrics);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("Completeness"));
        assert!(violations[0].contains("85.0%"));
    }

    #[test]
    fn test_evaluate_quality_contract_missing_metrics() {
        let contract = QualityContract {
            min_completeness: Some(0.90),
            min_freshness: None,
            min_overall: None,
        };

        let metrics = QualityMetrics {
            completeness_score: None, // Missing!
            freshness_score: None,
            overall_score: None,
            staleness_secs: None,
        };

        let violations = evaluate_quality_contract(&contract, &metrics);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("not available"));
    }

    #[test]
    fn test_evaluate_freshness_contract_pass() {
        let contract = FreshnessContract {
            max_staleness_secs: 3600,           // 1 hour
            expected_interval_secs: Some(1800), // 30 minutes
        };

        let metrics = QualityMetrics {
            completeness_score: None,
            freshness_score: None,
            overall_score: None,
            staleness_secs: Some(1200), // 20 minutes - within threshold
        };

        let violations = evaluate_freshness_contract(&contract, &metrics);
        assert!(
            violations.is_empty(),
            "Expected no violations: {:?}",
            violations
        );
    }

    #[test]
    fn test_evaluate_freshness_contract_staleness_violation() {
        let contract = FreshnessContract {
            max_staleness_secs: 3600, // 1 hour
            expected_interval_secs: None,
        };

        let metrics = QualityMetrics {
            completeness_score: None,
            freshness_score: None,
            overall_score: None,
            staleness_secs: Some(7200), // 2 hours - exceeds threshold
        };

        let violations = evaluate_freshness_contract(&contract, &metrics);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("staleness"));
        assert!(violations[0].contains("2 hours"));
    }

    #[test]
    fn test_evaluate_freshness_contract_interval_violation() {
        let contract = FreshnessContract {
            max_staleness_secs: 86400,          // 24 hours (high threshold)
            expected_interval_secs: Some(3600), // 1 hour expected
        };

        let metrics = QualityMetrics {
            completeness_score: None,
            freshness_score: None,
            overall_score: None,
            staleness_secs: Some(10800), // 3 hours - 3x expected interval
        };

        let violations = evaluate_freshness_contract(&contract, &metrics);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("update periods"));
    }

    #[test]
    fn test_enforcement_action_should_block() {
        assert!(!EnforcementAction::Allow.should_block());
        assert!(!EnforcementAction::Warn(vec!["test".to_string()]).should_block());
        assert!(!EnforcementAction::Alert(vec!["test".to_string()]).should_block());
        assert!(EnforcementAction::Block(vec!["test".to_string()]).should_block());
    }

    #[test]
    fn test_enforcement_action_violations() {
        assert!(EnforcementAction::Allow.violations().is_none());

        let violations = vec!["v1".to_string(), "v2".to_string()];
        assert_eq!(
            EnforcementAction::Warn(violations.clone()).violations(),
            Some(violations.as_slice())
        );
    }

    #[test]
    fn test_contract_evaluator_full() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Create a dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated) VALUES ('orders', '/data/orders', 'delta', datetime('now'), datetime('now'))",
            [],
        ).unwrap();

        let dataset_id: i64 = conn.last_insert_rowid();

        // Add fields
        conn.execute(
            "INSERT INTO fields (dataset_id, name, data_type, nullable) VALUES (?1, 'order_id', 'Int64', 0)",
            [dataset_id],
        ).unwrap();
        conn.execute(
            "INSERT INTO fields (dataset_id, name, data_type, nullable) VALUES (?1, 'amount', 'Float64', 1)",
            [dataset_id],
        ).unwrap();

        // Create a contract that the dataset should pass
        let passing_contract = DataContract {
            id: None,
            name: "orders_contract".to_string(),
            dataset_pattern: "orders".to_string(),
            version: 1,
            schema_contract: Some(SchemaContract {
                required_columns: vec![RequiredColumn {
                    name: "order_id".to_string(),
                    data_type: "Int64".to_string(),
                    nullable: false,
                }],
                allow_additional_columns: true,
            }),
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        create_contract(&conn, &passing_contract).unwrap();

        // Evaluate
        let evaluator = ContractEvaluator::new(&conn);
        let ctx = DatasetContext {
            id: dataset_id,
            name: "orders".to_string(),
            tenant_id: None,
        };

        let results = evaluator.evaluate_for_dataset(&ctx).unwrap();
        assert_eq!(results.len(), 1);
        assert!(
            results[0].passed,
            "Contract should pass: {:?}",
            results[0].violations
        );
    }

    #[test]
    fn test_contract_evaluator_with_violation() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Create a dataset without required field
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated) VALUES ('incomplete', '/data/incomplete', 'delta', datetime('now'), datetime('now'))",
            [],
        ).unwrap();

        let dataset_id: i64 = conn.last_insert_rowid();

        // Add only one field
        conn.execute(
            "INSERT INTO fields (dataset_id, name, data_type, nullable) VALUES (?1, 'amount', 'Float64', 1)",
            [dataset_id],
        ).unwrap();

        // Create contract requiring order_id
        let contract = DataContract {
            id: None,
            name: "strict_contract".to_string(),
            dataset_pattern: "incomplete".to_string(),
            version: 1,
            schema_contract: Some(SchemaContract {
                required_columns: vec![RequiredColumn {
                    name: "order_id".to_string(),
                    data_type: "Int64".to_string(),
                    nullable: false,
                }],
                allow_additional_columns: true,
            }),
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Block,
            alert_channels: vec![],
            enabled: true,
        };

        create_contract(&conn, &contract).unwrap();

        // Evaluate
        let evaluator = ContractEvaluator::new(&conn);
        let ctx = DatasetContext {
            id: dataset_id,
            name: "incomplete".to_string(),
            tenant_id: None,
        };

        let results = evaluator.evaluate_for_dataset(&ctx).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed, "Contract should fail");
        assert!(results[0].violations[0].contains("Missing required column"));

        // Check enforcement
        let action = evaluator.determine_enforcement(&contract, &results[0].violations);
        assert!(action.should_block());
    }
}
