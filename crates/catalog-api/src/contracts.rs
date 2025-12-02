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
}
