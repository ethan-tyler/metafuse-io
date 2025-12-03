//! Core types for column-level lineage tracking.
//!
//! This module defines the data structures used to represent column-to-column
//! lineage edges extracted from SQL queries.

use serde::{Deserialize, Serialize};

/// A column-to-column lineage edge representing a data flow relationship.
///
/// Each edge captures how a source column contributes to a target column,
/// including the type of transformation applied.
///
/// # Example
///
/// For the query:
/// ```sql
/// SELECT customer_id, SUM(amount) AS total_amount FROM orders GROUP BY customer_id
/// ```
///
/// Two edges would be created:
/// - `orders.customer_id` → `result.customer_id` (Direct)
/// - `orders.amount` → `result.total_amount` (Aggregate)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnLineageEdge {
    /// Source table/dataset name (may be an alias)
    pub source_table: String,
    /// Source column name
    pub source_column: String,
    /// Target table/dataset name
    pub target_table: String,
    /// Target column name
    pub target_column: String,
    /// Type of transformation applied
    pub transformation: TransformationType,
    /// Original SQL expression (for non-direct transformations)
    pub expression: Option<String>,
}

impl ColumnLineageEdge {
    /// Create a direct (1:1) column mapping.
    pub fn direct(
        source_table: impl Into<String>,
        source_column: impl Into<String>,
        target_table: impl Into<String>,
        target_column: impl Into<String>,
    ) -> Self {
        Self {
            source_table: source_table.into(),
            source_column: source_column.into(),
            target_table: target_table.into(),
            target_column: target_column.into(),
            transformation: TransformationType::Direct,
            expression: None,
        }
    }

    /// Create a transformed column mapping with an expression.
    pub fn with_expression(
        source_table: impl Into<String>,
        source_column: impl Into<String>,
        target_table: impl Into<String>,
        target_column: impl Into<String>,
        transformation: TransformationType,
        expression: impl Into<String>,
    ) -> Self {
        Self {
            source_table: source_table.into(),
            source_column: source_column.into(),
            target_table: target_table.into(),
            target_column: target_column.into(),
            transformation,
            expression: Some(expression.into()),
        }
    }
}

/// Type of transformation applied to a column.
///
/// This helps classify how source columns are transformed into target columns,
/// which is useful for:
/// - Understanding data lineage complexity
/// - Impact analysis (direct mappings are simpler to reason about)
/// - PII propagation (aggregates may anonymize data)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransformationType {
    /// Direct column reference: `SELECT a FROM t`
    #[default]
    Direct,
    /// Expression involving the column: `SELECT a + b AS c`
    Expression,
    /// Aggregate function: `SELECT SUM(a) AS total`
    Aggregate,
    /// Window function: `SELECT ROW_NUMBER() OVER (...)`
    Window,
    /// CASE expression: `SELECT CASE WHEN a > 0 THEN 'yes' END`
    Case,
    /// Type cast: `SELECT CAST(a AS INT)`
    Cast,
}

impl TransformationType {
    /// Returns the string representation of this transformation type.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransformationType::Direct => "direct",
            TransformationType::Expression => "expression",
            TransformationType::Aggregate => "aggregate",
            TransformationType::Window => "window",
            TransformationType::Case => "case",
            TransformationType::Cast => "cast",
        }
    }

    /// Returns true if this transformation might anonymize PII.
    ///
    /// Aggregates are the primary example - `COUNT(ssn)` doesn't expose individual SSNs.
    pub fn may_anonymize(&self) -> bool {
        matches!(self, TransformationType::Aggregate)
    }
}

impl std::fmt::Display for TransformationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for TransformationType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "direct" => Ok(TransformationType::Direct),
            "expression" => Ok(TransformationType::Expression),
            "aggregate" => Ok(TransformationType::Aggregate),
            "window" => Ok(TransformationType::Window),
            "case" => Ok(TransformationType::Case),
            "cast" => Ok(TransformationType::Cast),
            _ => Err(format!("Unknown transformation type: {}", s)),
        }
    }
}

/// Result of parsing a SQL query for column lineage.
#[derive(Debug, Clone)]
pub struct LineageParseResult {
    /// Extracted column lineage edges
    pub edges: Vec<ColumnLineageEdge>,
    /// Source tables referenced in the query
    pub source_tables: Vec<TableReference>,
    /// Warnings encountered during parsing (non-fatal issues)
    pub warnings: Vec<String>,
}

impl LineageParseResult {
    /// Create an empty result.
    pub fn empty() -> Self {
        Self {
            edges: Vec::new(),
            source_tables: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a result with edges.
    pub fn with_edges(edges: Vec<ColumnLineageEdge>) -> Self {
        Self {
            edges,
            source_tables: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Add a warning to the result.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }
}

/// A reference to a table in a SQL query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableReference {
    /// Table name (possibly qualified: schema.table)
    pub name: String,
    /// Alias if specified (e.g., `orders AS o`)
    pub alias: Option<String>,
}

impl TableReference {
    /// Create a table reference without an alias.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            alias: None,
        }
    }

    /// Create a table reference with an alias.
    pub fn with_alias(name: impl Into<String>, alias: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            alias: Some(alias.into()),
        }
    }

    /// Get the effective name to use in lineage (alias if present, otherwise name).
    pub fn effective_name(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_edge() {
        let edge = ColumnLineageEdge::direct("orders", "customer_id", "summary", "customer_id");

        assert_eq!(edge.source_table, "orders");
        assert_eq!(edge.source_column, "customer_id");
        assert_eq!(edge.target_table, "summary");
        assert_eq!(edge.target_column, "customer_id");
        assert_eq!(edge.transformation, TransformationType::Direct);
        assert!(edge.expression.is_none());
    }

    #[test]
    fn test_expression_edge() {
        let edge = ColumnLineageEdge::with_expression(
            "orders",
            "amount",
            "summary",
            "total_amount",
            TransformationType::Aggregate,
            "SUM(amount)",
        );

        assert_eq!(edge.transformation, TransformationType::Aggregate);
        assert_eq!(edge.expression, Some("SUM(amount)".to_string()));
    }

    #[test]
    fn test_transformation_type_display() {
        assert_eq!(TransformationType::Direct.to_string(), "direct");
        assert_eq!(TransformationType::Aggregate.to_string(), "aggregate");
        assert_eq!(TransformationType::Window.to_string(), "window");
    }

    #[test]
    fn test_transformation_type_from_str() {
        assert_eq!(
            "direct".parse::<TransformationType>().unwrap(),
            TransformationType::Direct
        );
        assert_eq!(
            "AGGREGATE".parse::<TransformationType>().unwrap(),
            TransformationType::Aggregate
        );
        assert!("unknown".parse::<TransformationType>().is_err());
    }

    #[test]
    fn test_may_anonymize() {
        assert!(TransformationType::Aggregate.may_anonymize());
        assert!(!TransformationType::Direct.may_anonymize());
        assert!(!TransformationType::Expression.may_anonymize());
    }

    #[test]
    fn test_table_reference() {
        let ref1 = TableReference::new("orders");
        assert_eq!(ref1.effective_name(), "orders");

        let ref2 = TableReference::with_alias("orders", "o");
        assert_eq!(ref2.effective_name(), "o");
    }

    #[test]
    fn test_edge_serialization() {
        let edge = ColumnLineageEdge::direct("orders", "id", "summary", "order_id");
        let json = serde_json::to_string(&edge).unwrap();
        let parsed: ColumnLineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, parsed);
    }
}
