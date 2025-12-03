//! Column-level lineage extraction for MetaFuse catalog.
//!
//! This crate provides SQL parsing capabilities to extract column-to-column
//! lineage from SQL queries. It identifies how source columns are transformed
//! into target columns, enabling:
//!
//! - **PII Propagation Tracking**: Trace where sensitive data flows
//! - **Impact Analysis**: Understand what breaks when columns change
//! - **Data Lineage Visualization**: Build column-level lineage graphs
//!
//! # Features
//!
//! - Parse SELECT statements with direct columns, aliases, and qualified names
//! - Handle binary expressions, aggregates, CASE, CAST, and window functions
//! - Support for JOINs (INNER, LEFT, RIGHT, FULL)
//! - Best-effort approach: logs warnings for unsupported SQL, doesn't block
//!
//! # Example
//!
//! ```
//! use metafuse_catalog_lineage::{ColumnLineageParser, TransformationType};
//!
//! let parser = ColumnLineageParser::new();
//!
//! // Parse a SQL query and extract lineage
//! let result = parser.parse_lineage(
//!     "SELECT customer_id, SUM(amount) AS total_amount FROM orders GROUP BY customer_id",
//!     "customer_summary"
//! ).unwrap();
//!
//! // Two edges: customer_id (direct) and amount -> total_amount (aggregate)
//! assert_eq!(result.edges.len(), 2);
//!
//! // Check transformation types
//! let direct_edge = result.edges.iter().find(|e| e.target_column == "customer_id").unwrap();
//! assert_eq!(direct_edge.transformation, TransformationType::Direct);
//!
//! let agg_edge = result.edges.iter().find(|e| e.target_column == "total_amount").unwrap();
//! assert_eq!(agg_edge.transformation, TransformationType::Aggregate);
//! ```
//!
//! # SQL Support Matrix
//!
//! | Feature | Support |
//! |---------|---------|
//! | SELECT columns | ✅ |
//! | Column aliases | ✅ |
//! | Qualified columns (t.col) | ✅ |
//! | Binary expressions | ✅ |
//! | Aggregate functions | ✅ |
//! | CASE expressions | ✅ |
//! | CAST/TryCast | ✅ |
//! | JOINs | ✅ |
//! | Window functions | ✅ |
//! | Subqueries | ⚠️ Partial |
//! | CTEs (WITH) | ⚠️ Partial |
//! | SELECT * | ❌ (requires schema) |

mod error;
mod parser;
mod types;

// Re-export public types
pub use error::{LineageError, Result};
pub use parser::ColumnLineageParser;
pub use types::{ColumnLineageEdge, LineageParseResult, TableReference, TransformationType};

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// End-to-end test for a typical analytical query.
    #[test]
    fn test_analytical_query() {
        let parser = ColumnLineageParser::new();
        let sql = r#"
            SELECT
                c.customer_id,
                c.customer_name,
                COUNT(o.order_id) AS order_count,
                SUM(o.amount) AS total_spent,
                AVG(o.amount) AS avg_order_value,
                MAX(o.order_date) AS last_order_date
            FROM customers c
            LEFT JOIN orders o ON c.customer_id = o.customer_id
            GROUP BY c.customer_id, c.customer_name
        "#;

        let result = parser.parse_lineage(sql, "customer_summary").unwrap();

        // Should have edges for all selected columns
        assert!(result.edges.len() >= 6);

        // Check we captured both source tables
        assert!(result
            .source_tables
            .iter()
            .any(|t| t.alias == Some("c".to_string())));
        assert!(result
            .source_tables
            .iter()
            .any(|t| t.alias == Some("o".to_string())));

        // Verify transformation types
        assert!(result
            .edges
            .iter()
            .any(|e| e.target_column == "customer_id"
                && e.transformation == TransformationType::Direct));
        assert!(result.edges.iter().any(|e| e.target_column == "order_count"
            && e.transformation == TransformationType::Aggregate));
        assert!(result.edges.iter().any(|e| e.target_column == "total_spent"
            && e.transformation == TransformationType::Aggregate));
    }

    /// Test that PII propagation can be traced.
    #[test]
    fn test_pii_propagation_scenario() {
        let parser = ColumnLineageParser::new();

        // Scenario: SSN flows through multiple transformations
        let sql = r#"
            SELECT
                customer_id,
                SUBSTRING(ssn, 1, 3) AS ssn_prefix,
                CASE WHEN ssn IS NOT NULL THEN 'has_ssn' ELSE 'no_ssn' END AS ssn_status
            FROM customers
        "#;

        let result = parser.parse_lineage(sql, "customer_pii_view").unwrap();

        // SSN should appear in lineage for both derived columns
        let ssn_edges: Vec<_> = result
            .edges
            .iter()
            .filter(|e| e.source_column == "ssn")
            .collect();

        assert!(ssn_edges.len() >= 2);

        // One should be Expression (SUBSTRING), one should be Case
        assert!(ssn_edges
            .iter()
            .any(|e| e.transformation == TransformationType::Expression));
        assert!(ssn_edges
            .iter()
            .any(|e| e.transformation == TransformationType::Case));
    }

    /// Test CREATE TABLE AS SELECT.
    #[test]
    fn test_ctas() {
        let parser = ColumnLineageParser::new();
        let sql = r#"
            CREATE TABLE monthly_sales AS
            SELECT
                DATE_TRUNC('month', order_date) AS month,
                SUM(amount) AS total_sales,
                COUNT(*) AS order_count
            FROM orders
            GROUP BY DATE_TRUNC('month', order_date)
        "#;

        let result = parser.parse_lineage(sql, "ignored").unwrap();

        assert!(!result.edges.is_empty());
        assert!(result
            .edges
            .iter()
            .any(|e| e.target_column == "total_sales"));
    }

    /// Test that warnings are generated for unsupported features.
    #[test]
    fn test_warnings_generated() {
        let parser = ColumnLineageParser::new();

        let result = parser
            .parse_lineage("SELECT * FROM orders", "target")
            .unwrap();

        assert!(result.edges.is_empty());
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("SELECT *"));
    }
}
