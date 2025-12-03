// Allow clippy warnings that are intentional for this module
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::too_many_arguments)]

//! SQL parser for column-level lineage extraction.
//!
//! This module provides the core parsing logic to extract column-to-column
//! lineage from SQL queries using the sqlparser-rs crate.
//!
//! # Supported SQL Features
//!
//! - SELECT statements with direct columns, aliases, and qualified names
//! - Binary expressions (a + b, a * b, etc.)
//! - Aggregate functions (SUM, COUNT, AVG, MIN, MAX)
//! - CASE expressions
//! - CAST expressions
//! - JOINs (INNER, LEFT, RIGHT, FULL)
//! - Window functions (basic support)
//!
//! # Example
//!
//! ```
//! use metafuse_catalog_lineage::ColumnLineageParser;
//!
//! let parser = ColumnLineageParser::new();
//! let result = parser.parse_lineage(
//!     "SELECT customer_id, SUM(amount) AS total FROM orders GROUP BY customer_id",
//!     "order_summary"
//! ).unwrap();
//!
//! assert_eq!(result.edges.len(), 2);
//! ```

use sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Query, Select, SelectItem, SetExpr,
    Statement, TableFactor, TableWithJoins,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use crate::error::{LineageError, Result};
use crate::types::{ColumnLineageEdge, LineageParseResult, TableReference, TransformationType};

/// SQL parser for extracting column-level lineage.
///
/// Uses the generic SQL dialect by default, which handles most ANSI SQL.
#[derive(Debug, Default)]
pub struct ColumnLineageParser {
    // Marker field to ensure we use GenericDialect
    _private: (),
}

impl ColumnLineageParser {
    /// Create a new parser with the default generic dialect.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Parse a SQL query and extract column lineage edges.
    ///
    /// # Arguments
    ///
    /// * `sql` - The SQL query to parse
    /// * `target_table` - The name of the target table/dataset the query creates
    ///
    /// # Returns
    ///
    /// A `LineageParseResult` containing extracted edges and any warnings.
    ///
    /// # Errors
    ///
    /// Returns an error if the SQL cannot be parsed or is not supported.
    pub fn parse_lineage(&self, sql: &str, target_table: &str) -> Result<LineageParseResult> {
        let sql = sql.trim();
        if sql.is_empty() {
            return Err(LineageError::EmptyQuery);
        }

        // Parse SQL into AST
        let statements = Parser::parse_sql(&GenericDialect {}, sql)?;

        if statements.is_empty() {
            return Err(LineageError::EmptyQuery);
        }

        if statements.len() > 1 {
            return Err(LineageError::MultipleStatements(statements.len()));
        }

        let stmt = &statements[0];

        match stmt {
            Statement::Query(query) => self.extract_from_query(query, target_table),
            Statement::Insert(insert) => {
                if let Some(source) = &insert.source {
                    let table_name = insert.table.to_string();
                    self.extract_from_query(source, &table_name)
                } else {
                    Err(LineageError::UnsupportedStatement(
                        "INSERT without source query".to_string(),
                    ))
                }
            }
            Statement::CreateTable(create) => {
                if let Some(query) = &create.query {
                    let table_name = create.name.to_string();
                    self.extract_from_query(query, &table_name)
                } else {
                    Err(LineageError::UnsupportedStatement(
                        "CREATE TABLE without AS SELECT".to_string(),
                    ))
                }
            }
            _ => Err(LineageError::UnsupportedStatement(format!(
                "Statement type not supported: {:?}",
                stmt
            ))),
        }
    }

    /// Extract lineage from a Query (SELECT statement).
    fn extract_from_query(&self, query: &Query, target_table: &str) -> Result<LineageParseResult> {
        let mut result = LineageParseResult::empty();

        // Handle the main query body
        match query.body.as_ref() {
            SetExpr::Select(select) => {
                self.extract_from_select(select, target_table, &mut result)?;
            }
            SetExpr::Query(subquery) => {
                return self.extract_from_query(subquery, target_table);
            }
            SetExpr::SetOperation { left, right, .. } => {
                // For UNION/INTERSECT/EXCEPT, extract from both sides
                let mut left_result = LineageParseResult::empty();
                let mut right_result = LineageParseResult::empty();

                if let SetExpr::Select(left_select) = left.as_ref() {
                    self.extract_from_select(left_select, target_table, &mut left_result)?;
                }
                if let SetExpr::Select(right_select) = right.as_ref() {
                    self.extract_from_select(right_select, target_table, &mut right_result)?;
                }

                result.edges.extend(left_result.edges);
                result.edges.extend(right_result.edges);
                result.warnings.extend(left_result.warnings);
                result.warnings.extend(right_result.warnings);
            }
            _ => {
                result.add_warning(format!("Unsupported query body type: {:?}", query.body));
            }
        }

        Ok(result)
    }

    /// Extract lineage from a SELECT statement.
    fn extract_from_select(
        &self,
        select: &Select,
        target_table: &str,
        result: &mut LineageParseResult,
    ) -> Result<()> {
        // Build table alias map from FROM clause
        let table_map = self.build_table_map(&select.from);
        result.source_tables = table_map
            .iter()
            .map(|(alias, name)| {
                if alias == name {
                    TableReference::new(name.clone())
                } else {
                    TableReference::with_alias(name.clone(), alias.clone())
                }
            })
            .collect();

        // Process each SELECT item
        for item in &select.projection {
            match item {
                SelectItem::UnnamedExpr(expr) => {
                    let target_col = self.infer_column_name(expr);
                    self.extract_from_expr(expr, target_table, &target_col, &table_map, result)?;
                }
                SelectItem::ExprWithAlias { expr, alias } => {
                    self.extract_from_expr(expr, target_table, &alias.value, &table_map, result)?;
                }
                SelectItem::Wildcard(_) => {
                    // SELECT * - we can't know columns without schema
                    result.add_warning("SELECT * requires schema lookup - columns not extracted");
                }
                SelectItem::QualifiedWildcard(name, _) => {
                    // SELECT table.* - same issue
                    result.add_warning(format!(
                        "SELECT {}.* requires schema lookup - columns not extracted",
                        name
                    ));
                }
            }
        }

        Ok(())
    }

    /// Build a map from table alias/name to actual table name.
    fn build_table_map(&self, from: &[TableWithJoins]) -> Vec<(String, String)> {
        let mut map = Vec::new();

        for table_with_joins in from {
            // Process main table
            self.add_table_to_map(&table_with_joins.relation, &mut map);

            // Process JOINed tables
            for join in &table_with_joins.joins {
                self.add_table_to_map(&join.relation, &mut map);
            }
        }

        map
    }

    /// Add a table factor to the table map.
    fn add_table_to_map(&self, factor: &TableFactor, map: &mut Vec<(String, String)>) {
        match factor {
            TableFactor::Table { name, alias, .. } => {
                let table_name = name.to_string();
                let effective_name = alias
                    .as_ref()
                    .map(|a| a.name.value.clone())
                    .unwrap_or_else(|| table_name.clone());
                map.push((effective_name, table_name));
            }
            TableFactor::Derived {
                alias, subquery, ..
            } => {
                // Subquery in FROM clause
                if let Some(alias) = alias {
                    map.push((
                        alias.name.value.clone(),
                        format!("<subquery:{}>", alias.name.value),
                    ));
                }
                // Note: We could recursively extract from subquery here
                let _ = subquery; // Suppress unused warning
            }
            TableFactor::NestedJoin {
                table_with_joins,
                alias,
            } => {
                // Nested join - process recursively
                self.add_table_to_map(&table_with_joins.relation, map);
                for join in &table_with_joins.joins {
                    self.add_table_to_map(&join.relation, map);
                }
                let _ = alias; // Suppress unused warning
            }
            _ => {
                // Other table factors (UNNEST, TableFunction, etc.) - skip for now
            }
        }
    }

    /// Extract lineage from an expression.
    fn extract_from_expr(
        &self,
        expr: &Expr,
        target_table: &str,
        target_column: &str,
        table_map: &[(String, String)],
        result: &mut LineageParseResult,
    ) -> Result<()> {
        match expr {
            // Direct column reference: SELECT customer_id
            Expr::Identifier(ident) => {
                let source_col = &ident.value;
                // If no qualifier, use first table (or unknown)
                let source_table = table_map
                    .first()
                    .map(|(alias, _)| alias.clone())
                    .unwrap_or_else(|| "<unknown>".to_string());

                result.edges.push(ColumnLineageEdge::direct(
                    source_table,
                    source_col,
                    target_table,
                    target_column,
                ));
            }

            // Qualified column: SELECT orders.customer_id
            Expr::CompoundIdentifier(parts) => {
                if parts.len() >= 2 {
                    let table_ref = &parts[parts.len() - 2].value;
                    let column = &parts[parts.len() - 1].value;

                    // Resolve alias to actual table name
                    let source_table = table_map
                        .iter()
                        .find(|(alias, _)| alias == table_ref)
                        .map(|(alias, _)| alias.clone())
                        .unwrap_or_else(|| table_ref.clone());

                    result.edges.push(ColumnLineageEdge::direct(
                        source_table,
                        column,
                        target_table,
                        target_column,
                    ));
                }
            }

            // Binary operation: SELECT a + b AS total
            Expr::BinaryOp { left, right, op } => {
                let expr_str = format!("{} {} {}", left, op, right);
                self.extract_with_transformation(
                    &[left.as_ref(), right.as_ref()],
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // Unary operation: SELECT -amount
            Expr::UnaryOp { expr: inner, op } => {
                let expr_str = format!("{}{}", op, inner);
                self.extract_with_transformation(
                    &[inner.as_ref()],
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // Function call: SELECT SUM(amount), UPPER(name)
            Expr::Function(func) => {
                let func_name = func.name.to_string().to_uppercase();
                let is_aggregate = is_aggregate_function(&func_name);
                let is_window = func.over.is_some();

                let transformation = if is_window {
                    TransformationType::Window
                } else if is_aggregate {
                    TransformationType::Aggregate
                } else {
                    TransformationType::Expression
                };

                // Extract columns from function arguments
                let mut arg_exprs: Vec<&Expr> = match &func.args {
                    FunctionArguments::List(arg_list) => arg_list
                        .args
                        .iter()
                        .filter_map(|arg| match arg {
                            FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => Some(e),
                            FunctionArg::Named {
                                arg: FunctionArgExpr::Expr(e),
                                ..
                            } => Some(e),
                            _ => None,
                        })
                        .collect(),
                    FunctionArguments::None | FunctionArguments::Subquery(_) => Vec::new(),
                };

                // For window functions, also extract from OVER clause (PARTITION BY, ORDER BY)
                if let Some(sqlparser::ast::WindowType::WindowSpec(spec)) = &func.over {
                    // Add PARTITION BY expressions
                    for partition_expr in &spec.partition_by {
                        arg_exprs.push(partition_expr);
                    }
                    // Add ORDER BY expressions
                    for order_expr in &spec.order_by {
                        arg_exprs.push(&order_expr.expr);
                    }
                }

                let expr_str = expr.to_string();
                self.extract_with_transformation(
                    &arg_exprs,
                    target_table,
                    target_column,
                    transformation,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // CASE expression
            Expr::Case {
                operand,
                conditions,
                results,
                else_result,
            } => {
                let mut all_exprs: Vec<&Expr> = Vec::new();

                if let Some(op) = operand {
                    all_exprs.push(op.as_ref());
                }
                all_exprs.extend(conditions.iter());
                all_exprs.extend(results.iter());
                if let Some(else_expr) = else_result {
                    all_exprs.push(else_expr.as_ref());
                }

                let expr_str = expr.to_string();
                self.extract_with_transformation(
                    &all_exprs,
                    target_table,
                    target_column,
                    TransformationType::Case,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // CAST expression
            Expr::Cast { expr: inner, .. } => {
                let expr_str = expr.to_string();
                self.extract_with_transformation(
                    &[inner.as_ref()],
                    target_table,
                    target_column,
                    TransformationType::Cast,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // TRIM expression: TRIM(value) or TRIM(BOTH ' ' FROM value)
            Expr::Trim { expr: inner, .. } => {
                let expr_str = expr.to_string();
                self.extract_with_transformation(
                    &[inner.as_ref()],
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // SUBSTRING expression: SUBSTRING(value FROM start FOR length)
            Expr::Substring {
                expr: inner,
                substring_from,
                substring_for,
                ..
            } => {
                let mut exprs: Vec<&Expr> = vec![inner.as_ref()];
                if let Some(from_expr) = substring_from {
                    exprs.push(from_expr.as_ref());
                }
                if let Some(for_expr) = substring_for {
                    exprs.push(for_expr.as_ref());
                }
                let expr_str = expr.to_string();
                self.extract_with_transformation(
                    &exprs,
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // EXTRACT expression: EXTRACT(YEAR FROM date)
            Expr::Extract { expr: inner, .. } => {
                let expr_str = expr.to_string();
                self.extract_with_transformation(
                    &[inner.as_ref()],
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // POSITION expression: POSITION(substring IN string)
            Expr::Position {
                expr: inner,
                r#in: in_expr,
            } => {
                let expr_str = expr.to_string();
                self.extract_with_transformation(
                    &[inner.as_ref(), in_expr.as_ref()],
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // OVERLAY expression
            Expr::Overlay {
                expr: inner,
                overlay_what,
                overlay_from,
                overlay_for,
            } => {
                let mut exprs: Vec<&Expr> =
                    vec![inner.as_ref(), overlay_what.as_ref(), overlay_from.as_ref()];
                if let Some(for_expr) = overlay_for {
                    exprs.push(for_expr.as_ref());
                }
                let expr_str = expr.to_string();
                self.extract_with_transformation(
                    &exprs,
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // LIKE/ILIKE expressions
            Expr::Like {
                expr: inner,
                pattern,
                ..
            }
            | Expr::ILike {
                expr: inner,
                pattern,
                ..
            } => {
                let expr_str = expr.to_string();
                self.extract_with_transformation(
                    &[inner.as_ref(), pattern.as_ref()],
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &expr_str,
                    table_map,
                    result,
                )?;
            }

            // Nested expression (parenthesized)
            Expr::Nested(inner) => {
                self.extract_from_expr(inner, target_table, target_column, table_map, result)?;
            }

            // Subquery
            Expr::Subquery(query) => {
                // For now, just note that there's a subquery
                result.add_warning(format!(
                    "Subquery in expression for column '{}' - lineage may be incomplete",
                    target_column
                ));
                let _ = query; // Suppress unused warning
            }

            // Value expressions (literals, etc.) - no lineage
            Expr::Value(_) => {
                // Literal values don't contribute to lineage
            }

            // Between expression
            Expr::Between {
                expr, low, high, ..
            } => {
                self.extract_with_transformation(
                    &[expr.as_ref(), low.as_ref(), high.as_ref()],
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &format!("{}", expr),
                    table_map,
                    result,
                )?;
            }

            // IN expression
            Expr::InList { expr, list, .. } => {
                let mut exprs = vec![expr.as_ref()];
                exprs.extend(list.iter());
                self.extract_with_transformation(
                    &exprs,
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &format!("{}", expr),
                    table_map,
                    result,
                )?;
            }

            // IS NULL, IS NOT NULL
            Expr::IsNull(inner) | Expr::IsNotNull(inner) => {
                self.extract_with_transformation(
                    &[inner.as_ref()],
                    target_table,
                    target_column,
                    TransformationType::Expression,
                    &expr.to_string(),
                    table_map,
                    result,
                )?;
            }

            // Other expressions - log warning
            _ => {
                result.add_warning(format!(
                    "Unsupported expression type for column '{}': {:?}",
                    target_column, expr
                ));
            }
        }

        Ok(())
    }

    /// Extract lineage from multiple source expressions with a transformation.
    fn extract_with_transformation(
        &self,
        source_exprs: &[&Expr],
        target_table: &str,
        target_column: &str,
        transformation: TransformationType,
        expression_text: &str,
        table_map: &[(String, String)],
        result: &mut LineageParseResult,
    ) -> Result<()> {
        for expr in source_exprs {
            // Recursively extract column references
            let columns = self.extract_column_refs(expr, table_map);

            for (source_table, source_column) in columns {
                result.edges.push(ColumnLineageEdge::with_expression(
                    source_table,
                    source_column,
                    target_table,
                    target_column,
                    transformation,
                    expression_text,
                ));
            }
        }

        Ok(())
    }

    /// Extract all column references from an expression.
    fn extract_column_refs(
        &self,
        expr: &Expr,
        table_map: &[(String, String)],
    ) -> Vec<(String, String)> {
        let mut columns = Vec::new();
        self.collect_column_refs(expr, table_map, &mut columns);
        columns
    }

    /// Recursively collect column references from an expression.
    fn collect_column_refs(
        &self,
        expr: &Expr,
        table_map: &[(String, String)],
        columns: &mut Vec<(String, String)>,
    ) {
        match expr {
            Expr::Identifier(ident) => {
                let source_table = table_map
                    .first()
                    .map(|(alias, _)| alias.clone())
                    .unwrap_or_else(|| "<unknown>".to_string());
                columns.push((source_table, ident.value.clone()));
            }
            Expr::CompoundIdentifier(parts) => {
                if parts.len() >= 2 {
                    let table_ref = &parts[parts.len() - 2].value;
                    let column = &parts[parts.len() - 1].value;
                    let source_table = table_map
                        .iter()
                        .find(|(alias, _)| alias == table_ref)
                        .map(|(alias, _)| alias.clone())
                        .unwrap_or_else(|| table_ref.clone());
                    columns.push((source_table, column.clone()));
                }
            }
            Expr::BinaryOp { left, right, .. } => {
                self.collect_column_refs(left, table_map, columns);
                self.collect_column_refs(right, table_map, columns);
            }
            Expr::UnaryOp { expr, .. } => {
                self.collect_column_refs(expr, table_map, columns);
            }
            Expr::Function(func) => {
                if let FunctionArguments::List(arg_list) = &func.args {
                    for arg in &arg_list.args {
                        if let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = arg {
                            self.collect_column_refs(e, table_map, columns);
                        }
                    }
                }
            }
            Expr::Case {
                operand,
                conditions,
                results,
                else_result,
            } => {
                if let Some(op) = operand {
                    self.collect_column_refs(op, table_map, columns);
                }
                for cond in conditions {
                    self.collect_column_refs(cond, table_map, columns);
                }
                for res in results {
                    self.collect_column_refs(res, table_map, columns);
                }
                if let Some(else_expr) = else_result {
                    self.collect_column_refs(else_expr, table_map, columns);
                }
            }
            Expr::Cast { expr, .. } => {
                self.collect_column_refs(expr, table_map, columns);
            }
            Expr::Trim { expr, .. } => {
                self.collect_column_refs(expr, table_map, columns);
            }
            Expr::Substring {
                expr,
                substring_from,
                substring_for,
                ..
            } => {
                self.collect_column_refs(expr, table_map, columns);
                if let Some(from_expr) = substring_from {
                    self.collect_column_refs(from_expr, table_map, columns);
                }
                if let Some(for_expr) = substring_for {
                    self.collect_column_refs(for_expr, table_map, columns);
                }
            }
            Expr::Extract { expr, .. } => {
                self.collect_column_refs(expr, table_map, columns);
            }
            Expr::Position {
                expr,
                r#in: in_expr,
            } => {
                self.collect_column_refs(expr, table_map, columns);
                self.collect_column_refs(in_expr, table_map, columns);
            }
            Expr::Overlay {
                expr,
                overlay_what,
                overlay_from,
                overlay_for,
            } => {
                self.collect_column_refs(expr, table_map, columns);
                self.collect_column_refs(overlay_what, table_map, columns);
                self.collect_column_refs(overlay_from, table_map, columns);
                if let Some(for_expr) = overlay_for {
                    self.collect_column_refs(for_expr, table_map, columns);
                }
            }
            Expr::Like { expr, pattern, .. } | Expr::ILike { expr, pattern, .. } => {
                self.collect_column_refs(expr, table_map, columns);
                self.collect_column_refs(pattern, table_map, columns);
            }
            Expr::Nested(inner) => {
                self.collect_column_refs(inner, table_map, columns);
            }
            Expr::IsNull(inner) | Expr::IsNotNull(inner) => {
                self.collect_column_refs(inner, table_map, columns);
            }
            _ => {
                // Other expressions don't contain column refs we can extract
            }
        }
    }

    /// Infer a column name from an expression (for unnamed SELECT items).
    fn infer_column_name(&self, expr: &Expr) -> String {
        match expr {
            Expr::Identifier(ident) => ident.value.clone(),
            Expr::CompoundIdentifier(parts) => parts
                .last()
                .map(|i| i.value.clone())
                .unwrap_or_else(|| "?column?".to_string()),
            Expr::Function(func) => func.name.to_string(),
            _ => "?column?".to_string(),
        }
    }
}

/// Check if a function name is an aggregate function.
fn is_aggregate_function(name: &str) -> bool {
    matches!(
        name,
        "SUM"
            | "COUNT"
            | "AVG"
            | "MIN"
            | "MAX"
            | "STDDEV"
            | "STDDEV_POP"
            | "STDDEV_SAMP"
            | "VARIANCE"
            | "VAR_POP"
            | "VAR_SAMP"
            | "ARRAY_AGG"
            | "STRING_AGG"
            | "GROUP_CONCAT"
            | "LISTAGG"
            | "BOOL_AND"
            | "BOOL_OR"
            | "EVERY"
            | "BIT_AND"
            | "BIT_OR"
            | "BIT_XOR"
            | "APPROX_COUNT_DISTINCT"
            | "APPROX_PERCENTILE"
            | "PERCENTILE_CONT"
            | "PERCENTILE_DISC"
            | "FIRST_VALUE"
            | "LAST_VALUE"
            | "NTH_VALUE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(sql: &str) -> LineageParseResult {
        ColumnLineageParser::new()
            .parse_lineage(sql, "target")
            .unwrap()
    }

    #[test]
    fn test_simple_select() {
        let result = parse("SELECT customer_id FROM orders");

        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].source_table, "orders");
        assert_eq!(result.edges[0].source_column, "customer_id");
        assert_eq!(result.edges[0].target_column, "customer_id");
        assert_eq!(result.edges[0].transformation, TransformationType::Direct);
    }

    #[test]
    fn test_select_with_alias() {
        let result = parse("SELECT customer_id AS cust_id FROM orders");

        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].source_column, "customer_id");
        assert_eq!(result.edges[0].target_column, "cust_id");
    }

    #[test]
    fn test_qualified_column() {
        let result = parse("SELECT o.customer_id FROM orders o");

        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].source_table, "o");
        assert_eq!(result.edges[0].source_column, "customer_id");
    }

    #[test]
    fn test_multiple_columns() {
        let result = parse("SELECT customer_id, order_date, amount FROM orders");

        assert_eq!(result.edges.len(), 3);
        assert_eq!(result.edges[0].source_column, "customer_id");
        assert_eq!(result.edges[1].source_column, "order_date");
        assert_eq!(result.edges[2].source_column, "amount");
    }

    #[test]
    fn test_aggregate_sum() {
        let result = parse("SELECT SUM(amount) AS total FROM orders");

        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].source_column, "amount");
        assert_eq!(result.edges[0].target_column, "total");
        assert_eq!(
            result.edges[0].transformation,
            TransformationType::Aggregate
        );
        assert!(result.edges[0].expression.is_some());
    }

    #[test]
    fn test_aggregate_count() {
        let result = parse("SELECT COUNT(order_id) AS order_count FROM orders");

        assert_eq!(result.edges.len(), 1);
        assert_eq!(
            result.edges[0].transformation,
            TransformationType::Aggregate
        );
    }

    #[test]
    fn test_binary_expression() {
        let result = parse("SELECT price * quantity AS total FROM orders");

        assert_eq!(result.edges.len(), 2);
        assert!(result.edges.iter().any(|e| e.source_column == "price"));
        assert!(result.edges.iter().any(|e| e.source_column == "quantity"));
        assert!(result.edges.iter().all(|e| e.target_column == "total"));
        assert!(result
            .edges
            .iter()
            .all(|e| e.transformation == TransformationType::Expression));
    }

    #[test]
    fn test_case_expression() {
        let result = parse(
            "SELECT CASE WHEN status = 'active' THEN 1 ELSE 0 END AS is_active FROM customers",
        );

        assert!(result.edges.iter().any(|e| e.source_column == "status"));
        assert!(result
            .edges
            .iter()
            .all(|e| e.transformation == TransformationType::Case));
    }

    #[test]
    fn test_cast_expression() {
        let result = parse("SELECT CAST(amount AS INTEGER) AS amount_int FROM orders");

        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].source_column, "amount");
        assert_eq!(result.edges[0].transformation, TransformationType::Cast);
    }

    #[test]
    fn test_join() {
        let result = parse(
            "SELECT o.order_id, c.customer_name
             FROM orders o
             JOIN customers c ON o.customer_id = c.id",
        );

        assert_eq!(result.edges.len(), 2);
        assert!(result.edges.iter().any(|e| e.source_table == "o"));
        assert!(result.edges.iter().any(|e| e.source_table == "c"));
    }

    #[test]
    fn test_multiple_joins() {
        let result = parse(
            "SELECT o.order_id, c.customer_name, p.product_name
             FROM orders o
             JOIN customers c ON o.customer_id = c.id
             JOIN products p ON o.product_id = p.id",
        );

        assert_eq!(result.edges.len(), 3);
        assert_eq!(result.source_tables.len(), 3);
    }

    #[test]
    fn test_window_function() {
        let result = parse(
            "SELECT customer_id, ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY order_date) as rn FROM orders",
        );

        assert!(result
            .edges
            .iter()
            .any(|e| e.source_column == "customer_id"));
        // ROW_NUMBER with customer_id partition
        assert!(result
            .edges
            .iter()
            .any(|e| e.transformation == TransformationType::Window));
    }

    #[test]
    fn test_nested_function() {
        let result = parse("SELECT UPPER(TRIM(customer_name)) AS clean_name FROM customers");

        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].source_column, "customer_name");
        assert_eq!(
            result.edges[0].transformation,
            TransformationType::Expression
        );
    }

    #[test]
    fn test_select_star_warning() {
        let result = parse("SELECT * FROM orders");

        assert!(result.edges.is_empty());
        assert!(result.warnings.iter().any(|w| w.contains("SELECT *")));
    }

    #[test]
    fn test_empty_query_error() {
        let parser = ColumnLineageParser::new();
        let err = parser.parse_lineage("", "target").unwrap_err();
        assert!(matches!(err, LineageError::EmptyQuery));
    }

    #[test]
    fn test_invalid_sql_error() {
        let parser = ColumnLineageParser::new();
        let err = parser.parse_lineage("SELEC wrong", "target").unwrap_err();
        assert!(matches!(err, LineageError::ParseError(_)));
    }

    #[test]
    fn test_multiple_statements_error() {
        let parser = ColumnLineageParser::new();
        let err = parser
            .parse_lineage("SELECT a FROM t1; SELECT b FROM t2", "target")
            .unwrap_err();
        assert!(matches!(err, LineageError::MultipleStatements(2)));
    }

    #[test]
    fn test_create_table_as_select() {
        let parser = ColumnLineageParser::new();
        let result = parser
            .parse_lineage(
                "CREATE TABLE summary AS SELECT customer_id, SUM(amount) AS total FROM orders GROUP BY customer_id",
                "ignored", // table name comes from CREATE TABLE
            )
            .unwrap();

        assert_eq!(result.edges.len(), 2);
    }

    #[test]
    fn test_source_tables_extracted() {
        let result =
            parse("SELECT o.id, c.name FROM orders o JOIN customers c ON o.cust_id = c.id");

        assert_eq!(result.source_tables.len(), 2);
        assert!(result.source_tables.iter().any(|t| t.name == "orders"));
        assert!(result.source_tables.iter().any(|t| t.name == "customers"));
    }

    #[test]
    fn test_group_by_with_aggregate() {
        // Use COUNT(order_id) instead of COUNT(*) since COUNT(*) doesn't reference a column
        let result = parse(
            "SELECT customer_id, COUNT(order_id) as order_count, SUM(amount) as total
             FROM orders
             GROUP BY customer_id",
        );

        assert!(result
            .edges
            .iter()
            .any(|e| e.source_column == "customer_id"));
        assert!(result
            .edges
            .iter()
            .any(|e| e.target_column == "order_count"));
        assert!(result.edges.iter().any(|e| e.target_column == "total"));
    }

    #[test]
    fn test_count_star_no_lineage() {
        // COUNT(*) doesn't reference a specific column, so no lineage edge
        let result = parse("SELECT COUNT(*) as row_count FROM orders");

        // COUNT(*) has no column references, so no edges
        assert!(result.edges.is_empty());
    }

    #[test]
    fn test_left_join() {
        let result = parse(
            "SELECT o.id, c.name
             FROM orders o
             LEFT JOIN customers c ON o.customer_id = c.id",
        );

        assert_eq!(result.edges.len(), 2);
    }

    #[test]
    fn test_arithmetic_with_alias() {
        let result = parse("SELECT (price * quantity) - discount AS net_amount FROM orders");

        assert!(result.edges.iter().any(|e| e.source_column == "price"));
        assert!(result.edges.iter().any(|e| e.source_column == "quantity"));
        assert!(result.edges.iter().any(|e| e.source_column == "discount"));
        assert!(result.edges.iter().all(|e| e.target_column == "net_amount"));
    }
}
