//! Error types for column lineage parsing.

use thiserror::Error;

/// Errors that can occur during column lineage extraction.
#[derive(Debug, Error)]
pub enum LineageError {
    /// SQL parsing failed
    #[error("SQL parsing failed: {0}")]
    ParseError(String),

    /// Unsupported SQL statement type
    #[error("Unsupported SQL statement: {0}")]
    UnsupportedStatement(String),

    /// Unsupported SQL expression
    #[error("Unsupported expression: {0}")]
    UnsupportedExpression(String),

    /// Missing required information
    #[error("Missing required information: {0}")]
    MissingInfo(String),

    /// Multiple statements in query (only single statement supported)
    #[error("Multiple statements not supported, found {0} statements")]
    MultipleStatements(usize),

    /// Empty query
    #[error("Empty SQL query")]
    EmptyQuery,
}

impl From<sqlparser::parser::ParserError> for LineageError {
    fn from(err: sqlparser::parser::ParserError) -> Self {
        LineageError::ParseError(err.to_string())
    }
}

/// A specialized Result type for lineage operations.
pub type Result<T> = std::result::Result<T, LineageError>;
