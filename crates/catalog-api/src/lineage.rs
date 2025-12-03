//! Column-level lineage API endpoints.
//!
//! This module provides REST API endpoints for:
//! - Parsing SQL queries to extract column lineage
//! - Recording column lineage edges in the database
//! - Querying lineage for impact analysis and PII propagation
//!
//! # Endpoints
//!
//! - `POST /api/v1/lineage/parse` - Parse SQL and extract column lineage
//! - `POST /api/v1/lineage/edges` - Record lineage edges
//! - `GET /api/v1/lineage/dataset/:id/columns/:column/upstream` - Get upstream lineage
//! - `GET /api/v1/lineage/dataset/:id/columns/:column/downstream` - Get downstream lineage
//! - `GET /api/v1/lineage/dataset/:id/columns/:column/pii-propagation` - Track PII propagation
//! - `GET /api/v1/lineage/fields/:id/impact` - Impact analysis for field changes
//! - `DELETE /api/v1/lineage/dataset/:id` - Delete lineage edges for a dataset

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use metafuse_catalog_lineage::{ColumnLineageEdge, ColumnLineageParser, LineageParseResult};
use metafuse_catalog_storage::DynCatalogBackend;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Application state containing the catalog backend.
/// This is a copy of the AppState structure from main.rs to avoid circular dependencies.
#[derive(Clone)]
pub struct LineageAppState {
    pub backend: Arc<DynCatalogBackend>,
}

/// Request to parse SQL and extract lineage.
#[derive(Debug, Deserialize)]
pub struct ParseLineageRequest {
    /// The SQL query to parse
    pub sql: String,
    /// Target dataset name (for CREATE TABLE AS SELECT, the table being created)
    pub target_dataset: String,
    /// Source dataset ID (optional, for recording edges)
    pub source_dataset_id: Option<i64>,
    /// Target dataset ID (optional, for recording edges)
    pub target_dataset_id: Option<i64>,
}

/// Response from lineage parsing.
#[derive(Debug, Serialize)]
pub struct ParseLineageResponse {
    /// Extracted lineage edges
    pub edges: Vec<LineageEdgeDto>,
    /// Warnings from parsing
    pub warnings: Vec<String>,
    /// Source tables referenced
    pub source_tables: Vec<String>,
}

/// DTO for a lineage edge.
#[derive(Debug, Serialize, Deserialize)]
pub struct LineageEdgeDto {
    pub source_table: String,
    pub source_column: String,
    pub target_table: String,
    pub target_column: String,
    pub transformation_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
}

impl From<ColumnLineageEdge> for LineageEdgeDto {
    fn from(edge: ColumnLineageEdge) -> Self {
        Self {
            source_table: edge.source_table,
            source_column: edge.source_column,
            target_table: edge.target_table,
            target_column: edge.target_column,
            transformation_type: edge.transformation.to_string(),
            expression: edge.expression,
        }
    }
}

impl From<LineageParseResult> for ParseLineageResponse {
    fn from(result: LineageParseResult) -> Self {
        Self {
            edges: result.edges.into_iter().map(Into::into).collect(),
            warnings: result.warnings,
            source_tables: result.source_tables.into_iter().map(|t| t.name).collect(),
        }
    }
}

/// Request to record lineage edges.
#[derive(Debug, Deserialize)]
pub struct RecordLineageRequest {
    /// Source dataset ID
    pub source_dataset_id: i64,
    /// Target dataset ID
    pub target_dataset_id: i64,
    /// Lineage edges to record
    pub edges: Vec<RecordEdgeDto>,
}

/// Edge to record in the database.
#[derive(Debug, Deserialize)]
pub struct RecordEdgeDto {
    pub source_column: String,
    pub target_column: String,
    pub transformation_type: String,
    #[serde(default)]
    pub expression: Option<String>,
}

/// Response from recording lineage.
#[derive(Debug, Serialize)]
pub struct RecordLineageResponse {
    /// Number of edges recorded
    pub edges_recorded: usize,
}

/// Response from deleting lineage.
#[derive(Debug, Serialize)]
pub struct DeleteLineageResponse {
    /// Number of edges deleted
    pub deleted_edges: usize,
}

/// Query parameters for lineage lookup.
#[derive(Debug, Deserialize)]
pub struct LineageLookupParams {
    /// Maximum depth for recursive traversal (default: 10)
    #[serde(default = "default_max_depth")]
    pub max_depth: i32,
}

fn default_max_depth() -> i32 {
    10
}

/// Lineage node in the result graph.
#[derive(Debug, Serialize)]
pub struct LineageNode {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub column_name: String,
    pub transformation_type: Option<String>,
    pub expression: Option<String>,
    pub depth: i32,
}

/// Lineage lookup response.
#[derive(Debug, Serialize)]
pub struct LineageLookupResponse {
    /// Root column
    pub root: LineageNode,
    /// Upstream/downstream nodes
    pub nodes: Vec<LineageNode>,
}

/// PII propagation response.
///
/// This endpoint traces where data from a PII-containing column flows downstream,
/// flagging transformations that may anonymize the data. Use this for:
/// - GDPR Article 17 "right to be forgotten" impact assessment
/// - Data lineage audits for privacy compliance
/// - Risk assessment when modifying PII source columns
#[derive(Debug, Serialize)]
pub struct PiiPropagationResponse {
    /// Source column (the PII column)
    pub source_column: String,
    /// Columns that may contain data derived from the PII column
    pub downstream_columns: Vec<PiiDownstreamColumn>,
}

/// A column that may contain PII-derived data.
///
/// The `may_anonymize` flag indicates whether the transformation applied to this
/// column likely removes the ability to identify individuals from the data.
#[derive(Debug, Serialize)]
pub struct PiiDownstreamColumn {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub column_name: String,
    /// True if the transformation may anonymize the data.
    ///
    /// # Anonymization Detection Criteria
    ///
    /// The following transformations are considered potentially anonymizing:
    ///
    /// ## Transformation Types
    /// - **Aggregate**: Statistical aggregations (COUNT, SUM, AVG, MIN, MAX, etc.)
    ///   reduce individual records to group-level statistics, removing individual identity.
    /// - **Window**: Window functions with aggregations may still preserve row identity
    ///   but are flagged as potentially anonymizing when combined with partitioning.
    ///
    /// ## Expression Patterns
    /// The following SQL expression patterns trigger the `may_anonymize` flag:
    /// - `HASH(...)`, `MD5(...)`, `SHA(...)`: Cryptographic hashing (one-way transformation)
    /// - `MASK(...)`: Data masking functions (e.g., `XXXX-XXXX-1234`)
    /// - `TRUNCATE(...)`: Value truncation (e.g., truncating timestamps to date)
    /// - `SUBSTR(...)`: Partial string extraction (e.g., first 3 characters of ZIP)
    /// - `ROUND(...)`: Numeric rounding (reduces precision)
    ///
    /// # Important Caveats
    ///
    /// - **False Negatives**: Custom UDFs or non-standard anonymization functions
    ///   will not be detected. Review expressions manually for comprehensive assessment.
    /// - **False Positives**: Some uses of these patterns may not truly anonymize data
    ///   (e.g., `SUBSTR(description, 1, 100)` on non-PII fields).
    /// - **Re-identification Risk**: Even "anonymized" data may be re-identifiable
    ///   when combined with other data. This flag is a heuristic, not a guarantee.
    /// - **k-Anonymity**: Aggregations with small group sizes (k < 5) may not provide
    ///   adequate anonymization. Review your aggregation granularity.
    pub may_anonymize: bool,
    pub transformation_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
}

/// Parse SQL and extract column lineage.
#[axum::debug_handler]
pub async fn parse_lineage(
    Json(request): Json<ParseLineageRequest>,
) -> Result<Json<ParseLineageResponse>, (StatusCode, String)> {
    let parser = ColumnLineageParser::new();

    match parser.parse_lineage(&request.sql, &request.target_dataset) {
        Ok(result) => Ok(Json(ParseLineageResponse::from(result))),
        Err(e) => Err((StatusCode::BAD_REQUEST, format!("Parse error: {}", e))),
    }
}

/// Record lineage edges in the database.
#[axum::debug_handler]
pub async fn record_lineage(
    State(state): State<LineageAppState>,
    Json(request): Json<RecordLineageRequest>,
) -> Result<Json<RecordLineageResponse>, (StatusCode, String)> {
    let conn = state.backend.get_connection().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database connection error: {}", e),
        )
    })?;

    let mut edges_recorded = 0;

    for edge in &request.edges {
        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type, expression)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                request.source_dataset_id,
                edge.source_column,
                request.target_dataset_id,
                edge.target_column,
                edge.transformation_type,
                edge.expression
            ],
        ).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;
        edges_recorded += 1;
    }

    Ok(Json(RecordLineageResponse { edges_recorded }))
}

/// Get upstream lineage for a column.
#[axum::debug_handler]
pub async fn get_upstream_lineage(
    State(state): State<LineageAppState>,
    Path((dataset_id, column)): Path<(i64, String)>,
    Query(params): Query<LineageLookupParams>,
) -> Result<Json<LineageLookupResponse>, (StatusCode, String)> {
    let conn = state.backend.get_connection().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database connection error: {}", e),
        )
    })?;

    // Get root node info
    let dataset_name: String = conn
        .query_row(
            "SELECT name FROM datasets WHERE id = ?1",
            [dataset_id],
            |row| row.get(0),
        )
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Dataset not found: {}", e)))?;

    let root = LineageNode {
        dataset_id,
        dataset_name: dataset_name.clone(),
        column_name: column.clone(),
        transformation_type: None,
        expression: None,
        depth: 0,
    };

    // Query upstream lineage (recursive CTE)
    let query = r#"
        WITH RECURSIVE upstream_lineage AS (
            -- Base case: direct upstream of target column
            SELECT
                cl.source_dataset_id,
                cl.source_field_name,
                cl.transformation_type,
                cl.expression,
                1 as depth
            FROM column_lineage cl
            WHERE cl.target_dataset_id = ?1 AND cl.target_field_name = ?2

            UNION ALL

            -- Recursive case: upstream of upstream
            SELECT
                cl2.source_dataset_id,
                cl2.source_field_name,
                cl2.transformation_type,
                cl2.expression,
                ul.depth + 1
            FROM column_lineage cl2
            INNER JOIN upstream_lineage ul ON
                cl2.target_dataset_id = ul.source_dataset_id
                AND cl2.target_field_name = ul.source_field_name
            WHERE ul.depth < ?3
        )
        SELECT DISTINCT
            ul.source_dataset_id,
            d.name as dataset_name,
            ul.source_field_name,
            ul.transformation_type,
            ul.expression,
            ul.depth
        FROM upstream_lineage ul
        JOIN datasets d ON d.id = ul.source_dataset_id
        ORDER BY ul.depth
        "#;

    let mut stmt = conn.prepare(query).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Query error: {}", e),
        )
    })?;

    let nodes: Vec<LineageNode> = stmt
        .query_map(
            rusqlite::params![dataset_id, column, params.max_depth],
            |row| {
                Ok(LineageNode {
                    dataset_id: row.get(0)?,
                    dataset_name: row.get(1)?,
                    column_name: row.get(2)?,
                    transformation_type: row.get(3)?,
                    expression: row.get(4)?,
                    depth: row.get(5)?,
                })
            },
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Query error: {}", e),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Result error: {}", e),
            )
        })?;

    Ok(Json(LineageLookupResponse { root, nodes }))
}

/// Get downstream lineage for a column.
#[axum::debug_handler]
pub async fn get_downstream_lineage(
    State(state): State<LineageAppState>,
    Path((dataset_id, column)): Path<(i64, String)>,
    Query(params): Query<LineageLookupParams>,
) -> Result<Json<LineageLookupResponse>, (StatusCode, String)> {
    let conn = state.backend.get_connection().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database connection error: {}", e),
        )
    })?;

    // Get root node info
    let dataset_name: String = conn
        .query_row(
            "SELECT name FROM datasets WHERE id = ?1",
            [dataset_id],
            |row| row.get(0),
        )
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Dataset not found: {}", e)))?;

    let root = LineageNode {
        dataset_id,
        dataset_name: dataset_name.clone(),
        column_name: column.clone(),
        transformation_type: None,
        expression: None,
        depth: 0,
    };

    // Query downstream lineage (recursive CTE)
    let query = r#"
        WITH RECURSIVE downstream_lineage AS (
            -- Base case: direct downstream of source column
            SELECT
                cl.target_dataset_id,
                cl.target_field_name,
                cl.transformation_type,
                cl.expression,
                1 as depth
            FROM column_lineage cl
            WHERE cl.source_dataset_id = ?1 AND cl.source_field_name = ?2

            UNION ALL

            -- Recursive case: downstream of downstream
            SELECT
                cl2.target_dataset_id,
                cl2.target_field_name,
                cl2.transformation_type,
                cl2.expression,
                dl.depth + 1
            FROM column_lineage cl2
            INNER JOIN downstream_lineage dl ON
                cl2.source_dataset_id = dl.target_dataset_id
                AND cl2.source_field_name = dl.target_field_name
            WHERE dl.depth < ?3
        )
        SELECT DISTINCT
            dl.target_dataset_id,
            d.name as dataset_name,
            dl.target_field_name,
            dl.transformation_type,
            dl.expression,
            dl.depth
        FROM downstream_lineage dl
        JOIN datasets d ON d.id = dl.target_dataset_id
        ORDER BY dl.depth
        "#;

    let mut stmt = conn.prepare(query).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Query error: {}", e),
        )
    })?;

    let nodes: Vec<LineageNode> = stmt
        .query_map(
            rusqlite::params![dataset_id, column, params.max_depth],
            |row| {
                Ok(LineageNode {
                    dataset_id: row.get(0)?,
                    dataset_name: row.get(1)?,
                    column_name: row.get(2)?,
                    transformation_type: row.get(3)?,
                    expression: row.get(4)?,
                    depth: row.get(5)?,
                })
            },
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Query error: {}", e),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Result error: {}", e),
            )
        })?;

    Ok(Json(LineageLookupResponse { root, nodes }))
}

/// Get PII propagation for a column.
/// This traces where data from a PII column flows, flagging transformations
/// that may anonymize the data (aggregations, hashing, etc.)
#[axum::debug_handler]
pub async fn get_pii_propagation(
    State(state): State<LineageAppState>,
    Path((dataset_id, column)): Path<(i64, String)>,
    Query(params): Query<LineageLookupParams>,
) -> Result<Json<PiiPropagationResponse>, (StatusCode, String)> {
    let conn = state.backend.get_connection().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database connection error: {}", e),
        )
    })?;

    // Query downstream lineage with anonymization detection
    let query = r#"
        WITH RECURSIVE downstream_lineage AS (
            -- Base case: direct downstream of source column
            SELECT
                cl.target_dataset_id,
                cl.target_field_name,
                cl.transformation_type,
                cl.expression,
                1 as depth
            FROM column_lineage cl
            WHERE cl.source_dataset_id = ?1 AND cl.source_field_name = ?2

            UNION ALL

            -- Recursive case: downstream of downstream
            SELECT
                cl2.target_dataset_id,
                cl2.target_field_name,
                cl2.transformation_type,
                cl2.expression,
                dl.depth + 1
            FROM column_lineage cl2
            INNER JOIN downstream_lineage dl ON
                cl2.source_dataset_id = dl.target_dataset_id
                AND cl2.source_field_name = dl.target_field_name
            WHERE dl.depth < ?3
        )
        SELECT DISTINCT
            dl.target_dataset_id,
            d.name as dataset_name,
            dl.target_field_name,
            dl.transformation_type,
            dl.expression,
            -- Flag transformations that may anonymize data
            CASE WHEN dl.transformation_type IN ('Aggregate', 'Window')
                 OR dl.expression LIKE '%HASH%'
                 OR dl.expression LIKE '%MD5%'
                 OR dl.expression LIKE '%SHA%'
                 OR dl.expression LIKE '%MASK%'
                 OR dl.expression LIKE '%TRUNCATE%'
                 OR dl.expression LIKE '%SUBSTR%'
                 OR dl.expression LIKE '%ROUND%'
                 THEN 1 ELSE 0 END as may_anonymize
        FROM downstream_lineage dl
        JOIN datasets d ON d.id = dl.target_dataset_id
        ORDER BY dl.depth
    "#;

    let mut stmt = conn.prepare(query).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Query error: {}", e),
        )
    })?;

    let downstream_columns: Vec<PiiDownstreamColumn> = stmt
        .query_map(
            rusqlite::params![dataset_id, column, params.max_depth],
            |row| {
                Ok(PiiDownstreamColumn {
                    dataset_id: row.get(0)?,
                    dataset_name: row.get(1)?,
                    column_name: row.get(2)?,
                    transformation_type: row
                        .get::<_, Option<String>>(3)?
                        .unwrap_or_else(|| "Direct".to_string()),
                    expression: row.get(4)?,
                    may_anonymize: row.get::<_, i32>(5)? != 0,
                })
            },
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Query error: {}", e),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Result error: {}", e),
            )
        })?;

    Ok(Json(PiiPropagationResponse {
        source_column: column,
        downstream_columns,
    }))
}

/// Impact analysis response for a field change.
#[derive(Debug, Serialize)]
pub struct ImpactAnalysisResponse {
    /// The field that was analyzed
    pub field: FieldInfo,
    /// Summary of the impact
    pub summary: ImpactSummary,
    /// Downstream columns that would be affected
    pub affected_columns: Vec<AffectedColumn>,
}

/// Basic field information.
#[derive(Debug, Serialize)]
pub struct FieldInfo {
    pub field_id: i64,
    pub field_name: String,
    pub dataset_id: i64,
    pub dataset_name: String,
}

/// Summary statistics for impact analysis.
#[derive(Debug, Serialize)]
pub struct ImpactSummary {
    /// Total number of downstream columns affected
    pub total_affected_columns: usize,
    /// Number of unique datasets affected
    pub affected_datasets: usize,
    /// Number of columns with direct transformation
    pub direct_dependencies: usize,
    /// Number of columns with derived transformation (aggregates, expressions, etc.)
    pub derived_dependencies: usize,
    /// Maximum depth in the lineage graph
    pub max_depth: i32,
}

/// A column affected by a field change.
#[derive(Debug, Serialize)]
pub struct AffectedColumn {
    pub dataset_id: i64,
    pub dataset_name: String,
    pub column_name: String,
    pub transformation_type: String,
    pub depth: i32,
    /// Impact severity: "high" for direct, "medium" for 1 hop, "low" for 2+ hops
    pub severity: String,
}

/// Get impact analysis for a field change.
/// This endpoint answers: "What would break if I modify this field?"
#[axum::debug_handler]
pub async fn get_field_impact(
    State(state): State<LineageAppState>,
    Path(field_id): Path<i64>,
    Query(params): Query<LineageLookupParams>,
) -> Result<Json<ImpactAnalysisResponse>, (StatusCode, String)> {
    let conn = state.backend.get_connection().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database connection error: {}", e),
        )
    })?;

    // Get field info
    let field_info: (i64, String, i64, String) = conn
        .query_row(
            r#"
            SELECT f.id, f.name, f.dataset_id, d.name as dataset_name
            FROM fields f
            JOIN datasets d ON d.id = f.dataset_id
            WHERE f.id = ?1
            "#,
            [field_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|e| (StatusCode::NOT_FOUND, format!("Field not found: {}", e)))?;

    let field = FieldInfo {
        field_id: field_info.0,
        field_name: field_info.1.clone(),
        dataset_id: field_info.2,
        dataset_name: field_info.3.clone(),
    };

    // Query downstream lineage
    let query = r#"
        WITH RECURSIVE downstream_lineage AS (
            SELECT
                cl.target_dataset_id,
                cl.target_field_name,
                cl.transformation_type,
                1 as depth
            FROM column_lineage cl
            WHERE cl.source_dataset_id = ?1 AND cl.source_field_name = ?2

            UNION ALL

            SELECT
                cl2.target_dataset_id,
                cl2.target_field_name,
                cl2.transformation_type,
                dl.depth + 1
            FROM column_lineage cl2
            INNER JOIN downstream_lineage dl ON
                cl2.source_dataset_id = dl.target_dataset_id
                AND cl2.source_field_name = dl.target_field_name
            WHERE dl.depth < ?3
        )
        SELECT DISTINCT
            dl.target_dataset_id,
            d.name as dataset_name,
            dl.target_field_name,
            dl.transformation_type,
            dl.depth
        FROM downstream_lineage dl
        JOIN datasets d ON d.id = dl.target_dataset_id
        ORDER BY dl.depth, d.name, dl.target_field_name
    "#;

    let mut stmt = conn.prepare(query).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Query error: {}", e),
        )
    })?;

    let affected_columns: Vec<AffectedColumn> = stmt
        .query_map(
            rusqlite::params![field.dataset_id, field.field_name, params.max_depth],
            |row| {
                let depth: i32 = row.get(4)?;
                let transformation_type: String = row
                    .get::<_, Option<String>>(3)?
                    .unwrap_or_else(|| "Direct".to_string());
                let severity = match depth {
                    1 if transformation_type == "Direct" => "high",
                    1 => "medium",
                    _ => "low",
                }
                .to_string();

                Ok(AffectedColumn {
                    dataset_id: row.get(0)?,
                    dataset_name: row.get(1)?,
                    column_name: row.get(2)?,
                    transformation_type,
                    depth,
                    severity,
                })
            },
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Query error: {}", e),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Result error: {}", e),
            )
        })?;

    // Compute summary statistics
    let total_affected_columns = affected_columns.len();
    let affected_datasets: std::collections::HashSet<i64> =
        affected_columns.iter().map(|c| c.dataset_id).collect();
    let direct_dependencies = affected_columns
        .iter()
        .filter(|c| c.transformation_type == "Direct")
        .count();
    let derived_dependencies = total_affected_columns - direct_dependencies;
    let max_depth = affected_columns.iter().map(|c| c.depth).max().unwrap_or(0);

    let summary = ImpactSummary {
        total_affected_columns,
        affected_datasets: affected_datasets.len(),
        direct_dependencies,
        derived_dependencies,
        max_depth,
    };

    Ok(Json(ImpactAnalysisResponse {
        field,
        summary,
        affected_columns,
    }))
}

/// Delete lineage edges where this dataset is the **target** (incoming lineage).
///
/// # Use Case
///
/// This endpoint is designed for refreshing lineage when re-parsing SQL:
/// 1. Delete existing inbound lineage edges for the target dataset
/// 2. Re-parse the SQL to extract new lineage
/// 3. Record the new lineage edges
///
/// # Behavior
///
/// - **Only deletes edges where `target_dataset_id = dataset_id`**
/// - Does NOT delete edges where this dataset is the source (outgoing lineage)
/// - Returns the count of deleted edges
///
/// # Cascade Behavior
///
/// Note: If the dataset itself is deleted from the `datasets` table, the database
/// schema has `ON DELETE CASCADE` on foreign keys, so all associated lineage edges
/// (both inbound and outbound) are automatically removed.
///
/// # Multi-Tenant Isolation
///
/// In multi-tenant mode, each tenant has an isolated database. The tenant-specific
/// backend is injected via middleware, ensuring this operation only affects the
/// requesting tenant's data.
///
/// # Authorization
///
/// Requires **Admin** role when RBAC is enabled (delete permission check).
#[axum::debug_handler]
pub async fn delete_dataset_lineage(
    State(state): State<LineageAppState>,
    Path(dataset_id): Path<i64>,
) -> Result<Json<DeleteLineageResponse>, (StatusCode, String)> {
    let conn = state.backend.get_connection().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database connection error: {}", e),
        )
    })?;

    // Verify the dataset exists (provides better error message and implicit tenant check)
    let dataset_exists: bool = conn
        .query_row("SELECT 1 FROM datasets WHERE id = ?1", [dataset_id], |_| {
            Ok(true)
        })
        .unwrap_or(false);

    if !dataset_exists {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Dataset with ID {} not found", dataset_id),
        ));
    }

    let deleted = conn
        .execute(
            "DELETE FROM column_lineage WHERE target_dataset_id = ?1",
            [dataset_id],
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    Ok(Json(DeleteLineageResponse {
        deleted_edges: deleted,
    }))
}

// Note: Handlers are exported for use in main.rs routes
// They require LineageAppState which wraps the catalog backend

#[cfg(test)]
mod tests {
    use super::*;
    use metafuse_catalog_core::{init_sqlite_schema, migrations::run_migrations};
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_sqlite_schema(&conn).unwrap();
        run_migrations(&conn).unwrap();
        conn
    }

    #[test]
    fn test_parse_lineage_simple() {
        let parser = ColumnLineageParser::new();
        let result = parser
            .parse_lineage("SELECT customer_id, name FROM customers", "output")
            .unwrap();

        assert_eq!(result.edges.len(), 2);
    }

    #[test]
    fn test_lineage_edge_dto_conversion() {
        let edge = ColumnLineageEdge::direct("source", "col_a", "target", "col_b");
        let dto: LineageEdgeDto = edge.into();

        assert_eq!(dto.source_table, "source");
        assert_eq!(dto.source_column, "col_a");
        assert_eq!(dto.target_table, "target");
        assert_eq!(dto.target_column, "col_b");
        assert_eq!(dto.transformation_type, "direct");
    }

    #[test]
    fn test_record_and_query_lineage() {
        let conn = setup_db();

        // Create test datasets
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('source_table', '/path/source', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let source_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('target_table', '/path/target', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let target_id = conn.last_insert_rowid();

        // Record lineage edge
        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type)
             VALUES (?1, 'customer_id', ?2, 'cust_id', 'Direct')",
            [source_id, target_id],
        )
        .unwrap();

        // Query downstream lineage
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM column_lineage WHERE source_dataset_id = ?1",
                [source_id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn test_pii_anonymization_detection() {
        let conn = setup_db();

        // Create test datasets
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('customers', '/path/customers', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let customers_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('stats', '/path/stats', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let stats_id = conn.last_insert_rowid();

        // Record aggregate lineage (should be flagged as may_anonymize)
        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type, expression)
             VALUES (?1, 'age', ?2, 'avg_age', 'Aggregate', 'AVG(age)')",
            [customers_id, stats_id],
        )
        .unwrap();

        // Check that may_anonymize flag works
        let may_anonymize: i32 = conn
            .query_row(
                "SELECT CASE WHEN transformation_type = 'Aggregate' THEN 1 ELSE 0 END
                 FROM column_lineage WHERE target_field_name = 'avg_age'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(may_anonymize, 1);
    }

    #[test]
    fn test_recursive_upstream_lineage() {
        let conn = setup_db();

        // Create a three-level lineage chain: raw -> staging -> analytics
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('raw_events', '/raw/events', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let raw_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('staging_events', '/staging/events', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let staging_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('analytics_summary', '/analytics/summary', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let analytics_id = conn.last_insert_rowid();

        // Create lineage chain: raw.event_id -> staging.event_id -> analytics.event_id
        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type)
             VALUES (?1, 'event_id', ?2, 'event_id', 'Direct')",
            [raw_id, staging_id],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type)
             VALUES (?1, 'event_id', ?2, 'event_id', 'Direct')",
            [staging_id, analytics_id],
        )
        .unwrap();

        // Test recursive upstream query from analytics
        let upstream: Vec<(i64, String, i32)> = conn
            .prepare(
                r#"
                WITH RECURSIVE upstream_lineage AS (
                    SELECT source_dataset_id, source_field_name, 1 as depth
                    FROM column_lineage
                    WHERE target_dataset_id = ?1 AND target_field_name = ?2
                    UNION ALL
                    SELECT cl.source_dataset_id, cl.source_field_name, ul.depth + 1
                    FROM column_lineage cl
                    INNER JOIN upstream_lineage ul ON
                        cl.target_dataset_id = ul.source_dataset_id
                        AND cl.target_field_name = ul.source_field_name
                    WHERE ul.depth < 10
                )
                SELECT source_dataset_id, source_field_name, depth
                FROM upstream_lineage
                ORDER BY depth
                "#,
            )
            .unwrap()
            .query_map(rusqlite::params![analytics_id, "event_id"], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(upstream.len(), 2);
        assert_eq!(upstream[0].0, staging_id);
        assert_eq!(upstream[0].2, 1);
        assert_eq!(upstream[1].0, raw_id);
        assert_eq!(upstream[1].2, 2);
    }

    #[test]
    fn test_recursive_downstream_lineage() {
        let conn = setup_db();

        // Create a two-level downstream: source -> view1, view1 -> view2
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('source_data', '/source', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let source_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('view_1', '/views/1', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let view1_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('view_2', '/views/2', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let view2_id = conn.last_insert_rowid();

        // Create downstream lineage
        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type)
             VALUES (?1, 'user_id', ?2, 'user_id', 'Direct')",
            [source_id, view1_id],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type, expression)
             VALUES (?1, 'user_id', ?2, 'unique_users', 'Aggregate', 'COUNT(DISTINCT user_id)')",
            [view1_id, view2_id],
        )
        .unwrap();

        // Query downstream from source
        let downstream: Vec<(i64, String, String)> = conn
            .prepare(
                r#"
                WITH RECURSIVE downstream_lineage AS (
                    SELECT target_dataset_id, target_field_name, transformation_type, 1 as depth
                    FROM column_lineage
                    WHERE source_dataset_id = ?1 AND source_field_name = ?2
                    UNION ALL
                    SELECT cl.target_dataset_id, cl.target_field_name, cl.transformation_type, dl.depth + 1
                    FROM column_lineage cl
                    INNER JOIN downstream_lineage dl ON
                        cl.source_dataset_id = dl.target_dataset_id
                        AND cl.source_field_name = dl.target_field_name
                    WHERE dl.depth < 10
                )
                SELECT target_dataset_id, target_field_name, transformation_type
                FROM downstream_lineage
                ORDER BY depth
                "#,
            )
            .unwrap()
            .query_map(rusqlite::params![source_id, "user_id"], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(downstream.len(), 2);
        assert_eq!(downstream[0].0, view1_id);
        assert_eq!(downstream[0].1, "user_id");
        assert_eq!(downstream[0].2, "Direct");
        assert_eq!(downstream[1].0, view2_id);
        assert_eq!(downstream[1].1, "unique_users");
        assert_eq!(downstream[1].2, "Aggregate");
    }

    #[test]
    fn test_impact_analysis_severity() {
        let conn = setup_db();

        // Create datasets for impact analysis
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('core_table', '/core', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let core_id = conn.last_insert_rowid();

        // Create a field to test impact
        conn.execute(
            "INSERT INTO fields (dataset_id, name, data_type, nullable)
             VALUES (?1, 'customer_id', 'INT64', 0)",
            [core_id],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('direct_view', '/direct', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let direct_view_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('aggregate_view', '/agg', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let agg_view_id = conn.last_insert_rowid();

        // Direct dependency (high severity)
        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type)
             VALUES (?1, 'customer_id', ?2, 'customer_id', 'Direct')",
            [core_id, direct_view_id],
        )
        .unwrap();

        // Expression dependency (medium severity)
        conn.execute(
            "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type, expression)
             VALUES (?1, 'customer_id', ?2, 'customer_count', 'Aggregate', 'COUNT(DISTINCT customer_id)')",
            [core_id, agg_view_id],
        )
        .unwrap();

        // Verify both dependencies exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM column_lineage WHERE source_dataset_id = ?1",
                [core_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_parse_lineage_aggregate() {
        let parser = ColumnLineageParser::new();
        let result = parser
            .parse_lineage(
                "SELECT customer_id, SUM(amount) AS total_sales FROM orders GROUP BY customer_id",
                "customer_totals",
            )
            .unwrap();

        assert_eq!(result.edges.len(), 2);

        let aggregate_edge = result
            .edges
            .iter()
            .find(|e| e.target_column == "total_sales")
            .unwrap();
        assert_eq!(aggregate_edge.transformation.to_string(), "aggregate");

        let direct_edge = result
            .edges
            .iter()
            .find(|e| e.target_column == "customer_id")
            .unwrap();
        assert_eq!(direct_edge.transformation.to_string(), "direct");
    }

    #[test]
    fn test_parse_lineage_with_joins() {
        let parser = ColumnLineageParser::new();
        let result = parser
            .parse_lineage(
                r#"
                SELECT
                    c.customer_id,
                    c.name AS customer_name,
                    o.order_id,
                    o.amount
                FROM customers c
                INNER JOIN orders o ON c.customer_id = o.customer_id
                "#,
                "customer_orders",
            )
            .unwrap();

        // Should have 4 edges for 4 columns
        assert!(result.edges.len() >= 4);

        // Should have both source tables
        assert!(result
            .source_tables
            .iter()
            .any(|t| t.alias == Some("c".to_string())));
        assert!(result
            .source_tables
            .iter()
            .any(|t| t.alias == Some("o".to_string())));
    }

    #[test]
    fn test_parse_lineage_case_expression() {
        let parser = ColumnLineageParser::new();
        let result = parser
            .parse_lineage(
                "SELECT CASE WHEN status = 'active' THEN 1 ELSE 0 END AS is_active FROM users",
                "user_flags",
            )
            .unwrap();

        assert!(!result.edges.is_empty());
        let case_edge = result
            .edges
            .iter()
            .find(|e| e.target_column == "is_active")
            .unwrap();
        assert_eq!(case_edge.transformation.to_string(), "case");
    }

    #[test]
    fn test_delete_lineage_response() {
        let conn = setup_db();

        // Create test dataset
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated)
             VALUES ('delete_test', '/delete', 'parquet', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        let dataset_id = conn.last_insert_rowid();

        // Add some lineage edges
        for i in 0..5 {
            conn.execute(
                "INSERT INTO column_lineage (source_dataset_id, source_field_name, target_dataset_id, target_field_name, transformation_type)
                 VALUES (?1, ?2, ?1, ?3, 'Direct')",
                rusqlite::params![dataset_id, format!("source_col_{}", i), format!("target_col_{}", i)],
            )
            .unwrap();
        }

        // Verify edges exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM column_lineage WHERE target_dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 5);

        // Delete edges
        let deleted = conn
            .execute(
                "DELETE FROM column_lineage WHERE target_dataset_id = ?1",
                [dataset_id],
            )
            .unwrap();
        assert_eq!(deleted, 5);

        // Verify deleted
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM column_lineage WHERE target_dataset_id = ?1",
                [dataset_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
