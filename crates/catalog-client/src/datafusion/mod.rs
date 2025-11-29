//! DataFusion integration for MetaFuse.
//!
//! This module provides DataFusion catalog/schema/table providers that allow
//! querying MetaFuse datasets using SQL.
//!
//! # Architecture
//!
//! The integration follows DataFusion's catalog hierarchy:
//!
//! ```text
//! MetafuseCatalogProvider (catalog)
//! └── MetafuseSchemaProvider (domain = schema)
//!     └── MetafuseTableProvider (dataset = table)
//! ```
//!
//! - **Domains** map to DataFusion **schemas**
//! - **Datasets** map to DataFusion **tables**
//!
//! # Example
//!
//! ```rust,ignore
//! use datafusion::prelude::*;
//! use metafuse_catalog_client::{MetafuseClient, ClientConfig};
//! use metafuse_catalog_client::datafusion::MetafuseCatalogProvider;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let ctx = SessionContext::new();
//!
//!     let client = Arc::new(MetafuseClient::new(
//!         ClientConfig::builder("http://localhost:3000").build()?
//!     )?);
//!
//!     let catalog = Arc::new(MetafuseCatalogProvider::new(client));
//!     ctx.register_catalog("metafuse", catalog);
//!
//!     // Query: SELECT * FROM metafuse.analytics.orders LIMIT 10
//!     let df = ctx.sql("SELECT * FROM metafuse.analytics.orders LIMIT 10").await?;
//!     df.show().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Delta Lake Delegation
//!
//! When a dataset has a `delta_location` configured, the `TableProvider` delegates
//! actual data scanning to Delta Lake. If `delta_location` is not set, queries
//! will return a clear error indicating the dataset is metadata-only.
//!
//! # Version Compatibility
//!
//! This integration requires **DataFusion 50.x** to be compatible with deltalake 0.29.
//! The workspace pins `datafusion = "50"` to ensure the `DeltaTable` implements the
//! correct `TableProvider` trait version. If you're using this crate as a dependency,
//! ensure your DataFusion version aligns with 50.x.
//!
//! # Metadata-Only Mode
//!
//! Datasets without `delta_location` can still provide schema information through
//! `TableProvider::schema()`, but attempting to scan them will return:
//!
//! ```text
//! Error: Dataset 'my_dataset' has no delta_location configured.
//!        This dataset contains metadata only and cannot be scanned.
//!        Set delta_location to enable data access.
//! ```
//!
//! # Known Limitation: Sync-Async Boundary
//!
//! **Important:** DataFusion's `CatalogProvider` and `SchemaProvider` traits have
//! synchronous methods (`schema_names()`, `table_names()`, `table_exist()`) that
//! must return results immediately. However, this integration needs to make HTTP
//! calls to the MetaFuse API, which are inherently asynchronous.
//!
//! ## Current Behavior
//!
//! The providers use `tokio::runtime::Handle::try_current()` with `block_on()` to
//! bridge this gap. This works correctly in most cases but has limitations:
//!
//! 1. **Empty results on failure**: If no tokio runtime is available or the API
//!    call fails, these methods return empty vectors (`Vec::new()`) rather than
//!    propagating errors. A warning is logged in these cases.
//!
//! 2. **Potential deadlock risk**: If called from within an async context that
//!    doesn't allow blocking (e.g., a single-threaded tokio runtime), `block_on()`
//!    may cause issues. Use a multi-threaded runtime (`#[tokio::main]` or
//!    `Runtime::new().unwrap()`) to avoid this.
//!
//! ## Recommended Usage
//!
//! ```rust,ignore
//! // RECOMMENDED: Multi-threaded runtime
//! #[tokio::main]
//! async fn main() {
//!     let ctx = SessionContext::new();
//!     // ... register catalog ...
//!     let df = ctx.sql("SHOW SCHEMAS FROM metafuse").await?;
//! }
//!
//! // ALSO WORKS: Explicit multi-threaded runtime
//! let runtime = tokio::runtime::Builder::new_multi_thread()
//!     .enable_all()
//!     .build()
//!     .unwrap();
//! runtime.block_on(async { /* ... */ });
//! ```
//!
//! ## Async Methods Work Normally
//!
//! The async methods (`table()`, `scan()`) work correctly without these
//! limitations since they can properly await HTTP calls.
//!
//! # Thread Safety
//!
//! All providers are thread-safe when wrapped in `Arc`:
//! - Safe to clone and share across async tasks
//! - Safe to use from multiple `SessionContext` instances
//! - The underlying `MetafuseClient` uses connection pooling automatically

mod catalog;
mod schema;
mod table;

pub use catalog::MetafuseCatalogProvider;
pub use schema::MetafuseSchemaProvider;
pub use table::MetafuseTableProvider;
