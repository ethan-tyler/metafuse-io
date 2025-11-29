//! MetaFuse Catalog Client SDK
//!
//! A Rust HTTP client for the MetaFuse data catalog REST API, with optional
//! DataFusion integration for querying datasets directly via SQL.
//!
//! # Features
//!
//! - **HTTP Client**: Full CRUD operations for datasets, search, and Delta metadata
//! - **Automatic Retries**: Exponential backoff with jitter for transient failures
//! - **LRU Caching**: Configurable TTL-based caching for metadata
//! - **DataFusion Integration**: (Optional) CatalogProvider for SQL queries
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use metafuse_catalog_client::{MetafuseClient, ClientConfig};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create client with builder pattern
//!     let client = MetafuseClient::new(
//!         ClientConfig::builder("http://localhost:3000")
//!             .api_key("mf_your_api_key")
//!             .timeout(Duration::from_secs(30))
//!             .cache_ttl(Duration::from_secs(300))
//!             .build()?
//!     )?;
//!
//!     // List all datasets
//!     let datasets = client.list_datasets().await?;
//!     for ds in datasets {
//!         println!("{}: {} rows", ds.name, ds.row_count.unwrap_or(0));
//!     }
//!
//!     // Get dataset with Delta metadata
//!     let dataset = client.get_dataset_with_includes("orders", &["delta", "quality"]).await?;
//!     println!("Schema: {:?}", dataset.fields);
//!
//!     Ok(())
//! }
//! ```
//!
//! # DataFusion Integration
//!
//! Enable the `datafusion` feature to use MetaFuse as a DataFusion catalog:
//!
//! ```toml
//! [dependencies]
//! metafuse-catalog-client = { version = "0.5", features = ["datafusion"] }
//! ```
//!
//! ```rust,ignore
//! use datafusion::prelude::*;
//! use metafuse_catalog_client::datafusion::MetafuseCatalogProvider;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let ctx = SessionContext::new();
//!
//!     let client = MetafuseClient::new(
//!         ClientConfig::builder("http://localhost:3000").build()?
//!     )?;
//!     let catalog = MetafuseCatalogProvider::new(Arc::new(client));
//!
//!     // Register MetaFuse as a catalog
//!     ctx.register_catalog("metafuse", Arc::new(catalog));
//!
//!     // Query using SQL - domains become schemas, datasets become tables
//!     let df = ctx.sql("SELECT * FROM metafuse.analytics.user_events LIMIT 10").await?;
//!     df.show().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Caching
//!
//! The client includes an LRU cache with configurable TTL:
//!
//! - Cache entries expire after the configured TTL
//! - Expired entries are lazily evicted on access
//! - Use `cache_ttl(Duration::ZERO)` or `no_cache()` to disable caching
//!
//! # Error Handling
//!
//! All operations return `Result<T, ClientError>`. Errors include:
//!
//! - `NotFound`: Dataset doesn't exist (404)
//! - `Unauthorized`: Invalid or missing API key (401)
//! - `RateLimited`: Too many requests (429)
//! - `ServerError`: Server-side failures (5xx)
//!
//! Retryable errors are automatically retried with exponential backoff.

pub mod cache;
pub mod client;
pub mod config;
pub mod error;
pub mod types;

#[cfg(feature = "datafusion")]
pub mod datafusion;

// Re-exports for convenience
pub use cache::{CacheStats, MetadataCache};
pub use client::{MetafuseClient, SharedClient};
pub use config::{ClientConfig, ClientConfigBuilder};
pub use error::{ClientError, Result};
pub use types::{
    ClassificationInfo, ColumnStats, Dataset, DatasetSummary, DeltaHistory, DeltaInfo,
    DeltaVersion, Field, HealthResponse, QualityDimension, QualityInfo, SearchResults,
};
