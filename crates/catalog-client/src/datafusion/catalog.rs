//! CatalogProvider implementation for MetaFuse.
//!
//! Maps MetaFuse domains to DataFusion schemas.

use super::schema::MetafuseSchemaProvider;
use crate::client::MetafuseClient;
use async_trait::async_trait;
use datafusion::catalog::{CatalogProvider, SchemaProvider};
use std::any::Any;
use std::sync::Arc;
use tokio::runtime::Handle;

/// DataFusion CatalogProvider backed by MetaFuse.
///
/// This provider maps MetaFuse **domains** to DataFusion **schemas**.
/// Each domain becomes a schema that contains tables for datasets
/// in that domain.
pub struct MetafuseCatalogProvider {
    client: Arc<MetafuseClient>,
}

impl MetafuseCatalogProvider {
    /// Create a new catalog provider with the given client.
    pub fn new(client: Arc<MetafuseClient>) -> Self {
        Self { client }
    }
}

impl std::fmt::Debug for MetafuseCatalogProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetafuseCatalogProvider")
            .field("base_url", &self.client.base_url())
            .finish()
    }
}

#[async_trait]
impl CatalogProvider for MetafuseCatalogProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema_names(&self) -> Vec<String> {
        // Synchronously fetch domains using the current runtime
        // This is a limitation of DataFusion's sync CatalogProvider interface
        match Handle::try_current() {
            Ok(handle) => match handle.block_on(self.client.list_domains()) {
                Ok(domains) => domains,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to list domains");
                    vec![]
                }
            },
            Err(_) => {
                tracing::warn!("No tokio runtime available for schema_names");
                vec![]
            }
        }
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn SchemaProvider>> {
        // Create a schema provider for this domain
        Some(Arc::new(MetafuseSchemaProvider::new(
            self.client.clone(),
            name.to_string(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientConfig;

    #[test]
    fn test_catalog_provider_creation() {
        let config = ClientConfig::builder("http://localhost:3000")
            .no_cache()
            .build()
            .unwrap();
        let client = Arc::new(MetafuseClient::new(config).unwrap());
        let provider = MetafuseCatalogProvider::new(client);

        assert!(format!("{:?}", provider).contains("MetafuseCatalogProvider"));
    }
}
