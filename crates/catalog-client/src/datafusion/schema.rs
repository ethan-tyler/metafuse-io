//! SchemaProvider implementation for MetaFuse.
//!
//! Maps datasets within a domain to DataFusion tables.

use super::table::MetafuseTableProvider;
use crate::client::MetafuseClient;
use async_trait::async_trait;
use datafusion::catalog::SchemaProvider;
use datafusion::datasource::TableProvider;
use datafusion::error::Result as DataFusionResult;
use std::any::Any;
use std::sync::Arc;
use tokio::runtime::Handle;

/// DataFusion SchemaProvider for a MetaFuse domain.
///
/// Each dataset in the domain becomes a table in this schema.
pub struct MetafuseSchemaProvider {
    client: Arc<MetafuseClient>,
    domain: String,
}

impl MetafuseSchemaProvider {
    /// Create a new schema provider for the given domain.
    pub fn new(client: Arc<MetafuseClient>, domain: String) -> Self {
        Self { client, domain }
    }
}

impl std::fmt::Debug for MetafuseSchemaProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetafuseSchemaProvider")
            .field("domain", &self.domain)
            .finish()
    }
}

#[async_trait]
impl SchemaProvider for MetafuseSchemaProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn table_names(&self) -> Vec<String> {
        // Synchronously fetch datasets using the current runtime
        // Uses cached data when available to reduce HTTP calls
        match Handle::try_current() {
            Ok(handle) => {
                match handle.block_on(self.client.list_dataset_names_by_domain(&self.domain)) {
                    Ok(names) => names,
                    Err(e) => {
                        tracing::warn!(
                            domain = %self.domain,
                            error = %e,
                            "Failed to list datasets for domain"
                        );
                        vec![]
                    }
                }
            }
            Err(_) => {
                tracing::warn!("No tokio runtime available for table_names");
                vec![]
            }
        }
    }

    async fn table(&self, name: &str) -> DataFusionResult<Option<Arc<dyn TableProvider>>> {
        // Fetch dataset with Delta metadata
        let dataset = match self
            .client
            .get_dataset_with_includes(name, &["delta"])
            .await
        {
            Ok(ds) => ds,
            Err(crate::error::ClientError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        // Verify this dataset belongs to our domain
        if dataset.domain.as_deref() != Some(&self.domain) {
            return Ok(None);
        }

        // Create table provider
        let table = MetafuseTableProvider::new(self.client.clone(), dataset).await?;
        Ok(Some(Arc::new(table)))
    }

    fn table_exist(&self, name: &str) -> bool {
        // Use the sync interface - check if dataset exists in this domain
        match Handle::try_current() {
            Ok(handle) => match handle.block_on(self.client.get_dataset(name)) {
                Ok(ds) => ds.domain.as_deref() == Some(&self.domain),
                Err(_) => false,
            },
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientConfig;

    #[test]
    fn test_schema_provider_creation() {
        let config = ClientConfig::builder("http://localhost:3000")
            .no_cache()
            .build()
            .unwrap();
        let client = Arc::new(MetafuseClient::new(config).unwrap());
        let provider = MetafuseSchemaProvider::new(client, "analytics".to_string());

        assert!(format!("{:?}", provider).contains("analytics"));
    }
}
