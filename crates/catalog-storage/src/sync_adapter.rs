//! Legacy Synchronous Adapter for CatalogBackend
//!
//! **DEPRECATED**: This module provides temporary backward compatibility for code
//! that hasn't migrated to async yet. It will be removed in v0.5.0.
//!
//! ## Migration Path
//!
//! Instead of using `SyncBackendAdapter`, migrate your code to use async/await:
//!
//! ```rust,ignore
//! // Old (deprecated):
//! use metafuse_catalog_storage::sync_adapter::SyncBackendAdapter;
//! let adapter = SyncBackendAdapter::new(backend);
//! let download = adapter.download_blocking()?;
//!
//! // New (recommended):
//! let download = backend.download().await?;
//! ```
//!
//! ## Feature Flag
//!
//! This module requires the `legacy-sync` feature flag:
//! ```toml
//! metafuse-catalog-storage = { version = "0.3.2", features = ["legacy-sync"] }
//! ```

use crate::{CatalogBackend, CatalogDownload, Result};
use rusqlite::Connection;

/// Synchronous adapter for async CatalogBackend
///
/// **DEPRECATED since v0.3.2**: This adapter provides temporary backward compatibility
/// for code that hasn't migrated to async yet. It will be removed in v0.5.0.
///
/// ## Performance Warning
///
/// This adapter uses a dedicated Tokio runtime for each operation, which adds overhead.
/// For better performance, migrate to async/await.
///
/// ## Example
///
/// ```rust,ignore
/// use metafuse_catalog_storage::{LocalSqliteBackend, sync_adapter::SyncBackendAdapter};
///
/// let backend = LocalSqliteBackend::new("catalog.db");
/// let adapter = SyncBackendAdapter::new(backend);
///
/// // Use sync methods
/// let download = adapter.download_blocking()?;
/// adapter.upload_blocking(&download)?;
/// ```
#[deprecated(
    since = "0.3.2",
    note = "Use async CatalogBackend methods directly. Removal in v0.5.0"
)]
pub struct SyncBackendAdapter<B: CatalogBackend> {
    backend: B,
    runtime: tokio::runtime::Runtime,
}

#[allow(deprecated)]
impl<B: CatalogBackend> SyncBackendAdapter<B> {
    /// Create a new sync adapter
    ///
    /// **DEPRECATED**: Migrate to async/await instead.
    #[deprecated(
        since = "0.3.2",
        note = "Use async CatalogBackend methods directly. Removal in v0.5.0"
    )]
    pub fn new(backend: B) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                metafuse_catalog_core::CatalogError::Other(format!(
                    "Failed to create Tokio runtime: {}",
                    e
                ))
            })?;

        Ok(Self { backend, runtime })
    }

    /// Download catalog synchronously
    ///
    /// **DEPRECATED**: Use `backend.download().await` instead.
    #[deprecated(since = "0.3.2", note = "Use backend.download().await")]
    pub fn download_blocking(&self) -> Result<CatalogDownload> {
        self.runtime.block_on(self.backend.download())
    }

    /// Upload catalog synchronously
    ///
    /// **DEPRECATED**: Use `backend.upload(&download).await` instead.
    #[deprecated(since = "0.3.2", note = "Use backend.upload(&download).await")]
    pub fn upload_blocking(&self, download: &CatalogDownload) -> Result<()> {
        self.runtime.block_on(self.backend.upload(download))
    }

    /// Get connection synchronously
    ///
    /// **DEPRECATED**: Use `backend.get_connection().await` instead.
    #[deprecated(since = "0.3.2", note = "Use backend.get_connection().await")]
    pub fn get_connection_blocking(&self) -> Result<Connection> {
        self.runtime.block_on(self.backend.get_connection())
    }

    /// Check if catalog exists synchronously
    ///
    /// **DEPRECATED**: Use `backend.exists().await` instead.
    #[deprecated(since = "0.3.2", note = "Use backend.exists().await")]
    pub fn exists_blocking(&self) -> Result<bool> {
        self.runtime.block_on(self.backend.exists())
    }

    /// Initialize catalog synchronously
    ///
    /// **DEPRECATED**: Use `backend.initialize().await` instead.
    #[deprecated(since = "0.3.2", note = "Use backend.initialize().await")]
    pub fn initialize_blocking(&self) -> Result<()> {
        self.runtime.block_on(self.backend.initialize())
    }

    /// Get a reference to the underlying async backend
    ///
    /// Use this to migrate incrementally to async code.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Get a mutable reference to the underlying async backend
    ///
    /// Use this to migrate incrementally to async code.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Consume the adapter and return the underlying async backend
    ///
    /// Use this to migrate incrementally to async code.
    pub fn into_backend(self) -> B {
        self.backend
    }
}

// Make the adapter Debug if the backend is Debug
#[allow(deprecated)]
impl<B: CatalogBackend + std::fmt::Debug> std::fmt::Debug for SyncBackendAdapter<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncBackendAdapter")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}
