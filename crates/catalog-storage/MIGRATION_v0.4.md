# Migration Guide: v0.3.x → v0.4.0

This guide helps you migrate from synchronous `CatalogBackend` to the new async API.

## Overview

**v0.3.2** introduced async methods to `CatalogBackend` with a temporary `legacy-sync` adapter for backward compatibility.

**v0.4.0** will remove the sync adapter entirely. All code must use async/await.

## Quick Migration Examples

### Basic Backend Usage

#### Before (v0.3.1)
```rust
use metafuse_catalog_storage::LocalSqliteBackend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = LocalSqliteBackend::new("catalog.db");

    // Initialize catalog
    backend.initialize()?;

    // Download catalog
    let download = backend.download()?;

    // Upload catalog
    backend.upload(&download)?;

    Ok(())
}
```

#### After (v0.4.0)
```rust
use metafuse_catalog_storage::LocalSqliteBackend;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = LocalSqliteBackend::new("catalog.db");

    // Initialize catalog
    backend.initialize().await?;

    // Download catalog
    let download = backend.download().await?;

    // Upload catalog
    backend.upload(&download).await?;

    Ok(())
}
```

**Key changes:**
1. Add `#[tokio::main]` attribute to main function
2. Make main function `async`
3. Add `.await` after every backend method call
4. Add `tokio` dependency to `Cargo.toml`

### CLI Applications

#### Before (v0.3.1)
```rust
use clap::Parser;
use metafuse_catalog_storage::backend_from_uri;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    catalog_uri: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let backend = backend_from_uri(&args.catalog_uri)?;

    backend.initialize()?;
    println!("Catalog initialized");

    Ok(())
}
```

#### After (v0.4.0)
```rust
use clap::Parser;
use metafuse_catalog_storage::backend_from_uri;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    catalog_uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let backend = backend_from_uri(&args.catalog_uri)?;

    backend.initialize().await?;
    println!("Catalog initialized");

    Ok(())
}
```

### DataFusion Integration

#### Before (v0.3.1)
```rust
use datafusion::prelude::*;
use metafuse_catalog_storage::LocalSqliteBackend;

fn run_query() -> Result<(), Box<dyn std::error::Error>> {
    let backend = LocalSqliteBackend::new("catalog.db");
    let conn = backend.get_connection()?;

    // Query catalog metadata
    let mut stmt = conn.prepare("SELECT * FROM datasets")?;
    // ... process results

    Ok(())
}
```

#### After (v0.4.0)
```rust
use datafusion::prelude::*;
use metafuse_catalog_storage::LocalSqliteBackend;

async fn run_query() -> Result<(), Box<dyn std::error::Error>> {
    let backend = LocalSqliteBackend::new("catalog.db");
    let conn = backend.get_connection().await?;

    // Query catalog metadata
    let mut stmt = conn.prepare("SELECT * FROM datasets")?;
    // ... process results

    Ok(())
}
```

## Temporary Compatibility Layer (v0.3.2 only)

If you need time to migrate, v0.3.2 provides a temporary sync adapter:

### Using the Sync Adapter

**Cargo.toml:**
```toml
[dependencies]
metafuse-catalog-storage = { version = "0.3.2", features = ["legacy-sync"] }
```

**Code:**
```rust
use metafuse_catalog_storage::{LocalSqliteBackend, sync_adapter::SyncBackendAdapter};

#[allow(deprecated)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = LocalSqliteBackend::new("catalog.db");
    let adapter = SyncBackendAdapter::new(backend)?;

    // Use sync methods (deprecated)
    adapter.initialize_blocking()?;
    let download = adapter.download_blocking()?;
    adapter.upload_blocking(&download)?;

    Ok(())
}
```

**⚠️ Warning:** The `legacy-sync` feature and `SyncBackendAdapter` will be removed in v0.5.0.

## Cargo.toml Updates

Add or update the `tokio` dependency:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
metafuse-catalog-storage = "0.4"
```

For minimal feature set (if you only need local backend):

```toml
[dependencies]
tokio = { version = "1", features = ["rt", "macros"] }
metafuse-catalog-storage = { version = "0.4", default-features = false, features = ["local"] }
```

## Common Patterns

### Pattern: Trait Objects

#### Before
```rust
fn process_catalog(backend: &dyn CatalogBackend) -> Result<()> {
    let download = backend.download()?;
    // ... process
    Ok(())
}
```

#### After
```rust
async fn process_catalog(backend: &dyn CatalogBackend) -> Result<()> {
    let download = backend.download().await?;
    // ... process
    Ok(())
}
```

### Pattern: Struct Methods

#### Before
```rust
struct CatalogManager {
    backend: Box<dyn CatalogBackend>,
}

impl CatalogManager {
    fn sync_catalog(&self) -> Result<()> {
        let download = self.backend.download()?;
        self.backend.upload(&download)?;
        Ok(())
    }
}
```

#### After
```rust
struct CatalogManager {
    backend: Box<dyn CatalogBackend>,
}

impl CatalogManager {
    async fn sync_catalog(&self) -> Result<()> {
        let download = self.backend.download().await?;
        self.backend.upload(&download).await?;
        Ok(())
    }
}
```

### Pattern: Testing

#### Before
```rust
#[test]
fn test_catalog_operations() {
    let backend = LocalSqliteBackend::new("test.db");
    backend.initialize().unwrap();
    assert!(backend.exists().unwrap());
}
```

#### After
```rust
#[tokio::test]
async fn test_catalog_operations() {
    let backend = LocalSqliteBackend::new("test.db");
    backend.initialize().await.unwrap();
    assert!(backend.exists().await.unwrap());
}
```

## Performance Considerations

### SQLite Connection Safety

The async backend uses `tokio::task::spawn_blocking` for all SQLite operations. This prevents holding non-`Send` connections across await points, ensuring safety.

**What this means:**
- SQLite operations run in blocking thread pool
- No performance regression for local backends
- Cloud backends benefit from true async I/O for downloads/uploads

### Migration Timeline

- **v0.3.2** (current): Async backend + legacy sync adapter
- **v0.4.0** (next): Remove sync adapter, async only
- **v0.5.0** (future): May remove legacy compatibility layers

## Troubleshooting

### Error: "there is no reactor running"

**Problem:** Calling async method outside async context.

**Solution:** Add `#[tokio::main]` or `#[tokio::test]`:
```rust
#[tokio::main]
async fn main() {
    // your code
}
```

### Error: "future cannot be sent between threads safely"

**Problem:** Trying to send backend across threads without proper bounds.

**Solution:** Use `Box<dyn CatalogBackend>` which is `Send + Sync`:
```rust
async fn spawn_catalog_task(backend: Box<dyn CatalogBackend>) {
    tokio::spawn(async move {
        backend.download().await.unwrap();
    });
}
```

### Warning: "use of deprecated..."

If you see deprecation warnings in v0.3.2, you're using the old sync adapter. Migrate to async/await to remove them.

## Getting Help

- Check [examples/](../../examples/) for async usage patterns
- See [CHANGELOG.md](../../CHANGELOG.md) for detailed release notes
- Open an issue at https://github.com/ethan-tyler/MetaFuse/issues
