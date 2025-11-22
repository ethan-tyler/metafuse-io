# Migration Guide: v0.3.x → v0.4.0

## Overview

MetaFuse v0.4.0 introduces **async/await** throughout the codebase, replacing the previous synchronous API. This enables:
- Better integration with async Rust ecosystems (Tokio, async-std)
- Non-blocking I/O for cloud storage backends (GCS, S3)
- Improved performance for concurrent operations
- Compatibility with async frameworks like Axum (API server)

**Compatibility:** v0.4.0 is a **breaking release** requiring code changes.

---

## What Changed

### 1. CatalogBackend Trait (All Backends)

All `CatalogBackend` methods are now `async`:

**Before (v0.3.x):**
```rust
pub trait CatalogBackend {
    fn initialize(&self) -> Result<()>;
    fn download(&self) -> Result<Download>;
    fn upload(&self, download: &Download) -> Result<()>;
    fn get_connection(&self) -> Result<Connection>;
    fn exists(&self) -> Result<bool>;
}
```

**After (v0.4.0):**
```rust
#[async_trait::async_trait]
pub trait CatalogBackend: Send + Sync {
    async fn initialize(&self) -> Result<()>;
    async fn download(&self) -> Result<Download>;
    async fn upload(&self, download: &Download) -> Result<()>;
    async fn get_connection(&self) -> Result<Connection>;
    async fn exists(&self) -> Result<bool>;
}
```

**Key Change:** Add `.await` to all backend method calls.

---

### 2. Emitter API

The `Emitter::emit_dataset` method is now `async`:

**Before (v0.3.x):**
```rust
fn main() -> Result<()> {
    let backend = LocalSqliteBackend::new("catalog.db");
    let emitter = Emitter::new(backend);

    emitter.emit_dataset(
        "my_dataset",
        "/path/to/data",
        "parquet",
        // ...
    )?;

    Ok(())
}
```

**After (v0.4.0):**
```rust
#[tokio::main]
async fn main() -> Result<()> {
    let backend = LocalSqliteBackend::new("catalog.db");
    let emitter = Emitter::new(backend);

    emitter.emit_dataset(
        "my_dataset",
        "/path/to/data",
        "parquet",
        // ...
    ).await?;  // Add .await

    Ok(())
}
```

**Key Changes:**
- Add `#[tokio::main]` to your `main` function
- Add `.await` to `emit_dataset` calls

---

### 3. CLI (No Changes Required)

The CLI already uses async internally. **No migration needed** for CLI users:

```bash
# These commands work the same in v0.4.0
metafuse init
metafuse list
metafuse show my_dataset
```

---

### 4. API Server (Already Async)

The API server (Axum-based) was already async in v0.3.x. **No migration needed**.

---

## Migration Steps

### Step 1: Update Dependencies

Update your `Cargo.toml`:

```toml
[dependencies]
metafuse-catalog-emitter = "0.4"
metafuse-catalog-storage = "0.4"
metafuse-catalog-core = "0.4"

# Add tokio if not already present
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros"] }
```

### Step 2: Make Your Main Function Async

**Before:**
```rust
fn main() -> Result<()> {
    // Your code
    Ok(())
}
```

**After:**
```rust
#[tokio::main]
async fn main() -> Result<()> {
    // Your code
    Ok(())
}
```

Alternatively, use `async-std`:
```rust
#[async_std::main]
async fn main() -> Result<()> {
    // Your code
    Ok(())
}
```

### Step 3: Add `.await` to Backend Calls

Update all backend method calls:

```rust
// Before: Sync calls
let backend = LocalSqliteBackend::new("catalog.db");
backend.initialize()?;
let conn = backend.get_connection()?;

// After: Async calls
let backend = LocalSqliteBackend::new("catalog.db");
backend.initialize().await?;
let conn = backend.get_connection().await?;
```

### Step 4: Add `.await` to Emitter Calls

```rust
// Before: Sync emit
emitter.emit_dataset(
    "dataset_name",
    "/path/to/data",
    "parquet",
    // ... parameters
)?;

// After: Async emit
emitter.emit_dataset(
    "dataset_name",
    "/path/to/data",
    "parquet",
    // ... parameters
).await?;
```

### Step 5: Update Tests

Convert your tests to `async`:

**Before:**
```rust
#[test]
fn test_emit_dataset() {
    let backend = LocalSqliteBackend::new("test.db");
    let emitter = Emitter::new(backend);
    emitter.emit_dataset(/* ... */).unwrap();
}
```

**After:**
```rust
#[tokio::test]
async fn test_emit_dataset() {
    let backend = LocalSqliteBackend::new("test.db");
    let emitter = Emitter::new(backend);
    emitter.emit_dataset(/* ... */).await.unwrap();
}
```

---

## Complete Example Migration

### Before (v0.3.x): Sync Pipeline

```rust
use datafusion::prelude::*;
use metafuse_catalog_emitter::Emitter;
use metafuse_catalog_storage::LocalSqliteBackend;
use metafuse_catalog_core::OperationalMeta;

fn main() -> datafusion::error::Result<()> {
    // 1. Create backend and emitter
    let backend = LocalSqliteBackend::new("catalog.db");
    let emitter = Emitter::new(backend);

    // 2. Run DataFusion pipeline
    let ctx = SessionContext::new();
    let df = ctx.sql("SELECT * FROM my_table")?;
    let results = df.collect()?;
    let schema = df.schema();

    // 3. Emit metadata (sync)
    emitter.emit_dataset(
        "my_dataset",
        "s3://bucket/path",
        "parquet",
        Some("My dataset"),
        None,
        None,
        None,
        schema,
        Some(OperationalMeta {
            row_count: Some(1000),
            size_bytes: Some(50000),
            partition_keys: vec![],
        }),
        vec![],
        vec!["prod".to_string()],
    )?;

    Ok(())
}
```

### After (v0.4.0): Async Pipeline

```rust
use datafusion::prelude::*;
use metafuse_catalog_emitter::Emitter;
use metafuse_catalog_storage::LocalSqliteBackend;
use metafuse_catalog_core::OperationalMeta;

#[tokio::main]  // ← Add this
async fn main() -> datafusion::error::Result<()> {
    // 1. Create backend and emitter (no changes)
    let backend = LocalSqliteBackend::new("catalog.db");
    let emitter = Emitter::new(backend);

    // 2. Run DataFusion pipeline (already async in v0.3.x)
    let ctx = SessionContext::new();
    let df = ctx.sql("SELECT * FROM my_table").await?;  // ← .await was already here
    let results = df.collect().await?;  // ← .await was already here
    let schema = df.schema();

    // 3. Emit metadata (now async)
    emitter.emit_dataset(
        "my_dataset",
        "s3://bucket/path",
        "parquet",
        Some("My dataset"),
        None,
        None,
        None,
        schema,
        Some(OperationalMeta {
            row_count: Some(1000),
            size_bytes: Some(50000),
            partition_keys: vec![],
        }),
        vec![],
        vec!["prod".to_string()],
    ).await?;  // ← Add .await

    Ok(())
}
```

**Summary of Changes:**
1. Added `#[tokio::main]`
2. Changed `fn main()` to `async fn main()`
3. Added `.await` to `emit_dataset()`

---

## Performance Considerations

### SQLite Operations Use `spawn_blocking`

MetaFuse automatically offloads blocking SQLite operations to a thread pool via `tokio::task::spawn_blocking`. This ensures:
- SQLite I/O doesn't block the async executor
- Optimal performance for concurrent operations
- No manual thread management required

### Cloud Backends Are Truly Async

GCS and S3 backends now use native async HTTP clients (no `tokio::block_on` internally):
- **GCS:** Uses `object_store` with async reqwest
- **S3:** Uses `object_store` with async AWS SDK
- Better scalability for concurrent cloud operations

---

## Troubleshooting

### Error: "`await` is only allowed inside `async` functions"

**Problem:**
```rust
fn main() {
    backend.initialize().await?;  // ❌ Error
}
```

**Solution:** Make the function `async` and add a runtime:
```rust
#[tokio::main]
async fn main() {
    backend.initialize().await?;  // ✅ OK
}
```

---

### Error: "no method named `unwrap`" (on futures)

**Problem:**
```rust
let result = backend.initialize();  // Returns a Future, not a Result
result.unwrap();  // ❌ Error: Future doesn't have unwrap()
```

**Solution:** Add `.await` before `.unwrap()`:
```rust
let result = backend.initialize().await;  // Now it's a Result
result.unwrap();  // ✅ OK
```

---

### Error: "trait `CatalogBackend` is not implemented"

**Problem:** You may be using the old trait definition.

**Solution:** Update to v0.4.0:
```bash
cargo update -p metafuse-catalog-storage
cargo update -p metafuse-catalog-emitter
```

---

## Deprecation Notice

The `SyncBackendAdapter` (for backward compatibility) is **deprecated** and will be removed in v0.5.0. Migrate to async APIs before upgrading to v0.5.0.

---

## Need Help?

- **Issues:** https://github.com/ethan-tyler/MetaFuse/issues
- **Examples:** See `examples/` directory for updated async examples
- **Documentation:** https://docs.rs/metafuse-catalog-emitter/0.4.0

---

**Last Updated:** 2025-01-22
**Applies To:** MetaFuse v0.4.0
