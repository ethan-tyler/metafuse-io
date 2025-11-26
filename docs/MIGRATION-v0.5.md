# Migration Guide: v0.4.x → v0.5.0

This guide helps you upgrade from MetaFuse v0.4.x to v0.5.0.

---

## TL;DR

**v0.5.0 removes deprecated synchronous APIs.** If you're already using v0.4.x async APIs, **no changes are required**.

**Breaking changes:**
- Removed `legacy-sync` feature flag
- Removed `SyncBackendAdapter` module

**Quick upgrade:**

```bash
# If on v0.4.x with async/await (most users):
cargo update -p metafuse-catalog-api
cargo update -p metafuse-catalog-storage
cargo update -p metafuse-catalog-cli

# Build and test
cargo build
cargo test
```

---

## What's New in v0.5.0

### Production Hardening & Technical Debt Cleanup

MetaFuse v0.5.0 focuses on production hardening following the v0.4.x async migration:

- **Removed deprecated sync adapter** - Clean async-only API surface
- **Enhanced CI validation** - Cloud emulator tests for GCS/S3 backends
- **Security integration tests** - Rate limiting and API key authentication validation
- **Cloud backend benchmarks** - Performance benchmarks for GCS/S3 (compile-only in CI)
- **Improved documentation** - Updated guides and examples

**No new features** - this is a cleanup release to remove technical debt.

---

## Breaking Changes

### 1. Removed `legacy-sync` Feature Flag

**What changed:**
- The `legacy-sync` Cargo feature has been removed
- `SyncBackendAdapter` module has been removed
- All code must use async/await APIs introduced in v0.4.0

**Who is affected:**
- Users still using `SyncBackendAdapter` from v0.3.x or earlier
- Projects with `features = ["legacy-sync"]` in Cargo.toml

**Migration path:**

#### Before (v0.4.x with legacy-sync):

```toml
# Cargo.toml
[dependencies]
metafuse-catalog-storage = { version = "0.4.2", features = ["legacy-sync"] }
```

```rust
use metafuse_catalog_storage::sync_adapter::SyncBackendAdapter;

// Synchronous blocking calls
let adapter = SyncBackendAdapter::new(backend)?;
let download = adapter.download_blocking()?;
adapter.upload_blocking(&download)?;
```

#### After (v0.5.0 with async/await):

```toml
# Cargo.toml
[dependencies]
metafuse-catalog-storage = { version = "0.5.0" }
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros"] }
```

```rust
// Use async/await directly
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let download = backend.download().await?;
    backend.upload(&download).await?;
    Ok(())
}
```

---

## Step-by-Step Migration

### Step 1: Check Your Current Version

Determine if you need to migrate:

```bash
grep "metafuse-catalog" Cargo.toml
```

**Decision tree:**
- **v0.4.x without `legacy-sync`**: ✅ No changes needed, just update
- **v0.4.x with `legacy-sync`**: ⚠️ Follow migration steps below
- **v0.3.x or earlier**: ⚠️ Migrate to v0.4.x first, then v0.5.0

### Step 2: Remove `legacy-sync` Feature (If Present)

**Update Cargo.toml:**

```diff
[dependencies]
- metafuse-catalog-storage = { version = "0.4.2", features = ["legacy-sync"] }
+ metafuse-catalog-storage = { version = "0.5.0" }
```

### Step 3: Convert Sync Code to Async

**Pattern 1: Main function conversion**

```diff
- fn main() -> Result<(), Box<dyn std::error::Error>> {
-     let adapter = SyncBackendAdapter::new(backend)?;
-     let download = adapter.download_blocking()?;
-     Ok(())
- }

+ #[tokio::main]
+ async fn main() -> Result<(), Box<dyn std::error::Error>> {
+     let download = backend.download().await?;
+     Ok(())
+ }
```

**Pattern 2: Existing async context**

```diff
async fn process_catalog(backend: Arc<dyn CatalogBackend>) -> Result<()> {
-     // Don't create sync adapter in async context!
-     let adapter = SyncBackendAdapter::new(backend.as_ref().clone())?;
-     let download = adapter.download_blocking()?;

+     // Use async methods directly
+     let download = backend.download().await?;
    Ok(())
}
```

**Pattern 3: Tests**

```diff
- #[test]
- fn test_catalog_download() {
-     let adapter = SyncBackendAdapter::new(backend).unwrap();
-     let result = adapter.download_blocking();
-     assert!(result.is_ok());
- }

+ #[tokio::test]
+ async fn test_catalog_download() {
+     let result = backend.download().await;
+     assert!(result.is_ok());
+ }
```

### Step 4: Update Tokio Dependency (If Needed)

Ensure you have Tokio in your Cargo.toml:

```toml
[dependencies]
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros"] }
```

### Step 5: Build and Test

```bash
# Clean build
cargo clean
cargo build

# Run tests
cargo test

# If using cloud backends
cargo test --features cloud

# If using emulators (requires Docker)
RUN_CLOUD_TESTS=1 cargo test --features cloud
```

### Step 6: Verify Migration

**Checklist:**

- [ ] No references to `SyncBackendAdapter` in your code
- [ ] No `features = ["legacy-sync"]` in Cargo.toml
- [ ] All catalog operations use `.await`
- [ ] Main function or test functions use `#[tokio::main]` or `#[tokio::test]`
- [ ] All tests pass
- [ ] No deprecation warnings during build

---

## Common Migration Patterns

### Pattern 1: CLI Applications

**Before:**

```rust
use metafuse_catalog_storage::sync_adapter::SyncBackendAdapter;

fn main() {
    let backend = LocalSqliteBackend::new("catalog.db");
    let adapter = SyncBackendAdapter::new(backend).unwrap();

    let datasets = adapter.get_connection_blocking()
        .unwrap()
        .prepare("SELECT * FROM datasets")
        // ...
}
```

**After:**

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = LocalSqliteBackend::new("catalog.db");

    let conn = backend.get_connection().await?;
    let datasets = conn.prepare("SELECT * FROM datasets")?;
    // ...
    Ok(())
}
```

### Pattern 2: Library Functions

**Before:**

```rust
pub fn process_catalog(path: &str) -> Result<Vec<Dataset>> {
    let backend = LocalSqliteBackend::new(path);
    let adapter = SyncBackendAdapter::new(backend)?;
    let conn = adapter.get_connection_blocking()?;
    // ... query datasets
}
```

**After:**

```rust
pub async fn process_catalog(path: &str) -> Result<Vec<Dataset>> {
    let backend = LocalSqliteBackend::new(path);
    let conn = backend.get_connection().await?;
    // ... query datasets
}
```

### Pattern 3: Background Tasks

**Before:**

```rust
fn start_background_sync(backend: Arc<dyn CatalogBackend>) {
    std::thread::spawn(move || {
        let adapter = SyncBackendAdapter::new(backend.as_ref().clone()).unwrap();
        loop {
            adapter.download_blocking().unwrap();
            std::thread::sleep(Duration::from_secs(60));
        }
    });
}
```

**After:**

```rust
fn start_background_sync(backend: Arc<dyn CatalogBackend>) {
    tokio::spawn(async move {
        loop {
            let _ = backend.download().await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}
```

---

## Upgrading from v0.3.x or Earlier

If you're on v0.3.x or earlier, you need a two-step upgrade:

### Step 1: Upgrade to v0.4.2

```bash
cargo update -p metafuse-catalog-api
cargo update -p metafuse-catalog-storage
cargo build --features legacy-sync  # Use legacy adapter temporarily
```

See [MIGRATION-v0.4.md](MIGRATION-v0.4.md) for v0.3.x → v0.4.x upgrade guide.

### Step 2: Migrate to Async

Follow the migration patterns above to convert your code to async/await.

### Step 3: Upgrade to v0.5.0

Remove `legacy-sync` feature and upgrade:

```bash
cargo update -p metafuse-catalog-api
cargo update -p metafuse-catalog-storage
cargo build
cargo test
```

---

## Testing Your Migration

### Unit Tests

```bash
# Test with default features
cargo test

# Test with cloud backends
cargo test --features cloud

# Test with security features
cargo test --features "rate-limiting,api-keys"
```

### Integration Tests

```bash
# Cloud emulator tests (requires Docker)
RUN_CLOUD_TESTS=1 cargo test --features cloud

# Security integration tests
cargo test --features rate-limiting,api-keys --test security_integration_tests
```

### Manual Testing

```bash
# Test catalog operations
metafuse init --uri "file:///tmp/catalog.db"
metafuse list
metafuse show <dataset_name>
metafuse search "query"

# Test cloud backends (if configured)
metafuse init --uri "gs://my-bucket/catalog.db"
metafuse init --uri "s3://my-bucket/catalog.db?region=us-west-2"
```

---

## Rollback Plan

If you encounter issues:

### Option 1: Stay on v0.4.2

```toml
[dependencies]
metafuse-catalog-api = "0.4.2"
metafuse-catalog-storage = { version = "0.4.2", features = ["legacy-sync"] }
```

```bash
cargo update
cargo build
```

### Option 2: Use Async APIs on v0.4.2

v0.4.2 supports both sync adapter and async APIs. You can migrate incrementally:

```toml
[dependencies]
metafuse-catalog-storage = "0.4.2"  # No legacy-sync feature
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros"] }
```

Test async migration on v0.4.2, then upgrade to v0.5.0 when ready.

---

## Performance Considerations

### Async is Faster

The sync adapter had overhead from creating dedicated Tokio runtimes. Direct async/await is more efficient:

**Before (sync adapter):**
- Each operation created a runtime: ~1-2ms overhead
- Blocked thread during I/O: inefficient for concurrent workloads

**After (native async):**
- Zero adapter overhead
- Efficient I/O multiplexing with Tokio
- Better throughput for concurrent operations

### Benchmarks

```bash
# Run benchmarks to verify performance
cargo bench --features bench

# Expected improvements:
# - Local SQLite: ~5-10% faster (reduced overhead)
# - Cloud backends: ~20-30% faster (native async HTTP)
# - Concurrent operations: ~50% faster (no thread blocking)
```

---

## Common Issues

### Issue: "SyncBackendAdapter not found"

**Symptom:**

```
error[E0432]: unresolved import `metafuse_catalog_storage::sync_adapter`
```

**Solution:**
You're trying to use the removed sync adapter. Follow the migration patterns above to convert to async/await.

### Issue: "Cannot use `await` outside async function"

**Symptom:**

```
error[E0728]: `await` is only allowed inside `async` functions and blocks
```

**Solution:**
Add `async` to your function signature and use `#[tokio::main]` or `#[tokio::test]`:

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Your async code here
    Ok(())
}
```

### Issue: "No runtime available"

**Symptom:**

```
thread 'main' panicked at 'there is no reactor running, must be called from the context of a Tokio runtime'
```

**Solution:**
Ensure your `main` function uses `#[tokio::main]`:

```rust
#[tokio::main]
async fn main() {
    // ...
}
```

### Issue: Tests fail with "runtime error"

**Symptom:**

```
Cannot start a runtime from within a runtime
```

**Solution:**
Use `#[tokio::test]` instead of `#[test]`:

```diff
- #[test]
- fn test_download() {
+ #[tokio::test]
+ async fn test_download() {
    let result = backend.download().await;
    assert!(result.is_ok());
}
```

---

## Getting Help

If you encounter migration issues:

1. **Check documentation**: [docs/](.)
2. **Search issues**: [GitHub Issues](https://github.com/ethan-tyler/MetaFuse/issues)
3. **Ask the community**: [GitHub Discussions](https://github.com/ethan-tyler/MetaFuse/discussions)
4. **Report bugs**: Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml)

---

## Summary

**Key Takeaways:**

- ✅ v0.5.0 removes `legacy-sync` adapter (deprecated in v0.4.0)
- ✅ All code must use async/await (already standard in v0.4.x)
- ✅ If you're on v0.4.x async APIs, upgrade is trivial
- ✅ Migration from sync is straightforward (add `async`/`.await`)
- ✅ Performance improves with native async

**Next Steps:**

1. Review your codebase for `SyncBackendAdapter` usage
2. Follow migration patterns to convert to async/await
3. Test thoroughly before upgrading to v0.5.0
4. Enjoy cleaner APIs and better performance!

---

**Welcome to MetaFuse v0.5.0!** 🎉
