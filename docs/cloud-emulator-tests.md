# Cloud Emulator Testing Guide

This guide covers MetaFuse's cloud emulator testing strategy for GCS and S3 backends, following industry best practices for integration testing with Docker-based emulators.

## TL;DR - Quick Start

**Requirements**: Docker installed and running

```bash
# Run cloud emulator tests (skipped by default)
RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests  # GCS
RUN_CLOUD_TESTS=1 cargo test --features s3 --test s3_emulator_tests    # S3
```

**What you get:**

- Cloud emulator tests validate cloud-specific behavior (versioning, concurrency, retries) without credentials or costs
- Uses Docker containers (fake-gcs-server, MinIO) that start/stop automatically

**CI Behavior:**

- Tests skipped by default (set `RUN_CLOUD_TESTS=1`)
- Linux-only in CI (Docker service containers not supported on macOS/Windows runners)
- Non-blocking until stable (>95% pass rate)

---

## Table of Contents

- [Overview](#overview)
- [Why Emulator Testing?](#why-emulator-testing)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [GCS Emulator Tests](#gcs-emulator-tests)
- [S3 Emulator Tests](#s3-emulator-tests)
- [Environment-Gated Execution](#environment-gated-execution)
- [Best Practices](#best-practices)
- [Common Patterns](#common-patterns)
- [Troubleshooting](#troubleshooting)
- [CI/CD Integration](#cicd-integration)
- [Performance Considerations](#performance-considerations)
- [Security Considerations](#security-considerations)

## Overview

MetaFuse includes comprehensive integration tests for cloud backends (GCS and S3) using Docker-based emulators. These tests validate cloud-specific behavior without requiring actual cloud credentials or incurring cloud costs.

**Key Benefits:**

- **No Cloud Credentials Required**: Tests run entirely locally using Docker emulators
- **Fast Feedback**: Faster than testing against real cloud services
- **Cost-Free**: No cloud storage costs during development
- **Reproducible**: Consistent behavior across development environments
- **Safe**: Isolated from production infrastructure

**Test Coverage:**

- Catalog initialization and existence checks
- Upload/download roundtrips with versioning (generations/ETags)
- Concurrent write detection and conflict handling
- Retry logic with exponential backoff
- Cache behavior (enabled/disabled)
- Metadata preservation and region configuration

## Why Emulator Testing?

Emulator testing sits between unit tests and full integration tests:

| Test Type | Speed | Cost | Fidelity | Isolation |
|-----------|-------|------|----------|-----------|
| **Unit Tests** | Fast | Free | Low | Complete |
| **Emulator Tests** | Medium | Free | High | Complete |
| **Cloud Integration** | Slow | $$$ | Perfect | Shared |

**When to Use Each:**

1. **Unit Tests**: Core business logic, schema operations, local SQLite backend
2. **Emulator Tests**: Cloud-specific behavior (versioning, concurrency, retries)
3. **Cloud Integration**: Final validation before release, cloud-specific edge cases

**Industry Precedent:**

- AWS uses [LocalStack](https://localstack.cloud/) for S3/DynamoDB testing
- Google Cloud provides [Cloud Storage Emulator](https://cloud.google.com/storage/docs/emulator) (gRPC-based)
- Microsoft Azure uses [Azurite](https://github.com/Azure/Azurite) for blob storage testing

## Architecture

MetaFuse emulator tests use the following architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    Test Process (Rust)                      │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │         testcontainers-rs                           │  │
│  │  (Manages Docker container lifecycle)                │  │
│  └────────────┬─────────────────────────┬───────────────┘  │
│               │                         │                   │
│               ▼                         ▼                   │
│  ┌────────────────────┐    ┌────────────────────┐         │
│  │  GcsBackend        │    │  S3Backend         │         │
│  │  (with emulator    │    │  (with emulator    │         │
│  │   endpoint)        │    │   endpoint)        │         │
│  └─────────┬──────────┘    └─────────┬──────────┘         │
└────────────┼────────────────────────────┼──────────────────┘
             │                            │
             │ HTTP API                   │ S3 API
             │                            │
┌────────────▼────────────┐  ┌───────────▼──────────┐
│   fake-gcs-server       │  │     MinIO            │
│   Docker Container      │  │  Docker Container    │
│   (GCS emulator)        │  │  (S3 emulator)       │
└─────────────────────────┘  └──────────────────────┘
```

**Key Components:**

1. **`testcontainers-rs`**: Manages Docker container lifecycle (start, wait for ready, cleanup)
2. **Emulator Images**:
   - GCS: `fsouza/fake-gcs-server` - HTTP-compatible GCS API emulator
   - S3: `minio/minio` - S3-compatible object storage
3. **Backend Adapters**: `GcsBackend` and `S3Backend` configured with emulator endpoints

## Requirements

### System Requirements

- **Docker**: Installed and running
  - Docker Desktop (macOS/Windows)
  - Docker Engine (Linux)
- **Rust**: 1.75+ with `cargo`
- **Internet**: Initial image pull only (images cached locally)

### Rust Dependencies

Already included in `Cargo.toml` dev-dependencies:

```toml
[dev-dependencies]
testcontainers = "0.15"
tokio = { version = "1.35", features = ["full"] }
```

### Verify Setup

```bash
# Check Docker is running
docker ps

# Check Rust version
rustc --version

# Pull emulator images (optional, happens automatically)
docker pull fsouza/fake-gcs-server
docker pull minio/minio
```

## Quick Start

### Run All Emulator Tests

```bash
# GCS emulator tests
RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests

# S3 emulator tests
RUN_CLOUD_TESTS=1 cargo test --features s3 --test s3_emulator_tests

# Both in parallel
RUN_CLOUD_TESTS=1 cargo test --features cloud --test gcs_emulator_tests --test s3_emulator_tests
```

### Run Specific Test

```bash
# Run single GCS test
RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests test_gcs_emulator_roundtrip

# Run with verbose output
RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests -- --nocapture
```

### Skip Emulator Tests (Default)

```bash
# Without RUN_CLOUD_TESTS, emulator tests are skipped
cargo test --features cloud
# Output: test gcs_emulator_tests::test_gcs_emulator_roundtrip ... ignored
```

## GCS Emulator Tests

### Overview

GCS emulator tests use `fake-gcs-server`, a community-maintained GCS emulator that implements the JSON API.

**Emulator Details:**

- **Image**: `fsouza/fake-gcs-server:latest`
- **Port**: 4443 (HTTP, configurable)
- **API Compatibility**: JSON API (v1), not gRPC
- **Versioning**: Generation-based (matches GCS behavior)

### Test File Location

```
tests/
└── gcs_emulator_tests.rs
```

### Example Test Structure

```rust
use metafuse_catalog_storage::GcsBackend;
use testcontainers::{clients::Cli, images::generic::GenericImage};

#[tokio::test]
#[ignore] // Requires Docker and RUN_CLOUD_TESTS=1
async fn test_gcs_emulator_roundtrip() {
    // Skip if RUN_CLOUD_TESTS not set
    if std::env::var("RUN_CLOUD_TESTS").is_err() {
        return;
    }

    // Start fake-gcs-server container
    let docker = Cli::default();
    let gcs_emulator = docker.run(
        GenericImage::new("fsouza/fake-gcs-server", "latest")
            .with_exposed_port(4443)
            .with_wait_for(testcontainers::core::WaitFor::message_on_stdout(
                "server started",
            )),
    );

    let port = gcs_emulator.get_host_port_ipv4(4443);
    let emulator_url = format!("http://127.0.0.1:{}", port);

    // Create bucket via HTTP API
    let client = reqwest::Client::new();
    let bucket_name = "test-bucket";
    client
        .post(format!("{}/storage/v1/b", emulator_url))
        .json(&serde_json::json!({ "name": bucket_name }))
        .send()
        .await
        .unwrap();

    // Configure GcsBackend with emulator endpoint
    std::env::set_var("STORAGE_EMULATOR_HOST", emulator_url);
    let backend = GcsBackend::new(&format!("gs://{}/catalog.db", bucket_name));

    // Test operations
    backend.init().await.unwrap();
    assert!(backend.exists().await.unwrap());

    // Container automatically cleaned up when gcs_emulator is dropped
}
```

### GCS-Specific Test Cases

**1. Generation-Based Versioning**

```rust
#[tokio::test]
async fn test_gcs_generation_versioning() {
    // Validate that concurrent writes use generation metadata
    // Expected: Second write detects version mismatch and returns conflict
}
```

**2. Metadata Preservation**

```rust
#[tokio::test]
async fn test_gcs_metadata_preservation() {
    // Upload with custom metadata
    // Download and verify metadata matches
}
```

**3. Retry Logic**

```rust
#[tokio::test]
async fn test_gcs_retry_on_transient_error() {
    // Simulate network error
    // Verify exponential backoff retry succeeds
}
```

**4. Cache Behavior**

```rust
#[tokio::test]
async fn test_gcs_cache_ttl() {
    // Enable cache with TTL
    // Verify cache hit/miss behavior
}
```

## S3 Emulator Tests

### Overview

S3 emulator tests use MinIO, an industry-standard S3-compatible object storage emulator.

**Emulator Details:**

- **Image**: `minio/minio:latest`
- **Port**: 9000 (S3 API), 9001 (Console, optional)
- **API Compatibility**: Full S3 API compatibility
- **Versioning**: ETag-based (MD5 hash)
- **Credentials**: `minioadmin` / `minioadmin` (default)

### Test File Location

```
tests/
└── s3_emulator_tests.rs
```

### Example Test Structure

```rust
use metafuse_catalog_storage::S3Backend;
use testcontainers::{clients::Cli, images::generic::GenericImage};

#[tokio::test]
#[ignore] // Requires Docker and RUN_CLOUD_TESTS=1
async fn test_s3_emulator_roundtrip() {
    // Skip if RUN_CLOUD_TESTS not set
    if std::env::var("RUN_CLOUD_TESTS").is_err() {
        return;
    }

    // Start MinIO container
    let docker = Cli::default();
    let minio = docker.run(
        GenericImage::new("minio/minio", "latest")
            .with_exposed_port(9000)
            .with_env_var("MINIO_ROOT_USER", "minioadmin")
            .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
            .with_wait_for(testcontainers::core::WaitFor::message_on_stdout(
                "MinIO Object Storage Server",
            ))
            .with_cmd(vec!["server", "/data"]),
    );

    let port = minio.get_host_port_ipv4(9000);
    let endpoint = format!("http://127.0.0.1:{}", port);

    // Configure AWS SDK with MinIO endpoint
    let config = aws_sdk_s3::config::Builder::new()
        .endpoint_url(&endpoint)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            "minioadmin",
            "minioadmin",
            None,
            None,
            "static",
        ))
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .force_path_style(true)
        .build();

    let s3_client = aws_sdk_s3::Client::from_conf(&config);

    // Create bucket
    let bucket_name = "test-bucket";
    s3_client
        .create_bucket()
        .bucket(bucket_name)
        .send()
        .await
        .unwrap();

    // Configure S3Backend with emulator endpoint
    let backend = S3Backend::new_with_client(
        s3_client,
        bucket_name,
        "catalog.db",
        "us-east-1",
    );

    // Test operations
    backend.init().await.unwrap();
    assert!(backend.exists().await.unwrap());

    // Container automatically cleaned up when minio is dropped
}
```

### S3-Specific Test Cases

**1. ETag-Based Versioning**

```rust
#[tokio::test]
async fn test_s3_etag_versioning() {
    // Validate that concurrent writes use ETag metadata
    // Expected: Second write detects ETag mismatch and returns conflict
}
```

**2. Region Configuration**

```rust
#[tokio::test]
async fn test_s3_region_handling() {
    // Create backend with specific region
    // Verify requests include correct region headers
}
```

**3. Path-Style vs. Virtual-Hosted-Style**

```rust
#[tokio::test]
async fn test_s3_path_style_urls() {
    // Force path-style URLs (required for MinIO)
    // Verify URL format: http://endpoint/bucket/key
}
```

**4. Multipart Upload (Future)**

```rust
#[tokio::test]
async fn test_s3_multipart_upload() {
    // For large catalogs (>5MB)
    // Verify multipart upload completion
}
```

## Environment-Gated Execution

### Why Environment Gating?

Emulator tests require Docker and take longer than unit tests. By default, they are skipped to maintain fast test suite execution.

**Gating Strategy:**

```rust
#[tokio::test]
#[ignore] // Skipped by default
async fn test_cloud_backend() {
    // Early return if RUN_CLOUD_TESTS not set
    if std::env::var("RUN_CLOUD_TESTS").is_err() {
        return;
    }

    // Test logic...
}
```

**Execution Modes:**

| Command | Behavior |
|---------|----------|
| `cargo test` | Skips emulator tests (fast) |
| `cargo test --features cloud` | Compiles cloud code but skips emulator tests |
| `RUN_CLOUD_TESTS=1 cargo test --features cloud` | Runs emulator tests |
| `cargo test --test gcs_emulator_tests` | Compiles GCS tests but skips execution |
| `RUN_CLOUD_TESTS=1 cargo test --test gcs_emulator_tests` | Runs GCS emulator tests |

### Alternative Gating Patterns

**1. cfg-based (Not Recommended for Emulators)**

```rust
#[cfg(feature = "emulator-tests")]
#[tokio::test]
async fn test_emulator() {
    // Problem: Requires separate feature flag, complicates CI
}
```

**2. Environment-Only (Recommended)**

```rust
#[tokio::test]
#[ignore]
async fn test_emulator() {
    if std::env::var("RUN_CLOUD_TESTS").is_err() {
        return;
    }
    // Flexible, runtime-controlled, no feature flag needed
}
```

## Best Practices

### 1. Container Lifecycle Management

**Use RAII for Cleanup:**

```rust
{
    let container = docker.run(image);
    // Container running

    // Test operations...

} // Container automatically stopped and removed
```

**Avoid Manual Cleanup:**

```rust
// BAD: Manual cleanup is error-prone
let container = docker.run(image);
// ... test logic ...
container.stop(); // Might not execute if test panics
```

### 2. Port Handling

**Always Use Dynamic Ports:**

```rust
// GOOD: testcontainers assigns random host port
let port = container.get_host_port_ipv4(4443);
let url = format!("http://127.0.0.1:{}", port);
```

**Avoid Hardcoded Ports:**

```rust
// BAD: Port conflicts if multiple tests run concurrently
let url = "http://127.0.0.1:4443";
```

### 3. Wait for Readiness

**Use WaitFor Strategies:**

```rust
GenericImage::new("fsouza/fake-gcs-server", "latest")
    .with_wait_for(WaitFor::message_on_stdout("server started"))
    .with_wait_for(WaitFor::seconds(2)) // Additional safety margin
```

**Common Wait Strategies:**

- `WaitFor::message_on_stdout("...")`: Wait for log message
- `WaitFor::seconds(N)`: Wait fixed duration (use sparingly)
- `WaitFor::http(...)`: Wait for HTTP endpoint (future testcontainers feature)

### 4. Isolation and Idempotence

**Use Unique Resource Names:**

```rust
let bucket_name = format!("test-bucket-{}", uuid::Uuid::new_v4());
```

**Clean State Between Tests:**

```rust
#[tokio::test]
async fn test_with_clean_state() {
    let container = docker.run(image);

    // Each test gets fresh container = isolated state
}
```

### 5. Error Handling

**Fail Fast on Setup Errors:**

```rust
let container = docker.run(image);
let port = container.get_host_port_ipv4(9000);

// Setup operations should not swallow errors
let result = create_bucket(&client, "test-bucket").await;
result.expect("Failed to create test bucket - emulator not ready?");
```

**Meaningful Assertion Messages:**

```rust
assert!(
    backend.exists().await.unwrap(),
    "Catalog should exist after init()"
);
```

### 6. Performance Optimization

**Reuse Containers Across Tests (If Safe):**

```rust
// Advanced: Share container for read-only tests
static EMULATOR: OnceCell<Container> = OnceCell::new();

#[tokio::test]
async fn test_read_only_1() {
    let container = EMULATOR.get_or_init(|| docker.run(image));
    // ...
}
```

**Parallel Test Execution:**

```rust
// Tests with separate containers can run in parallel
cargo test --features cloud -- --test-threads=4
```

## Common Patterns

### Pattern 1: Emulator Factory

```rust
async fn setup_gcs_emulator() -> (Container, String) {
    let docker = Cli::default();
    let container = docker.run(
        GenericImage::new("fsouza/fake-gcs-server", "latest")
            .with_exposed_port(4443)
            .with_wait_for(WaitFor::message_on_stdout("server started")),
    );

    let port = container.get_host_port_ipv4(4443);
    let url = format!("http://127.0.0.1:{}", port);

    (container, url)
}

#[tokio::test]
async fn test_with_factory() {
    let (_container, url) = setup_gcs_emulator().await;
    // Use url...
}
```

### Pattern 2: Fixture Data

```rust
async fn seed_test_data(backend: &GcsBackend) {
    backend.init().await.unwrap();

    // Emit sample datasets
    let emitter = Emitter::new(backend.clone());
    emitter
        .emit_dataset(
            "fixture_dataset",
            "test.parquet",
            "parquet",
            None,
            None,
            None,
            None,
            Arc::new(Schema::empty()),
            None,
            vec![],
            vec![],
        )
        .unwrap();
}

#[tokio::test]
async fn test_with_fixtures() {
    let (_container, backend) = setup_gcs_backend().await;
    seed_test_data(&backend).await;

    // Test against pre-populated catalog
}
```

### Pattern 3: Snapshot Testing

```rust
#[tokio::test]
async fn test_catalog_schema_snapshot() {
    let (_container, backend) = setup_s3_backend().await;
    backend.init().await.unwrap();

    // Download catalog and verify schema
    let catalog_bytes = backend.download().await.unwrap();
    let conn = Connection::open_in_memory().unwrap();
    conn.restore("main", catalog_bytes.as_slice(), None).unwrap();

    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;

    assert_eq!(
        tables,
        vec!["datasets", "fields", "tags", "lineage", "glossary"]
    );
}
```

## Troubleshooting

### Container Startup Failures

**Symptom:** Test hangs or fails with "Container did not become ready"

**Solutions:**

1. Check Docker is running:
   ```bash
   docker ps
   ```

2. Verify image pulls successfully:
   ```bash
   docker pull fsouza/fake-gcs-server
   docker pull minio/minio
   ```

3. Increase wait timeout:
   ```rust
   .with_wait_for(WaitFor::seconds(30))
   ```

4. Check logs:
   ```rust
   let logs = docker.logs(&container);
   eprintln!("Container logs: {}", logs);
   ```

### Port Binding Errors

**Symptom:** "Address already in use"

**Solutions:**

1. Always use dynamic ports via `get_host_port_ipv4()`
2. Ensure containers are cleaned up between test runs:
   ```bash
   docker ps -a | grep fake-gcs-server
   docker rm -f <container-id>
   ```

### Permission Errors

**Symptom:** "Permission denied when accessing Docker socket"

**Solutions:**

1. **Linux:** Add user to `docker` group:
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

2. **macOS:** Ensure Docker Desktop is running

3. **Windows (WSL):** Configure Docker Desktop for WSL 2 integration

### Slow Test Execution

**Symptom:** Emulator tests take 30+ seconds

**Solutions:**

1. Cache Docker images locally (first run is slow, subsequent runs fast)
2. Use `--test-threads=1` if tests interfere
3. Run emulator tests separately:
   ```bash
   RUN_CLOUD_TESTS=1 cargo test --test gcs_emulator_tests
   ```

### Flaky Tests

**Symptom:** Tests pass sometimes, fail other times

**Solutions:**

1. Increase readiness wait time
2. Add retries for transient network errors
3. Ensure unique resource names (avoid conflicts)
4. Check for race conditions in concurrent tests

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Emulator Tests

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  emulator-tests:
    name: Cloud Emulator Tests
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v6

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Cache dependencies
        uses: Swatinem/rust-cache@v2

      - name: Pull emulator images
        run: |
          docker pull fsouza/fake-gcs-server
          docker pull minio/minio

      - name: Run GCS emulator tests
        run: RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests

      - name: Run S3 emulator tests
        run: RUN_CLOUD_TESTS=1 cargo test --features s3 --test s3_emulator_tests
```

### GitLab CI Example

```yaml
emulator-tests:
  stage: test
  image: rust:latest
  services:
    - docker:dind
  variables:
    DOCKER_HOST: tcp://docker:2375
    RUN_CLOUD_TESTS: "1"
  before_script:
    - docker pull fsouza/fake-gcs-server
    - docker pull minio/minio
  script:
    - cargo test --features cloud --test gcs_emulator_tests
    - cargo test --features cloud --test s3_emulator_tests
```

## Performance Considerations

### Emulator Overhead

**Typical Test Duration:**

- Unit test: 1-10ms
- Emulator test (cold start): 2-5 seconds (container startup)
- Emulator test (warm): 100-500ms (container reuse)

**Optimization Strategies:**

1. **Run emulator tests less frequently** (e.g., pre-commit, not on every save)
2. **Parallelize tests** with separate containers
3. **Cache Docker images** in CI to avoid pulls
4. **Use smaller emulator images** if available

### Resource Usage

**Memory:**

- fake-gcs-server: ~50MB
- MinIO: ~100MB
- Total overhead: ~200MB per test run

**CPU:**

- Minimal during idle
- Spikes during upload/download

**Disk:**

- Docker images: ~500MB (one-time)
- Container overlays: ~10MB per test

## Security Considerations

### Credential Handling

**Emulator Tests:**

- Use hardcoded test credentials (`minioadmin`/`minioadmin`)
- Never use production credentials in tests
- Emulators run locally, no network exposure

**Environment Isolation:**

```rust
// Good: Isolated test credentials
std::env::set_var("AWS_ACCESS_KEY_ID", "test-key");
std::env::set_var("AWS_SECRET_ACCESS_KEY", "test-secret");

// Run test...

// Optional: Clean up
std::env::remove_var("AWS_ACCESS_KEY_ID");
std::env::remove_var("AWS_SECRET_ACCESS_KEY");
```

### Network Isolation

**Emulators are local-only:**

- Bind to `127.0.0.1` (localhost)
- Not accessible from external network
- No firewall rules needed

**Container-to-Host Communication:**

- Uses Docker bridge network
- Port mapping: `127.0.0.1:<random-port>` → `container:4443`

### Data Sanitization

**Test Data Best Practices:**

- Use synthetic data only
- Avoid PII (Personally Identifiable Information)
- Use random/unique identifiers
- Clean up after tests (automatic with testcontainers)

## Further Reading

- [testcontainers-rs Documentation](https://docs.rs/testcontainers)
- [fake-gcs-server Repository](https://github.com/fsouza/fake-gcs-server)
- [MinIO Documentation](https://min.io/docs/minio/linux/index.html)
- [Docker Documentation](https://docs.docker.com/)
- [Integration Testing Best Practices](https://martinfowler.com/articles/practical-test-pyramid.html)

---

**Next Steps:**

- Review existing emulator tests: [`tests/gcs_emulator_tests.rs`](../tests/gcs_emulator_tests.rs), [`tests/s3_emulator_tests.rs`](../tests/s3_emulator_tests.rs)
- Run emulator tests locally: `RUN_CLOUD_TESTS=1 cargo test --features cloud`
- Contribute new test cases following patterns in this guide
