# Contributing to MetaFuse

Thank you for your interest in contributing to MetaFuse! We welcome contributions from the community.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Rust 1.75+ (recommended: latest stable)
- Git
- Optional: Docker (for containerized development)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/ethan-tyler/MetaFuse.git
   cd metafuse
   ```

2. **Build the project**
   ```bash
   cargo build --workspace --all-features
   ```

3. **Run tests**
   ```bash
   cargo test --workspace --all-features
   cargo test --doc  # Run documentation tests
   ```

4. **Run examples**
   ```bash
   ./run_examples.sh
   # Or individually:
   cargo run --example simple_pipeline
   cargo run --example lineage_tracking
   ```

5. **Check code quality**
   ```bash
   cargo fmt --all -- --check    # Format check
   cargo clippy --workspace --all-features -- -D warnings  # Linting
   ```

## Development Workflow

### Making Changes

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Make your changes** following our coding standards (see below)

3. **Test your changes**:
   ```bash
   cargo test --workspace
   cargo clippy --workspace --all-features -- -D warnings
   cargo fmt --all
   ```

4. **Commit your changes** using [Conventional Commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat: add support for column-level lineage"
   git commit -m "fix: resolve SQLite lock contention in concurrent writes"
   git commit -m "docs: update getting started guide"
   ```

   Commit types:
   - `feat`: New features
   - `fix`: Bug fixes
   - `docs`: Documentation changes
   - `test`: Adding or updating tests
   - `refactor`: Code refactoring
   - `perf`: Performance improvements
   - `chore`: Build process or tooling changes

5. **Push to your fork** and **create a Pull Request**

### Pull Request Guidelines

Before submitting a PR, ensure:

- [ ] All tests pass: `cargo test --workspace --all-features`
- [ ] Code is formatted: `cargo fmt --all`
- [ ] Clippy is clean: `cargo clippy --workspace --all-features -- -D warnings`
- [ ] Documentation is updated (if applicable)
- [ ] New tests are added for new functionality
- [ ] Commit messages follow Conventional Commits format
- [ ] PR description clearly explains the changes and motivation

**Local clippy flags MUST match CI configuration.** Run:
```bash
cargo clippy --workspace --all-features -- -D warnings
```

If this passes locally, it will pass in CI.

### PR Review Process

1. A maintainer will review your PR within 3-5 business days
2. Address any feedback by pushing new commits to your branch
3. Once approved, a maintainer will merge your PR
4. Your contribution will be included in the next release

## Coding Standards

### Rust Style

- Follow Rust API guidelines: https://rust-lang.github.io/api-guidelines/
- Use `rustfmt` (default settings) for all code formatting
- Write idiomatic Rust (leverage the type system, avoid `unwrap()` in library code)
- Prefer explicit error handling over panics
- Document public APIs with `///` doc comments

### Error Handling

- Use `CatalogError` for all errors in the catalog domain
- Provide context with error messages
- Avoid `panic!`, `unwrap()`, and `expect()` in library code (tests are OK)
- Use `Result<T>` return types for fallible operations

### Testing

- Write unit tests for individual functions/modules
- Write integration tests for multi-crate workflows
- Ensure tests are idempotent and isolated (use `tempfile::TempDir`)
- Test both success and error paths
- Aim for meaningful coverage, not just high percentages

### Cloud Emulator Testing

MetaFuse includes integration tests for cloud backends (GCS and S3) using Docker-based emulators. These tests are **optional** for most contributions but **required** if you're modifying cloud backend code.

**When to run emulator tests:**

- When modifying cloud storage backend code (`catalog-storage/src/gcs.rs`, `catalog-storage/src/s3.rs`)
- When changing versioning, concurrency, or retry logic
- Before submitting PRs that affect cloud functionality

**Requirements:**

- Docker installed and running
- `RUN_CLOUD_TESTS=1` environment variable

**Running emulator tests:**

```bash
# GCS emulator tests (requires Docker)
RUN_CLOUD_TESTS=1 cargo test --features gcs --test gcs_emulator_tests

# S3 emulator tests (requires Docker)
RUN_CLOUD_TESTS=1 cargo test --features s3 --test s3_emulator_tests

# Skip emulator tests (default)
cargo test --features cloud  # Emulator tests are skipped without RUN_CLOUD_TESTS
```

**What emulator tests cover:**

- Catalog initialization and versioning (GCS generations, S3 ETags)
- Concurrent write detection and conflict handling
- Retry logic with exponential backoff
- Cache behavior
- Metadata preservation

For detailed documentation on writing and debugging emulator tests, see [Cloud Emulator Testing Guide](docs/cloud-emulator-tests.md).

### Documentation

- Add `///` doc comments for all public items
- Include examples in doc comments where helpful
- Keep examples runnable (they will be tested with `cargo test --doc`)
- Update relevant docs in `docs/` for significant changes

## Project Structure

```
MetaFuse/
|-- crates/
|   |-- catalog-core/      # Core types, schema, errors
|   |-- catalog-storage/   # Storage backend abstraction
|   |-- catalog-emitter/   # DataFusion integration
|   |-- catalog-api/       # REST API (Axum)
|   `-- catalog-cli/       # CLI tool (Clap)
|-- docs/                  # Documentation
|-- examples/              # Runnable examples
|-- tests/                 # Integration tests
`-- benches/               # Performance benchmarks
```

## Areas for Contribution

### Good First Issues

Look for issues labeled `good-first-issue` in the issue tracker. These are typically:
- Documentation improvements
- Adding tests
- Small bug fixes
- Example projects

### Priority Areas

- Cloud storage backends (GCS, S3)
- Web UI for catalog visualization
- Performance optimizations
- DataFusion integration improvements
- Ecosystem integrations (dbt, Airflow, etc.)

## Running the Full Test Suite

```bash
# Build everything
cargo build --workspace --all-features

# Run all tests (unit + integration + doc tests)
cargo test --workspace --all-features
cargo test --doc

# Run linting
cargo clippy --workspace --all-features -- -D warnings

# Check formatting
cargo fmt --all -- --check

# Run examples
./run_examples.sh
```

## Benchmarking (Optional)

Benchmarks are gated behind a feature flag:

```bash
cargo bench --features bench
```

## Release Process

(For maintainers)

1. Update version numbers in `Cargo.toml` files
2. Update `CHANGELOG.md`
3. Create a git tag: `git tag -a v0.2.0 -m "Release v0.2.0"`
4. Push tag: `git push origin v0.2.0`
5. GitHub Actions will build and publish the release

## Questions?

- Open a [Discussion](https://github.com/ethan-tyler/MetaFuse/discussions) for questions
- Open an [Issue](https://github.com/ethan-tyler/MetaFuse/issues) for bug reports or feature requests
- Review the [documentation](docs/) for technical details

## License

By contributing to MetaFuse, you agree that your contributions will be licensed under the Apache License 2.0.
