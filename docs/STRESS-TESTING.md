# Stress Testing Guide

This guide covers MetaFuse's stress testing suite for validating concurrent access patterns and resource management under load.

## TL;DR - Quick Start

**Requirements**: None (runs against local SQLite)

```bash
# Run all stress tests with defaults (10 clients, 30s duration)
RUN_STRESS_TESTS=1 cargo test --test stress_tests

# Run with custom configuration
RUN_STRESS_TESTS=1 STRESS_TEST_CLIENTS=20 STRESS_TEST_DURATION_SECS=60 cargo test --test stress_tests

# Run specific stress test
RUN_STRESS_TESTS=1 cargo test --test stress_tests test_concurrent_writers
```

**What you get:**

- Validates concurrent access patterns (multiple readers/writers)
- Detects race conditions and resource leaks
- Measures performance under load
- Verifies optimistic locking correctness

**Note**: Stress tests are opt-in and NOT run in CI by default. They are designed for local development and manual testing.

---

## Table of Contents

- [Overview](#overview)
- [Test Scenarios](#test-scenarios)
- [Configuration](#configuration)
- [Running Tests](#running-tests)
- [Interpreting Results](#interpreting-results)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Overview

MetaFuse's stress test suite validates the catalog storage layer under concurrent access patterns. These tests complement unit and integration tests by exercising the system under realistic load conditions.

### Why Stress Testing?

**Validate Concurrent Access**:

- Multiple processes writing to the same catalog
- Read-heavy workloads with many concurrent readers
- Cache invalidation race conditions

**Detect Issues**:

- Race conditions in optimistic locking
- Resource leaks (connections, file handles)
- Deadlocks or lock contention
- Cache consistency problems

**Measure Performance**:

- Throughput under load (reads/writes per second)
- Conflict resolution efficiency
- Resource cleanup correctness

### Test Philosophy

- **Opt-in**: Stress tests are gated by `RUN_STRESS_TESTS=1` and NOT run by default
- **Time-bounded**: Tests run for ≤30 seconds by default (configurable up to 300s)
- **Resource-limited**: Client count capped at 50 to avoid overwhelming test machines
- **Isolated**: Each test uses a temporary database and cleans up resources

## Test Scenarios

### 1. Concurrent Writers

**Purpose**: Validate optimistic locking with multiple writers

**Test**: `test_concurrent_writers`

**Scenario**:

- Multiple clients (default: 10) write to the same 5 datasets simultaneously
- Concurrent writes to the same dataset should trigger version conflicts
- System should correctly detect and report conflicts

**What it validates**:

- Optimistic concurrency control works correctly
- Version-based conflict detection
- No data corruption under concurrent writes
- Graceful conflict handling

**Expected behavior**:

- Some successful writes (no conflict)
- Some conflicts detected (expected with concurrent writes)
- Zero unexpected errors

### 2. Read-Heavy Workload

**Purpose**: Validate concurrent read performance

**Test**: `test_read_heavy_workload`

**Scenario**:

- Many clients (default: 20) read from a pre-populated catalog
- Clients read random datasets continuously
- Measures read throughput

**What it validates**:

- Concurrent read performance
- Cache effectiveness (if enabled)
- No read contention issues
- Stable throughput under load

**Expected behavior**:

- High read throughput (>10 reads/sec)
- No read errors
- Consistent performance throughout test

### 3. Optimistic Lock Resolution

**Purpose**: Validate retry logic and eventual consistency

**Test**: `test_optimistic_lock_resolution`

**Scenario**:

- All clients attempt to update the same dataset simultaneously
- Clients retry on version conflicts (max 5 attempts)
- All clients should eventually succeed

**What it validates**:

- Retry logic works correctly
- No lost updates
- Eventual consistency achieved
- Bounded retry behavior

**Expected behavior**:

- All clients eventually succeed (may take multiple attempts)
- Conflicts detected and handled gracefully
- No infinite retry loops

### 4. Cache Invalidation Race

**Purpose**: Validate cache consistency under concurrent read/write

**Test**: `test_cache_invalidation_race`

**Scenario**:

- 33% writers, 67% readers (configurable client count)
- Writers continuously update a dataset
- Readers track unique versions observed
- Test runs for 15 seconds

**What it validates**:

- Cache invalidation correctness
- No stale reads
- Version tracking accuracy
- Cache consistency under concurrent access

**Expected behavior**:

- Multiple unique versions observed (indicating cache invalidation works)
- No version inconsistencies
- Readers see updates from writers

### 5. Connection Cleanup

**Purpose**: Validate resource leak prevention

**Test**: `test_connection_cleanup`

**Scenario**:

- Many clients perform mixed operations (write, read, list)
- All clients complete and drop their connections
- Verify catalog still accessible after cleanup

**What it validates**:

- No resource leaks (connections, file handles)
- Proper cleanup after concurrent access
- Catalog remains healthy after load

**Expected behavior**:

- All datasets remain accessible
- No orphaned connections
- Clean resource cleanup

## Configuration

### Environment Variables

**`RUN_STRESS_TESTS`** (required):

- Set to `1` to run stress tests
- Default: unset (tests skipped)

**`STRESS_TEST_CLIENTS`** (optional):

- Number of concurrent clients
- Default: `10`
- Min: `1`
- Max: `50` (enforced to prevent overwhelming test machine)

**`STRESS_TEST_DURATION_SECS`** (optional):

- Test duration in seconds
- Default: `30`
- Min: `1`
- Max: `300` (5 minutes, enforced for reasonable test runtime)

### Example Configurations

**Default (quick validation)**:

```bash
RUN_STRESS_TESTS=1 cargo test --test stress_tests
# 10 clients, 30s duration
```

**Heavy load**:

```bash
RUN_STRESS_TESTS=1 STRESS_TEST_CLIENTS=50 STRESS_TEST_DURATION_SECS=120 cargo test --test stress_tests
# 50 clients, 2 minutes
```

**Single test with custom config**:

```bash
RUN_STRESS_TESTS=1 STRESS_TEST_CLIENTS=20 cargo test --test stress_tests test_concurrent_writers
# 20 clients, 30s duration
```

## Running Tests

### Prerequisites

- Rust toolchain installed
- No special dependencies (uses local SQLite)
- Sufficient disk space for temporary databases

### Basic Execution

```bash
# Run all stress tests
RUN_STRESS_TESTS=1 cargo test --test stress_tests

# Run with verbose output
RUN_STRESS_TESTS=1 cargo test --test stress_tests -- --nocapture

# Run specific test
RUN_STRESS_TESTS=1 cargo test --test stress_tests test_read_heavy_workload
```

### Advanced Execution

**Parallel vs Sequential**:

```bash
# Run tests sequentially (safer for resource-constrained machines)
RUN_STRESS_TESTS=1 cargo test --test stress_tests -- --test-threads=1

# Run tests in parallel (default, faster)
RUN_STRESS_TESTS=1 cargo test --test stress_tests
```

**Release Mode** (for performance benchmarking):

```bash
RUN_STRESS_TESTS=1 cargo test --test stress_tests --release
```

## Interpreting Results

### Successful Output

```
Running concurrent writer stress test: 10 clients, 30s duration
Results:
  Successful writes: 1523
  Conflicts detected: 87
  Errors: 0

test test_concurrent_writers ... ok
```

**Analysis**:

- ✅ Successful writes > 0 (system is making progress)
- ✅ Conflicts detected (expected with concurrent writes to same datasets)
- ✅ Errors = 0 (no unexpected failures)

### Performance Metrics

```
Running read-heavy stress test: 20 clients, 30s duration
Results:
  Total reads: 12456
  Reads/sec: 415.20

test test_read_heavy_workload ... ok
```

**Analysis**:

- ✅ Reads/sec > 10 (acceptable performance threshold)
- Higher is better, but depends on machine specs

### Cache Effectiveness

```
Running cache invalidation test: 10 clients, 15s duration
Results:
  Unique versions observed: 23

test test_cache_invalidation_race ... ok
```

**Analysis**:

- ✅ Unique versions > 1 (cache invalidation is working)
- More versions = more updates = cache is being invalidated correctly

## Troubleshooting

### Test Failures

**"Should have successful writes" assertion failed**:

- **Cause**: No writes completed successfully
- **Solution**: Check disk space, permissions on temp directory, increase `STRESS_TEST_DURATION_SECS`

**"Should have no errors" assertion failed**:

- **Cause**: Unexpected errors during test
- **Solution**: Check stderr output for error messages, verify SQLite is working correctly

**"All clients should eventually succeed" assertion failed**:

- **Cause**: Retry logic not working, or too many conflicts
- **Solution**: Increase max retry attempts in test, reduce client count

### Performance Issues

**Low reads/sec (<10)**:

- **Possible causes**: Slow disk I/O, CPU contention, too many concurrent tests
- **Solutions**:
  - Run tests sequentially (`--test-threads=1`)
  - Reduce client count
  - Run in release mode (`--release`)
  - Check system resources (disk I/O, CPU usage)

**Test timeouts**:

- **Possible causes**: Deadlock, infinite retry loop, system overload
- **Solutions**:
  - Reduce `STRESS_TEST_DURATION_SECS`
  - Reduce `STRESS_TEST_CLIENTS`
  - Check for system resource exhaustion

### Resource Issues

**"Too many open files" error**:

- **Cause**: Operating system file descriptor limit
- **Solution**:
  - macOS/Linux: `ulimit -n 4096` (increase limit)
  - Reduce `STRESS_TEST_CLIENTS`

**Disk space errors**:

- **Cause**: Insufficient disk space for temporary databases
- **Solution**: Free up disk space, verify `/tmp` has space

## Best Practices

### When to Run Stress Tests

**During Development**:

- After implementing concurrent access patterns
- Before committing changes to storage layer
- When debugging concurrency issues

**Before Release**:

- Final validation before cutting a release
- Regression testing after major refactors
- Performance baseline establishment

**NOT in CI** (by design):

- Stress tests are resource-intensive
- Results can be flaky on shared CI runners
- Better suited for local development and manual QA

### Interpreting Conflicts

**Conflicts are EXPECTED**:

- Concurrent writes to the same dataset will conflict
- This is correct behavior for optimistic locking
- Zero conflicts might indicate tests aren't stressing the system

**Too many conflicts**:

- If conflicts outnumber successful writes significantly, consider:
  - Reducing client count
  - Using more unique datasets
  - Adjusting retry strategies

### Performance Baselines

**Establish baselines** for your machine:

```bash
# Run once to establish baseline
RUN_STRESS_TESTS=1 cargo test --test stress_tests --release -- --nocapture > baseline.txt

# Compare future runs against baseline
RUN_STRESS_TESTS=1 cargo test --test stress_tests --release -- --nocapture > current.txt
diff baseline.txt current.txt
```

**Track metrics over time**:

- Reads/sec (should remain stable or improve)
- Writes/sec (should remain stable)
- Conflict rate (should be consistent)

### Debugging Concurrency Issues

**Enable verbose logging**:

```bash
RUST_LOG=debug RUN_STRESS_TESTS=1 cargo test --test stress_tests -- --nocapture
```

**Reduce concurrency to isolate issues**:

```bash
# Minimal concurrency
RUN_STRESS_TESTS=1 STRESS_TEST_CLIENTS=2 STRESS_TEST_DURATION_SECS=10 cargo test --test stress_tests -- --nocapture
```

**Run individual tests**:

```bash
# Isolate specific failure
RUN_STRESS_TESTS=1 cargo test --test stress_tests test_optimistic_lock_resolution -- --nocapture
```

## Advanced Topics

### Custom Stress Scenarios

To add custom stress scenarios, edit `crates/catalog-storage/tests/stress_tests.rs` and follow the existing patterns:

1. Use `test_guard()` for opt-in execution
2. Create isolated temp database per test
3. Respect `get_client_count()` and `get_test_duration()`
4. Use `Arc<AtomicUsize>` for thread-safe counters
5. Clean up resources with RAII (temp dir drops automatically)

### Integration with CI

While stress tests are NOT run in default CI, you can create a scheduled/manual workflow:

```yaml
# .github/workflows/stress-tests.yml (example, not included by default)
name: Stress Tests (Manual)

on:
  workflow_dispatch:
    inputs:
      clients:
        description: 'Number of clients'
        default: '10'
      duration:
        description: 'Duration in seconds'
        default: '30'

jobs:
  stress:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
      - name: Run stress tests
        env:
          RUN_STRESS_TESTS: 1
          STRESS_TEST_CLIENTS: ${{ github.event.inputs.clients }}
          STRESS_TEST_DURATION_SECS: ${{ github.event.inputs.duration }}
        run: cargo test --test stress_tests --release -- --nocapture
```

## Related Documentation

- [Cloud Emulator Testing](cloud-emulator-tests.md) - Cloud backend integration tests
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute to MetaFuse
- [Architecture](architecture.md) - System architecture and design decisions

## Questions?

- Open a [Discussion](https://github.com/ethan-tyler/MetaFuse/discussions) for questions
- Submit a [Bug Report](https://github.com/ethan-tyler/MetaFuse/issues) if stress tests reveal issues
