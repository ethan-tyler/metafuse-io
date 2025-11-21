# Changelog

## v0.1.0 (Phase 1 MVP)

- Core SQLite schema (datasets, fields, lineage, tags, glossary) with FTS5 search and deterministic triggers to keep `dataset_search` in sync.
- Optimistic concurrency for catalog writes with retry/backoff; version tracking via `catalog_meta`.
- DataFusion emitter integrates schema extraction, lineage, tags, and operational metadata (row_count, size_bytes, partition_keys).
- CLI and API support listing, detail, search, lineage, and stats; partition keys and operational metadata are surfaced in responses.
- Backend abstraction with URI selection (`file://`/`gs://`/`s3://`); cloud backends are feature-gated stubs pending Phase 2.
- Integration tests and examples (simple pipeline, lineage) verified.

Notes:
- Cloud backends (GCS/S3) are not yet implemented; use the local SQLite backend for v0.1.0.
- Authentication/authorization is deferred to future phases.
