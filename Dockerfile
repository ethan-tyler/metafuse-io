# MetaFuse API Server Dockerfile
#
# Multi-stage build for optimized image size
# Produces a minimal runtime image with just the API binary

# Build stage
FROM rust:1.75-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/catalog-core/Cargo.toml ./crates/catalog-core/
COPY crates/catalog-storage/Cargo.toml ./crates/catalog-storage/
COPY crates/catalog-emitter/Cargo.toml ./crates/catalog-emitter/
COPY crates/catalog-api/Cargo.toml ./crates/catalog-api/
COPY crates/catalog-cli/Cargo.toml ./crates/catalog-cli/

# Create dummy source files to cache dependencies
RUN mkdir -p crates/catalog-core/src && \
    mkdir -p crates/catalog-storage/src && \
    mkdir -p crates/catalog-emitter/src && \
    mkdir -p crates/catalog-api/src && \
    mkdir -p crates/catalog-cli/src && \
    echo "fn main() {}" > crates/catalog-api/src/main.rs && \
    echo "fn main() {}" > crates/catalog-cli/src/main.rs && \
    touch crates/catalog-core/src/lib.rs && \
    touch crates/catalog-storage/src/lib.rs && \
    touch crates/catalog-emitter/src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release --package metafuse-catalog-api --all-features

# Remove dummy files
RUN rm -rf crates/*/src

# Copy actual source code
COPY crates/ ./crates/

# Force rebuild with actual source
RUN touch crates/catalog-api/src/main.rs && \
    cargo build --release --package metafuse-catalog-api --all-features

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 -s /bin/bash metafuse

# Copy binary from builder
COPY --from=builder /build/target/release/metafuse-api /usr/local/bin/metafuse-api

# Set ownership
RUN chown metafuse:metafuse /usr/local/bin/metafuse-api

# Create data directory for catalog storage
RUN mkdir -p /data && chown metafuse:metafuse /data

# Switch to app user
USER metafuse
WORKDIR /home/metafuse

# Environment variables
ENV METAFUSE_CATALOG_PATH=/data/metafuse_catalog.db
ENV METAFUSE_PORT=8080
ENV RUST_LOG=info

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1"]

# Run API server
CMD ["/usr/local/bin/metafuse-api"]
