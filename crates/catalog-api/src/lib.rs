//! MetaFuse Catalog API Library
//!
//! This crate provides library components for the MetaFuse Catalog API server,
//! including API key management, rate limiting, and enterprise features.

#[cfg(feature = "metrics")]
pub mod metrics;

#[cfg(feature = "api-keys")]
pub mod api_keys;

#[cfg(feature = "rate-limiting")]
pub mod rate_limiting;

// Phase 3: Enterprise Features
#[cfg(feature = "audit")]
pub mod audit;

#[cfg(feature = "usage-analytics")]
pub mod usage_analytics;

// Quality Framework (core functionality, not feature-gated)
pub mod quality;

#[cfg(feature = "classification")]
pub mod classification;

// Multi-Tenant Control Plane
pub mod control_plane;

// Tenant Resolution Middleware
#[cfg(feature = "api-keys")]
pub mod tenant_resolver;

// Multi-Tenant Integration Layer
pub mod multi_tenant;

// v0.9.0: Alerting and Data Contracts
#[cfg(feature = "alerting")]
pub mod alerting;

#[cfg(feature = "contracts")]
pub mod contracts;

// Test utilities (feature-gated)
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
