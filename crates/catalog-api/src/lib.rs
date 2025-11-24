//! MetaFuse Catalog API Library
//!
//! This crate provides library components for the MetaFuse Catalog API server,
//! including API key management and rate limiting.

#[cfg(feature = "api-keys")]
pub mod api_keys;

#[cfg(feature = "rate-limiting")]
pub mod rate_limiting;
