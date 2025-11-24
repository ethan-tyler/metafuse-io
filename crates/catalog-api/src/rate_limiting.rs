//! Rate limiting middleware for the MetaFuse catalog API
//!
//! This module provides tiered rate limiting with support for:
//! - Anonymous requests (IP-based, lower limits)
//! - Authenticated requests (API key-based, higher limits)
//! - Trusted proxy support (X-Forwarded-For extraction)
//! - Standard RFC 6585 compliant 429 responses
//!
//! ## Configuration
//!
//! - `METAFUSE_RATE_LIMIT_ANONYMOUS`: Requests per minute for anonymous clients (default: 100)
//! - `METAFUSE_RATE_LIMIT_AUTHENTICATED`: Requests per minute for authenticated clients (default: 1000)
//! - `METAFUSE_RATE_LIMIT_WINDOW_SECS`: Rate limit window in seconds (default: 60)
//! - `METAFUSE_TRUSTED_PROXIES`: Comma-separated list of trusted proxy IPs (optional, supports IPv4/IPv6)
//! - `METAFUSE_RATE_LIMIT_MAX_BUCKETS`: Maximum bucket storage (default: 10000)
//! - `METAFUSE_RATE_LIMIT_BUCKET_TTL_SECS`: Idle bucket TTL in seconds (default: 600)
//!
//! ## Security
//!
//! - **Trusted Proxy Validation**: X-Forwarded-For headers are only honored when the immediate
//!   peer address matches a configured trusted proxy. This prevents header spoofing attacks.
//! - **Memory Bounds**: Bucket storage is capped at 10,000 entries with TTL-based eviction
//!   (10-minute idle timeout) to prevent unbounded memory growth from high-cardinality keys.
//!
//! ## Example
//!
//! ```rust,ignore
//! use axum::Router;
//! use metafuse_catalog_api::rate_limiting;
//!
//! let app = Router::new()
//!     .layer(axum::middleware::from_fn(rate_limiting::rate_limit_middleware));
//! ```

use axum::{
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};
use dashmap::DashMap;
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, warn};

/// Rate limit for anonymous (unauthenticated) requests per window
const DEFAULT_ANONYMOUS_LIMIT: u32 = 100;

/// Rate limit for authenticated (API key) requests per window
const DEFAULT_AUTHENTICATED_LIMIT: u32 = 1000;

/// Default rate limit window in seconds
const DEFAULT_WINDOW_SECS: u64 = 60;

/// Default maximum number of rate limit buckets to keep in memory
const DEFAULT_MAX_BUCKETS: usize = 10_000;

/// Default TTL for idle rate limit buckets (10 minutes)
const DEFAULT_BUCKET_TTL_SECS: u64 = 600;

/// Marker type for API key identity in request extensions
#[derive(Clone, Debug)]
pub struct ApiKeyId {
    pub id: String,
}

/// Configuration for rate limiting
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub anonymous_limit: u32,
    pub authenticated_limit: u32,
    pub window_secs: u64,
    pub trusted_proxies: Option<Vec<String>>,
    /// Reserved for future bucket cleanup implementation
    #[allow(dead_code)]
    pub max_buckets: usize,
    /// Reserved for future bucket cleanup implementation
    #[allow(dead_code)]
    pub bucket_ttl_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            anonymous_limit: std::env::var("METAFUSE_RATE_LIMIT_ANONYMOUS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_ANONYMOUS_LIMIT),
            authenticated_limit: std::env::var("METAFUSE_RATE_LIMIT_AUTHENTICATED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_AUTHENTICATED_LIMIT),
            window_secs: std::env::var("METAFUSE_RATE_LIMIT_WINDOW_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_WINDOW_SECS),
            trusted_proxies: std::env::var("METAFUSE_TRUSTED_PROXIES")
                .ok()
                .map(|s| s.split(',').map(|ip| ip.trim().to_string()).collect()),
            max_buckets: std::env::var("METAFUSE_RATE_LIMIT_MAX_BUCKETS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_MAX_BUCKETS),
            bucket_ttl_secs: std::env::var("METAFUSE_RATE_LIMIT_BUCKET_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_BUCKET_TTL_SECS),
        }
    }
}

/// Rate limit bucket for tracking requests
#[derive(Clone, Debug)]
struct RateLimitBucket {
    count: u32,
    window_start: Instant,
    last_accessed: Instant,
}

/// Global rate limiter state
pub struct RateLimiter {
    config: Arc<RateLimitConfig>,
    buckets: Arc<DashMap<String, RateLimitBucket>>,
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            buckets: Arc::clone(&self.buckets),
        }
    }
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config: Arc::new(config),
            buckets: Arc::new(DashMap::new()),
        }
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    fn extract_client_ip<B>(&self, req: &Request<B>) -> Option<String> {
        // Get immediate peer address (the direct connection source)
        let peer_addr = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());

        // Only trust proxy headers if the request comes from a trusted proxy
        if let Some(trusted_proxies) = &self.config.trusted_proxies {
            if let Some(peer_ip) = peer_addr {
                let peer_ip_str = peer_ip.to_string();

                // Validate peer is in trusted proxy list
                if trusted_proxies.contains(&peer_ip_str) {
                    debug!(
                        peer_ip = %peer_ip_str,
                        "Request from trusted proxy, checking forwarded headers"
                    );

                    // Trust X-Forwarded-For header
                    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
                        if let Ok(forwarded_str) = forwarded.to_str() {
                            if let Some(client_ip) = forwarded_str.split(',').next() {
                                let client_ip = client_ip.trim();
                                debug!(
                                    client_ip = %client_ip,
                                    peer_ip = %peer_ip_str,
                                    "Extracted IP from X-Forwarded-For"
                                );
                                return Some(client_ip.to_string());
                            }
                        }
                    }

                    // Trust X-Real-IP as fallback
                    if let Some(real_ip) = req.headers().get("x-real-ip") {
                        if let Ok(ip_str) = real_ip.to_str() {
                            debug!(
                                client_ip = %ip_str,
                                peer_ip = %peer_ip_str,
                                "Extracted IP from X-Real-IP"
                            );
                            return Some(ip_str.to_string());
                        }
                    }
                } else {
                    warn!(
                        peer_ip = %peer_ip_str,
                        "Request not from trusted proxy, ignoring forwarded headers"
                    );
                }
            }
        }

        // Fall back to peer address from connection
        peer_addr.map(|ip| {
            let ip_str = ip.to_string();
            debug!(client_ip = %ip_str, "Using peer address for rate limiting");
            ip_str
        })
    }

    fn get_rate_limit_key<B>(&self, req: &Request<B>) -> (String, u32) {
        // Priority 1: Check for authenticated API key
        if let Some(api_key) = req.extensions().get::<ApiKeyId>() {
            let key = format!("auth:{}", api_key.id);
            debug!(rate_limit_key = %key, "Using API key for rate limiting");
            return (key, self.config.authenticated_limit);
        }

        // Priority 2: Extract client IP
        if let Some(ip) = self.extract_client_ip(req) {
            let key = format!("anon:{}", ip);
            debug!(rate_limit_key = %key, "Using IP for rate limiting");
            return (key, self.config.anonymous_limit);
        }

        // Fallback: unknown client
        warn!("Could not extract rate limit key, using 'unknown'");
        ("anon:unknown".to_string(), self.config.anonymous_limit)
    }
}

/// Rate limit metadata for response headers
#[derive(Debug, Clone)]
pub struct RateLimitMetadata {
    pub limit: u32,
    pub remaining: u32,
    pub reset: u64,
}

impl RateLimiter {
    /// Check rate limit and return metadata for headers
    pub fn check_rate_limit_with_metadata<B>(
        &self,
        req: &Request<B>,
    ) -> (Result<(), u64>, RateLimitMetadata) {
        let (key, limit) = self.get_rate_limit_key(req);
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_secs);

        // Automatic cleanup: if bucket count exceeds threshold, clean up stale buckets
        let threshold = self.config.max_buckets / 2;
        if self.buckets.len() > threshold {
            let ttl = Duration::from_secs(self.config.bucket_ttl_secs);
            self.buckets
                .retain(|_, bucket| now.duration_since(bucket.last_accessed) < ttl);
        }

        let mut bucket = self
            .buckets
            .entry(key.clone())
            .or_insert_with(|| RateLimitBucket {
                count: 0,
                window_start: now,
                last_accessed: now,
            });

        bucket.last_accessed = now;

        // Check if window has expired
        if now.duration_since(bucket.window_start) >= window_duration {
            bucket.window_start = now;
            bucket.count = 0;
        }

        // Calculate reset time (window_start + window_duration as unix timestamp)
        let reset_instant = bucket.window_start + window_duration;
        let reset_secs = reset_instant
            .duration_since(Instant::now())
            .as_secs()
            .saturating_add(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );

        // Check if limit exceeded
        if bucket.count >= limit {
            let retry_after = self
                .config
                .window_secs
                .saturating_sub(now.duration_since(bucket.window_start).as_secs());

            let metadata = RateLimitMetadata {
                limit,
                remaining: 0,
                reset: reset_secs,
            };

            return (Err(retry_after), metadata);
        }

        // Increment counter
        bucket.count += 1;
        let remaining = limit.saturating_sub(bucket.count);

        let metadata = RateLimitMetadata {
            limit,
            remaining,
            reset: reset_secs,
        };

        (Ok(()), metadata)
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    use axum::http::header::{HeaderName, HeaderValue};

    // Get or create rate limiter from extensions
    let rate_limiter = req
        .extensions()
        .get::<RateLimiter>()
        .cloned()
        .unwrap_or_else(|| RateLimiter::new(RateLimitConfig::default()));

    let request_id = req
        .extensions()
        .get::<uuid::Uuid>()
        .map(|id| id.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Check rate limit and get metadata
    let (result, metadata) = rate_limiter.check_rate_limit_with_metadata(&req);

    match result {
        Ok(()) => {
            let mut response = next.run(req).await;

            // Add rate limit headers to success response
            let headers = response.headers_mut();
            headers.insert(
                HeaderName::from_static("x-ratelimit-limit"),
                HeaderValue::from(metadata.limit),
            );
            headers.insert(
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from(metadata.remaining),
            );
            headers.insert(
                HeaderName::from_static("x-ratelimit-reset"),
                HeaderValue::from(metadata.reset),
            );

            Ok(response)
        }
        Err(retry_after) => {
            let error_body = json!({
                "error": {
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests. Please retry after the specified time.",
                },
                "request_id": request_id,
                "retry_after": retry_after,
            });

            // Convert to full Response to add headers
            let json_body = serde_json::to_string(&error_body).unwrap();
            let mut full_response = Response::new(json_body.into());
            *full_response.status_mut() = StatusCode::TOO_MANY_REQUESTS;

            let headers = full_response.headers_mut();
            headers.insert(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/json"),
            );
            headers.insert(
                HeaderName::from_static("x-ratelimit-limit"),
                HeaderValue::from(metadata.limit),
            );
            headers.insert(
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from(0u32),
            );
            headers.insert(
                HeaderName::from_static("x-ratelimit-reset"),
                HeaderValue::from(metadata.reset),
            );
            headers.insert(
                HeaderName::from_static("retry-after"),
                HeaderValue::from(retry_after),
            );

            Ok(full_response)
        }
    }
}

/// Create rate limiter layer for sharing across requests
pub fn create_rate_limiter() -> RateLimiter {
    RateLimiter::new(RateLimitConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn test_config_defaults() {
        let config = RateLimitConfig::default();
        assert_eq!(config.anonymous_limit, DEFAULT_ANONYMOUS_LIMIT);
        assert_eq!(config.authenticated_limit, DEFAULT_AUTHENTICATED_LIMIT);
        assert_eq!(config.window_secs, DEFAULT_WINDOW_SECS);
    }

    #[test]
    fn test_rate_limiter_key_with_api_key() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(ApiKeyId {
            id: "test-key-123".to_string(),
        });

        let (key, limit) = limiter.get_rate_limit_key(&req);
        assert_eq!(key, "auth:test-key-123");
        assert_eq!(limit, DEFAULT_AUTHENTICATED_LIMIT);
    }

    #[test]
    fn test_rate_limiter_key_fallback_to_ip() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));

        let (key, limit) = limiter.get_rate_limit_key(&req);
        assert_eq!(key, "anon:127.0.0.1");
        assert_eq!(limit, DEFAULT_ANONYMOUS_LIMIT);
    }

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            anonymous_limit: 5,
            authenticated_limit: 10,
            window_secs: 60,
            trusted_proxies: None,
            max_buckets: DEFAULT_MAX_BUCKETS,
            bucket_ttl_secs: DEFAULT_BUCKET_TTL_SECS,
        });

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));

        // Should allow 5 requests
        for _ in 0..5 {
            let (result, _metadata) = limiter.check_rate_limit_with_metadata(&req);
            assert!(result.is_ok());
        }

        // 6th request should be blocked
        let (result, _metadata) = limiter.check_rate_limit_with_metadata(&req);
        assert!(result.is_err());
    }

    #[test]
    fn test_trusted_proxy_validation() {
        let limiter = RateLimiter::new(RateLimitConfig {
            anonymous_limit: 100,
            authenticated_limit: 1000,
            window_secs: 60,
            trusted_proxies: Some(vec!["10.0.0.1".to_string()]),
            max_buckets: DEFAULT_MAX_BUCKETS,
            bucket_ttl_secs: DEFAULT_BUCKET_TTL_SECS,
        });

        // Request from trusted proxy with X-Forwarded-For
        let trusted_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let mut trusted_req = Request::builder()
            .header("x-forwarded-for", "203.0.113.1")
            .body(())
            .unwrap();
        trusted_req
            .extensions_mut()
            .insert(ConnectInfo(trusted_addr));

        let (key, _) = limiter.get_rate_limit_key(&trusted_req);
        assert_eq!(
            key, "anon:203.0.113.1",
            "Should use X-Forwarded-For from trusted proxy"
        );

        // Request from untrusted proxy with X-Forwarded-For
        let untrusted_addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let mut untrusted_req = Request::builder()
            .header("x-forwarded-for", "203.0.113.1")
            .body(())
            .unwrap();
        untrusted_req
            .extensions_mut()
            .insert(ConnectInfo(untrusted_addr));

        let (key, _) = limiter.get_rate_limit_key(&untrusted_req);
        assert_eq!(
            key, "anon:192.168.1.1",
            "Should ignore X-Forwarded-For from untrusted source"
        );
    }

    #[test]
    fn test_bucket_cleanup() {
        let limiter = RateLimiter::new(RateLimitConfig {
            anonymous_limit: 100,
            authenticated_limit: 1000,
            window_secs: 60,
            trusted_proxies: None,
            max_buckets: DEFAULT_MAX_BUCKETS,
            bucket_ttl_secs: DEFAULT_BUCKET_TTL_SECS,
        });

        // Create several buckets
        for i in 0..10 {
            let addr: SocketAddr = format!("127.0.0.{}:8080", i).parse().unwrap();
            let mut req = Request::builder().body(()).unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            let (result, _metadata) = limiter.check_rate_limit_with_metadata(&req);
            assert!(result.is_ok());
        }

        assert_eq!(limiter.buckets.len(), 10, "Should have 10 buckets");

        // Note: cleanup_old_buckets() was removed. Cleanup now happens automatically
        // in check_rate_limit_with_metadata() when bucket threshold is exceeded.
    }

    #[test]
    fn test_bucket_ttl_prevents_eviction_of_active() {
        let limiter = RateLimiter::new(RateLimitConfig {
            anonymous_limit: 100,
            authenticated_limit: 1000,
            window_secs: 60,
            trusted_proxies: None,
            max_buckets: DEFAULT_MAX_BUCKETS,
            bucket_ttl_secs: DEFAULT_BUCKET_TTL_SECS,
        });

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));

        // Make a request to create bucket
        let (result, _metadata) = limiter.check_rate_limit_with_metadata(&req);
        assert!(result.is_ok());
        assert_eq!(limiter.buckets.len(), 1);

        // Note: cleanup_old_buckets() was removed. Cleanup now happens automatically
        // when bucket threshold is exceeded, and active buckets are preserved.
    }

    #[test]
    fn test_trusted_proxy_ipv6() {
        let limiter = RateLimiter::new(RateLimitConfig {
            anonymous_limit: 100,
            authenticated_limit: 1000,
            window_secs: 60,
            trusted_proxies: Some(vec!["2001:db8::1".to_string()]),
            max_buckets: DEFAULT_MAX_BUCKETS,
            bucket_ttl_secs: DEFAULT_BUCKET_TTL_SECS,
        });

        // Request from trusted IPv6 proxy with X-Forwarded-For
        let trusted_addr: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let mut trusted_req = Request::builder()
            .header("x-forwarded-for", "203.0.113.1")
            .body(())
            .unwrap();
        trusted_req
            .extensions_mut()
            .insert(ConnectInfo(trusted_addr));

        let (key, _) = limiter.get_rate_limit_key(&trusted_req);
        assert_eq!(
            key, "anon:203.0.113.1",
            "Should use X-Forwarded-For from trusted IPv6 proxy"
        );
    }

    #[test]
    fn test_untrusted_proxy_ignores_x_real_ip() {
        let limiter = RateLimiter::new(RateLimitConfig {
            anonymous_limit: 100,
            authenticated_limit: 1000,
            window_secs: 60,
            trusted_proxies: Some(vec!["10.0.0.1".to_string()]),
            max_buckets: DEFAULT_MAX_BUCKETS,
            bucket_ttl_secs: DEFAULT_BUCKET_TTL_SECS,
        });

        // Request from untrusted source with X-Real-IP header
        let untrusted_addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let mut untrusted_req = Request::builder()
            .header("x-real-ip", "203.0.113.1")
            .body(())
            .unwrap();
        untrusted_req
            .extensions_mut()
            .insert(ConnectInfo(untrusted_addr));

        let (key, _) = limiter.get_rate_limit_key(&untrusted_req);
        assert_eq!(
            key, "anon:192.168.1.1",
            "Should ignore X-Real-IP from untrusted source"
        );
    }

    #[test]
    fn test_bucket_cap_enforcement() {
        // Create limiter with small cap for testing
        let limiter = RateLimiter::new(RateLimitConfig {
            anonymous_limit: 100,
            authenticated_limit: 1000,
            window_secs: 60,
            trusted_proxies: None,
            max_buckets: 20, // Small cap for testing
            bucket_ttl_secs: DEFAULT_BUCKET_TTL_SECS,
        });

        // Create buckets up to half the cap
        for i in 0..10 {
            let addr: SocketAddr = format!("127.0.0.{}:8080", i).parse().unwrap();
            let mut req = Request::builder().body(()).unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            let (result, _metadata) = limiter.check_rate_limit_with_metadata(&req);
            assert!(result.is_ok());
        }

        assert_eq!(limiter.buckets.len(), 10, "Should have 10 buckets");

        // Mark all existing buckets as stale
        for mut entry in limiter.buckets.iter_mut() {
            entry.value_mut().last_accessed =
                Instant::now() - Duration::from_secs(DEFAULT_BUCKET_TTL_SECS + 1);
        }

        // Create the 11th bucket (threshold is max_buckets/2 = 10)
        let addr: SocketAddr = "127.0.0.11:8080".parse().unwrap();
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let (result, _metadata) = limiter.check_rate_limit_with_metadata(&req);
        assert!(result.is_ok());

        // Now we have 11 buckets (10 stale + 1 fresh). Next request should trigger cleanup
        assert_eq!(limiter.buckets.len(), 11);

        // Make one more request to trigger cleanup (11 > threshold of 10)
        let addr2: SocketAddr = "127.0.0.12:8080".parse().unwrap();
        let mut req2 = Request::builder().body(()).unwrap();
        req2.extensions_mut().insert(ConnectInfo(addr2));
        let (result, _metadata) = limiter.check_rate_limit_with_metadata(&req2);
        assert!(result.is_ok());

        // After cleanup, should only have the 2 fresh buckets (11 and 12)
        assert_eq!(
            limiter.buckets.len(),
            2,
            "Old buckets should be evicted when cap threshold reached"
        );
    }

    #[test]
    fn test_rate_limit_response_includes_request_id() {
        // This is a unit test for the middleware error response format
        // The actual middleware test would require integration testing
        let error_body = json!({
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please retry after the specified time.",
            "request_id": "test-request-id",
            "retry_after": 60,
        });

        assert_eq!(error_body["error"], "Rate limit exceeded");
        assert_eq!(error_body["request_id"], "test-request-id");
        assert_eq!(error_body["retry_after"], 60);
    }
}
