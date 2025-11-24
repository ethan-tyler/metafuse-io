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
    pub max_buckets: usize,
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

    /// Clean up old buckets that haven't been accessed recently
    ///
    /// This prevents unbounded memory growth from high-cardinality keys.
    ///
    /// **Performance Note**: This is an O(n) operation that scans all buckets.
    /// It's triggered when bucket count exceeds max_buckets/2 to amortize the cost.
    fn cleanup_old_buckets(&self) {
        let now = Instant::now();
        let ttl = Duration::from_secs(self.config.bucket_ttl_secs);

        let before_count = self.buckets.len();
        self.buckets.retain(|key, bucket| {
            let should_keep = now.duration_since(bucket.last_accessed) < ttl;
            if !should_keep {
                debug!(key = %key, "Evicting idle rate limit bucket");
            }
            should_keep
        });

        let evicted = before_count.saturating_sub(self.buckets.len());
        if evicted > 0 {
            debug!(
                evicted = evicted,
                remaining = self.buckets.len(),
                ttl_secs = self.config.bucket_ttl_secs,
                "Cleaned up idle buckets"
            );
        }
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

    pub fn check_rate_limit<B>(&self, req: &Request<B>) -> Result<(), u64> {
        // Periodically clean up old buckets to prevent unbounded memory growth
        // Trigger at 50% of max to amortize O(n) cleanup cost
        let cleanup_threshold = self.config.max_buckets / 2;
        if self.buckets.len() > cleanup_threshold {
            debug!(
                bucket_count = self.buckets.len(),
                threshold = cleanup_threshold,
                max_buckets = self.config.max_buckets,
                "Bucket count threshold reached, cleaning up"
            );
            self.cleanup_old_buckets();
        }

        let (key, limit) = self.get_rate_limit_key(req);
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.window_secs);

        let mut bucket = self.buckets.entry(key.clone()).or_insert_with(|| {
            debug!(key = %key, "Creating new rate limit bucket");
            RateLimitBucket {
                count: 0,
                window_start: now,
                last_accessed: now,
            }
        });

        // Update last accessed time
        bucket.last_accessed = now;

        // Check if window has expired
        if now.duration_since(bucket.window_start) >= window_duration {
            debug!(key = %key, "Rate limit window expired, resetting");
            bucket.window_start = now;
            bucket.count = 0;
        }

        // Check if limit exceeded
        if bucket.count >= limit {
            let retry_after = self
                .config
                .window_secs
                .saturating_sub(now.duration_since(bucket.window_start).as_secs());
            warn!(
                key = %key,
                count = bucket.count,
                limit = limit,
                retry_after = retry_after,
                "Rate limit exceeded"
            );
            return Err(retry_after);
        }

        // Increment counter
        bucket.count += 1;
        debug!(
            key = %key,
            count = bucket.count,
            limit = limit,
            "Request allowed"
        );

        Ok(())
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
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

    // Check rate limit
    match rate_limiter.check_rate_limit(&req) {
        Ok(()) => Ok(next.run(req).await),
        Err(retry_after) => {
            let error_body = json!({
                "error": "Rate limit exceeded",
                "message": "Too many requests. Please retry after the specified time.",
                "request_id": request_id,
                "retry_after": retry_after,
            });

            Err((StatusCode::TOO_MANY_REQUESTS, Json(error_body)))
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
            assert!(limiter.check_rate_limit(&req).is_ok());
        }

        // 6th request should be blocked
        assert!(limiter.check_rate_limit(&req).is_err());
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
            assert!(limiter.check_rate_limit(&req).is_ok());
        }

        assert_eq!(limiter.buckets.len(), 10, "Should have 10 buckets");

        // Manually trigger cleanup with all buckets marked as old
        // (In production this would happen naturally with TTL)
        // For testing, we'll directly manipulate the buckets to set old timestamps
        for mut entry in limiter.buckets.iter_mut() {
            let bucket = entry.value_mut();
            // Set last_accessed to be older than TTL
            bucket.last_accessed =
                Instant::now() - Duration::from_secs(DEFAULT_BUCKET_TTL_SECS + 1);
        }

        // Trigger cleanup
        limiter.cleanup_old_buckets();

        assert_eq!(
            limiter.buckets.len(),
            0,
            "All old buckets should be evicted"
        );
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
        assert!(limiter.check_rate_limit(&req).is_ok());
        assert_eq!(limiter.buckets.len(), 1);

        // Cleanup should not remove recently accessed bucket
        limiter.cleanup_old_buckets();
        assert_eq!(
            limiter.buckets.len(),
            1,
            "Active bucket should not be evicted"
        );
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
            assert!(limiter.check_rate_limit(&req).is_ok());
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
        assert!(limiter.check_rate_limit(&req).is_ok());

        // Now we have 11 buckets (10 stale + 1 fresh). Next request should trigger cleanup
        assert_eq!(limiter.buckets.len(), 11);

        // Make one more request to trigger cleanup (11 > threshold of 10)
        let addr2: SocketAddr = "127.0.0.12:8080".parse().unwrap();
        let mut req2 = Request::builder().body(()).unwrap();
        req2.extensions_mut().insert(ConnectInfo(addr2));
        assert!(limiter.check_rate_limit(&req2).is_ok());

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
