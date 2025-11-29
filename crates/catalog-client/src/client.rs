//! HTTP client with retry logic and caching.

use crate::cache::MetadataCache;
use crate::config::ClientConfig;
use crate::error::{ClientError, Result};
use crate::types::{
    ApiError, Dataset, DatasetSummary, DeltaHistory, HealthResponse, ListDatasetsResponse,
    SearchResults,
};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::{Method, StatusCode};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{
    policies::ExponentialBackoff, RetryTransientMiddleware, Retryable, RetryableStrategy,
};
use std::sync::Arc;

/// MetaFuse HTTP client with automatic retries and caching.
pub struct MetafuseClient {
    http: ClientWithMiddleware,
    config: ClientConfig,
    cache: MetadataCache,
}

impl MetafuseClient {
    /// Create a new client builder with the given base URL.
    pub fn builder(base_url: impl Into<String>) -> crate::config::ClientConfigBuilder {
        crate::config::ClientConfigBuilder::new(base_url)
    }

    /// Create a new client with the given configuration.
    pub fn new(config: ClientConfig) -> Result<Self> {
        config.validate()?;

        // Build reqwest client
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&config.user_agent)
                .unwrap_or_else(|_| HeaderValue::from_static("metafuse-client")),
        );

        if let Some(ref api_key) = config.api_key {
            let auth_value = format!("Bearer {}", api_key);
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_value)
                    .map_err(|_| ClientError::Config("Invalid API key format".to_string()))?,
            );
        }

        let reqwest_client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(config.timeout)
            .danger_accept_invalid_certs(!config.tls_verify)
            .build()?;

        // Build retry policy with exponential backoff
        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(config.retry_initial_delay, config.retry_max_delay)
            .build_with_max_retries(config.max_retries);

        // Custom retry strategy that respects our semantics
        let retry_strategy = MetafuseRetryStrategy;

        let client = ClientBuilder::new(reqwest_client)
            .with(RetryTransientMiddleware::new_with_policy_and_strategy(
                retry_policy,
                retry_strategy,
            ))
            .build();

        // Build cache
        let cache = MetadataCache::new(config.cache_capacity, config.cache_ttl);

        Ok(Self {
            http: client,
            config,
            cache,
        })
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    // =========================================================================
    // Health & Info
    // =========================================================================

    /// Check API health.
    pub async fn health(&self) -> Result<HealthResponse> {
        self.get("/health").await
    }

    // =========================================================================
    // Dataset Operations
    // =========================================================================

    /// List all datasets.
    pub async fn list_datasets(&self) -> Result<Vec<DatasetSummary>> {
        let response: ListDatasetsResponse = self.get("/datasets").await?;
        Ok(response.datasets)
    }

    /// List datasets by domain.
    ///
    /// Results are cached to reduce HTTP calls (especially useful for
    /// `SchemaProvider::table_names()` which is called frequently).
    pub async fn list_datasets_by_domain(&self, domain: &str) -> Result<Vec<DatasetSummary>> {
        let url = format!("/datasets?domain={}", urlencoding::encode(domain));
        let response: ListDatasetsResponse = self.get(&url).await?;

        // Cache the dataset names for this domain
        let names: Vec<String> = response.datasets.iter().map(|d| d.name.clone()).collect();
        self.cache
            .put_domain_datasets(domain.to_string(), names)
            .await;

        Ok(response.datasets)
    }

    /// List dataset names for a domain (cached).
    ///
    /// This is a lightweight version of `list_datasets_by_domain` that only
    /// returns dataset names. It's optimized for `SchemaProvider::table_names()`
    /// where full dataset details aren't needed.
    ///
    /// Uses cached data when available, otherwise fetches from the API.
    pub async fn list_dataset_names_by_domain(&self, domain: &str) -> Result<Vec<String>> {
        // Check cache first
        if let Some(cached) = self.cache.get_domain_datasets(domain).await {
            return Ok(cached);
        }

        // Fetch from API (this will also populate the cache)
        let datasets = self.list_datasets_by_domain(domain).await?;
        Ok(datasets.into_iter().map(|d| d.name).collect())
    }

    /// List all domains.
    pub async fn list_domains(&self) -> Result<Vec<String>> {
        self.get("/domains").await
    }

    /// Get a dataset by name.
    pub async fn get_dataset(&self, name: &str) -> Result<Dataset> {
        // Check cache first
        if let Some(cached) = self.cache.get_dataset(name).await {
            return Ok(cached);
        }

        let url = format!("/datasets/{}", urlencoding::encode(name));
        let dataset: Dataset = self.get(&url).await?;

        // Cache the result
        self.cache
            .put_dataset(name.to_string(), dataset.clone())
            .await;

        Ok(dataset)
    }

    /// Get a dataset with additional includes (delta, quality, classification).
    pub async fn get_dataset_with_includes(
        &self,
        name: &str,
        includes: &[&str],
    ) -> Result<Dataset> {
        let include_param = includes.join(",");
        let url = format!(
            "/datasets/{}?include={}",
            urlencoding::encode(name),
            urlencoding::encode(&include_param)
        );
        self.get(&url).await
    }

    /// Search datasets.
    pub async fn search(&self, query: &str) -> Result<Vec<DatasetSummary>> {
        let url = format!("/search?q={}", urlencoding::encode(query));
        let response: SearchResults = self.get(&url).await?;
        Ok(response.datasets)
    }

    // =========================================================================
    // Delta Operations
    // =========================================================================

    /// Get Delta table history for a dataset.
    pub async fn get_history(&self, name: &str, limit: Option<usize>) -> Result<DeltaHistory> {
        let mut url = format!("/datasets/{}/delta/history", urlencoding::encode(name));
        if let Some(limit) = limit {
            url.push_str(&format!("?limit={}", limit));
        }
        self.get(&url).await
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Invalidate a cached dataset.
    pub async fn invalidate_cache(&self, name: &str) {
        self.cache.invalidate(name).await;
    }

    /// Invalidate a cached domain's dataset list.
    pub async fn invalidate_domain_cache(&self, domain: &str) {
        self.cache.invalidate_domain(domain).await;
    }

    /// Clear all cached data (datasets and domain lists).
    pub async fn clear_cache(&self) {
        self.cache.clear().await;
    }

    /// Get cache statistics.
    pub async fn cache_stats(&self) -> crate::cache::CacheStats {
        self.cache.stats().await
    }

    // =========================================================================
    // Internal HTTP Methods
    // =========================================================================

    /// Perform a GET request and deserialize the response.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(Method::GET, path, Option::<()>::None).await
    }

    /// Perform an HTTP request with optional body.
    async fn request<T, B>(&self, method: Method, path: &str, body: Option<B>) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: serde::Serialize,
    {
        let url = format!("{}{}", self.config.base_url, path);
        let start = std::time::Instant::now();

        tracing::debug!(
            method = %method,
            path = %path,
            "Sending request"
        );

        let request = if let Some(ref b) = body {
            let json_body = serde_json::to_vec(b)?;
            self.http.request(method.clone(), &url).body(json_body)
        } else {
            self.http.request(method.clone(), &url)
        };

        let response = request.send().await?;
        let status = response.status();
        let duration = start.elapsed();

        // Extract request ID from response headers if present
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        tracing::debug!(
            method = %method,
            path = %path,
            status = %status.as_u16(),
            duration_ms = %duration.as_millis(),
            request_id = ?request_id,
            "Received response"
        );

        if status.is_success() {
            let body = response.bytes().await?;
            serde_json::from_slice(&body).map_err(|e| {
                ClientError::InvalidResponse(format!(
                    "Failed to parse response: {} (body: {})",
                    e,
                    String::from_utf8_lossy(&body)
                ))
            })
        } else {
            // Extract Retry-After header before consuming the body
            let retry_after = Self::parse_retry_after(response.headers());

            // Try to parse error response
            let error_body = response.bytes().await.ok();
            let api_error: Option<ApiError> = error_body
                .as_ref()
                .and_then(|b| serde_json::from_slice(b).ok());

            let message = api_error
                .as_ref()
                .map(|e| e.error.clone())
                .unwrap_or_else(|| {
                    error_body
                        .map(|b| String::from_utf8_lossy(&b).to_string())
                        .unwrap_or_else(|| status.to_string())
                });

            let request_id = api_error
                .as_ref()
                .and_then(|e| e.request_id.clone())
                .or(request_id);

            tracing::warn!(
                method = %method,
                path = %path,
                status = %status.as_u16(),
                duration_ms = %duration.as_millis(),
                request_id = ?request_id,
                error = %message,
                "Request failed"
            );

            Err(Self::status_to_error(
                status,
                message,
                request_id,
                retry_after,
            ))
        }
    }

    /// Convert HTTP status to appropriate error type.
    fn status_to_error(
        status: StatusCode,
        message: String,
        request_id: Option<String>,
        retry_after: Option<std::time::Duration>,
    ) -> ClientError {
        match status {
            StatusCode::NOT_FOUND => ClientError::NotFound(message),
            StatusCode::UNAUTHORIZED => ClientError::Unauthorized(message),
            StatusCode::FORBIDDEN => ClientError::Forbidden(message),
            StatusCode::CONFLICT => ClientError::Conflict(message),
            StatusCode::TOO_MANY_REQUESTS => ClientError::RateLimited {
                retry_after,
                request_id,
            },
            s if s.is_server_error() => ClientError::ServerError {
                status: s.as_u16(),
                message,
                request_id,
            },
            _ => ClientError::ServerError {
                status: status.as_u16(),
                message,
                request_id,
            },
        }
    }

    /// Parse the Retry-After header value into a Duration.
    ///
    /// Supports both formats per RFC 7231:
    /// - Seconds: "120" -> Duration::from_secs(120)
    /// - HTTP-date: "Fri, 31 Dec 2024 23:59:59 GMT" -> Duration until that time
    fn parse_retry_after(headers: &HeaderMap) -> Option<std::time::Duration> {
        let header_value = headers.get("retry-after")?.to_str().ok()?;

        // Try parsing as seconds first (most common)
        if let Ok(seconds) = header_value.parse::<u64>() {
            return Some(std::time::Duration::from_secs(seconds));
        }

        // Try parsing as HTTP-date (RFC 7231 format)
        // Format: "Fri, 31 Dec 2024 23:59:59 GMT"
        if let Ok(date) = httpdate::parse_http_date(header_value) {
            let now = std::time::SystemTime::now();
            if let Ok(duration) = date.duration_since(now) {
                return Some(duration);
            }
            // If the date is in the past, return zero duration
            return Some(std::time::Duration::ZERO);
        }

        None
    }
}

/// Custom retry strategy for MetaFuse.
///
/// Retries on:
/// - Transient network errors
/// - 5xx server errors
/// - 429 rate limiting
///
/// Does NOT retry:
/// - 4xx client errors (except 429)
///
/// # Note on Idempotency
///
/// Currently the client only exposes GET methods which are idempotent.
/// If POST/PUT/DELETE methods are added in the future, this strategy
/// should be updated to check the request method and only retry
/// idempotent operations (or those explicitly marked safe to retry).
struct MetafuseRetryStrategy;

impl RetryableStrategy for MetafuseRetryStrategy {
    fn handle(&self, res: &reqwest_middleware::Result<reqwest::Response>) -> Option<Retryable> {
        match res {
            Ok(response) => {
                let status = response.status();
                if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
                    Some(Retryable::Transient)
                } else if status.is_success() {
                    None
                } else {
                    Some(Retryable::Fatal)
                }
            }
            Err(error) => {
                // Check if it's a transient network error
                if error.is_timeout() || error.is_connect() {
                    Some(Retryable::Transient)
                } else {
                    Some(Retryable::Fatal)
                }
            }
        }
    }
}

/// Arc-wrapped client for shared ownership.
pub type SharedClient = Arc<MetafuseClient>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_builder_creates_client() {
        // Just test that builder pattern works
        let config = ClientConfig::builder("http://localhost:3000")
            .api_key("test_key")
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        assert_eq!(config.base_url, "http://localhost:3000");
        assert_eq!(config.api_key, Some("test_key".to_string()));
    }

    #[test]
    fn test_parse_retry_after_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("120"));

        let result = MetafuseClient::parse_retry_after(&headers);
        assert_eq!(result, Some(Duration::from_secs(120)));
    }

    #[test]
    fn test_parse_retry_after_zero() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("0"));

        let result = MetafuseClient::parse_retry_after(&headers);
        assert_eq!(result, Some(Duration::ZERO));
    }

    #[test]
    fn test_parse_retry_after_missing() {
        let headers = HeaderMap::new();

        let result = MetafuseClient::parse_retry_after(&headers);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_retry_after_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("not-a-number"));

        // Invalid values that aren't valid HTTP-dates return None
        let result = MetafuseClient::parse_retry_after(&headers);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_retry_after_large_seconds() {
        let mut headers = HeaderMap::new();
        // Test with a larger value (1 hour)
        headers.insert("retry-after", HeaderValue::from_static("3600"));

        let result = MetafuseClient::parse_retry_after(&headers);
        assert_eq!(result, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_parse_retry_after_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static(""));

        let result = MetafuseClient::parse_retry_after(&headers);
        // Empty string can't be parsed
        assert_eq!(result, None);
    }
}
