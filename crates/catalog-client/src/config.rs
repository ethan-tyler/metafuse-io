//! Client configuration and builder pattern.

use crate::error::{ClientError, Result};
use std::fmt;
use std::time::Duration;

/// Configuration for the MetaFuse client.
///
/// # Security
///
/// The `Debug` implementation masks the API key to prevent accidental exposure
/// in logs. The key is shown as `"***REDACTED***"` in debug output.
#[derive(Clone)]
pub struct ClientConfig {
    /// Base URL of the MetaFuse API server (e.g., "http://localhost:3000")
    pub base_url: String,
    /// Optional API key for authentication
    pub api_key: Option<String>,
    /// Request timeout (default: 30 seconds)
    pub timeout: Duration,
    /// Maximum number of retries for transient failures (default: 3)
    pub max_retries: u32,
    /// Initial retry delay for exponential backoff (default: 100ms)
    pub retry_initial_delay: Duration,
    /// Maximum retry delay (default: 10 seconds)
    pub retry_max_delay: Duration,
    /// Cache TTL for metadata (default: 5 minutes, 0 to disable)
    pub cache_ttl: Duration,
    /// Maximum number of cached entries (default: 100)
    pub cache_capacity: usize,
    /// Whether to verify TLS certificates (default: true)
    pub tls_verify: bool,
    /// User-Agent header value
    pub user_agent: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:3000".to_string(),
            api_key: None,
            timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_initial_delay: Duration::from_millis(100),
            retry_max_delay: Duration::from_secs(10),
            cache_ttl: Duration::from_secs(300), // 5 minutes
            cache_capacity: 100,
            tls_verify: true,
            user_agent: format!("metafuse-client/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "***REDACTED***"))
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .field("retry_initial_delay", &self.retry_initial_delay)
            .field("retry_max_delay", &self.retry_max_delay)
            .field("cache_ttl", &self.cache_ttl)
            .field("cache_capacity", &self.cache_capacity)
            .field("tls_verify", &self.tls_verify)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl ClientConfig {
    /// Create a new configuration builder.
    pub fn builder(base_url: impl Into<String>) -> ClientConfigBuilder {
        ClientConfigBuilder::new(base_url)
    }

    /// Minimum allowed timeout value.
    pub const MIN_TIMEOUT: Duration = Duration::from_millis(100);

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate base URL
        if self.base_url.is_empty() {
            return Err(ClientError::Config("base_url cannot be empty".to_string()));
        }

        // Parse and validate URL
        url::Url::parse(&self.base_url)
            .map_err(|e| ClientError::Config(format!("Invalid base_url: {}", e)))?;

        // Validate cache capacity
        if self.cache_capacity == 0 && self.cache_ttl > Duration::ZERO {
            return Err(ClientError::Config(
                "cache_capacity must be > 0 when caching is enabled".to_string(),
            ));
        }

        // Validate retry delay bounds
        if self.retry_initial_delay > self.retry_max_delay {
            return Err(ClientError::Config(format!(
                "retry_initial_delay ({:?}) must be <= retry_max_delay ({:?})",
                self.retry_initial_delay, self.retry_max_delay
            )));
        }

        // Validate minimum timeout
        if self.timeout < Self::MIN_TIMEOUT {
            return Err(ClientError::Config(format!(
                "timeout ({:?}) must be >= {:?}",
                self.timeout,
                Self::MIN_TIMEOUT
            )));
        }

        Ok(())
    }
}

/// Builder for client configuration.
#[derive(Debug)]
pub struct ClientConfigBuilder {
    config: ClientConfig,
}

impl ClientConfigBuilder {
    /// Create a new builder with the given base URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            config: ClientConfig {
                base_url: base_url.into(),
                ..Default::default()
            },
        }
    }

    /// Set the API key for authentication.
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.config.api_key = Some(api_key.into());
        self
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set the maximum number of retries.
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.config.max_retries = max_retries;
        self
    }

    /// Set the initial retry delay for exponential backoff.
    pub fn retry_initial_delay(mut self, delay: Duration) -> Self {
        self.config.retry_initial_delay = delay;
        self
    }

    /// Set the maximum retry delay.
    pub fn retry_max_delay(mut self, delay: Duration) -> Self {
        self.config.retry_max_delay = delay;
        self
    }

    /// Set the cache TTL. Set to Duration::ZERO to disable caching.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.config.cache_ttl = ttl;
        self
    }

    /// Set the maximum number of cached entries.
    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.config.cache_capacity = capacity;
        self
    }

    /// Disable caching entirely.
    pub fn no_cache(mut self) -> Self {
        self.config.cache_ttl = Duration::ZERO;
        self
    }

    /// Set whether to verify TLS certificates.
    pub fn tls_verify(mut self, verify: bool) -> Self {
        self.config.tls_verify = verify;
        self
    }

    /// Set a custom User-Agent header.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.config.user_agent = user_agent.into();
        self
    }

    /// Build the configuration, validating all settings.
    pub fn build(self) -> Result<ClientConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert_eq!(config.base_url, "http://localhost:3000");
        assert!(config.api_key.is_none());
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.cache_ttl, Duration::from_secs(300));
    }

    #[test]
    fn test_builder() {
        let config = ClientConfig::builder("https://api.example.com")
            .api_key("mf_test_key")
            .timeout(Duration::from_secs(60))
            .max_retries(5)
            .cache_ttl(Duration::from_secs(600))
            .cache_capacity(500)
            .build()
            .unwrap();

        assert_eq!(config.base_url, "https://api.example.com");
        assert_eq!(config.api_key, Some("mf_test_key".to_string()));
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.cache_ttl, Duration::from_secs(600));
        assert_eq!(config.cache_capacity, 500);
    }

    #[test]
    fn test_no_cache() {
        let config = ClientConfig::builder("http://localhost:3000")
            .no_cache()
            .build()
            .unwrap();

        assert_eq!(config.cache_ttl, Duration::ZERO);
    }

    #[test]
    fn test_invalid_url() {
        let result = ClientConfig::builder("not a valid url").build();
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_url() {
        let result = ClientConfig::builder("").build();
        assert!(result.is_err());
    }

    #[test]
    fn test_api_key_masked_in_debug() {
        let config = ClientConfig::builder("http://localhost:3000")
            .api_key("mf_super_secret_key_12345")
            .build()
            .unwrap();

        let debug_output = format!("{:?}", config);

        // API key should NOT appear in debug output
        assert!(
            !debug_output.contains("mf_super_secret_key_12345"),
            "API key should not appear in debug output"
        );
        assert!(
            !debug_output.contains("super_secret"),
            "API key fragments should not appear in debug output"
        );

        // Redacted marker should appear
        assert!(
            debug_output.contains("REDACTED"),
            "Debug output should show REDACTED marker"
        );
    }

    #[test]
    fn test_no_api_key_debug() {
        let config = ClientConfig::builder("http://localhost:3000")
            .build()
            .unwrap();

        let debug_output = format!("{:?}", config);

        // Should show None for api_key when not set
        assert!(
            debug_output.contains("None"),
            "Debug output should show None when no API key is set"
        );
    }

    #[test]
    fn test_retry_delay_validation_invalid() {
        // Initial delay > max delay should fail
        let result = ClientConfig::builder("http://localhost:3000")
            .retry_initial_delay(Duration::from_secs(10))
            .retry_max_delay(Duration::from_secs(1))
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("retry_initial_delay"),
            "Error should mention retry_initial_delay"
        );
    }

    #[test]
    fn test_retry_delay_validation_valid() {
        // Initial delay == max delay should work
        let result = ClientConfig::builder("http://localhost:3000")
            .retry_initial_delay(Duration::from_secs(1))
            .retry_max_delay(Duration::from_secs(1))
            .build();

        assert!(result.is_ok());

        // Initial delay < max delay should work
        let result = ClientConfig::builder("http://localhost:3000")
            .retry_initial_delay(Duration::from_millis(100))
            .retry_max_delay(Duration::from_secs(10))
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_timeout_too_small() {
        // Timeout below minimum should fail
        let result = ClientConfig::builder("http://localhost:3000")
            .timeout(Duration::from_millis(50))
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("timeout"),
            "Error should mention timeout"
        );
    }

    #[test]
    fn test_timeout_at_minimum() {
        // Timeout at minimum should work
        let result = ClientConfig::builder("http://localhost:3000")
            .timeout(ClientConfig::MIN_TIMEOUT)
            .build();

        assert!(result.is_ok());
    }
}
