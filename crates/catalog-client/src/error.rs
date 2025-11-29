//! Error types for the MetaFuse client SDK.

use std::time::Duration;

/// Errors that can occur when using the MetaFuse client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// HTTP transport error (connection, DNS, TLS, etc.)
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// HTTP request was built incorrectly
    #[error("HTTP request error: {0}")]
    HttpMiddleware(#[from] reqwest_middleware::Error),

    /// Dataset not found (404)
    #[error("Dataset not found: {0}")]
    NotFound(String),

    /// Authentication failed (401)
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Permission denied (403)
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after:?}")]
    RateLimited {
        /// Optional retry-after duration from server
        retry_after: Option<Duration>,
        /// Request ID for tracking
        request_id: Option<String>,
    },

    /// Conflict (409) - e.g., optimistic locking failure
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Server error (5xx)
    #[error("Server error ({status}): {message}")]
    ServerError {
        /// HTTP status code
        status: u16,
        /// Error message from server
        message: String,
        /// Request ID for tracking
        request_id: Option<String>,
    },

    /// Invalid response from server
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Request validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// URL parsing error
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Cache error
    #[error("Cache error: {0}")]
    Cache(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Delta table error (when datafusion feature is enabled)
    #[error("Delta error: {0}")]
    Delta(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
}

impl ClientError {
    /// Returns true if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            ClientError::RateLimited { .. } => true,
            ClientError::ServerError { status, .. } => *status >= 500,
            _ => false,
        }
    }

    /// Returns the request ID if available.
    pub fn request_id(&self) -> Option<&str> {
        match self {
            ClientError::RateLimited { request_id, .. } => request_id.as_deref(),
            ClientError::ServerError { request_id, .. } => request_id.as_deref(),
            _ => None,
        }
    }
}

/// Result type for client operations.
pub type Result<T> = std::result::Result<T, ClientError>;

// DataFusion error conversion (when feature is enabled)
#[cfg(feature = "datafusion")]
impl From<ClientError> for datafusion::error::DataFusionError {
    fn from(err: ClientError) -> Self {
        datafusion::error::DataFusionError::External(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retryable_errors() {
        let rate_limited = ClientError::RateLimited {
            retry_after: Some(Duration::from_secs(60)),
            request_id: Some("req-123".to_string()),
        };
        assert!(rate_limited.is_retryable());

        let server_error = ClientError::ServerError {
            status: 503,
            message: "Service unavailable".to_string(),
            request_id: None,
        };
        assert!(server_error.is_retryable());

        let not_found = ClientError::NotFound("test".to_string());
        assert!(!not_found.is_retryable());
    }

    #[test]
    fn test_request_id_extraction() {
        let error = ClientError::RateLimited {
            retry_after: None,
            request_id: Some("req-456".to_string()),
        };
        assert_eq!(error.request_id(), Some("req-456"));

        let not_found = ClientError::NotFound("test".to_string());
        assert_eq!(not_found.request_id(), None);
    }
}
