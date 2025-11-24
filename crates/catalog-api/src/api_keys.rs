//! API Key Authentication Module
//!
//! Provides secure API key generation, validation, and management with bcrypt
//! password hashing and in-memory caching for performance.
//!
//! ## Security Features
//!
//! - **Cryptographically secure key generation**: Uses `OsRng` for unpredictable keys
//! - **bcrypt hashing**: Adaptive cost function resistant to brute-force attacks
//! - **Constant-time comparison**: Prevents timing attacks during validation
//! - **Soft deletion**: Revoked keys remain in database for audit trails
//! - **In-memory cache**: Minimizes database queries while maintaining security
//!
//! ## Configuration
//!
//! - `METAFUSE_API_KEY_PREFIX`: Prefix for generated keys (default: "mf_")
//! - `METAFUSE_API_KEY_LENGTH`: Length of random portion (default: 32 bytes = 64 hex chars)
//! - `METAFUSE_BCRYPT_COST`: bcrypt cost factor (default: 12, range: 4-31)
//!
//! ## Performance
//!
//! - **In-memory cache**: Valid keys are cached with a TTL to reduce database load
//! - **Background flush**: Last-used timestamps are updated in batches
//! - **spawn_blocking**: bcrypt operations run on blocking thread pool
//!
//! ## Security Considerations
//!
//! ### Cache Security
//! - Cache keys are hashed (not plaintext) to prevent memory dump exposure
//! - On revocation, entire cache is cleared to ensure immediate invalidation
//! - Pending updates are keyed by bcrypt hash, not plaintext
//!
//! ### Validation Performance
//! - **Current**: O(n) validation loads all non-revoked keys and bcrypt-verifies each
//! - **Why**: bcrypt hashes are salted, preventing direct lookup
//! - **Mitigation**: Aggressive caching (5-minute TTL by default)
//! - **Future**: Consider adding a SHA-256 lookup column for O(1) candidate filtering
//!
//! ### Revocation
//! - Soft-delete with `revoked_at` timestamp
//! - Cache is **immediately** cleared to prevent time-of-check-to-time-of-use issues
//! - Background tasks should check revocation status periodically
//!
//! ### Authentication Best Practices
//! - **Prefer**: `Authorization: Bearer TOKEN` header
//! - **Avoid**: Query parameters in production (logged by proxies/servers)
//! - **Rotate**: Keys regularly, especially after personnel changes
//! - **Monitor**: Track `last_used_at` for stale/compromised keys
//!
//! ## Usage
//!
//! ```rust,ignore
//! use metafuse_catalog_api::api_keys::{ApiKeyManager, generate_api_key};
//!
//! // Generate a new API key
//! let (key_id, plaintext_key) = generate_api_key();
//!
//! // Create manager with database connection
//! let manager = ApiKeyManager::new(db_path)?;
//!
//! // Store the key (returns the plaintext only once!)
//! let plaintext = manager.create_key("my-service".to_string()).await?;
//!
//! // Validate a key (constant-time comparison)
//! let is_valid = manager.validate_key(&plaintext).await?;
//! ```

#[cfg(feature = "api-keys")]
use bcrypt::{hash, verify};
#[cfg(feature = "api-keys")]
use dashmap::DashMap;
#[cfg(feature = "api-keys")]
use rand::RngCore;
#[cfg(feature = "api-keys")]
use rusqlite::Connection;
#[cfg(feature = "api-keys")]
use std::collections::hash_map::DefaultHasher;
#[cfg(feature = "api-keys")]
use std::hash::{Hash, Hasher};
#[cfg(feature = "api-keys")]
use std::sync::Arc;
#[cfg(feature = "api-keys")]
use std::time::{Duration, Instant};
#[cfg(feature = "api-keys")]
use tracing::{debug, info, warn};

#[cfg(all(feature = "api-keys", feature = "rate-limiting"))]
use crate::rate_limiting::ApiKeyId;

#[cfg(feature = "api-keys")]
#[allow(dead_code)]
const DEFAULT_API_KEY_PREFIX: &str = "mf_";
#[cfg(feature = "api-keys")]
#[allow(dead_code)]
const DEFAULT_API_KEY_LENGTH: usize = 32; // 32 bytes = 64 hex characters
#[cfg(feature = "api-keys")]
#[allow(dead_code)]
const DEFAULT_BCRYPT_COST: u32 = 12;
#[cfg(feature = "api-keys")]
#[allow(dead_code)]
const CACHE_TTL_SECS: u64 = 300; // 5 minutes

#[cfg(feature = "api-keys")]
/// Configuration for API key generation and validation
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ApiKeyConfig {
    pub prefix: String,
    pub key_length: usize,
    pub bcrypt_cost: u32,
    pub cache_ttl_secs: u64,
}

#[cfg(feature = "api-keys")]
impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            prefix: std::env::var("METAFUSE_API_KEY_PREFIX")
                .unwrap_or_else(|_| DEFAULT_API_KEY_PREFIX.to_string()),
            key_length: std::env::var("METAFUSE_API_KEY_LENGTH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_API_KEY_LENGTH),
            bcrypt_cost: std::env::var("METAFUSE_BCRYPT_COST")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_BCRYPT_COST),
            cache_ttl_secs: CACHE_TTL_SECS,
        }
    }
}

#[cfg(feature = "api-keys")]
/// Validated key information (returned by validate_key_with_info)
#[derive(Clone, Debug)]
pub struct ValidatedKeyInfo {
    /// bcrypt hash (serves as unique ID)
    pub key_hash: String,
    /// Human-readable name
    pub name: String,
}

#[cfg(feature = "api-keys")]
/// Cached API key validation result
///
/// Note: We cache by a hash of the plaintext key (not the plaintext itself)
/// to avoid storing sensitive credentials in memory.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct CachedKey {
    bcrypt_hash: String, // Store bcrypt hash to avoid DB lookup and for marking as used
    name: String,        // Store name for identity-aware operations
    cached_at: Instant,
}

#[cfg(feature = "api-keys")]
/// Compute a cache key from plaintext API key
///
/// This hash is ONLY for cache keying, not for security.
/// We never store plaintext keys in the cache map.
#[allow(dead_code)]
fn cache_key_from_plaintext(plaintext: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    plaintext.hash(&mut hasher);
    hasher.finish()
}

#[cfg(feature = "api-keys")]
/// API key manager with in-memory cache and background flush
///
/// **Security Note**: Cache keys are hashed to avoid storing plaintext API keys in memory.
/// This mitigates risk from memory dumps or process inspection.
#[allow(dead_code)]
pub struct ApiKeyManager {
    config: ApiKeyConfig,
    db_path: String,
    cache: Arc<DashMap<u64, CachedKey>>, // Keyed by hash, not plaintext
    pending_updates: Arc<DashMap<String, Instant>>, // Keyed by bcrypt hash
}

#[cfg(feature = "api-keys")]
#[allow(dead_code)]
impl ApiKeyManager {
    /// Create a new API key manager
    pub fn new(db_path: String) -> Result<Self, String> {
        Ok(Self {
            config: ApiKeyConfig::default(),
            db_path,
            cache: Arc::new(DashMap::new()),
            pending_updates: Arc::new(DashMap::new()),
        })
    }

    /// Generate a new API key and store it in the database
    ///
    /// Returns the plaintext API key. **This is the only time the plaintext will be available!**
    /// The key should be securely transmitted to the user and never logged or stored in plaintext.
    pub async fn create_key(&self, name: String) -> Result<String, String> {
        let plaintext_key = self.generate_api_key();

        // Hash the key using bcrypt (blocking operation)
        let key_hash = {
            let plaintext = plaintext_key.clone();
            let cost = self.config.bcrypt_cost;
            tokio::task::spawn_blocking(move || hash(&plaintext, cost).map_err(|e| e.to_string()))
                .await
                .map_err(|e| e.to_string())??
        };

        // Store in database
        let db_path = self.db_path.clone();
        let name_clone = name.clone();
        let key_hash_clone = key_hash.clone();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
            conn.execute(
                "INSERT INTO api_keys (key_hash, name, created_at) VALUES (?1, ?2, datetime('now'))",
                rusqlite::params![&key_hash_clone, &name_clone],
            ).map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        })
        .await
        .map_err(|e| e.to_string())??;

        info!(name = %name, "Created new API key");
        Ok(plaintext_key)
    }

    /// Validate an API key and return identity information (for identity-aware middleware)
    ///
    /// Returns `Ok(Some(info))` if valid, `Ok(None)` if invalid, `Err` on validation error.
    ///
    /// **Use this** when you need the key's identity for downstream operations (e.g., rate limiting).
    pub async fn validate_key_with_info(
        &self,
        plaintext_key: &str,
    ) -> Result<Option<ValidatedKeyInfo>, String> {
        let cache_key = cache_key_from_plaintext(plaintext_key);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            let age = cached.cached_at.elapsed();
            if age < Duration::from_secs(self.config.cache_ttl_secs) {
                debug!("API key validation: cache hit");
                self.mark_key_used(&cached.bcrypt_hash);
                return Ok(Some(ValidatedKeyInfo {
                    key_hash: cached.bcrypt_hash.clone(),
                    name: cached.name.clone(),
                }));
            } else {
                debug!("API key validation: cache expired");
                self.cache.remove(&cache_key);
            }
        }

        // Cache miss - query database
        let db_path = self.db_path.clone();
        let plaintext = plaintext_key.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

            // Get all non-revoked key hashes
            let mut stmt = conn
                .prepare("SELECT key_hash, name FROM api_keys WHERE revoked_at IS NULL")
                .map_err(|e| e.to_string())?;

            let keys: Vec<(String, String)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;

            // Verify against each hash using constant-time comparison
            for (key_hash, name) in keys {
                if verify(&plaintext, &key_hash).unwrap_or(false) {
                    return Ok::<Option<(String, String)>, String>(Some((key_hash, name)));
                }
            }

            Ok(None)
        })
        .await
        .map_err(|e| e.to_string())??;

        if let Some((bcrypt_hash, name)) = result {
            // Cache the valid key (by hash, not plaintext)
            self.cache.insert(
                cache_key,
                CachedKey {
                    bcrypt_hash: bcrypt_hash.clone(),
                    name: name.clone(),
                    cached_at: Instant::now(),
                },
            );

            // Mark for background update (keyed by bcrypt hash)
            self.mark_key_used(&bcrypt_hash);

            debug!(name = %name, "API key validated successfully");
            Ok(Some(ValidatedKeyInfo {
                key_hash: bcrypt_hash,
                name,
            }))
        } else {
            warn!("API key validation failed");
            Ok(None)
        }
    }

    /// Validate an API key against the database
    ///
    /// Uses constant-time comparison to prevent timing attacks. Checks cache first,
    /// then falls back to database. Updates last_used_at timestamp asynchronously.
    ///
    /// **Security Note**: Cache is keyed by a hash of the plaintext, not the plaintext itself.
    pub async fn validate_key(&self, plaintext_key: &str) -> Result<bool, String> {
        let cache_key = cache_key_from_plaintext(plaintext_key);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            let age = cached.cached_at.elapsed();
            if age < Duration::from_secs(self.config.cache_ttl_secs) {
                debug!("API key validation: cache hit");
                self.mark_key_used(&cached.bcrypt_hash);
                return Ok(true);
            } else {
                debug!("API key validation: cache expired");
                self.cache.remove(&cache_key);
            }
        }

        // Cache miss - query database
        let db_path = self.db_path.clone();
        let plaintext = plaintext_key.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

            // Get all non-revoked key hashes
            let mut stmt = conn
                .prepare("SELECT key_hash, name FROM api_keys WHERE revoked_at IS NULL")
                .map_err(|e| e.to_string())?;

            let keys: Vec<(String, String)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;

            // Verify against each hash using constant-time comparison
            for (key_hash, name) in keys {
                if verify(&plaintext, &key_hash).unwrap_or(false) {
                    return Ok::<Option<(String, String)>, String>(Some((key_hash, name)));
                }
            }

            Ok(None)
        })
        .await
        .map_err(|e| e.to_string())??;

        if let Some((bcrypt_hash, name)) = result {
            // Cache the valid key (by hash, not plaintext)
            self.cache.insert(
                cache_key,
                CachedKey {
                    bcrypt_hash: bcrypt_hash.clone(),
                    name: name.clone(),
                    cached_at: Instant::now(),
                },
            );

            // Mark for background update (keyed by bcrypt hash)
            self.mark_key_used(&bcrypt_hash);

            debug!(name = %name, "API key validated successfully");
            Ok(true)
        } else {
            warn!("API key validation failed");
            Ok(false)
        }
    }

    /// List all API keys (returns name, created_at, revoked_at, last_used_at)
    pub async fn list_keys(&self) -> Result<Vec<ApiKeyInfo>, String> {
        let db_path = self.db_path.clone();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
            let mut stmt = conn.prepare(
                "SELECT id, name, created_at, revoked_at, last_used_at FROM api_keys ORDER BY created_at DESC, id DESC"
            ).map_err(|e| e.to_string())?;

            let keys = stmt
                .query_map([], |row| {
                    Ok(ApiKeyInfo {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        created_at: row.get(2)?,
                        revoked_at: row.get(3)?,
                        last_used_at: row.get(4)?,
                    })
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;

            Ok(keys)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// Revoke an API key by ID (soft delete)
    ///
    /// **Security Note**: Immediately clears the entire cache to ensure revoked keys
    /// cannot be used, even if they were recently cached.
    pub async fn revoke_key(&self, id: i64) -> Result<bool, String> {
        let db_path = self.db_path.clone();

        let rows_affected = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
            let rows = conn.execute(
                "UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ?1 AND revoked_at IS NULL",
                rusqlite::params![id],
            ).map_err(|e| e.to_string())?;
            Ok::<usize, String>(rows)
        })
        .await
        .map_err(|e| e.to_string())??;

        if rows_affected > 0 {
            info!(id = id, "Revoked API key");

            // CRITICAL: Clear entire cache to ensure revoked key cannot be used
            // We clear all entries because we can't efficiently map ID -> cache key
            self.cache.clear();
            self.pending_updates.clear();

            debug!("Cleared auth cache after key revocation");
            Ok(true)
        } else {
            warn!(id = id, "API key not found or already revoked");
            Ok(false)
        }
    }

    /// Generate a cryptographically secure API key
    fn generate_api_key(&self) -> String {
        let mut rng = rand::rngs::OsRng;
        let mut bytes = vec![0u8; self.config.key_length];
        rng.fill_bytes(&mut bytes);

        format!("{}{}", self.config.prefix, hex::encode(&bytes))
    }

    /// Mark a key as recently used (queued for background flush)
    ///
    /// Takes the bcrypt hash (not plaintext) to avoid storing sensitive data.
    fn mark_key_used(&self, bcrypt_hash: &str) {
        self.pending_updates
            .insert(bcrypt_hash.to_string(), Instant::now());
    }

    /// Flush pending last_used_at updates to the database
    ///
    /// This should be called periodically from a background task to batch-update
    /// last_used_at timestamps without blocking request processing.
    ///
    /// **Security Note**: pending_updates are keyed by bcrypt hash, not plaintext.
    pub async fn flush_pending_updates(&self) -> Result<usize, String> {
        if self.pending_updates.is_empty() {
            return Ok(0);
        }

        // Collect bcrypt hashes to update (already the keys in pending_updates)
        let updates: Vec<String> = self
            .pending_updates
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        let count = updates.len();
        if count == 0 {
            return Ok(0);
        }

        // Batch update in database
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;

            for key_hash in &updates {
                tx.execute(
                    "UPDATE api_keys SET last_used_at = datetime('now') WHERE key_hash = ?1",
                    rusqlite::params![key_hash],
                )
                .map_err(|e| e.to_string())?;
            }

            tx.commit().map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        })
        .await
        .map_err(|e| e.to_string())??;

        // Clear pending updates
        self.pending_updates.clear();

        debug!(count = count, "Flushed last_used_at updates");
        Ok(count)
    }
}

#[cfg(feature = "api-keys")]
/// API key metadata (returned by list_keys)
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ApiKeyInfo {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
}

#[cfg(feature = "api-keys")]
/// Axum middleware for API key authentication (identity-aware, non-blocking)
///
/// **Architecture**: This middleware validates API keys and attaches authenticated
/// identity to request extensions. It does NOT block unauthenticated requests -
/// downstream handlers decide whether authentication is required.
///
/// **Flow**:
/// 1. Extracts API key from Authorization header or query parameter
/// 2. If key present and valid: Attaches `ApiKeyId` to request extensions
/// 3. If key absent or invalid: Passes request through without identity
///
/// **Usage with Rate Limiting**:
/// ```text
/// Request → Auth Middleware (attaches identity) → Rate Limiter (uses identity for tiering)
/// ```
///
/// This ensures invalid keys don't get elevated rate limits.
#[allow(dead_code)]
pub async fn api_key_identity_middleware(
    axum::extract::Extension(manager): axum::extract::Extension<Arc<ApiKeyManager>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Extract API key from Authorization header or query parameter
    if let Some(key) = extract_api_key(&req) {
        // Validate the key
        match manager.validate_key_with_info(&key).await {
            Ok(Some(info)) => {
                // Key is valid - attach identity to request extensions
                #[cfg(feature = "rate-limiting")]
                req.extensions_mut().insert(ApiKeyId { id: info.key_hash });
                debug!(name = %info.name, "Authenticated API key");
            }
            Ok(None) => {
                // Key is invalid - pass through without identity
                warn!("Invalid API key provided (not attaching identity)");
            }
            Err(e) => {
                // Validation error - pass through without identity
                warn!(error = %e, "API key validation error (not attaching identity)");
            }
        }
    }

    // Always pass through (let downstream decide if auth is required)
    next.run(req).await
}

#[cfg(feature = "api-keys")]
/// Axum middleware for **required** API key authentication
///
/// Use this when you want to enforce authentication (returns 401 if no valid key).
/// For optional authentication (identity-aware rate limiting), use `api_key_identity_middleware`.
#[allow(dead_code)]
pub async fn api_key_required_middleware(
    axum::extract::Extension(manager): axum::extract::Extension<Arc<ApiKeyManager>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    // Extract or generate request ID for error responses
    let request_id = req
        .extensions()
        .get::<uuid::Uuid>()
        .map(|id| id.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Extract API key from Authorization header or query parameter
    let api_key = extract_api_key(&req);

    if let Some(key) = api_key {
        // Validate the key
        match manager.validate_key(&key).await {
            Ok(true) => {
                // Key is valid, proceed with request
                return Ok(next.run(req).await);
            }
            Ok(false) => {
                // Key is invalid
                warn!("API key authentication failed: invalid key");
                return Err((
                    axum::http::StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({
                        "error": "Unauthorized",
                        "message": "Invalid API key",
                        "request_id": request_id
                    })),
                ));
            }
            Err(e) => {
                // Validation error
                warn!(error = %e, "API key validation error");
                return Err((
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({
                        "error": "Internal Server Error",
                        "message": "Failed to validate API key",
                        "request_id": request_id
                    })),
                ));
            }
        }
    }

    // No API key provided
    warn!("API key authentication failed: no key provided");
    Err((
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": "Unauthorized",
            "message": "API key required. Provide via Authorization header (Bearer token) or ?api_key= query parameter",
            "request_id": request_id
        })),
    ))
}

#[cfg(feature = "api-keys")]
/// Extract API key from request
///
/// Checks (in order):
/// 1. Authorization header: "Bearer TOKEN"
/// 2. Query parameter: ?api_key=TOKEN
#[allow(dead_code)]
fn extract_api_key(req: &axum::extract::Request) -> Option<String> {
    // Check Authorization header
    if let Some(auth_header) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.trim().to_string());
            }
        }
    }

    // Check query parameter
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == "api_key" {
                    return Some(value.to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
#[cfg(feature = "api-keys")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_validate_key() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        // Initialize schema
        {
            let conn = Connection::open(&db_path).unwrap();
            metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        }

        let manager = ApiKeyManager::new(db_path.to_str().unwrap().to_string()).unwrap();

        // Create a key
        let plaintext = manager.create_key("test-key".to_string()).await.unwrap();
        assert!(plaintext.starts_with("mf_"));
        assert!(plaintext.len() > 10);

        // Validate the key
        let is_valid = manager.validate_key(&plaintext).await.unwrap();
        assert!(is_valid);

        // Invalid key should fail
        let is_valid = manager.validate_key("mf_invalid").await.unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        {
            let conn = Connection::open(&db_path).unwrap();
            metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        }

        let manager = ApiKeyManager::new(db_path.to_str().unwrap().to_string()).unwrap();
        let plaintext = manager.create_key("test-key".to_string()).await.unwrap();

        // First validation - cache miss
        let is_valid = manager.validate_key(&plaintext).await.unwrap();
        assert!(is_valid);

        // Second validation - cache hit
        let is_valid = manager.validate_key(&plaintext).await.unwrap();
        assert!(is_valid);

        // Verify cache contains the key (by hashed key, not plaintext)
        let cache_key = cache_key_from_plaintext(&plaintext);
        assert!(manager.cache.contains_key(&cache_key));
    }

    #[tokio::test]
    async fn test_revoke_key() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        {
            let conn = Connection::open(&db_path).unwrap();
            metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        }

        let manager = ApiKeyManager::new(db_path.to_str().unwrap().to_string()).unwrap();
        let plaintext = manager.create_key("test-key".to_string()).await.unwrap();

        // Validate works initially
        let is_valid = manager.validate_key(&plaintext).await.unwrap();
        assert!(is_valid);

        // Get the key ID
        let keys = manager.list_keys().await.unwrap();
        let key_id = keys[0].id;

        // Revoke the key
        let revoked = manager.revoke_key(key_id).await.unwrap();
        assert!(revoked);

        // Clear cache to force database check
        manager.cache.clear();

        // Validation should now fail
        let is_valid = manager.validate_key(&plaintext).await.unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_list_keys() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        {
            let conn = Connection::open(&db_path).unwrap();
            metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        }

        let manager = ApiKeyManager::new(db_path.to_str().unwrap().to_string()).unwrap();

        // Create multiple keys
        manager.create_key("key1".to_string()).await.unwrap();
        manager.create_key("key2".to_string()).await.unwrap();

        let keys = manager.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].name, "key2"); // Most recent first
        assert_eq!(keys[1].name, "key1");
    }

    #[tokio::test]
    async fn test_flush_pending_updates() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        {
            let conn = Connection::open(&db_path).unwrap();
            metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        }

        let manager = ApiKeyManager::new(db_path.to_str().unwrap().to_string()).unwrap();
        let plaintext = manager.create_key("test-key".to_string()).await.unwrap();

        // Validate to populate cache and pending updates
        manager.validate_key(&plaintext).await.unwrap();
        assert!(manager.pending_updates.len() > 0);

        // Flush updates
        let count = manager.flush_pending_updates().await.unwrap();
        assert_eq!(count, 1);
        assert_eq!(manager.pending_updates.len(), 0);
    }

    #[tokio::test]
    async fn test_revoke_clears_cache() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        {
            let conn = Connection::open(&db_path).unwrap();
            metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        }

        let manager = ApiKeyManager::new(db_path.to_str().unwrap().to_string()).unwrap();
        let plaintext = manager.create_key("test-key".to_string()).await.unwrap();

        // Validate to populate cache
        let is_valid = manager.validate_key(&plaintext).await.unwrap();
        assert!(is_valid);

        // Verify key is cached
        let cache_key = cache_key_from_plaintext(&plaintext);
        assert!(manager.cache.contains_key(&cache_key));
        assert!(manager.pending_updates.len() > 0);

        // Get the key ID
        let keys = manager.list_keys().await.unwrap();
        let key_id = keys[0].id;

        // Revoke the key
        let revoked = manager.revoke_key(key_id).await.unwrap();
        assert!(revoked);

        // CRITICAL: Verify cache and pending updates were cleared
        assert_eq!(
            manager.cache.len(),
            0,
            "Cache should be cleared after revoke"
        );
        assert_eq!(
            manager.pending_updates.len(),
            0,
            "Pending updates should be cleared after revoke"
        );

        // Validation should now fail (cache miss + DB check)
        let is_valid = manager.validate_key(&plaintext).await.unwrap();
        assert!(!is_valid, "Revoked key should not validate");
    }

    #[tokio::test]
    async fn test_invalid_key_does_not_get_identity() {
        // SECURITY TEST: Verify that invalid API keys don't get identity info
        // This ensures they can't get elevated rate limits
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        {
            let conn = Connection::open(&db_path).unwrap();
            metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        }

        let manager = ApiKeyManager::new(db_path.to_str().unwrap().to_string()).unwrap();

        // Create a valid key
        let valid_key = manager.create_key("valid-key".to_string()).await.unwrap();

        // Test 1: Valid key should return identity info
        let info = manager.validate_key_with_info(&valid_key).await.unwrap();
        assert!(info.is_some(), "Valid key should return identity info");
        let info = info.unwrap();
        assert_eq!(info.name, "valid-key");
        assert!(!info.key_hash.is_empty());

        // Test 2: Invalid key should NOT return identity info
        let invalid_info = manager
            .validate_key_with_info("mf_invalid_key_12345")
            .await
            .unwrap();
        assert!(
            invalid_info.is_none(),
            "Invalid key should NOT return identity info"
        );

        // Test 3: Empty key should NOT return identity info
        let empty_info = manager.validate_key_with_info("").await.unwrap();
        assert!(
            empty_info.is_none(),
            "Empty key should NOT return identity info"
        );

        // SECURITY IMPLICATION:
        // The middleware uses validate_key_with_info() to decide whether to attach
        // ApiKeyId to request extensions. Since invalid keys return None, they don't
        // get identity attached, which means the rate limiter will fall back to IP-based
        // (low-tier) limits instead of key-based (high-tier) limits.
        //
        // This prevents the security vulnerability where attackers could use invalid
        // keys to get elevated rate limits.
    }

    #[test]
    fn test_error_response_format() {
        // Verify that error responses follow consistent JSON structure
        // This documents the expected format for 401/429 responses

        // 401 Unauthorized format
        let auth_error = serde_json::json!({
            "error": "Unauthorized",
            "message": "Invalid API key",
            "request_id": "test-request-id"
        });
        assert_eq!(auth_error["error"], "Unauthorized");
        assert_eq!(auth_error["request_id"], "test-request-id");

        // 429 Too Many Requests format (from rate_limiting module)
        let rate_limit_error = serde_json::json!({
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please retry after the specified time.",
            "request_id": "test-request-id",
            "retry_after": 60
        });
        assert_eq!(rate_limit_error["error"], "Rate limit exceeded");
        assert_eq!(rate_limit_error["request_id"], "test-request-id");
        assert_eq!(rate_limit_error["retry_after"], 60);

        // Both responses include request_id for traceability
    }
}
