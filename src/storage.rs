//! Shared storage utilities for distributed backends

#[cfg(feature = "redis-storage")]
use std::sync::Arc;

#[cfg(feature = "redis-storage")]
use redis::Client as RedisClient;

/// Error type for storage operations
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Redis error: {0}")]
    Redis(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Shared Redis client wrapper for reuse across modules
#[cfg(feature = "redis-storage")]
#[derive(Clone)]
pub struct SharedRedisClient {
    client: Arc<RedisClient>,
}

#[cfg(feature = "redis-storage")]
impl SharedRedisClient {
    pub fn new(redis_url: &str) -> Result<Self> {
        let client =
            RedisClient::open(redis_url).map_err(|e| StorageError::Redis(e.to_string()))?;

        Ok(Self {
            client: Arc::new(client),
        })
    }

    pub fn client(&self) -> &Arc<RedisClient> {
        &self.client
    }
}
