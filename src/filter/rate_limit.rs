//! Rate limiting filter using GCRA (Generic Cell Rate Algorithm)
//!
//! Supports both in-memory (single node) and Redis (distributed) storage.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use hyper::Request;
use hyper::body::Incoming;

#[cfg(feature = "redis-storage")]
use redis::AsyncCommands;

use super::{Filter, FilterAction, ChallengeType};

/// Error type for rate limit storage operations
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Redis error: {0}")]
    Redis(String),
}

type Result<T> = std::result::Result<T, StorageError>;

/// Trait for rate limit storage backends
#[async_trait::async_trait]
pub trait RateLimitStorage: Send + Sync {
    async fn check_and_update(
        &self,
        key: &str,
        now_nanos: u64,
        emission_interval_nanos: u64,
        delay_tolerance_nanos: u64,
    ) -> Result<Option<u64>>;
}


pub struct InMemoryStorage {
    state: DashMap<String, u64>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            state: DashMap::new(),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl RateLimitStorage for InMemoryStorage {
    async fn check_and_update(
        &self,
        key: &str,
        now_nanos: u64,
        emission_interval_nanos: u64,
        delay_tolerance_nanos: u64,
    ) -> Result<Option<u64>> {
        let initial_tat = now_nanos.saturating_sub(delay_tolerance_nanos + emission_interval_nanos);
        let mut entry = self.state.entry(key.to_string()).or_insert(initial_tat);

        let tat = *entry;
        let allow_at = tat.saturating_sub(delay_tolerance_nanos);
        
        if now_nanos <= allow_at {
            let retry_after_nanos = allow_at.saturating_sub(now_nanos) + 1;
            return Ok(Some(retry_after_nanos));
        }

        let new_tat = tat.max(now_nanos) + emission_interval_nanos;
        *entry = new_tat;

        Ok(None)
    }
}

/// Redis storage for distributed rate limiting
#[cfg(feature = "redis-storage")]
pub struct RedisStorage {
    client: Arc<redis::Client>,
}

#[cfg(feature = "redis-storage")]
impl RedisStorage {
    pub fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        Ok(Self {
            client: Arc::new(client),
        })
    }

    fn redis_key(key: &str) -> String {
        format!("ratelimit:tat:{}", key)
    }
}

#[cfg(feature = "redis-storage")]
#[async_trait::async_trait]
impl RateLimitStorage for RedisStorage {
    async fn check_and_update(
        &self,
        key: &str,
        now_nanos: u64,
        emission_interval_nanos: u64,
        delay_tolerance_nanos: u64,
    ) -> Result<Option<u64>> {
        let mut conn = self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let redis_key = Self::redis_key(key);

        let tat: Option<u64> = conn.get(&redis_key)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let tat = tat.unwrap_or(now_nanos);
        let allow_at = tat.saturating_sub(delay_tolerance_nanos);

        if now_nanos < allow_at {
            let retry_after_nanos = allow_at - now_nanos;
            return Ok(Some(retry_after_nanos));
        }

        let new_tat = tat.max(now_nanos) + emission_interval_nanos;
        let ttl_secs = (delay_tolerance_nanos / 1_000_000_000) + 60;

        conn.set_ex(&redis_key, new_tat, ttl_secs as u64)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        Ok(None)
    }
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_capacity: u32,
}

impl RateLimitConfig {
    pub fn new(requests_per_second: u32, burst_capacity: u32) -> Self {
        Self {
            requests_per_second,
            burst_capacity,
        }
    }

    pub fn emission_interval_nanos(&self) -> u64 {
        (1_000_000_000 / self.requests_per_second as u64).max(1)
    }

    pub fn delay_tolerance_nanos(&self) -> u64 {
        // delay_tolerance = emission_interval * (burst - 1)
        // burst=1 (no burst) -> tolerance=0
        // burst=5 -> tolerance=4*emission (can make 5 requests immediately)
        self.emission_interval_nanos() * (self.burst_capacity.saturating_sub(1)) as u64
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::new(10, 20)
    }
}

/// Rate limiting filter with pluggable storage backend
pub struct RateLimitFilter {
    config: RateLimitConfig,
    storage: Arc<dyn RateLimitStorage>,
}

impl RateLimitFilter {
    pub fn new(config: RateLimitConfig, storage: Arc<dyn RateLimitStorage>) -> Self {
        Self { config, storage }
    }

    pub fn with_in_memory(config: RateLimitConfig) -> Self {
        Self::new(config, Arc::new(InMemoryStorage::new()))
    }

    async fn check_rate_limit(&self, addr: SocketAddr) -> FilterAction {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let key = addr.ip().to_string();

        match self.storage.check_and_update(
            &key,
            now_nanos,
            self.config.emission_interval_nanos(),
            self.config.delay_tolerance_nanos(),
        ).await {
            Ok(Some(retry_after_nanos)) => {
                let retry_after = (retry_after_nanos / 1_000_000_000).max(1) as u32;
                FilterAction::Challenge {
                    challenge_type: ChallengeType::RateLimit { retry_after },
                }
            }
            Ok(None) => FilterAction::Allow,
            Err(e) => {
                tracing::error!(error = %e, "Rate limit storage error");
                FilterAction::Allow
            }
        }
    }
}

#[async_trait::async_trait]
impl Filter for RateLimitFilter {
    async fn filter(
        &self,
        _req: &Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> FilterAction {
        self.check_rate_limit(remote_addr).await
    }

    fn name(&self) -> &str {
        "rate_limit"
    }
}