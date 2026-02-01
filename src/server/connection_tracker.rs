//! Connection tracking for Slowloris attack protection
//!
//! Supports both in-memory (single node) and Redis (distributed) storage.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

#[cfg(feature = "redis-storage")]
use redis::AsyncCommands;

/// Error type for connection storage operations
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Redis error: {0}")]
    Redis(String),
}

type Result<T> = std::result::Result<T, StorageError>;

/// Connection metadata for tracking connection state
#[derive(Debug, Clone)]
pub struct ConnectionMetadata {
    /// Number of active connections from this IP
    pub active_connections: u32,
    /// Timestamp of the last connection attempt (nanoseconds since UNIX epoch)
    pub last_connection_nanos: u64,
    /// Timestamp of the last activity (nanoseconds since UNIX epoch)
    pub last_activity_nanos: u64,
}

impl ConnectionMetadata {
    pub fn new(now_nanos: u64) -> Self {
        Self {
            active_connections: 1,
            last_connection_nanos: now_nanos,
            last_activity_nanos: now_nanos,
        }
    }
}

/// Trait for connection tracking storage backends
#[async_trait::async_trait]
pub trait ConnectionStorage: Send + Sync {
    /// Check if a new connection should be allowed based on limits
    /// Returns Ok(true) if allowed, Ok(false) if denied
    async fn check_new_connection(
        &self,
        ip: IpAddr,
        now_nanos: u64,
        max_connections: u32,
        rate_limit_nanos: u64,
    ) -> Result<bool>;
    async fn register_connection(&self, ip: IpAddr, now_nanos: u64) -> Result<()>;
    async fn update_activity(&self, ip: IpAddr, now_nanos: u64) -> Result<()>;
    async fn unregister_connection(&self, ip: IpAddr) -> Result<()>;
    async fn cleanup_idle(&self, idle_timeout_nanos: u64, now_nanos: u64) -> Result<u32>;
}

/// In-memory storage using DashMap
pub struct InMemoryConnectionStorage {
    state: DashMap<IpAddr, ConnectionMetadata>,
}

impl InMemoryConnectionStorage {
    pub fn new() -> Self {
        Self {
            state: DashMap::new(),
        }
    }
}

impl Default for InMemoryConnectionStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ConnectionStorage for InMemoryConnectionStorage {
    async fn check_new_connection(
        &self,
        ip: IpAddr,
        now_nanos: u64,
        max_connections: u32,
        rate_limit_nanos: u64,
    ) -> Result<bool> {
        if let Some(entry) = self.state.get(&ip) {
            let metadata = entry.value();
            if metadata.active_connections >= max_connections {
                return Ok(false);
            }
            let time_since_last = now_nanos.saturating_sub(metadata.last_connection_nanos);
            if time_since_last < rate_limit_nanos {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn register_connection(&self, ip: IpAddr, now_nanos: u64) -> Result<()> {
        self.state
            .entry(ip)
            .and_modify(|metadata| {
                metadata.active_connections = metadata.active_connections.saturating_add(1);
                metadata.last_connection_nanos = now_nanos;
                metadata.last_activity_nanos = now_nanos;
            })
            .or_insert_with(|| ConnectionMetadata::new(now_nanos));

        Ok(())
    }

    async fn update_activity(&self, ip: IpAddr, now_nanos: u64) -> Result<()> {
        if let Some(mut entry) = self.state.get_mut(&ip) {
            entry.last_activity_nanos = now_nanos;
        }

        Ok(())
    }

    async fn unregister_connection(&self, ip: IpAddr) -> Result<()> {
        if let Some(mut entry) = self.state.get_mut(&ip) {
            entry.active_connections = entry.active_connections.saturating_sub(1);
            // Don't remove immediately - let cleanup_idle handle removal
        }

        Ok(())
    }

    async fn cleanup_idle(&self, idle_timeout_nanos: u64, now_nanos: u64) -> Result<u32> {
        let mut cleaned = 0u32;

        self.state.retain(|_ip, metadata| {
            let idle_time = now_nanos.saturating_sub(metadata.last_activity_nanos);
            if idle_time > idle_timeout_nanos && metadata.active_connections == 0 {
                cleaned += 1;
                false
            } else {
                true
            }
        });

        Ok(cleaned)
    }
}

/// Redis storage for distributed connection tracking
#[cfg(feature = "redis-storage")]
pub struct RedisConnectionStorage {
    client: Arc<redis::Client>,
}

#[cfg(feature = "redis-storage")]
impl RedisConnectionStorage {
    pub fn new(redis_url: &str) -> Result<Self> {
        let client =
            redis::Client::open(redis_url).map_err(|e| StorageError::Redis(e.to_string()))?;

        Ok(Self {
            client: Arc::new(client),
        })
    }

    fn connections_key(ip: IpAddr) -> String {
        format!("slowloris:conn:{}", ip)
    }

    fn last_conn_key(ip: IpAddr) -> String {
        format!("slowloris:last:{}", ip)
    }

    fn activity_key(ip: IpAddr) -> String {
        format!("slowloris:activity:{}", ip)
    }
}

#[cfg(feature = "redis-storage")]
#[async_trait::async_trait]
impl ConnectionStorage for RedisConnectionStorage {
    async fn check_new_connection(
        &self,
        ip: IpAddr,
        now_nanos: u64,
        max_connections: u32,
        rate_limit_nanos: u64,
    ) -> Result<bool> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let connections_key = Self::connections_key(ip);
        let last_conn_key = Self::last_conn_key(ip);

        let active_connections: Option<u32> = conn
            .get(&connections_key)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        if let Some(count) = active_connections {
            if count >= max_connections {
                return Ok(false);
            }
        }

        let last_connection: Option<u64> = conn
            .get(&last_conn_key)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        if let Some(last_nanos) = last_connection {
            let time_since_last = now_nanos.saturating_sub(last_nanos);
            if time_since_last < rate_limit_nanos {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn register_connection(&self, ip: IpAddr, now_nanos: u64) -> Result<()> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let connections_key = Self::connections_key(ip);
        let last_conn_key = Self::last_conn_key(ip);
        let activity_key = Self::activity_key(ip);

        let _: () = conn
            .incr(&connections_key, 1)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let _: () = conn
            .set(&last_conn_key, now_nanos)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let _: () = conn
            .set(&activity_key, now_nanos)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let ttl_secs = 86400u64;
        let _: () = conn
            .expire(&connections_key, ttl_secs as i64)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;
        let _: () = conn
            .expire(&last_conn_key, ttl_secs as i64)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;
        let _: () = conn
            .expire(&activity_key, ttl_secs as i64)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        Ok(())
    }

    async fn update_activity(&self, ip: IpAddr, now_nanos: u64) -> Result<()> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let activity_key = Self::activity_key(ip);

        let _: () = conn
            .set(&activity_key, now_nanos)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        Ok(())
    }

    async fn unregister_connection(&self, ip: IpAddr) -> Result<()> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let connections_key = Self::connections_key(ip);

        let new_count: i32 = conn
            .decr(&connections_key, 1)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        if new_count <= 0 {
            let _: () = conn
                .del(&connections_key)
                .await
                .map_err(|e| StorageError::Redis(e.to_string()))?;
        }

        Ok(())
    }

    async fn cleanup_idle(&self, idle_timeout_nanos: u64, now_nanos: u64) -> Result<u32> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let pattern = "slowloris:activity:*";
        let keys: Vec<String> = conn
            .keys(pattern)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        let mut cleaned = 0u32;

        for activity_key in keys {
            let last_activity: Option<u64> = conn
                .get(&activity_key)
                .await
                .map_err(|e| StorageError::Redis(e.to_string()))?;

            if let Some(last_nanos) = last_activity {
                let idle_time = now_nanos.saturating_sub(last_nanos);

                if idle_time > idle_timeout_nanos {
                    if let Some(ip_str) = activity_key.strip_prefix("slowloris:activity:") {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            let connections_key = Self::connections_key(ip);
                            let last_conn_key = Self::last_conn_key(ip);

                            let active: Option<u32> = conn
                                .get(&connections_key)
                                .await
                                .map_err(|e| StorageError::Redis(e.to_string()))?;

                            if active.unwrap_or(0) == 0 {
                                let _: () = conn
                                    .del(&[&connections_key, &last_conn_key, &activity_key])
                                    .await
                                    .map_err(|e| StorageError::Redis(e.to_string()))?;
                                cleaned += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(cleaned)
    }
}

/// Connection tracker with pluggable storage backend
pub struct ConnectionTracker {
    storage: Arc<dyn ConnectionStorage>,
    config: ConnectionTrackerConfig,
}

/// Configuration for connection tracking
#[derive(Debug, Clone)]
pub struct ConnectionTrackerConfig {
    pub max_connections_per_ip: u32,
    pub connection_rate_per_sec: u32,
    pub idle_timeout_secs: u64,
}

impl ConnectionTrackerConfig {
    pub fn new(max_connections: u32, rate_per_sec: u32, idle_timeout: u64) -> Self {
        Self {
            max_connections_per_ip: max_connections,
            connection_rate_per_sec: rate_per_sec,
            idle_timeout_secs: idle_timeout,
        }
    }

    fn rate_limit_nanos(&self) -> u64 {
        if self.connection_rate_per_sec == 0 {
            return 0;
        }
        1_000_000_000 / self.connection_rate_per_sec as u64
    }

    fn idle_timeout_nanos(&self) -> u64 {
        self.idle_timeout_secs * 1_000_000_000
    }
}

impl Default for ConnectionTrackerConfig {
    fn default() -> Self {
        Self::new(10, 5, 30)
    }
}

impl ConnectionTracker {
    pub fn new(config: ConnectionTrackerConfig, storage: Arc<dyn ConnectionStorage>) -> Self {
        Self { storage, config }
    }

    pub fn with_in_memory(config: ConnectionTrackerConfig) -> Self {
        Self::new(config, Arc::new(InMemoryConnectionStorage::new()))
    }

    pub async fn check_connection(&self, ip: IpAddr) -> bool {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        match self
            .storage
            .check_new_connection(
                ip,
                now_nanos,
                self.config.max_connections_per_ip,
                self.config.rate_limit_nanos(),
            )
            .await
        {
            Ok(allowed) => allowed,
            Err(e) => {
                tracing::error!(error = %e, %ip, "Connection tracking check failed, allowing");
                true // Fail-open
            }
        }
    }

    pub async fn register(&self, ip: IpAddr) -> Option<ConnectionGuard> {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        match self.storage.register_connection(ip, now_nanos).await {
            Ok(()) => Some(ConnectionGuard {
                ip,
                storage: self.storage.clone(),
            }),
            Err(e) => {
                tracing::error!(error = %e, %ip, "Connection registration failed");
                None
            }
        }
    }

    pub async fn update_activity(&self, ip: IpAddr) {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        if let Err(e) = self.storage.update_activity(ip, now_nanos).await {
            tracing::error!(error = %e, %ip, "Activity update failed");
        }
    }

    pub async fn cleanup_idle(&self) -> u32 {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        match self
            .storage
            .cleanup_idle(self.config.idle_timeout_nanos(), now_nanos)
            .await
        {
            Ok(count) => count,
            Err(e) => {
                tracing::error!(error = %e, "Idle connection cleanup failed");
                0
            }
        }
    }
}

/// RAII guard for automatic connection cleanup
pub struct ConnectionGuard {
    ip: IpAddr,
    storage: Arc<dyn ConnectionStorage>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let ip = self.ip;
        let storage = self.storage.clone();

        // Spawn a task to unregister the connection
        tokio::spawn(async move {
            if let Err(e) = storage.unregister_connection(ip).await {
                tracing::error!(error = %e, %ip, "Connection unregistration failed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_new_connection_allowed() {
        let storage = InMemoryConnectionStorage::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let now = 1000000u64;

        let allowed = storage
            .check_new_connection(ip, now, 10, 1000)
            .await
            .unwrap();
        assert!(allowed);
    }

    #[tokio::test]
    async fn test_in_memory_max_connections_limit() {
        let storage = InMemoryConnectionStorage::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let now = 1000000u64;

        // Register 3 connections
        storage.register_connection(ip, now).await.unwrap();
        storage
            .register_connection(ip, now + 1000000)
            .await
            .unwrap();
        storage
            .register_connection(ip, now + 2000000)
            .await
            .unwrap();

        // Should deny 4th connection if max is 3
        let allowed = storage
            .check_new_connection(ip, now + 3000000, 3, 1000)
            .await
            .unwrap();
        assert!(!allowed);

        // Should allow 4th connection if max is 10
        let allowed = storage
            .check_new_connection(ip, now + 3000000, 10, 1000)
            .await
            .unwrap();
        assert!(allowed);
    }

    #[tokio::test]
    async fn test_in_memory_connection_rate_limit() {
        let storage = InMemoryConnectionStorage::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let now = 1000000u64;
        let rate_limit_nanos = 1_000_000_000u64; // 1 second

        // First connection
        storage.register_connection(ip, now).await.unwrap();

        // Too soon for second connection
        let allowed = storage
            .check_new_connection(ip, now + 500_000_000, 10, rate_limit_nanos)
            .await
            .unwrap();
        assert!(!allowed);

        // After rate limit period
        let allowed = storage
            .check_new_connection(ip, now + 1_000_000_001, 10, rate_limit_nanos)
            .await
            .unwrap();
        assert!(allowed);
    }

    #[tokio::test]
    async fn test_in_memory_unregister_connection() {
        let storage = InMemoryConnectionStorage::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let now = 1000000u64;

        storage.register_connection(ip, now).await.unwrap();
        storage.unregister_connection(ip).await.unwrap();

        let metadata = storage.state.get(&ip).unwrap();
        assert_eq!(metadata.active_connections, 0);
    }

    #[tokio::test]
    async fn test_in_memory_cleanup_idle() {
        let storage = InMemoryConnectionStorage::new();
        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();
        let now = 1000000u64;
        let idle_timeout = 30_000_000_000u64; // 30 seconds

        storage.register_connection(ip1, now).await.unwrap();
        storage.unregister_connection(ip1).await.unwrap();

        storage.register_connection(ip2, now).await.unwrap();
        storage.unregister_connection(ip2).await.unwrap();

        storage
            .update_activity(ip2, now + 25_000_000_000)
            .await
            .unwrap();

        let cleaned = storage
            .cleanup_idle(idle_timeout, now + 35_000_000_000)
            .await
            .unwrap();

        assert_eq!(cleaned, 1);
        assert!(storage.state.get(&ip1).is_none());
        assert!(storage.state.get(&ip2).is_some());
    }

    #[tokio::test]
    async fn test_connection_tracker_config() {
        let config = ConnectionTrackerConfig::new(10, 5, 30);
        assert_eq!(config.max_connections_per_ip, 10);
        assert_eq!(config.connection_rate_per_sec, 5);
        assert_eq!(config.idle_timeout_secs, 30);
        assert_eq!(config.rate_limit_nanos(), 200_000_000); // 1s / 5 = 200ms
        assert_eq!(config.idle_timeout_nanos(), 30_000_000_000); // 30s
    }

    #[tokio::test]
    async fn test_connection_tracker_with_in_memory() {
        let config = ConnectionTrackerConfig::new(2, 10, 30);
        let tracker = ConnectionTracker::with_in_memory(config);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // First connection should be allowed
        assert!(tracker.check_connection(ip).await);

        // Register connection
        let _guard1 = tracker.register(ip).await;
        assert!(_guard1.is_some());

        // Second connection should be allowed (max is 2)
        let _guard2 = tracker.register(ip).await;
        assert!(_guard2.is_some());

        // Third connection should be denied (max is 2)
        assert!(!tracker.check_connection(ip).await);
    }

    #[tokio::test]
    async fn test_connection_guard_drop() {
        let storage = Arc::new(InMemoryConnectionStorage::new());
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let now = 1000000u64;

        // Register connection
        storage.register_connection(ip, now).await.unwrap();

        {
            let guard = ConnectionGuard {
                ip,
                storage: storage.clone(),
            };

            let metadata = storage.state.get(&ip).unwrap();
            assert_eq!(metadata.active_connections, 1);

            drop(guard);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let metadata = storage.state.get(&ip).unwrap();
        assert_eq!(metadata.active_connections, 0);
    }
}
