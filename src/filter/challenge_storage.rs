use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use crate::storage::Result;

#[cfg(feature = "redis-storage")]
use crate::storage::{SharedRedisClient, StorageError};

#[async_trait::async_trait]
pub trait ChallengeStorage: Send + Sync {
    async fn mark_completed(&self, session_token: &str, ip: &str, expiry_secs: u64) -> Result<()>;

    async fn verify_session(&self, session_token: &str) -> Result<bool>;
}

pub struct InMemoryChallengeStorage {
    sessions: DashMap<String, (String, u64)>,
}

impl InMemoryChallengeStorage {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl Default for InMemoryChallengeStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ChallengeStorage for InMemoryChallengeStorage {
    async fn mark_completed(&self, session_token: &str, ip: &str, expiry_secs: u64) -> Result<()> {
        let now = Self::now();
        let expiry = now + expiry_secs;
        self.sessions.insert(session_token.to_string(), (ip.to_string(), expiry));
        Ok(())
    }

    async fn verify_session(&self, session_token: &str) -> Result<bool> {
        let now = Self::now();

        if let Some(entry) = self.sessions.get(session_token) {
            let (_ip, expiry) = entry.value();
            Ok(*expiry > now)
        } else {
            Ok(false)
        }
    }
}

#[cfg(feature = "redis-storage")]
pub struct RedisChallengeStorage {
    client: Arc<redis::Client>,
}

#[cfg(feature = "redis-storage")]
impl RedisChallengeStorage {
    pub fn from_client(shared_client: SharedRedisClient) -> Self {
        Self {
            client: shared_client.client().clone(),
        }
    }
}

#[cfg(feature = "redis-storage")]
#[async_trait::async_trait]
impl ChallengeStorage for RedisChallengeStorage {
    async fn mark_completed(&self, session_token: &str, ip: &str, expiry_secs: u64) -> Result<()> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;
        let key = format!("challenge:session:{}", session_token);

        redis::cmd("SETEX")
            .arg(&key)
            .arg(expiry_secs)
            .arg(ip)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        Ok(())
    }

    async fn verify_session(&self, session_token: &str) -> Result<bool> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;
        let key = format!("challenge:session:{}", session_token);

        let exists: i64 = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::Redis(e.to_string()))?;

        Ok(exists > 0)
    }
}
