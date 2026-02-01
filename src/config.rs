//! Configuration management via environment variables
//!
//! Loads configuration from environment variables with .env file support.
//! Follows 12-factor app principles for cloud-native deployments.

use std::env;
use std::time::Duration;

use crate::error::{ArmorError, Result};

/// Main application configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub proxy: ProxyConfig,
    pub rate_limit: RateLimitConfig,
    pub fingerprint: FingerprintConfig,
}

/// Server binding configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub upstream_url: String,
    pub timeout: Duration,
    pub preserve_host: bool,
}

/// Rate limiting settings
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_capacity: u32,
    pub storage: StorageType,
    pub redis_url: Option<String>,
}

/// Storage backend type for rate limiting
#[derive(Debug, Clone, PartialEq)]
pub enum StorageType {
    Memory,
    #[cfg(feature = "redis-storage")]
    Redis,
}

/// Fingerprinting filter settings
#[derive(Debug, Clone)]
pub struct FingerprintConfig {
    pub enabled: bool,
    pub deny_threshold: u32,
    pub challenge_threshold: u32,
    pub user_agent_whitelist: Vec<String>,
    pub user_agent_blacklist: Vec<String>,
    pub strict_header_order: bool,
    pub require_common_headers: bool,
}

impl Config {
    /// Load configuration from environment variables
    ///
    /// Reads .env file if present, then parses environment variables.
    /// Returns error if required variables are missing or invalid.
    pub fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();

        Ok(Self {
            server: ServerConfig::from_env()?,
            proxy: ProxyConfig::from_env()?,
            rate_limit: RateLimitConfig::from_env()?,
            fingerprint: FingerprintConfig::from_env()?,
        })
    }
}

impl ServerConfig {
    fn from_env() -> Result<Self> {
        let host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

        let port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .map_err(|e| ArmorError::Config(format!("Invalid SERVER_PORT: {}", e)))?;

        Ok(Self { host, port })
    }
}

impl ProxyConfig {
    fn from_env() -> Result<Self> {
        let upstream_url = env::var("PROXY_UPSTREAM_URL")
            .map_err(|_| ArmorError::Config("PROXY_UPSTREAM_URL is required".to_string()))?;

        let timeout_secs = env::var("PROXY_TIMEOUT_SECS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u64>()
            .map_err(|e| ArmorError::Config(format!("Invalid PROXY_TIMEOUT_SECS: {}", e)))?;

        let preserve_host = env::var("PROXY_PRESERVE_HOST")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .map_err(|e| ArmorError::Config(format!("Invalid PROXY_PRESERVE_HOST: {}", e)))?;

        Ok(Self {
            upstream_url,
            timeout: Duration::from_secs(timeout_secs),
            preserve_host,
        })
    }
}

impl RateLimitConfig {
    fn from_env() -> Result<Self> {
        let enabled = env::var("RATE_LIMIT_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .map_err(|e| ArmorError::Config(format!("Invalid RATE_LIMIT_ENABLED: {}", e)))?;

        let requests_per_second = env::var("RATE_LIMIT_REQUESTS_PER_SECOND")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<u32>()
            .map_err(|e| ArmorError::Config(format!("Invalid RATE_LIMIT_REQUESTS_PER_SECOND: {}", e)))?;

        let burst_capacity = env::var("RATE_LIMIT_BURST_CAPACITY")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<u32>()
            .map_err(|e| ArmorError::Config(format!("Invalid RATE_LIMIT_BURST_CAPACITY: {}", e)))?;

        let storage_str = env::var("RATE_LIMIT_STORAGE")
            .unwrap_or_else(|_| "memory".to_string());

        let storage = match storage_str.to_lowercase().as_str() {
            "memory" => StorageType::Memory,
            #[cfg(feature = "redis-storage")]
            "redis" => StorageType::Redis,
            _ => {
                return Err(ArmorError::Config(format!(
                    "Invalid RATE_LIMIT_STORAGE: {}. Expected 'memory' or 'redis'",
                    storage_str
                )));
            }
        };

        let redis_url = if storage == StorageType::Memory {
            None
        } else {
            Some(env::var("REDIS_URL")
                .map_err(|_| ArmorError::Config("REDIS_URL is required when using Redis storage".to_string()))?)
        };

        Ok(Self {
            enabled,
            requests_per_second,
            burst_capacity,
            storage,
            redis_url,
        })
    }
}

impl FingerprintConfig {
    fn from_env() -> Result<Self> {
        let enabled = env::var("FINGERPRINT_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .map_err(|e| ArmorError::Config(format!("Invalid FINGERPRINT_ENABLED: {}", e)))?;

        let deny_threshold = env::var("FINGERPRINT_DENY_THRESHOLD")
            .unwrap_or_else(|_| "85".to_string())
            .parse::<u32>()
            .map_err(|e| {
                ArmorError::Config(format!("Invalid FINGERPRINT_DENY_THRESHOLD: {}", e))
            })?;

        if deny_threshold > 100 {
            return Err(ArmorError::Config(
                "FINGERPRINT_DENY_THRESHOLD must be 0-100".to_string(),
            ));
        }

        let challenge_threshold = env::var("FINGERPRINT_CHALLENGE_THRESHOLD")
            .unwrap_or_else(|_| "70".to_string())
            .parse::<u32>()
            .map_err(|e| {
                ArmorError::Config(format!("Invalid FINGERPRINT_CHALLENGE_THRESHOLD: {}", e))
            })?;

        if challenge_threshold > 100 {
            return Err(ArmorError::Config(
                "FINGERPRINT_CHALLENGE_THRESHOLD must be 0-100".to_string(),
            ));
        }

        if challenge_threshold > deny_threshold {
            return Err(ArmorError::Config(
                "FINGERPRINT_CHALLENGE_THRESHOLD must be <= FINGERPRINT_DENY_THRESHOLD"
                    .to_string(),
            ));
        }

        let user_agent_whitelist = env::var("FINGERPRINT_USER_AGENT_WHITELIST")
            .unwrap_or_else(|_| String::new())
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_lowercase())
            .collect();

        let user_agent_blacklist = env::var("FINGERPRINT_USER_AGENT_BLACKLIST")
            .unwrap_or_else(|_| String::new())
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_lowercase())
            .collect();

        let strict_header_order = env::var("FINGERPRINT_STRICT_HEADER_ORDER")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .map_err(|e| {
                ArmorError::Config(format!("Invalid FINGERPRINT_STRICT_HEADER_ORDER: {}", e))
            })?;

        let require_common_headers = env::var("FINGERPRINT_REQUIRE_COMMON_HEADERS")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .map_err(|e| {
                ArmorError::Config(format!("Invalid FINGERPRINT_REQUIRE_COMMON_HEADERS: {}", e))
            })?;

        Ok(Self {
            enabled,
            deny_threshold,
            challenge_threshold,
            user_agent_whitelist,
            user_agent_blacklist,
            strict_header_order,
            require_common_headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_defaults() {
        temp_env::with_vars_unset(vec!["SERVER_HOST", "SERVER_PORT"], || {
            let config = ServerConfig::from_env().unwrap();
            assert_eq!(config.host, "127.0.0.1");
            assert_eq!(config.port, 8080);
        });
    }

    #[test]
    fn test_server_config_custom() {
        temp_env::with_vars(
            vec![("SERVER_HOST", Some("0.0.0.0")), ("SERVER_PORT", Some("3000"))],
            || {
                let config = ServerConfig::from_env().unwrap();
                assert_eq!(config.host, "0.0.0.0");
                assert_eq!(config.port, 3000);
            },
        );
    }

    #[test]
    fn test_proxy_config_required_upstream() {
        temp_env::with_var_unset("PROXY_UPSTREAM_URL", || {
            let result = ProxyConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("PROXY_UPSTREAM_URL"));
        });
    }

    #[test]
    fn test_proxy_config_with_defaults() {
        temp_env::with_vars(
            vec![
                ("PROXY_UPSTREAM_URL", Some("http://backend:8000")),
                ("PROXY_TIMEOUT_SECS", None),
                ("PROXY_PRESERVE_HOST", None),
            ],
            || {
                let config = ProxyConfig::from_env().unwrap();
                assert_eq!(config.upstream_url, "http://backend:8000");
                assert_eq!(config.timeout, Duration::from_secs(30));
                assert_eq!(config.preserve_host, false);
            },
        );
    }

    #[test]
    fn test_rate_limit_defaults() {
        temp_env::with_vars_unset(
            vec![
                "RATE_LIMIT_ENABLED",
                "RATE_LIMIT_REQUESTS_PER_SECOND",
                "RATE_LIMIT_BURST_CAPACITY",
                "RATE_LIMIT_STORAGE",
            ],
            || {
                let config = RateLimitConfig::from_env().unwrap();
                assert_eq!(config.enabled, true);
                assert_eq!(config.requests_per_second, 100);
                assert_eq!(config.burst_capacity, 10);
                assert_eq!(config.storage, StorageType::Memory);
                assert!(config.redis_url.is_none());
            },
        );
    }

    #[test]
    fn test_rate_limit_custom() {
        temp_env::with_vars(
            vec![
                ("RATE_LIMIT_ENABLED", Some("true")),
                ("RATE_LIMIT_REQUESTS_PER_SECOND", Some("500")),
                ("RATE_LIMIT_BURST_CAPACITY", Some("50")),
                ("RATE_LIMIT_STORAGE", Some("memory")),
            ],
            || {
                let config = RateLimitConfig::from_env().unwrap();
                assert_eq!(config.enabled, true);
                assert_eq!(config.requests_per_second, 500);
                assert_eq!(config.burst_capacity, 50);
            },
        );
    }

    #[test]
    fn test_fingerprint_defaults() {
        temp_env::with_vars_unset(
            vec![
                "FINGERPRINT_ENABLED",
                "FINGERPRINT_DENY_THRESHOLD",
                "FINGERPRINT_CHALLENGE_THRESHOLD",
                "FINGERPRINT_USER_AGENT_WHITELIST",
                "FINGERPRINT_USER_AGENT_BLACKLIST",
                "FINGERPRINT_STRICT_HEADER_ORDER",
                "FINGERPRINT_REQUIRE_COMMON_HEADERS",
            ],
            || {
                let config = FingerprintConfig::from_env().unwrap();
                assert_eq!(config.enabled, true);
                assert_eq!(config.deny_threshold, 85);
                assert_eq!(config.challenge_threshold, 70);
                assert!(config.user_agent_whitelist.is_empty());
                assert!(config.user_agent_blacklist.is_empty());
                assert_eq!(config.strict_header_order, false);
                assert_eq!(config.require_common_headers, true);
            },
        );
    }

    #[test]
    fn test_fingerprint_custom() {
        temp_env::with_vars(
            vec![
                ("FINGERPRINT_ENABLED", Some("true")),
                ("FINGERPRINT_DENY_THRESHOLD", Some("90")),
                ("FINGERPRINT_CHALLENGE_THRESHOLD", Some("75")),
                ("FINGERPRINT_USER_AGENT_WHITELIST", Some("googlebot,bingbot")),
                ("FINGERPRINT_USER_AGENT_BLACKLIST", Some("curl,wget")),
                ("FINGERPRINT_STRICT_HEADER_ORDER", Some("true")),
                ("FINGERPRINT_REQUIRE_COMMON_HEADERS", Some("false")),
            ],
            || {
                let config = FingerprintConfig::from_env().unwrap();
                assert_eq!(config.enabled, true);
                assert_eq!(config.deny_threshold, 90);
                assert_eq!(config.challenge_threshold, 75);
                assert_eq!(config.user_agent_whitelist.len(), 2);
                assert!(config.user_agent_whitelist.contains(&"googlebot".to_string()));
                assert_eq!(config.user_agent_blacklist.len(), 2);
                assert!(config.user_agent_blacklist.contains(&"curl".to_string()));
                assert_eq!(config.strict_header_order, true);
                assert_eq!(config.require_common_headers, false);
            },
        );
    }

    #[test]
    fn test_fingerprint_threshold_validation() {
        temp_env::with_vars(vec![("FINGERPRINT_DENY_THRESHOLD", Some("101"))], || {
            let result = FingerprintConfig::from_env();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("must be 0-100"));
        });
        
        temp_env::with_vars(
            vec![
                ("FINGERPRINT_DENY_THRESHOLD", Some("70")),
                ("FINGERPRINT_CHALLENGE_THRESHOLD", Some("80")),
            ],
            || {
                let result = FingerprintConfig::from_env();
                assert!(result.is_err());
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("CHALLENGE_THRESHOLD must be <="));
            },
        );
    }

    #[test]
    fn test_fingerprint_whitelist_parsing() {
        temp_env::with_vars(
            vec![(
                "FINGERPRINT_USER_AGENT_WHITELIST",
                Some(" Googlebot , Bingbot , "),
            )],
            || {
                let config = FingerprintConfig::from_env().unwrap();
                assert_eq!(config.user_agent_whitelist.len(), 2);
                assert!(config.user_agent_whitelist.contains(&"googlebot".to_string()));
                assert!(config.user_agent_whitelist.contains(&"bingbot".to_string()));
            },
        );
    }
}