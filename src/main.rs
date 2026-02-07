//! Rust Armor L7 - Entry point

use std::net::SocketAddr;
use std::sync::Arc;

use intellegen_http_defender::config::{Config, StorageType};
use intellegen_http_defender::filter::RateLimitConfig;
use intellegen_http_defender::filter::challenge::{ProofOfWorkConfig, ProofOfWorkFilter};
use intellegen_http_defender::filter::challenge_storage::{
    ChallengeStorage, InMemoryChallengeStorage,
};
use intellegen_http_defender::filter::{
    FilterChain, FingerprintFilter, PassthroughFilter, RateLimitFilter,
};
use intellegen_http_defender::proxy::{ProxyClient, ProxyConfig as ProxyClientConfig};
use intellegen_http_defender::server::{
    ChallengeHandler, ConnectionTracker, ConnectionTrackerConfig, Server,
};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

#[cfg(feature = "redis-storage")]
use intellegen_http_defender::filter::challenge_storage::RedisChallengeStorage;
#[cfg(feature = "redis-storage")]
use intellegen_http_defender::storage::SharedRedisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let config = Config::from_env()?;

    info!("Starting Intellegen HTTP Defender");
    info!("Server: {}:{}", config.server.host, config.server.port);
    info!("Upstream: {}", config.proxy.upstream_url);
    info!(
        "Fingerprinting: enabled={}, deny_threshold={}, challenge_threshold={}",
        config.fingerprint.enabled,
        config.fingerprint.deny_threshold,
        config.fingerprint.challenge_threshold
    );
    info!(
        "Rate limiting: enabled={}, rps={}, burst={}",
        config.rate_limit.enabled,
        config.rate_limit.requests_per_second,
        config.rate_limit.burst_capacity
    );
    info!(
        "Slowloris protection: enabled={}, max_connections={}, connection_rate={}",
        config.slowloris.enabled,
        config.slowloris.max_connections_per_ip,
        config.slowloris.connection_rate_per_sec
    );
    info!(
        "Challenge-response: enabled={}, difficulty={}, timeout={}s",
        config.challenge.enabled, config.challenge.difficulty, config.challenge.timeout_secs
    );

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| format!("Invalid server address: {}", e))?;

    // Create shared Redis client if rate limiting, Slowloris, or challenge uses Redis
    #[cfg(feature = "redis-storage")]
    let shared_redis_client = {
        let needs_redis = matches!(config.rate_limit.storage, StorageType::Redis)
            || matches!(config.slowloris.storage, StorageType::Redis)
            || matches!(config.challenge.storage, StorageType::Redis);

        if needs_redis {
            let redis_url = config
                .rate_limit
                .redis_url
                .as_ref()
                .or(config.slowloris.redis_url.as_ref())
                .or(config.challenge.redis_url.as_ref())
                .expect("Redis URL required when using Redis storage");
            info!("Creating shared Redis client: {}", redis_url);
            Some(SharedRedisClient::new(redis_url)?)
        } else {
            None
        }
    };

    let mut filter_chain = FilterChain::new();

    if config.fingerprint.enabled {
        info!("Fingerprint detection enabled: user_agent checks, header analysis");
        let fingerprint_config = intellegen_http_defender::filter::FingerprintConfig::new(
            config.fingerprint.deny_threshold,
            config.fingerprint.challenge_threshold,
            config.fingerprint.user_agent_whitelist.clone(),
            config.fingerprint.user_agent_blacklist.clone(),
            config.fingerprint.strict_header_order,
            config.fingerprint.require_common_headers,
        );
        let filter = FingerprintFilter::new(fingerprint_config);
        filter_chain = filter_chain.add_filter(Arc::new(filter));
    }

    // Challenge-response filter and handler
    let challenge_handler = if config.challenge.enabled {
        info!(
            "Challenge-response enabled: difficulty={}, timeout={}s, session_duration={}s",
            config.challenge.difficulty,
            config.challenge.timeout_secs,
            config.challenge.session_duration_secs
        );

        let challenge_storage: Arc<dyn ChallengeStorage> = match config.challenge.storage {
            StorageType::Memory => {
                info!("Using in-memory challenge storage");
                Arc::new(InMemoryChallengeStorage::new())
            }
            #[cfg(feature = "redis-storage")]
            StorageType::Redis => {
                info!("Using Redis challenge storage (shared client)");
                Arc::new(RedisChallengeStorage::from_client(
                    shared_redis_client
                        .as_ref()
                        .expect("Shared Redis client should be initialized")
                        .clone(),
                ))
            }
        };

        let pow_config = ProofOfWorkConfig::new(
            config.challenge.difficulty,
            config.challenge.timeout_secs,
            config.challenge.session_duration_secs,
        );

        let filter = ProofOfWorkFilter::new(pow_config.clone(), challenge_storage.clone());
        filter_chain = filter_chain.add_filter(Arc::new(filter));

        let handler = ChallengeHandler::new(pow_config, challenge_storage);
        Some(handler)
    } else {
        None
    };

    if config.rate_limit.enabled {
        let rate_limit_config = RateLimitConfig::new(
            config.rate_limit.requests_per_second,
            config.rate_limit.burst_capacity,
        );

        let filter = match config.rate_limit.storage {
            StorageType::Memory => {
                info!("Using in-memory rate limiting storage");
                RateLimitFilter::with_in_memory(rate_limit_config)
            }
            #[cfg(feature = "redis-storage")]
            StorageType::Redis => {
                use intellegen_http_defender::filter::rate_limit::RedisStorage;
                info!("Using Redis rate limiting storage (shared client)");
                let storage = RedisStorage::from_client(
                    shared_redis_client
                        .as_ref()
                        .expect("Shared Redis client should be initialized")
                        .clone(),
                );
                RateLimitFilter::new(rate_limit_config, Arc::new(storage))
            }
        };

        filter_chain = filter_chain.add_filter(Arc::new(filter));
    }

    filter_chain = filter_chain.add_filter(Arc::new(PassthroughFilter));

    let proxy_config = ProxyClientConfig::new(config.proxy.upstream_url.clone())
        .with_timeout(config.proxy.timeout)
        .with_preserve_host(config.proxy.preserve_host);

    let proxy_client = ProxyClient::new(proxy_config)?;

    let connection_tracker = if config.slowloris.enabled {
        let tracker_config = ConnectionTrackerConfig::new(
            config.slowloris.max_connections_per_ip,
            config.slowloris.connection_rate_per_sec,
            config.slowloris.idle_timeout_secs,
        );

        match config.slowloris.storage {
            StorageType::Memory => {
                info!("Using in-memory connection tracking storage");
                ConnectionTracker::with_in_memory(tracker_config)
            }
            #[cfg(feature = "redis-storage")]
            StorageType::Redis => {
                use intellegen_http_defender::server::connection_tracker::RedisConnectionStorage;
                info!("Using Redis connection tracking storage (shared client)");
                let storage = RedisConnectionStorage::from_client(
                    shared_redis_client
                        .as_ref()
                        .expect("Shared Redis client should be initialized")
                        .clone(),
                );
                ConnectionTracker::new(tracker_config, Arc::new(storage))
            }
        }
    } else {
        info!("Slowloris protection disabled");
        ConnectionTracker::with_in_memory(ConnectionTrackerConfig::new(u32::MAX, 0, u64::MAX))
    };

    let server = Server::bind(
        addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        config.slowloris.clone(),
        challenge_handler,
    )
    .await?;

    info!("Server listening on {}", server.addr());

    server.run().await?;

    Ok(())
}
