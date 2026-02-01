//! Rust Armor L7 - Entry point

use std::net::SocketAddr;
use std::sync::Arc;

use intellegen_http_defender::config::{Config, StorageType};
use intellegen_http_defender::server::Server;
use intellegen_http_defender::filter::{FilterChain, PassthroughFilter, RateLimitFilter, FingerprintFilter};
use intellegen_http_defender::filter::RateLimitConfig;
use intellegen_http_defender::proxy::{ProxyClient, ProxyConfig as ProxyClientConfig};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

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
    info!("Fingerprinting: enabled={}, deny_threshold={}, challenge_threshold={}",
          config.fingerprint.enabled,
          config.fingerprint.deny_threshold,
          config.fingerprint.challenge_threshold);
    info!("Rate limiting: enabled={}, rps={}, burst={}",
          config.rate_limit.enabled,
          config.rate_limit.requests_per_second,
          config.rate_limit.burst_capacity);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| format!("Invalid server address: {}", e))?;

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
                let redis_url = config.rate_limit.redis_url
                    .as_ref()
                    .expect("Redis URL required for Redis storage");
                info!("Using Redis rate limiting storage: {}", redis_url);
                let storage = RedisStorage::new(redis_url)?;
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
    let server = Server::bind(addr, filter_chain, proxy_client).await?;

    info!("Server listening on {}", server.addr());

    server.run().await?;

    Ok(())
}