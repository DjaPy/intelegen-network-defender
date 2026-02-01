//! Rust Armor L7 - Entry point

use std::net::SocketAddr;
use std::sync::Arc;

use intellegen_http_defender::server::Server;
use intellegen_http_defender::filter::{FilterChain, PassthroughFilter};
use intellegen_http_defender::proxy::{ProxyClient, ProxyConfig};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    // TODO: Load from config file
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    // Build filter chain
    // TODO: Configure filters from config file
    let filter_chain = FilterChain::new()
        .add_filter(Arc::new(PassthroughFilter));

    // Create proxy client
    // TODO: Load upstream URL from config
    let proxy_config = ProxyConfig::new("http://localhost:3000".to_string());
    let proxy_client = ProxyClient::new(proxy_config)?;

    let server = Server::bind(addr, filter_chain, proxy_client).await?;
    server.run().await?;

    Ok(())
}