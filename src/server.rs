//! TCP server with connection handling
//!
//! Responsibilities:
//! - Accept TCP connections
//! - HTTP/1.1 parsing via hyper
//! - Spawn per-connection tasks
//! - Filter chain execution
//! - Graceful shutdown support

pub mod connection_tracker;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::config::SlowlorisConfig;
use crate::error::{ArmorError, Result};
use crate::filter::{FilterAction, FilterChain};
use crate::proxy::ProxyClient;
pub use connection_tracker::{ConnectionGuard, ConnectionTracker, ConnectionTrackerConfig};

/// Main server struct with integrated filter chain and proxy
pub struct Server {
    listener: TcpListener,
    addr: SocketAddr,
    filter_chain: Arc<FilterChain>,
    proxy_client: Arc<ProxyClient>,
    connection_tracker: Arc<ConnectionTracker>,
    slowloris_config: SlowlorisConfig,
}

impl Server {
    pub async fn bind(
        addr: SocketAddr,
        filter_chain: FilterChain,
        proxy_client: ProxyClient,
        connection_tracker: ConnectionTracker,
        slowloris_config: SlowlorisConfig,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ArmorError::Bind { addr, source: e })?;

        let actual_addr = listener
            .local_addr()
            .map_err(|e| ArmorError::Config(format!("Failed to get local address: {}", e)))?;

        info!(%actual_addr, "Server bound successfully");

        Ok(Self {
            listener,
            addr: actual_addr,
            filter_chain: Arc::new(filter_chain),
            proxy_client: Arc::new(proxy_client),
            connection_tracker: Arc::new(connection_tracker),
            slowloris_config,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!(addr = %self.addr, "Starting server");

        // Spawn periodic cleanup task
        let cleanup_tracker = self.connection_tracker.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let cleaned = cleanup_tracker.cleanup_idle().await;
                if cleaned > 0 {
                    info!(count = cleaned, "Cleaned up idle connections");
                }
            }
        });

        loop {
            let (stream, remote_addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!(%e, "Failed to accept connection");
                    continue;
                }
            };

            let ip = remote_addr.ip();
            if !self.connection_tracker.check_connection(ip).await {
                warn!(%remote_addr, "Connection denied: Slowloris protection triggered");
                drop(stream);
                continue;
            }

            let guard = match self.connection_tracker.register(ip).await {
                Some(guard) => guard,
                None => {
                    warn!(%remote_addr, "Connection registration failed");
                    drop(stream);
                    continue;
                }
            };

            let io = TokioIo::new(stream);
            let filter_chain = self.filter_chain.clone();
            let proxy_client = self.proxy_client.clone();
            let tracker = self.connection_tracker.clone();
            let header_timeout = Duration::from_secs(self.slowloris_config.header_timeout_secs);
            let request_timeout = Duration::from_secs(self.slowloris_config.request_timeout_secs);

            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let tracker_clone = tracker.clone();
                    let filter_chain_clone = filter_chain.clone();
                    let proxy_client_clone = proxy_client.clone();
                    async move {
                        tracker_clone.update_activity(ip).await;
                        handle_request(req, remote_addr, filter_chain_clone, proxy_client_clone)
                            .await
                    }
                });

                let conn = http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(header_timeout)
                    .serve_connection(io, service);

                let result = tokio::time::timeout(request_timeout, conn).await;

                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!(%remote_addr, %e, "Connection error");
                    }
                    Err(_) => {
                        warn!(%remote_addr, "Request timeout exceeded (Slowloris protection)");
                    }
                }

                drop(guard);
            });
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Handle a single HTTP request with filter chain and proxy
///
/// Flow:
/// 1. Execute filter chain
/// 2. If Allow: forward to upstream backend via proxy
/// 3. If Deny/Challenge: return filter chain response
async fn handle_request(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    filter_chain: Arc<FilterChain>,
    proxy_client: Arc<ProxyClient>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method();
    let uri = req.uri();

    info!(%remote_addr, %method, %uri, "Request received");

    // Execute filter chain
    let action = filter_chain.execute(&req, remote_addr).await;

    let response = match action {
        FilterAction::Allow => {
            info!(%remote_addr, "Request allowed, forwarding to upstream");

            match proxy_client.forward(req, remote_addr).await {
                Ok(response) => response,
                Err(e) => {
                    error!(%remote_addr, error = %e, "Proxy forward failed");
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .header("Content-Type", "text/plain")
                        .body(Full::new(Bytes::from("Bad Gateway")))
                        .unwrap()
                }
            }
        }
        other => filter_chain.action_to_response(other),
    };

    Ok(response)
}
