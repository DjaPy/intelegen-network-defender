//! TCP server with connection handling
//!
//! Responsibilities:
//! - Accept TCP connections
//! - HTTP/1.1 parsing via hyper
//! - Spawn per-connection tasks
//! - Filter chain execution
//! - Graceful shutdown support

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use tokio::net::TcpListener;
use tracing::{info, warn, error};

use crate::error::{ArmorError, Result};
use crate::filter::{FilterChain, FilterAction};
use crate::proxy::ProxyClient;

/// Main server struct with integrated filter chain and proxy
pub struct Server {
    listener: TcpListener,
    addr: SocketAddr,
    filter_chain: Arc<FilterChain>,
    proxy_client: Arc<ProxyClient>,
}

impl Server {
    pub async fn bind(
        addr: SocketAddr,
        filter_chain: FilterChain,
        proxy_client: ProxyClient,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ArmorError::Bind { addr, source: e })?;

        let actual_addr = listener.local_addr()
            .map_err(|e| ArmorError::Config(format!("Failed to get local address: {}", e)))?;

        info!(%actual_addr, "Server bound successfully");

        Ok(Self {
            listener,
            addr: actual_addr,
            filter_chain: Arc::new(filter_chain),
            proxy_client: Arc::new(proxy_client),
        })
    }

    pub async fn run(self) -> Result<()> {
        info!(addr = %self.addr, "Starting server");

        loop {
            let (stream, remote_addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!(%e, "Failed to accept connection");
                    continue;
                }
            };

            let io = TokioIo::new(stream);
            let filter_chain = self.filter_chain.clone();
            let proxy_client = self.proxy_client.clone();

            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    handle_request(req, remote_addr, filter_chain.clone(), proxy_client.clone())
                });
                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    warn!(%remote_addr, %e, "Connection error");
                }
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
        other => {
            // Deny or Challenge - return filter response
            filter_chain.action_to_response(other)
        }
    };

    Ok(response)
}