//! TCP server with connection handling
//!
//! Responsibilities:
//! - Accept TCP connections
//! - HTTP/1.1 parsing via hyper
//! - Spawn per-connection tasks
//! - Filter chain execution
//! - Graceful shutdown support

pub mod challenge_handler;
pub mod connection_tracker;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::metrics::METRICS;

use crate::config::SlowlorisConfig;
use crate::error::{ArmorError, Result};
use crate::filter::{FilterAction, FilterChain};
use crate::proxy::ProxyClient;
pub use challenge_handler::ChallengeHandler;
pub use connection_tracker::{ConnectionGuard, ConnectionTracker, ConnectionTrackerConfig};

/// Main server struct with integrated filter chain and proxy
pub struct Server {
    listener: TcpListener,
    addr: SocketAddr,
    filter_chain: Arc<FilterChain>,
    proxy_client: Arc<ProxyClient>,
    connection_tracker: Arc<ConnectionTracker>,
    slowloris_config: SlowlorisConfig,
    challenge_handler: Option<Arc<ChallengeHandler>>,
    #[cfg(feature = "tls")]
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
}

impl Server {
    pub async fn bind(
        addr: SocketAddr,
        filter_chain: FilterChain,
        proxy_client: ProxyClient,
        connection_tracker: ConnectionTracker,
        slowloris_config: SlowlorisConfig,
        challenge_handler: Option<ChallengeHandler>,
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
            challenge_handler: challenge_handler.map(Arc::new),
            #[cfg(feature = "tls")]
            tls_acceptor: None,
        })
    }

    /// Enable TLS termination with JA3/JA4 fingerprinting.
    #[cfg(feature = "tls")]
    pub fn with_tls(mut self, acceptor: tokio_rustls::TlsAcceptor) -> Self {
        self.tls_acceptor = Some(Arc::new(acceptor));
        self
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

            METRICS.active_connections.inc();

            let filter_chain = self.filter_chain.clone();
            let proxy_client = self.proxy_client.clone();
            let tracker = self.connection_tracker.clone();
            let challenge_handler = self.challenge_handler.clone();
            let header_timeout = Duration::from_secs(self.slowloris_config.header_timeout_secs);
            let request_timeout = Duration::from_secs(self.slowloris_config.request_timeout_secs);

            // TLS detection via peek — does not consume bytes from the stream.
            #[cfg(feature = "tls")]
            if let Some(ref tls_acceptor) = self.tls_acceptor {
                let mut first = [0u8; 1];
                if stream.peek(&mut first).await.is_ok() && first[0] == 0x16 {
                    let tls_fp = extract_tls_fingerprint(&stream).await;
                    let acceptor = tls_acceptor.clone();

                    // Extra clones for the TLS spawn — originals drop at `continue`
                    let fc = filter_chain.clone();
                    let pc = proxy_client.clone();
                    let tr = tracker.clone();
                    let ch = challenge_handler.clone();

                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let io = TokioIo::new(tls_stream);
                                let service = service_fn(move |mut req: Request<Incoming>| {
                                    let fp = tls_fp.clone();
                                    let fc2 = fc.clone();
                                    let pc2 = pc.clone();
                                    let ch2 = ch.clone();
                                    let tr2 = tr.clone();
                                    async move {
                                        tr2.update_activity(ip).await;
                                        if let Some(fingerprint) = fp {
                                            req.extensions_mut().insert(fingerprint);
                                        }
                                        handle_request(req, remote_addr, fc2, pc2, ch2).await
                                    }
                                });

                                let conn = http1::Builder::new()
                                    .timer(TokioTimer::new())
                                    .header_read_timeout(header_timeout)
                                    .serve_connection(io, service);

                                match tokio::time::timeout(request_timeout, conn).await {
                                    Ok(Ok(())) => {}
                                    Ok(Err(e)) => {
                                        warn!(%remote_addr, %e, "TLS connection error");
                                    }
                                    Err(_) => {
                                        warn!(%remote_addr, "TLS request timeout");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(%remote_addr, %e, "TLS handshake failed");
                            }
                        }
                        drop(guard);
                        METRICS.active_connections.dec();
                    });
                    continue; // skip plain HTTP spawn
                }
            }

            // Plain HTTP connection
            let io = TokioIo::new(stream);

            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let tracker_clone = tracker.clone();
                    let filter_chain_clone = filter_chain.clone();
                    let proxy_client_clone = proxy_client.clone();
                    let challenge_handler_clone = challenge_handler.clone();
                    async move {
                        tracker_clone.update_activity(ip).await;
                        handle_request(
                            req,
                            remote_addr,
                            filter_chain_clone,
                            proxy_client_clone,
                            challenge_handler_clone,
                        )
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
                METRICS.active_connections.dec();
            });
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Peek at a TCP stream and extract a TLS fingerprint from the ClientHello.
/// Uses `peek()` so rustls receives the full record for the handshake.
#[cfg(feature = "tls")]
async fn extract_tls_fingerprint(
    stream: &tokio::net::TcpStream,
) -> Option<std::sync::Arc<crate::tls::TlsFingerprint>> {
    let mut buf = vec![0u8; 8192];
    match stream.peek(&mut buf).await {
        Ok(n) if n > 0 => crate::tls::parse_clienthello(&buf[..n])
            .map(|info| std::sync::Arc::new(crate::tls::TlsFingerprint::compute(&info))),
        _ => None,
    }
}

/// Handle a single HTTP request with filter chain and proxy
///
/// Flow:
/// 1. Execute filter chain
/// 2. If Allow and /verify-challenge: handle challenge verification
/// 3. If Allow and other path: forward to upstream backend via proxy
/// 4. If Deny/Challenge: return filter chain response
async fn handle_request(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    filter_chain: Arc<FilterChain>,
    proxy_client: Arc<ProxyClient>,
    challenge_handler: Option<Arc<ChallengeHandler>>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    info!(%remote_addr, %method, %uri, "Request received");

    let start = Instant::now();
    let method_str = method.as_str().to_string();

    let is_verify_endpoint = uri.path() == "/verify-challenge" && method == Method::POST;
    let headers = req.headers().clone();
    let action = filter_chain.execute(&req, remote_addr).await;

    METRICS
        .filter_actions_total
        .with_label_values(&[match &action {
            FilterAction::Allow => "allow",
            FilterAction::Deny { .. } => "deny",
            FilterAction::Challenge { .. } => "challenge",
        }])
        .inc();

    let response = match action {
        FilterAction::Allow => {
            if is_verify_endpoint {
                if let Some(handler) = challenge_handler {
                    info!(%remote_addr, "Handling challenge verification");
                    match handler.handle(req, remote_addr).await {
                        Ok(response) => response,
                        Err(e) => {
                            error!(%remote_addr, error = %e, "Challenge handler failed");
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .header("Content-Type", "text/plain")
                                .body(Full::new(Bytes::from("Internal Server Error")))
                                .unwrap()
                        }
                    }
                } else {
                    warn!(%remote_addr, "Challenge endpoint accessed but handler not configured");
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header("Content-Type", "text/plain")
                        .body(Full::new(Bytes::from("Not Found")))
                        .unwrap()
                }
            } else {
                info!(%remote_addr, "Request allowed, forwarding to upstream");

                match proxy_client.forward(req, remote_addr).await {
                    Ok(response) => response,
                    Err(e) => {
                        error!(%remote_addr, error = %e, "Proxy forward failed");
                        if matches!(e, ArmorError::CircuitOpen) {
                            METRICS.circuit_breaker_open_total.inc();
                        } else {
                            METRICS.upstream_failures_total.inc();
                        }
                        let (status, body) = if matches!(e, ArmorError::CircuitOpen) {
                            (StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
                        } else {
                            (StatusCode::BAD_GATEWAY, "Bad Gateway")
                        };

                        Response::builder()
                            .status(status)
                            .header("Content-Type", "text/plain")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap()
                    }
                }
            }
        }
        other => filter_chain.action_to_response(other, &headers),
    };

    let status_str = response.status().as_str().to_string();
    METRICS
        .http_requests_total
        .with_label_values(&[&method_str, &status_str])
        .inc();
    METRICS
        .http_request_duration_seconds
        .with_label_values(&[&method_str])
        .observe(start.elapsed().as_secs_f64());

    Ok(response)
}
