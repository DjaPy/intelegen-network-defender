//! Internal metrics server on a separate port
//!
//! Serves Prometheus metrics at GET /metrics.
//! Binds on 127.0.0.1 by default — not exposed to the internet.

use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::error::{ArmorError, Result};
use crate::metrics::gather_text;

pub struct MetricsServer {
    listener: TcpListener,
    addr: SocketAddr,
}

impl MetricsServer {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ArmorError::Bind { addr, source: e })?;

        let actual_addr = listener
            .local_addr()
            .map_err(|e| ArmorError::Config(format!("Failed to get local address: {}", e)))?;

        info!(%actual_addr, "Metrics server bound");

        Ok(Self {
            listener,
            addr: actual_addr,
        })
    }

    pub async fn run(self) {
        loop {
            let (stream, remote_addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!(%e, "Metrics server: failed to accept connection");
                    continue;
                }
            };

            let io = TokioIo::new(stream);

            tokio::spawn(async move {
                let service = service_fn(move |req| async move {
                    Ok::<_, hyper::Error>(handle_metrics_request(req, remote_addr))
                });

                if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                    error!(%remote_addr, %e, "Metrics connection error");
                }
            });
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

fn handle_metrics_request(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
) -> Response<Full<Bytes>> {
    if req.uri().path() == "/metrics" && *req.method() == Method::GET {
        info!(%remote_addr, "Metrics scraped");
        let (body, content_type) = gather_text();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", content_type)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }
}
