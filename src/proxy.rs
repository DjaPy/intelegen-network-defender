//! Reverse proxy to upstream backend
//!
//! Handles request forwarding with:
//! - Connection pooling to backend
//! - Header rewriting (X-Forwarded-For, X-Real-IP, Host)
//! - Request/response streaming

use std::net::SocketAddr;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::{HeaderMap, Request, Response, Uri};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;

use crate::error::{ArmorError, Result};

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Upstream backend URL (e.g., "http://localhost:3000")
    pub upstream_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Preserve Host header from original request
    pub preserve_host: bool,
}

impl ProxyConfig {
    pub fn new(upstream_url: String) -> Self {
        Self {
            upstream_url,
            timeout: Duration::from_secs(30),
            preserve_host: false,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_preserve_host(mut self, preserve: bool) -> Self {
        self.preserve_host = preserve;
        self
    }
}

/// Reverse proxy client with connection pooling
pub struct ProxyClient {
    config: ProxyConfig,
    client: Client<HttpConnector, Incoming>,
    upstream_uri: Uri,
}

impl ProxyClient {
    pub fn new(config: ProxyConfig) -> Result<Self> {
        let upstream_uri: Uri = config
            .upstream_url
            .parse()
            .map_err(|e| ArmorError::Config(format!("Invalid upstream URL: {}", e)))?;

        let client = Client::builder(TokioExecutor::new()).build_http();

        Ok(Self {
            config,
            client,
            upstream_uri,
        })
    }

    pub async fn forward(
        &self,
        mut req: Request<Incoming>,
        client_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>> {
        let upstream_path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let upstream_uri = format!(
            "{}://{}{}",
            self.upstream_uri.scheme_str().unwrap_or("http"),
            self.upstream_uri
                .authority()
                .map(|a| a.as_str())
                .unwrap_or("localhost"),
            upstream_path
        );

        *req.uri_mut() = upstream_uri
            .parse()
            .map_err(|e| ArmorError::Upstream(format!("Failed to parse upstream URI: {}", e)))?;

        self.rewrite_headers(req.headers_mut(), client_addr);

        let response = tokio::time::timeout(self.config.timeout, self.client.request(req))
            .await
            .map_err(|_| ArmorError::Upstream("Upstream request timeout".to_string()))?
            .map_err(|e| ArmorError::Upstream(format!("Upstream request failed: {}", e)))?;

        let (parts, body) = response.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| ArmorError::Upstream(format!("Failed to read upstream response: {}", e)))?
            .to_bytes();

        let response = Response::from_parts(parts, Full::new(body_bytes));

        Ok(response)
    }

    /// Rewrite request headers for proxy
    fn rewrite_headers(&self, headers: &mut HeaderMap, client_addr: SocketAddr) {
        let client_ip = client_addr.ip().to_string();
        if let Some(existing) = headers.get("x-forwarded-for") {
            if let Ok(value) = existing.to_str() {
                let new_value = format!("{}, {}", value, client_ip);
                headers.insert("x-forwarded-for", new_value.parse().unwrap());
            }
        } else {
            headers.insert("x-forwarded-for", client_ip.parse().unwrap());
        }

        headers.insert("x-real-ip", client_addr.ip().to_string().parse().unwrap());

        if !self.config.preserve_host {
            if let Some(authority) = self.upstream_uri.authority() {
                headers.insert("host", authority.as_str().parse().unwrap());
            }
        }

        headers.remove("connection");
        headers.remove("keep-alive");
        headers.remove("proxy-authenticate");
        headers.remove("proxy-authorization");
        headers.remove("te");
        headers.remove("trailers");
        headers.remove("transfer-encoding");
        headers.remove("upgrade");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_config_builder() {
        let config = ProxyConfig::new("http://localhost:3000".to_string())
            .with_timeout(Duration::from_secs(10))
            .with_preserve_host(true);

        assert_eq!(config.upstream_url, "http://localhost:3000");
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert!(config.preserve_host);
    }

    #[test]
    fn test_proxy_client_creation() {
        let config = ProxyConfig::new("http://localhost:3000".to_string());
        let client = ProxyClient::new(config);

        assert!(client.is_ok());
    }

    #[test]
    fn test_proxy_client_invalid_url() {
        let config = ProxyConfig::new("not a url".to_string());
        let client = ProxyClient::new(config);

        assert!(client.is_err());
    }
}
