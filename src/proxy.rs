//! Reverse proxy to upstream backend
//!
//! Handles request forwarding with:
//! - Connection pooling to backend
//! - Header rewriting (X-Forwarded-For, X-Real-IP, Host)
//! - Request/response streaming

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

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
    /// Circuit breaker protection against failing upstream
    pub circuit_breaker: CircuitBreakerConfig,
}

impl ProxyConfig {
    pub fn new(upstream_url: String) -> Self {
        Self {
            upstream_url,
            timeout: Duration::from_secs(30),
            preserve_host: false,
            circuit_breaker: CircuitBreakerConfig::default(),
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

    pub fn with_circuit_breaker(mut self, circuit_breaker: CircuitBreakerConfig) -> Self {
        self.circuit_breaker = circuit_breaker;
        self
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Enable or disable circuit breaker logic
    pub enabled: bool,
    /// Number of consecutive failures required to open breaker
    pub failure_threshold: u32,
    /// How long breaker stays open before entering half-open state
    pub open_timeout: Duration,
    /// Number of successful trial requests required in half-open to close breaker
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            failure_threshold: 5,
            open_timeout: Duration::from_secs(60),
            half_open_max_requests: 1,
        }
    }
}

#[derive(Debug, Clone)]
enum CircuitBreakerState {
    Closed { failures: u32 },
    Open { opened_at: Instant },
    HalfOpen { in_flight: u32, successes: u32 },
}

#[derive(Debug)]
struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: CircuitBreakerState,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: CircuitBreakerState::Closed { failures: 0 },
        }
    }

    fn allow_request(&mut self) -> bool {
        self.allow_request_at(Instant::now())
    }

    fn allow_request_at(&mut self, now: Instant) -> bool {
        if !self.config.enabled {
            return true;
        }

        match &mut self.state {
            CircuitBreakerState::Closed { .. } => true,
            CircuitBreakerState::Open { opened_at } => {
                if now.duration_since(*opened_at) < self.config.open_timeout {
                    return false;
                }

                self.state = CircuitBreakerState::HalfOpen {
                    in_flight: 1,
                    successes: 0,
                };
                true
            }
            CircuitBreakerState::HalfOpen { in_flight, .. } => {
                if *in_flight >= self.config.half_open_max_requests {
                    return false;
                }

                *in_flight += 1;
                true
            }
        }
    }

    fn on_success(&mut self) {
        if !self.config.enabled {
            return;
        }

        match &mut self.state {
            CircuitBreakerState::Closed { failures } => {
                *failures = 0;
            }
            CircuitBreakerState::Open { .. } => {}
            CircuitBreakerState::HalfOpen {
                in_flight,
                successes,
            } => {
                if *in_flight > 0 {
                    *in_flight -= 1;
                }
                *successes += 1;

                if *successes >= self.config.half_open_max_requests && *in_flight == 0 {
                    self.state = CircuitBreakerState::Closed { failures: 0 };
                }
            }
        }
    }

    fn on_failure(&mut self) {
        self.on_failure_at(Instant::now());
    }

    fn on_failure_at(&mut self, now: Instant) {
        if !self.config.enabled {
            return;
        }

        match &mut self.state {
            CircuitBreakerState::Closed { failures } => {
                *failures += 1;
                if *failures >= self.config.failure_threshold {
                    self.state = CircuitBreakerState::Open { opened_at: now };
                }
            }
            CircuitBreakerState::Open { .. } => {}
            CircuitBreakerState::HalfOpen { in_flight, .. } => {
                if *in_flight > 0 {
                    *in_flight -= 1;
                }
                self.state = CircuitBreakerState::Open { opened_at: now };
            }
        }
    }
}

/// Reverse proxy client with connection pooling
pub struct ProxyClient {
    config: ProxyConfig,
    client: Client<HttpConnector, Incoming>,
    upstream_uri: Uri,
    circuit_breaker: Option<Mutex<CircuitBreaker>>,
}

impl ProxyClient {
    pub fn new(config: ProxyConfig) -> Result<Self> {
        let upstream_uri: Uri = config
            .upstream_url
            .parse()
            .map_err(|e| ArmorError::Config(format!("Invalid upstream URL: {}", e)))?;

        let client = Client::builder(TokioExecutor::new()).build_http();

        Ok(Self {
            circuit_breaker: if config.circuit_breaker.enabled {
                Some(Mutex::new(CircuitBreaker::new(
                    config.circuit_breaker.clone(),
                )))
            } else {
                None
            },
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
        if let Some(breaker) = &self.circuit_breaker {
            let mut breaker = breaker.lock().expect("circuit breaker mutex poisoned");
            if !breaker.allow_request() {
                return Err(ArmorError::CircuitOpen);
            }
        }

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

        let response =
            match tokio::time::timeout(self.config.timeout, self.client.request(req)).await {
                Ok(Ok(response)) => response,
                Ok(Err(e)) => {
                    self.record_failure();
                    return Err(ArmorError::Upstream(format!(
                        "Upstream request failed: {}",
                        e
                    )));
                }
                Err(_) => {
                    self.record_failure();
                    return Err(ArmorError::Upstream("Upstream request timeout".to_string()));
                }
            };

        let status = response.status();
        let (parts, body) = response.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| {
                self.record_failure();
                ArmorError::Upstream(format!("Failed to read upstream response: {}", e))
            })?
            .to_bytes();

        if status.is_server_error() {
            self.record_failure();
        } else {
            self.record_success();
        }

        let response = Response::from_parts(parts, Full::new(body_bytes));

        Ok(response)
    }

    fn record_success(&self) {
        if let Some(breaker) = &self.circuit_breaker {
            let mut breaker = breaker.lock().expect("circuit breaker mutex poisoned");
            breaker.on_success();
        }
    }

    fn record_failure(&self) {
        if let Some(breaker) = &self.circuit_breaker {
            let mut breaker = breaker.lock().expect("circuit breaker mutex poisoned");
            breaker.on_failure();
        }
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

        #[allow(clippy::collapsible_if)]
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
        assert!(!config.circuit_breaker.enabled);
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

    #[test]
    fn test_circuit_breaker_opens_after_failure_threshold() {
        let config = CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 3,
            open_timeout: Duration::from_secs(60),
            half_open_max_requests: 1,
        };

        let mut breaker = CircuitBreaker::new(config);
        let now = Instant::now();

        assert!(breaker.allow_request_at(now));
        breaker.on_failure_at(now);
        assert!(breaker.allow_request_at(now));
        breaker.on_failure_at(now);
        assert!(breaker.allow_request_at(now));
        breaker.on_failure_at(now);

        assert!(!breaker.allow_request_at(now + Duration::from_secs(1)));
    }

    #[test]
    fn test_circuit_breaker_half_open_success_closes() {
        let config = CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            open_timeout: Duration::from_secs(10),
            half_open_max_requests: 1,
        };

        let mut breaker = CircuitBreaker::new(config);
        let now = Instant::now();

        assert!(breaker.allow_request_at(now));
        breaker.on_failure_at(now);

        assert!(!breaker.allow_request_at(now + Duration::from_secs(1)));
        assert!(breaker.allow_request_at(now + Duration::from_secs(11)));
        breaker.on_success();

        assert!(breaker.allow_request_at(now + Duration::from_secs(12)));
    }

    #[test]
    fn test_circuit_breaker_half_open_failure_reopens() {
        let config = CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            open_timeout: Duration::from_secs(10),
            half_open_max_requests: 1,
        };

        let mut breaker = CircuitBreaker::new(config);
        let now = Instant::now();

        assert!(breaker.allow_request_at(now));
        breaker.on_failure_at(now);

        assert!(breaker.allow_request_at(now + Duration::from_secs(11)));
        breaker.on_failure_at(now + Duration::from_secs(11));

        assert!(!breaker.allow_request_at(now + Duration::from_secs(12)));
        assert!(breaker.allow_request_at(now + Duration::from_secs(22)));
    }
}
