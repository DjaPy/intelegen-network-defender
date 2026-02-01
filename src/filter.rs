//! Filter chain for request inspection
//!
//! Provides async trait-based filtering with composable filter chain.
//! Filters can Allow, Deny, or Challenge requests based on inspection.

pub mod rate_limit;
pub mod fingerprint;

pub use rate_limit::{RateLimitFilter, RateLimitConfig};
pub use fingerprint::{FingerprintFilter, FingerprintConfig};

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::{Request, Response, StatusCode};
use hyper::body::Incoming;
use http_body_util::Full;
use hyper::body::Bytes;

/// Action to take after filter inspection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAction {
    /// Allow request to proceed
    Allow,
    /// Deny request with HTTP status and reason
    Deny { status: u16, reason: String },
    /// Challenge client (e.g., CAPTCHA, proof-of-work)
    Challenge { challenge_type: ChallengeType },
}

/// Type of challenge to present to client
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeType {
    /// HTTP 429 with Retry-After header
    RateLimit { retry_after: u32 },
    /// Custom challenge (future: CAPTCHA, PoW)
    Custom(String),
}

impl fmt::Display for FilterAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterAction::Allow => write!(f, "Allow"),
            FilterAction::Deny { status, reason } => {
                write!(f, "Deny(status={}, reason={})", status, reason)
            }
            FilterAction::Challenge { challenge_type } => {
                write!(f, "Challenge({:?})", challenge_type)
            }
        }
    }
}

/// Trait for request filters
///
/// Filters inspect incoming requests and return actions.
/// They are async and can perform I/O (e.g., database lookups).
#[async_trait::async_trait]
pub trait Filter: Send + Sync {
    /// Inspect request and return action
    ///
    /// Note: Takes &Request to allow inspection without consuming body
    async fn filter(
        &self,
        req: &Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> FilterAction;

    /// Filter name for logging
    fn name(&self) -> &str;
}

/// Chain of filters executed sequentially
///
/// First non-Allow action short-circuits the chain.
pub struct FilterChain {
    filters: Vec<Arc<dyn Filter>>,
}

impl FilterChain {
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }
    
    pub fn add_filter(mut self, filter: Arc<dyn Filter>) -> Self {
        self.filters.push(filter);
        self
    }
    
    pub async fn execute(
        &self,
        req: &Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> FilterAction {
        for filter in &self.filters {
            let action = filter.filter(req, remote_addr).await;
            if action != FilterAction::Allow {
                tracing::info!(
                    filter = filter.name(),
                    action = %action,
                    "Filter blocked request"
                );
                return action;
            }
        }
        FilterAction::Allow
    }
    
    pub fn action_to_response(&self, action: FilterAction) -> Response<Full<Bytes>> {
        match action {
            FilterAction::Allow => {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from("OK")))
                    .unwrap()
            }
            FilterAction::Deny { status, reason } => {
                let status_code = StatusCode::from_u16(status)
                    .unwrap_or(StatusCode::FORBIDDEN);
                Response::builder()
                    .status(status_code)
                    .header("Content-Type", "text/plain")
                    .body(Full::new(Bytes::from(reason)))
                    .unwrap()
            }
            FilterAction::Challenge {
                challenge_type: ChallengeType::RateLimit { retry_after },
            } => Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Retry-After", retry_after.to_string())
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from("Rate limit exceeded")))
                .unwrap(),
            FilterAction::Challenge {
                challenge_type: ChallengeType::Custom(msg),
            } => Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from(msg)))
                .unwrap(),
        }
    }
}

impl Default for FilterChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Passthrough filter that allows all requests (for testing)
pub struct PassthroughFilter;

#[async_trait::async_trait]
impl Filter for PassthroughFilter {
    async fn filter(
        &self,
        _req: &Request<Incoming>,
        _remote_addr: SocketAddr,
    ) -> FilterAction {
        FilterAction::Allow
    }

    fn name(&self) -> &str {
        "passthrough"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_action_display() {
        assert_eq!(FilterAction::Allow.to_string(), "Allow");

        let deny = FilterAction::Deny {
            status: 403,
            reason: "Forbidden".to_string(),
        };
        assert_eq!(deny.to_string(), "Deny(status=403, reason=Forbidden)");
    }

    #[test]
    fn test_action_to_response_deny() {
        let chain = FilterChain::new();
        let action = FilterAction::Deny {
            status: 403,
            reason: "Access denied".to_string(),
        };

        let response = chain.action_to_response(action);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_action_to_response_rate_limit() {
        let chain = FilterChain::new();
        let action = FilterAction::Challenge {
            challenge_type: ChallengeType::RateLimit { retry_after: 30 },
        };

        let response = chain.action_to_response(action);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get("Retry-After").unwrap(), "30");
    }

    #[test]
    fn test_filter_chain_builder() {
        let chain = FilterChain::new()
            .add_filter(Arc::new(PassthroughFilter))
            .add_filter(Arc::new(PassthroughFilter));

        assert_eq!(chain.filters.len(), 2);
    }
}