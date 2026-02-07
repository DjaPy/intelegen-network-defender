//! Filter chain for request inspection
//!
//! Provides async trait-based filtering with composable filter chain.
//! Filters can Allow, Deny, or Challenge requests based on inspection.

pub mod challenge;
pub mod challenge_storage;
pub mod fingerprint;
pub mod rate_limit;

pub use challenge::{Challenge, ProofOfWorkConfig, ProofOfWorkFilter};
pub use challenge_storage::{ChallengeStorage, InMemoryChallengeStorage};
pub use fingerprint::{FingerprintConfig, FingerprintFilter};
pub use rate_limit::{RateLimitConfig, RateLimitFilter};

#[cfg(feature = "redis-storage")]
pub use challenge_storage::RedisChallengeStorage;

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::header::HeaderMap;
use hyper::{Request, Response, StatusCode};

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
    /// Proof-of-Work challenge
    ProofOfWork {
        challenge: String,
        difficulty: u8,
    },
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
    async fn filter(&self, req: &Request<Incoming>, remote_addr: SocketAddr) -> FilterAction;

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

    pub async fn execute(&self, req: &Request<Incoming>, remote_addr: SocketAddr) -> FilterAction {
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

    pub fn action_to_response(&self, action: FilterAction, headers: &HeaderMap) -> Response<Full<Bytes>> {
        match action {
            FilterAction::Allow => Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from("OK")))
                .unwrap(),
            FilterAction::Deny { status, reason } => {
                let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
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
            FilterAction::Challenge {
                challenge_type: ChallengeType::ProofOfWork { challenge, difficulty },
            } => {
                let accept_html = headers
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.contains("text/html"))
                    .unwrap_or(false);

                if accept_html {
                    let html = generate_challenge_html(&challenge, difficulty);
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("Content-Type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(html)))
                        .unwrap()
                } else {
                    let json = serde_json::json!({
                        "error": "proof_of_work_required",
                        "challenge": challenge,
                        "difficulty": difficulty,
                        "verify_url": "/verify-challenge",
                        "timeout_secs": 300
                    });
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(json.to_string())))
                        .unwrap()
                }
            }
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
    async fn filter(&self, _req: &Request<Incoming>, _remote_addr: SocketAddr) -> FilterAction {
        FilterAction::Allow
    }

    fn name(&self) -> &str {
        "passthrough"
    }
}

fn generate_challenge_html(challenge: &str, difficulty: u8) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verification Required</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }}
        .progress {{ width: 100%; height: 20px; background: #f0f0f0; border-radius: 10px; margin: 20px 0; }}
        .progress-bar {{ height: 100%; background: #4CAF50; border-radius: 10px; width: 0%; transition: width 0.3s; }}
        #status {{ color: #666; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>Verification Required</h1>
    <p>Please wait while we verify your browser...</p>
    <div class="progress"><div id="progress" class="progress-bar"></div></div>
    <p id="status">Computing proof of work...</p>

    <script>
        const challenge = "{challenge}";
        const difficulty = {difficulty};

        async function solveChallenge() {{
            const encoder = new TextEncoder();
            let nonce = 0;
            const startTime = Date.now();

            while (true) {{
                const data = encoder.encode(challenge + nonce.toString());
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                const hashArray = new Uint8Array(hashBuffer);

                let leadingZeros = 0;
                for (let byte of hashArray) {{
                    if (byte === 0) {{
                        leadingZeros += 8;
                    }} else {{
                        leadingZeros += Math.clz32(byte) - 24;
                        break;
                    }}
                }}

                if (leadingZeros >= difficulty) {{
                    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
                    document.getElementById('status').textContent = `Solved in ${{elapsed}}s! Redirecting...`;
                    await submitSolution(nonce);
                    return;
                }}

                nonce++;

                if (nonce % 10000 === 0) {{
                    const progress = Math.min(100, (nonce / Math.pow(2, difficulty)) * 100);
                    document.getElementById('progress').style.width = progress + '%';
                    await new Promise(resolve => setTimeout(resolve, 0));
                }}
            }}
        }}

        async function submitSolution(nonce) {{
            try {{
                const response = await fetch('/verify-challenge', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ challenge, nonce: nonce.toString() }})
                }});

                if (response.ok) {{
                    window.location.reload();
                }} else {{
                    document.getElementById('status').textContent = 'Verification failed. Please refresh.';
                }}
            }} catch (e) {{
                document.getElementById('status').textContent = 'Error: ' + e.message;
            }}
        }}

        solveChallenge();
    </script>
</body>
</html>"#,
        challenge = challenge,
        difficulty = difficulty
    )
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

        let headers = HeaderMap::new();
        let response = chain.action_to_response(action, &headers);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_action_to_response_rate_limit() {
        let chain = FilterChain::new();
        let action = FilterAction::Challenge {
            challenge_type: ChallengeType::RateLimit { retry_after: 30 },
        };

        let headers = HeaderMap::new();
        let response = chain.action_to_response(action, &headers);
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
