//! Fingerprinting filter for bot detection and request analysis
//!
//! Analyzes HTTP requests using multiple factors:
//! - User-Agent patterns (bot signatures, suspicious strings)
//! - HTTP header order (browser fingerprinting)
//! - Header presence/absence (missing expected headers)
//!
//! Implements a scoring system (0-100) with configurable thresholds:
//! - Score >= deny_threshold: Deny request (403)
//! - Score >= challenge_threshold: Challenge request
//! - Score < challenge_threshold: Allow request

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{HeaderMap, Request};

use crate::filter::{ChallengeType, Filter, FilterAction};

/// Configuration for fingerprinting filter
#[derive(Debug, Clone)]
pub struct FingerprintConfig {
    pub deny_threshold: u32,
    pub challenge_threshold: u32,
    pub user_agent_whitelist: Vec<String>,
    pub user_agent_blacklist: Vec<String>,
    pub strict_header_order: bool,
    pub require_common_headers: bool,
}

impl FingerprintConfig {
    pub fn new(
        deny_threshold: u32,
        challenge_threshold: u32,
        user_agent_whitelist: Vec<String>,
        user_agent_blacklist: Vec<String>,
        strict_header_order: bool,
        require_common_headers: bool,
    ) -> Self {
        Self {
            deny_threshold,
            challenge_threshold,
            user_agent_whitelist,
            user_agent_blacklist,
            strict_header_order,
            require_common_headers,
        }
    }
}

/// Bot signature pattern with score contribution
#[derive(Debug, Clone)]
struct BotSignature {
    pattern: &'static str,
    score: u32,
}

/// User-Agent pattern database
struct UserAgentPatterns {
    bot_signatures: Vec<BotSignature>,
}

impl UserAgentPatterns {
    fn new() -> Self {
        Self {
            bot_signatures: vec![
                BotSignature {
                    pattern: "bot",
                    score: 30,
                },
                BotSignature {
                    pattern: "spider",
                    score: 30,
                },
                BotSignature {
                    pattern: "crawler",
                    score: 30,
                },
                BotSignature {
                    pattern: "curl",
                    score: 40,
                },
                BotSignature {
                    pattern: "wget",
                    score: 40,
                },
                BotSignature {
                    pattern: "python-requests",
                    score: 40,
                },
                BotSignature {
                    pattern: "httpclient",
                    score: 35,
                },
                BotSignature {
                    pattern: "scanner",
                    score: 45,
                },
                BotSignature {
                    pattern: "nikto",
                    score: 50,
                },
                BotSignature {
                    pattern: "sqlmap",
                    score: 50,
                },
                BotSignature {
                    pattern: "masscan",
                    score: 50,
                },
            ],
        }
    }
}

/// Known browser header patterns for fingerprinting
struct HeaderPatterns {
    known_browsers: HashMap<&'static str, Vec<&'static str>>,
}

impl HeaderPatterns {
    fn new() -> Self {
        let mut known_browsers = HashMap::new();

        known_browsers.insert(
            "chrome",
            vec![
                "host",
                "connection",
                "upgrade-insecure-requests",
                "user-agent",
                "accept",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-dest",
                "accept-encoding",
                "accept-language",
            ],
        );

        known_browsers.insert(
            "firefox",
            vec![
                "host",
                "user-agent",
                "accept",
                "accept-language",
                "accept-encoding",
                "connection",
                "upgrade-insecure-requests",
            ],
        );

        Self { known_browsers }
    }
}

/// Scoring result with breakdown
#[derive(Debug)]
struct FingerprintScore {
    total: u32,
    user_agent_score: u32,
    header_order_score: u32,
    header_missing_score: u32,
    reasons: Vec<String>,
}

/// Fingerprinting filter
pub struct FingerprintFilter {
    config: FingerprintConfig,
    user_agent_patterns: Arc<UserAgentPatterns>,
    header_patterns: Arc<HeaderPatterns>,
}

impl FingerprintFilter {
    pub fn new(config: FingerprintConfig) -> Self {
        Self {
            config,
            user_agent_patterns: Arc::new(UserAgentPatterns::new()),
            header_patterns: Arc::new(HeaderPatterns::new()),
        }
    }

    /// Score User-Agent header (0-50 points)
    fn score_user_agent(&self, user_agent: &str) -> (u32, Vec<String>) {
        let mut score = 0;
        let mut reasons = Vec::new();

        let ua_lower = user_agent.to_lowercase();

        if self
            .config
            .user_agent_whitelist
            .iter()
            .any(|pattern| ua_lower.contains(pattern))
        {
            return (0, vec!["User-Agent whitelisted".to_string()]);
        }

        if self
            .config
            .user_agent_blacklist
            .iter()
            .any(|pattern| ua_lower.contains(pattern))
        {
            return (50, vec!["User-Agent blacklisted".to_string()]);
        }

        for signature in &self.user_agent_patterns.bot_signatures {
            if ua_lower.contains(signature.pattern) {
                score += signature.score;
                reasons.push(format!(
                    "Suspicious User-Agent pattern: {}",
                    signature.pattern
                ));
            }
        }

        if user_agent.is_empty() {
            score += 20;
            reasons.push("Missing User-Agent header".to_string());
        } else {
            if user_agent.len() < 10 {
                score += 15;
                reasons.push("Unusually short User-Agent".to_string());
            }

            if user_agent.len() > 500 {
                score += 10;
                reasons.push("Unusually long User-Agent".to_string());
            }
        }

        (score.min(50), reasons)
    }

    /// Score header order based on known browser patterns (0-30 points)
    fn score_header_order(&self, headers: &HeaderMap) -> (u32, Vec<String>) {
        let mut score = 0;
        let mut reasons = Vec::new();

        let header_names: Vec<String> = headers
            .iter()
            .map(|(name, _)| name.as_str().to_lowercase())
            .collect();

        let mut best_similarity = 0.0;
        for (browser_name, pattern) in &self.header_patterns.known_browsers {
            let similarity = calculate_jaccard_similarity(&header_names, pattern);
            if similarity > best_similarity {
                best_similarity = similarity;
                tracing::debug!(
                    browser = browser_name,
                    similarity = similarity,
                    "Header pattern match"
                );
            }
        }

        if self.config.strict_header_order {
            if best_similarity < 0.3 {
                score += 30;
                reasons.push("Header order doesn't match any known browser".to_string());
            } else if best_similarity < 0.6 {
                score += 15;
                reasons.push("Header order partially matches browser patterns".to_string());
            }
        } else if best_similarity < 0.2 {
            score += 20;
            reasons.push("Header order highly unusual".to_string());
        }

        (score, reasons)
    }

    /// Score missing common headers (0-20 points)
    fn score_header_presence(&self, headers: &HeaderMap) -> (u32, Vec<String>) {
        let mut score = 0;
        let mut reasons = Vec::new();

        if !self.config.require_common_headers {
            return (0, reasons);
        }

        let expected_headers = [
            ("user-agent", 10),
            ("accept", 5),
            ("accept-encoding", 3),
            ("accept-language", 2),
        ];

        for (header, penalty) in &expected_headers {
            if !headers.contains_key(*header) {
                score += penalty;
                reasons.push(format!("Missing expected header: {}", header));
            }
        }

        (score.min(20), reasons)
    }

    /// Calculate total fingerprint score
    async fn calculate_score(&self, req: &Request<Incoming>) -> FingerprintScore {
        let headers = req.headers();

        let user_agent = headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        let (user_agent_score, mut reasons) = self.score_user_agent(user_agent);
        let (header_order_score, mut order_reasons) = self.score_header_order(headers);
        let (header_missing_score, mut missing_reasons) = self.score_header_presence(headers);

        reasons.append(&mut order_reasons);
        reasons.append(&mut missing_reasons);

        let total = user_agent_score + header_order_score + header_missing_score;

        FingerprintScore {
            total: total.min(100),
            user_agent_score,
            header_order_score,
            header_missing_score,
            reasons,
        }
    }
}

/// Calculate Jaccard similarity coefficient between two sets
fn calculate_jaccard_similarity(a: &[String], b: &[&str]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let set_a: HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let set_b: HashSet<&str> = b.iter().copied().collect();

    let union = set_a.union(&set_b).count();

    if union == 0 {
        return 0.0;
    }
    let intersection = set_a.intersection(&set_b).count();
    intersection as f32 / union as f32
}

#[async_trait::async_trait]
impl Filter for FingerprintFilter {
    async fn filter(&self, req: &Request<Incoming>, remote_addr: SocketAddr) -> FilterAction {
        let score = self.calculate_score(req).await;

        tracing::debug!(
            score = score.total,
            user_agent = score.user_agent_score,
            header_order = score.header_order_score,
            header_missing = score.header_missing_score,
            remote = %remote_addr,
            "Fingerprint analysis"
        );

        if score.total >= self.config.deny_threshold {
            tracing::warn!(
                score = score.total,
                remote = %remote_addr,
                reasons = ?score.reasons,
                "Request denied by fingerprinting"
            );

            FilterAction::Deny {
                status: 403,
                reason: format!(
                    "Request fingerprint score too high ({}). Reasons: {}",
                    score.total,
                    score.reasons.join(", ")
                ),
            }
        } else if score.total >= self.config.challenge_threshold {
            tracing::info!(
                score = score.total,
                remote = %remote_addr,
                reasons = ?score.reasons,
                "Request challenged by fingerprinting"
            );

            FilterAction::Challenge {
                challenge_type: ChallengeType::Custom(format!(
                    "Suspicious request pattern detected (score: {})",
                    score.total
                )),
            }
        } else {
            FilterAction::Allow
        }
    }

    fn name(&self) -> &str {
        "fingerprint"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jaccard_similarity() {
        let a = vec!["host".to_string(), "user-agent".to_string()];
        let b = vec!["host", "user-agent", "accept"];

        let similarity = calculate_jaccard_similarity(&a, &b);
        assert!((similarity - 0.666).abs() < 0.01); // 2/3 = 0.666...
    }

    #[test]
    fn test_jaccard_similarity_empty() {
        let a: Vec<String> = vec![];
        let b: Vec<&str> = vec![];

        let similarity = calculate_jaccard_similarity(&a, &b);
        assert_eq!(similarity, 0.0);
    }

    #[test]
    fn test_jaccard_similarity_no_overlap() {
        let a = vec!["foo".to_string()];
        let b = vec!["bar"];

        let similarity = calculate_jaccard_similarity(&a, &b);
        assert_eq!(similarity, 0.0);
    }

    #[test]
    fn test_user_agent_whitelist() {
        let config =
            FingerprintConfig::new(85, 70, vec!["googlebot".to_string()], vec![], false, true);
        let filter = FingerprintFilter::new(config);

        let (score, _) = filter.score_user_agent("Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert_eq!(score, 0);
    }

    #[test]
    fn test_user_agent_blacklist() {
        let config = FingerprintConfig::new(85, 70, vec![], vec!["curl".to_string()], false, true);
        let filter = FingerprintFilter::new(config);

        let (score, _) = filter.score_user_agent("curl/7.64.1");
        assert_eq!(score, 50);
    }

    #[test]
    fn test_user_agent_bot_signature() {
        let config = FingerprintConfig::new(85, 70, vec![], vec![], false, true);
        let filter = FingerprintFilter::new(config);

        let (score, reasons) = filter.score_user_agent("BadBot/1.0");
        assert!(score >= 30); // Should match "bot" pattern
        assert!(!reasons.is_empty());
    }

    #[test]
    fn test_user_agent_empty() {
        let config = FingerprintConfig::new(85, 70, vec![], vec![], false, true);
        let filter = FingerprintFilter::new(config);

        let (score, reasons) = filter.score_user_agent("");
        assert_eq!(score, 20);
        assert!(reasons.contains(&"Missing User-Agent header".to_string()));
    }

    #[test]
    fn test_user_agent_short() {
        let config = FingerprintConfig::new(85, 70, vec![], vec![], false, true);
        let filter = FingerprintFilter::new(config);

        let (score, reasons) = filter.score_user_agent("abc");
        assert!(score >= 15);
        assert!(reasons.contains(&"Unusually short User-Agent".to_string()));
    }

    #[test]
    fn test_user_agent_long() {
        let config = FingerprintConfig::new(85, 70, vec![], vec![], false, true);
        let filter = FingerprintFilter::new(config);

        let long_ua = "a".repeat(600);
        let (score, reasons) = filter.score_user_agent(&long_ua);
        assert!(score >= 10);
        assert!(reasons.contains(&"Unusually long User-Agent".to_string()));
    }

    #[test]
    fn test_user_agent_score_capped() {
        let config = FingerprintConfig::new(85, 70, vec![], vec!["bot".to_string()], false, true);
        let filter = FingerprintFilter::new(config);

        // Blacklist gives 50, should cap at 50 even if other patterns match
        let (score, _) = filter.score_user_agent("bot curl scanner");
        assert_eq!(score, 50);
    }

    #[test]
    fn test_header_missing_score() {
        let config = FingerprintConfig::new(85, 70, vec![], vec![], false, true);
        let filter = FingerprintFilter::new(config);

        let headers = HeaderMap::new();
        let (score, reasons) = filter.score_header_presence(&headers);

        // Should penalize for missing user-agent (10), accept (5), accept-encoding (3), accept-language (2)
        assert_eq!(score, 20); // 10 + 5 + 3 + 2 = 20
        assert_eq!(reasons.len(), 4);
    }

    #[test]
    fn test_header_missing_score_disabled() {
        let config = FingerprintConfig::new(85, 70, vec![], vec![], false, false);
        let filter = FingerprintFilter::new(config);

        let headers = HeaderMap::new();
        let (score, reasons) = filter.score_header_presence(&headers);

        assert_eq!(score, 0);
        assert!(reasons.is_empty());
    }
}
