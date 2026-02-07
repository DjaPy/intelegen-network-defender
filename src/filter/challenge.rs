use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose;
use base64::Engine;
use hyper::body::Incoming;
use hyper::Request;
use rand::Rng;
use sha2::{Digest, Sha256};

use super::{ChallengeType, Filter, FilterAction};
use super::challenge_storage::ChallengeStorage;

#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: String,
    pub timestamp: u64,
    pub difficulty: u8,
    pub random_bytes: Vec<u8>,
}

impl Challenge {
    pub fn generate(difficulty: u8) -> Self {
        let mut rng = rand::thread_rng();
        let mut random_bytes = vec![0u8; 16];
        rng.fill(&mut random_bytes[..]);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let id = format!("{}-{}", timestamp, hex::encode(&random_bytes[..8]));

        Self {
            id,
            timestamp,
            difficulty,
            random_bytes,
        }
    }

    pub fn encode(&self) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.random_bytes);
        data.push(self.difficulty);

        general_purpose::STANDARD.encode(&data)
    }

    pub fn decode(encoded: &str) -> Result<Self, String> {
        let data = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("Invalid base64: {}", e))?;

        if data.len() < 9 {
            return Err("Invalid challenge data".to_string());
        }

        let timestamp = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let difficulty = *data.last().unwrap();
        let random_bytes = data[8..data.len() - 1].to_vec();

        let id = format!("{}-{}", timestamp, hex::encode(&random_bytes[..8.min(random_bytes.len())]));

        Ok(Self {
            id,
            timestamp,
            difficulty,
            random_bytes,
        })
    }

    pub fn is_expired(&self, timeout_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.timestamp > timeout_secs
    }

    pub fn verify(&self, nonce: u64) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.encode().as_bytes());
        hasher.update(&nonce.to_be_bytes());

        let result = hasher.finalize();
        count_leading_zero_bits(&result) >= self.difficulty as usize
    }
}

fn count_leading_zero_bits(hash: &[u8]) -> usize {
    let mut count = 0;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

#[derive(Debug, Clone)]
pub struct ProofOfWorkConfig {
    pub difficulty: u8,
    pub timeout_secs: u64,
    pub session_duration_secs: u64,
}

impl ProofOfWorkConfig {
    pub fn new(difficulty: u8, timeout_secs: u64, session_duration_secs: u64) -> Self {
        Self {
            difficulty,
            timeout_secs,
            session_duration_secs,
        }
    }
}

pub struct ProofOfWorkFilter {
    config: ProofOfWorkConfig,
    storage: Arc<dyn ChallengeStorage>,
}

impl ProofOfWorkFilter {
    pub fn new(config: ProofOfWorkConfig, storage: Arc<dyn ChallengeStorage>) -> Self {
        Self { config, storage }
    }

    pub fn with_in_memory(config: ProofOfWorkConfig) -> Self {
        use super::challenge_storage::InMemoryChallengeStorage;
        Self::new(config, Arc::new(InMemoryChallengeStorage::new()))
    }

    async fn has_valid_session(&self, req: &Request<Incoming>) -> bool {
        if let Some(cookie_header) = req.headers().get("cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if let Some(value) = cookie.strip_prefix("armor_session=") {
                        if let Ok(valid) = self.storage.verify_session(value).await {
                            if valid {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
}

#[async_trait::async_trait]
impl Filter for ProofOfWorkFilter {
    async fn filter(&self, req: &Request<Incoming>, _remote_addr: SocketAddr) -> FilterAction {
        if req.uri().path() == "/verify-challenge" {
            return FilterAction::Allow;
        }

        if self.has_valid_session(req).await {
            return FilterAction::Allow;
        }

        let challenge = Challenge::generate(self.config.difficulty);

        tracing::info!(
            challenge_id = %challenge.id,
            difficulty = challenge.difficulty,
            "Issuing PoW challenge"
        );

        FilterAction::Challenge {
            challenge_type: ChallengeType::ProofOfWork {
                challenge: challenge.encode(),
                difficulty: challenge.difficulty,
            },
        }
    }

    fn name(&self) -> &str {
        "proof_of_work"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_generation() {
        let challenge = Challenge::generate(20);
        assert_eq!(challenge.difficulty, 20);
        assert!(!challenge.is_expired(300));
    }

    #[test]
    fn test_challenge_encode_decode() {
        let challenge = Challenge::generate(20);
        let encoded = challenge.encode();
        let decoded = Challenge::decode(&encoded).unwrap();

        assert_eq!(challenge.timestamp, decoded.timestamp);
        assert_eq!(challenge.difficulty, decoded.difficulty);
        assert_eq!(challenge.random_bytes, decoded.random_bytes);
    }

    #[test]
    fn test_challenge_expiry() {
        let mut challenge = Challenge::generate(20);
        challenge.timestamp = 0;
        assert!(challenge.is_expired(300));
    }

    #[test]
    fn test_leading_zero_bits() {
        let hash = [0x00, 0x00, 0x80, 0xFF];
        assert_eq!(count_leading_zero_bits(&hash), 16);

        let hash2 = [0x00, 0x01, 0xFF];
        assert_eq!(count_leading_zero_bits(&hash2), 15);

        let hash3 = [0x00, 0x00, 0x00, 0x01];
        assert_eq!(count_leading_zero_bits(&hash3), 31);
    }

    #[test]
    fn test_pow_verification() {
        let challenge = Challenge {
            id: "test".to_string(),
            timestamp: 1234567890,
            difficulty: 8,
            random_bytes: vec![1, 2, 3, 4],
        };

        let mut nonce = 0u64;
        let mut found = false;

        for n in 0..1_000_000 {
            if challenge.verify(n) {
                nonce = n;
                found = true;
                break;
            }
        }

        assert!(found, "Should find valid nonce for difficulty 8");
        assert!(challenge.verify(nonce));
    }
}