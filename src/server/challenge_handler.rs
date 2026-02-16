use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;

use crate::filter::challenge::{Challenge, ProofOfWorkConfig};
use crate::filter::challenge_storage::ChallengeStorage;

#[derive(Deserialize)]
struct VerifyRequest {
    challenge: String,
    nonce: String,
}

pub struct ChallengeHandler {
    config: ProofOfWorkConfig,
    storage: Arc<dyn ChallengeStorage>,
}

impl ChallengeHandler {
    pub fn new(config: ProofOfWorkConfig, storage: Arc<dyn ChallengeStorage>) -> Self {
        Self { config, storage }
    }

    pub async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Limit body to 1KB to prevent DoS attacks
        const MAX_BODY_SIZE: usize = 1024;
        let limited_body = Limited::new(req.into_body(), MAX_BODY_SIZE);

        let whole_body = match limited_body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return Ok(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body too large (max 1KB)",
                ));
            }
        };

        let verify_req: VerifyRequest = match serde_json::from_slice(&whole_body) {
            Ok(req) => req,
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid JSON: {}", e),
                ));
            }
        };

        let challenge = match Challenge::decode(&verify_req.challenge) {
            Ok(c) => c,
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid challenge: {}", e),
                ));
            }
        };

        if challenge.is_expired(self.config.timeout_secs) {
            return Ok(error_response(StatusCode::BAD_REQUEST, "Challenge expired"));
        }

        let nonce = match verify_req.nonce.parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                return Ok(error_response(StatusCode::BAD_REQUEST, "Invalid nonce"));
            }
        };

        let challenge_clone = challenge.clone();
        let is_valid =
            match tokio::task::spawn_blocking(move || challenge_clone.verify(nonce)).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(error = %e, "PoW verification task panicked");
                    return Ok(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Verification failed",
                    ));
                }
            };

        if !is_valid {
            return Ok(error_response(
                StatusCode::FORBIDDEN,
                "Invalid proof of work",
            ));
        }

        let session_token = generate_session_token();
        let ip = remote_addr.ip().to_string();

        if let Err(e) = self
            .storage
            .mark_completed(&session_token, &ip, self.config.session_duration_secs)
            .await
        {
            tracing::error!(error = %e, "Failed to store session");
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create session",
            ));
        }

        tracing::info!(
            remote = %remote_addr,
            challenge_id = %challenge.id,
            "Challenge solved successfully"
        );

        let response_body = serde_json::json!({
            "success": true,
            "session_token": session_token
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header(
                "Set-Cookie",
                format!(
                    "armor_session={}; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
                    session_token, self.config.session_duration_secs
                ),
            )
            .body(Full::new(Bytes::from(response_body.to_string())))
            .unwrap())
    }
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "success": false,
        "error": message
    });

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn generate_session_token() -> String {
    use base64::Engine;
    use base64::engine::general_purpose;
    use rand::RngCore;

    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; 32];
    rng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}
