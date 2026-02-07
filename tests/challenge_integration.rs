use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::TcpListener;

use intellegen_http_defender::config::SlowlorisConfig;
use intellegen_http_defender::filter::challenge::{Challenge, ProofOfWorkConfig, ProofOfWorkFilter};
use intellegen_http_defender::filter::challenge_storage::{ChallengeStorage, InMemoryChallengeStorage};
use intellegen_http_defender::filter::{FilterChain, PassthroughFilter, RateLimitConfig, RateLimitFilter};
use intellegen_http_defender::proxy::{ProxyClient, ProxyConfig};
use intellegen_http_defender::server::{ChallengeHandler, ConnectionTracker, ConnectionTrackerConfig, Server};

/// Helper function to create disabled Slowloris config for tests
fn disabled_slowloris_config() -> SlowlorisConfig {
    SlowlorisConfig {
        enabled: false,
        header_timeout_secs: 300,
        request_timeout_secs: 600,
        max_connections_per_ip: u32::MAX,
        connection_rate_per_sec: u32::MAX,
        idle_timeout_secs: 3600,
        storage: intellegen_http_defender::config::StorageType::Memory,
        redis_url: None,
    }
}

/// Helper function to solve PoW challenge (brute force)
fn solve_challenge_sync(challenge: &Challenge) -> u64 {
    for nonce in 0..10_000_000 {
        if challenge.verify(nonce) {
            return nonce;
        }
    }
    panic!("Could not solve challenge within 10M attempts");
}

async fn run_backend_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };

            let io = TokioIo::new(stream);

            tokio::spawn(async move {
                let service = service_fn(|_req: hyper::Request<Incoming>| async {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("X-Backend", "test-backend")
                            .body(Full::new(Bytes::from("Hello from backend")))
                            .unwrap(),
                    )
                });

                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    (addr, handle)
}

/// Setup test server with challenge filter
/// Returns (proxy_addr, backend_handle)
async fn setup_test_server(
    pow_config: ProofOfWorkConfig,
    storage: Arc<dyn ChallengeStorage>,
    additional_filters: Vec<Arc<dyn intellegen_http_defender::filter::Filter>>,
    with_handler: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (backend_addr, backend_handle) = run_backend_server().await;

    let filter = ProofOfWorkFilter::new(pow_config.clone(), storage.clone());
    let mut filter_chain = FilterChain::new().add_filter(Arc::new(filter));

    for f in additional_filters {
        filter_chain = filter_chain.add_filter(f);
    }

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let tracker_config = ConnectionTrackerConfig::new(u32::MAX, 0, 3600);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let handler = if with_handler {
        Some(ChallengeHandler::new(pow_config, storage))
    } else {
        None
    };

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        disabled_slowloris_config(),
        handler,
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });

    (proxy_addr, backend_handle)
}

#[tokio::test]
async fn test_challenge_json_response_for_api() {
    let config = ProofOfWorkConfig::new(16, 300, 3600);
    let storage = Arc::new(InMemoryChallengeStorage::new());

    let (proxy_addr, backend_handle) = setup_test_server(config, storage, vec![], false).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Accept", "application/json")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["error"], "proof_of_work_required");
    assert!(json["challenge"].is_string());
    assert_eq!(json["difficulty"], 16);

    backend_handle.abort();
}

#[tokio::test]
async fn test_challenge_html_response_for_browser() {
    let config = ProofOfWorkConfig::new(16, 300, 3600);
    let storage = Arc::new(InMemoryChallengeStorage::new());

    let (proxy_addr, backend_handle) = setup_test_server(config, storage, vec![], false).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Accept", "text/html,application/xhtml+xml")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = response.collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&body);

    assert!(html.contains("<html"));
    assert!(html.contains("Verification Required"));
    assert!(html.contains("proof of work"));
    assert!(html.contains("script"));

    backend_handle.abort();
}

#[tokio::test]
async fn test_verify_challenge_success() {
    let config = ProofOfWorkConfig::new(12, 300, 3600);
    let storage = Arc::new(InMemoryChallengeStorage::new());

    let (proxy_addr, backend_handle) = setup_test_server(config, storage, vec![], true).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    // Get challenge
    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Accept", "application/json")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge_str = json["challenge"].as_str().unwrap();
    
    let challenge = Challenge::decode(challenge_str).unwrap();
    let nonce = solve_challenge_sync(&challenge);
    
    let verify_body = json!({
        "challenge": challenge_str,
        "nonce": nonce.to_string()
    });

    let req = hyper::Request::builder()
        .uri(format!("http://{}/verify-challenge", proxy_addr))
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(verify_body.to_string())))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);
    assert!(json["session_token"].is_string());

    backend_handle.abort();
}

#[tokio::test]
async fn test_verify_challenge_expired() {
    let config = ProofOfWorkConfig::new(12, 1, 3600); // 1 second timeout
    let storage = Arc::new(InMemoryChallengeStorage::new());

    let (proxy_addr, backend_handle) = setup_test_server(config, storage, vec![], true).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    
    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Accept", "application/json")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge_str = json["challenge"].as_str().unwrap();
    
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    let challenge = Challenge::decode(challenge_str).unwrap();
    let nonce = solve_challenge_sync(&challenge);
    
    let verify_body = json!({
        "challenge": challenge_str,
        "nonce": nonce.to_string()
    });

    let req = hyper::Request::builder()
        .uri(format!("http://{}/verify-challenge", proxy_addr))
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(verify_body.to_string())))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], false);
    assert!(json["error"].as_str().unwrap().contains("expired"));

    backend_handle.abort();
}

#[tokio::test]
async fn test_verify_challenge_invalid_nonce() {
    let config = ProofOfWorkConfig::new(12, 300, 3600);
    let storage = Arc::new(InMemoryChallengeStorage::new());

    let (proxy_addr, backend_handle) = setup_test_server(config, storage, vec![], true).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    
    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Accept", "application/json")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge_str = json["challenge"].as_str().unwrap();
    
    let verify_body = json!({
        "challenge": challenge_str,
        "nonce": "123456"
    });

    let req = hyper::Request::builder()
        .uri(format!("http://{}/verify-challenge", proxy_addr))
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(verify_body.to_string())))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], false);
    assert!(json["error"].as_str().unwrap().contains("proof of work"));

    backend_handle.abort();
}

#[tokio::test]
async fn test_session_cookie_allows_bypass() {
    let config = ProofOfWorkConfig::new(12, 300, 3600);
    let storage = Arc::new(InMemoryChallengeStorage::new());

    let (proxy_addr, backend_handle) = setup_test_server(config, storage, vec![], true).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    
    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Accept", "application/json")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge_str = json["challenge"].as_str().unwrap();

    let challenge = Challenge::decode(challenge_str).unwrap();
    let nonce = solve_challenge_sync(&challenge);
    
    let verify_body = json!({
        "challenge": challenge_str,
        "nonce": nonce.to_string()
    });

    let req = hyper::Request::builder()
        .uri(format!("http://{}/verify-challenge", proxy_addr))
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(verify_body.to_string())))
        .unwrap();

    let response = client.request(req).await.unwrap();
    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_token = json["session_token"].as_str().unwrap();
    
    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Cookie", format!("armor_session={}", session_token))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    backend_handle.abort();
}

#[tokio::test]
async fn test_verify_endpoint_protected_by_rate_limit() {
    let config = ProofOfWorkConfig::new(12, 300, 3600);
    let storage = Arc::new(InMemoryChallengeStorage::new());

    let rate_config = RateLimitConfig::new(10, 2);
    let rate_filter = RateLimitFilter::with_in_memory(rate_config);

    let (proxy_addr, backend_handle) =
        setup_test_server(config, storage, vec![Arc::new(rate_filter)], true).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    
    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Accept", "application/json")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge_str = json["challenge"].as_str().unwrap();

    let challenge = Challenge::decode(challenge_str).unwrap();
    let nonce = solve_challenge_sync(&challenge);

    let verify_body = json!({
        "challenge": challenge_str,
        "nonce": nonce.to_string()
    });
    
    for i in 0..5 {
        let req = hyper::Request::builder()
            .uri(format!("http://{}/verify-challenge", proxy_addr))
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(verify_body.to_string())))
            .unwrap();

        let response = client.request(req).await.unwrap();
        let status = response.status();

        if i < 2 {
            assert!(
                status == StatusCode::OK || status == StatusCode::FORBIDDEN,
                "Request {}: expected OK or FORBIDDEN, got {:?}",
                i,
                status
            );
        } else {
            assert_eq!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "Request {}: expected TOO_MANY_REQUESTS, got {:?}",
                i,
                status
            );
        }
    }

    backend_handle.abort();
}

#[tokio::test]
async fn test_challenge_disabled() {
    let (backend_addr, backend_handle) = run_backend_server().await;

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let tracker_config = ConnectionTrackerConfig::new(u32::MAX, 0, 3600);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        disabled_slowloris_config(),
        None,
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    backend_handle.abort();
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_redis_storage_integration() {
    use intellegen_http_defender::filter::challenge_storage::RedisChallengeStorage;
    use intellegen_http_defender::storage::SharedRedisClient;

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis_client = match SharedRedisClient::new(&redis_url) {
        Ok(client) => client,
        Err(_) => {
            eprintln!("Skipping Redis test - Redis not available");
            return;
        }
    };

    let config = ProofOfWorkConfig::new(12, 300, 3600);
    let storage = Arc::new(RedisChallengeStorage::from_client(redis_client));

    let (proxy_addr, backend_handle) = setup_test_server(config, storage, vec![], true).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    
    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Accept", "application/json")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge_str = json["challenge"].as_str().unwrap();

    let challenge = Challenge::decode(challenge_str).unwrap();
    let nonce = solve_challenge_sync(&challenge);
    
    let verify_body = json!({
        "challenge": challenge_str,
        "nonce": nonce.to_string()
    });

    let req = hyper::Request::builder()
        .uri(format!("http://{}/verify-challenge", proxy_addr))
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(verify_body.to_string())))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_token = json["session_token"].as_str().unwrap();

    let req = hyper::Request::builder()
        .uri(format!("http://{}/test", proxy_addr))
        .header("Cookie", format!("armor_session={}", session_token))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    backend_handle.abort();
}