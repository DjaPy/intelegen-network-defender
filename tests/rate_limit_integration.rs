//! Integration tests for rate limiting filter

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use intellegen_http_defender::filter::{
    FilterAction, FilterChain, RateLimitConfig, RateLimitFilter,
};

async fn run_test_server(chain: Arc<FilterChain>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };

            let io = TokioIo::new(stream);
            let chain = chain.clone();

            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let chain = chain.clone();
                    async move { handle_request(req, chain, remote_addr).await }
                });

                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    (addr, handle)
}

async fn handle_request(
    req: Request<Incoming>,
    chain: Arc<FilterChain>,
    remote_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let action = chain.execute(&req, remote_addr).await;

    let response = match action {
        FilterAction::Allow => Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("OK")))
            .unwrap(),
        other => chain.action_to_response(other),
    };

    Ok(response)
}

#[tokio::test]
async fn test_rate_limit_allows_within_limit() {
    let filter = RateLimitFilter::with_in_memory(RateLimitConfig::new(100, 10));

    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    let uri = format!("http://{}/test", addr);

    // First request - should be allowed
    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    server_handle.abort();
}

#[tokio::test]
async fn test_rate_limit_blocks_exceeding_limit() {
    // Very restrictive: 1 req/s, burst=1
    let filter = RateLimitFilter::with_in_memory(RateLimitConfig::new(1, 1));

    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    let uri = format!("http://{}/test", addr);

    // First request - allowed
    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Immediate second request - should be rate limited
    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key("retry-after"));

    server_handle.abort();
}

#[tokio::test]
async fn test_rate_limit_allows_burst() {
    // 10 req/s with burst capacity of 5
    let filter = RateLimitFilter::with_in_memory(RateLimitConfig::new(10, 5));

    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    let uri = format!("http://{}/test", addr);

    // All 5 burst requests should succeed immediately
    for i in 0..5 {
        let response = client.get(uri.parse().unwrap()).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Request {} should be allowed",
            i + 1
        );
    }

    // 6th request should be rate limited
    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    server_handle.abort();
}

#[tokio::test]
async fn test_rate_limit_recovers_after_delay() {
    // 10 req/s, burst=1 (100ms emission interval)
    let filter = RateLimitFilter::with_in_memory(RateLimitConfig::new(10, 1));

    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    let uri = format!("http://{}/test", addr);

    // First request - allowed
    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Immediate second - blocked
    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Wait for emission interval (100ms + buffer)
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Third request after delay - should be allowed again
    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    server_handle.abort();
}

#[tokio::test]
async fn test_rate_limit_shared_across_servers() {
    // Test that shared FilterChain correctly limits same client across multiple servers
    let filter = RateLimitFilter::with_in_memory(RateLimitConfig::new(1, 1));

    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr1, server_handle1) = run_test_server(chain.clone()).await;
    let (addr2, server_handle2) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let response = client
        .get(format!("http://{}/test", addr1).parse().unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = client
        .get(format!("http://{}/test", addr2).parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Shared FilterChain should limit same client across servers"
    );

    server_handle1.abort();
    server_handle2.abort();
}
