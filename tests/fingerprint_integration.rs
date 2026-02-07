use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use intellegen_http_defender::filter::{
    FilterAction, FilterChain, FingerprintConfig, FingerprintFilter, RateLimitConfig,
    RateLimitFilter,
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
    let headers = req.headers().clone();
    let action = chain.execute(&req, remote_addr).await;

    let response = match action {
        FilterAction::Allow => Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("OK")))
            .unwrap(),
        other => chain.action_to_response(other, &headers),
    };

    Ok(response)
}

#[tokio::test]
async fn test_fingerprint_allows_normal_browser() {
    let config = FingerprintConfig::new(
        85, // deny_threshold
        70, // challenge_threshold
        vec![],
        vec![],
        false,
        true,
    );
    let filter = FingerprintFilter::new(config);
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/test", addr))
        .header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "gzip, deflate")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    server_handle.abort();
}

#[tokio::test]
async fn test_fingerprint_denies_curl() {
    let config = FingerprintConfig::new(
        50, // Lower deny threshold for testing
        40, // Lower challenge threshold for testing
        vec![],
        vec![],
        false,
        true,
    );
    let filter = FingerprintFilter::new(config);
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/test", addr))
        .header("User-Agent", "curl/7.64.1")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    server_handle.abort();
}

#[tokio::test]
async fn test_fingerprint_denies_wget() {
    let config = FingerprintConfig::new(
        50, // Lower deny threshold for testing
        40, // Lower challenge threshold for testing
        vec![],
        vec![],
        false,
        true,
    );
    let filter = FingerprintFilter::new(config);
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/test", addr))
        .header("User-Agent", "Wget/1.20.3")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    server_handle.abort();
}

#[tokio::test]
async fn test_fingerprint_challenges_suspicious() {
    let config = FingerprintConfig::new(
        50, // deny_threshold (lower for testing)
        25, // challenge_threshold (lowered to trigger challenge)
        vec![],
        vec![],
        false,
        true,
    );
    let filter = FingerprintFilter::new(config);
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/test", addr))
        .header("User-Agent", "MyCustomBot/1.0")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    server_handle.abort();
}

#[tokio::test]
async fn test_fingerprint_respects_whitelist() {
    let config = FingerprintConfig::new(
        85,
        70,
        vec!["googlebot".to_string()], // whitelist
        vec![],
        false,
        true,
    );
    let filter = FingerprintFilter::new(config);
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/test", addr))
        .header(
            "User-Agent",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        )
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    server_handle.abort();
}

#[tokio::test]
async fn test_fingerprint_blacklist_override() {
    let config = FingerprintConfig::new(
        50, // Lower deny threshold for testing
        40,
        vec![],
        vec!["badbot".to_string()], // blacklist
        false,
        true,
    );
    let filter = FingerprintFilter::new(config);
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/test", addr))
        .header("User-Agent", "Mozilla/5.0 (BadBot crawler)")
        .header("Accept", "text/html")
        .header("Accept-Language", "en-US")
        .header("Accept-Encoding", "gzip")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    server_handle.abort();
}

#[tokio::test]
async fn test_fingerprint_missing_headers() {
    let config = FingerprintConfig::new(
        15, // Very low deny threshold to trigger on missing headers
        10,
        vec![],
        vec![],
        false,
        true, // require_common_headers
    );
    let filter = FingerprintFilter::new(config);
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/test", addr))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    server_handle.abort();
}

#[tokio::test]
async fn test_fingerprint_combined_with_rate_limit() {
    let fingerprint_config = FingerprintConfig::new(
        50, // Lower deny threshold for testing
        40,
        vec![],
        vec![],
        false,
        true,
    );
    let fingerprint_filter = FingerprintFilter::new(fingerprint_config);

    let rate_limit_config = RateLimitConfig::new(10, 5);
    let rate_limit_filter = RateLimitFilter::with_in_memory(rate_limit_config);

    let chain = Arc::new(
        FilterChain::new()
            .add_filter(Arc::new(fingerprint_filter))
            .add_filter(Arc::new(rate_limit_filter)),
    );

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/test", addr))
        .header("User-Agent", "curl/7.64.1")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    for _ in 0..5 {
        let req = Request::builder()
            .uri(format!("http://{}/test", addr))
            .header("User-Agent", "Mozilla/5.0 (Chrome)")
            .header("Accept", "text/html")
            .header("Accept-Language", "en-US")
            .header("Accept-Encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let response = client.request(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_fingerprint_disabled() {
    let config = FingerprintConfig::new(
        100, // Maximum threshold (nothing gets denied)
        100,
        vec![],
        vec![],
        false,
        true,
    );
    let filter = FingerprintFilter::new(config);
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/test", addr))
        .header("User-Agent", "curl/7.64.1")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    server_handle.abort();
}

#[tokio::test]
async fn test_fingerprint_scanner_detection() {
    let config = FingerprintConfig::new(
        50, // Lower deny threshold for testing
        40,
        vec![],
        vec![],
        false,
        true,
    );
    let filter = FingerprintFilter::new(config);
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(filter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let scanners = vec!["Nikto/2.1.6", "sqlmap/1.0", "masscan/1.0"];

    for scanner in scanners {
        let req = Request::builder()
            .uri(format!("http://{}/test", addr))
            .header("User-Agent", scanner)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let response = client.request(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Scanner {} should be denied",
            scanner
        );
    }

    server_handle.abort();
}
