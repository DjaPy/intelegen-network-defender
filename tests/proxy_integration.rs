//! Integration tests for proxy forwarding

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Response, StatusCode, body::Incoming};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use intellegen_http_defender::config::SlowlorisConfig;
use intellegen_http_defender::filter::{FilterChain, PassthroughFilter};
use intellegen_http_defender::proxy::{ProxyClient, ProxyConfig};
use intellegen_http_defender::server::{ConnectionTracker, ConnectionTrackerConfig, Server};

/// Helper function to create disabled Slowloris config for tests
fn disabled_slowloris_config() -> SlowlorisConfig {
    SlowlorisConfig {
        enabled: false,
        header_timeout_secs: 300,
        request_timeout_secs: 600,
        max_connections_per_ip: u32::MAX,
        connection_rate_per_sec: u32::MAX,
        idle_timeout_secs: u64::MAX,
        storage: intellegen_http_defender::config::StorageType::Memory,
        redis_url: None,
    }
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

#[tokio::test]
async fn test_proxy_forwards_to_backend() {
    let (backend_addr, backend_handle) = run_backend_server().await;

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

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

    let server_handle = tokio::spawn(async move { server.run().await });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let response = client
        .get(format!("http://{}/test", proxy_addr).parse().unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("X-Backend").unwrap(), "test-backend");

    use http_body_util::BodyExt;
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert_eq!(body_str, "Hello from backend");

    server_handle.abort();
    backend_handle.abort();
}

#[tokio::test]
async fn test_proxy_adds_forwarding_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let backend_handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };

            let io = TokioIo::new(stream);

            tokio::spawn(async move {
                let service = service_fn(|req: hyper::Request<Incoming>| async move {
                    let x_forwarded_for = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("missing");

                    let x_real_ip = req
                        .headers()
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("missing");

                    let body = format!(
                        "X-Forwarded-For: {}\nX-Real-IP: {}",
                        x_forwarded_for, x_real_ip
                    );

                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });

                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    // Create a disabled connection tracker for tests (high limits)
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

    let server_handle = tokio::spawn(async move { server.run().await });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let response = client
        .get(format!("http://{}/test", proxy_addr).parse().unwrap())
        .await
        .unwrap();

    use http_body_util::BodyExt;
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(body_str.contains("X-Forwarded-For: 127.0.0.1"));
    assert!(body_str.contains("X-Real-IP: 127.0.0.1"));

    server_handle.abort();
    backend_handle.abort();
}

#[tokio::test]
async fn test_proxy_returns_bad_gateway_on_backend_failure() {
    let proxy_config = ProxyConfig::new("http://localhost:9999".to_string());
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    // Create a disabled connection tracker for tests (high limits)
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

    let server_handle = tokio::spawn(async move { server.run().await });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let response = client
        .get(format!("http://{}/test", proxy_addr).parse().unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    server_handle.abort();
}
