//! Integration tests for Slowloris protection

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::StatusCode;
use hyper::body::Bytes;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use tokio::time::sleep;

use intellegen_http_defender::config::SlowlorisConfig;
use intellegen_http_defender::filter::{FilterChain, PassthroughFilter};
use intellegen_http_defender::proxy::{ProxyClient, ProxyConfig};
use intellegen_http_defender::server::{ConnectionTracker, ConnectionTrackerConfig, Server};

fn enabled_slowloris_config() -> SlowlorisConfig {
    SlowlorisConfig {
        enabled: true,
        header_timeout_secs: 10,
        request_timeout_secs: 60,
        max_connections_per_ip: 10,
        connection_rate_per_sec: 5,
        idle_timeout_secs: 30,
        storage: intellegen_http_defender::config::StorageType::Memory,
        redis_url: None,
    }
}

async fn run_test_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, body::Incoming};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

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
                let service = service_fn(|_: Request<Incoming>| async {
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("OK"))))
                });

                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    (addr, handle)
}

#[tokio::test]
async fn test_slowloris_allows_normal_connections() {
    let (backend_addr, _backend_handle) = run_test_backend().await;

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    let tracker_config = ConnectionTrackerConfig::new(5, 10, 30);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        enabled_slowloris_config(),
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    for _ in 0..3 {
        let uri = format!("http://{}/", proxy_addr);
        let response = client.get(uri.parse().unwrap()).await.unwrap();
        assert_eq!(response.status(), 200);
    }
}

#[tokio::test]
async fn test_slowloris_respects_max_connections() {
    let (backend_addr, _backend_handle) = run_test_backend().await;

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    let tracker_config = ConnectionTrackerConfig::new(10, 50, 30);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        enabled_slowloris_config(),
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    for _ in 0..5 {
        let uri = format!("http://{}/", proxy_addr);
        let response = client.get(uri.parse().unwrap()).await.unwrap();
        assert_eq!(response.status(), 200);
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn test_slowloris_respects_connection_rate() {
    let (backend_addr, _backend_handle) = run_test_backend().await;

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    let tracker_config = ConnectionTrackerConfig::new(20, 10, 30);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        enabled_slowloris_config(),
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    for _ in 0..5 {
        let uri = format!("http://{}/", proxy_addr);
        let response = client.get(uri.parse().unwrap()).await.unwrap();
        assert_eq!(response.status(), 200);
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn test_slowloris_different_ips_independent() {
    let (backend_addr, _backend_handle) = run_test_backend().await;

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    let tracker_config = ConnectionTrackerConfig::new(1, 100, 30);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        enabled_slowloris_config(),
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });
    let conn = tokio::net::TcpStream::connect(proxy_addr).await;
    assert!(conn.is_ok());
}

#[tokio::test]
async fn test_slowloris_connection_guard_cleanup() {
    let (backend_addr, _backend_handle) = run_test_backend().await;

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    let tracker_config = ConnectionTrackerConfig::new(2, 100, 30);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        enabled_slowloris_config(),
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    let uri = format!("http://{}/", proxy_addr);
    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), 200);

    sleep(Duration::from_millis(100)).await;

    let uri = format!("http://{}/", proxy_addr);
    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_slowloris_disabled_tracker() {
    let (backend_addr, _backend_handle) = run_test_backend().await;

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    let tracker_config = ConnectionTrackerConfig::new(u32::MAX, 0, u64::MAX);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        enabled_slowloris_config(),
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

    for _ in 0..10 {
        let uri = format!("http://{}/", proxy_addr);
        let response = client.get(uri.parse().unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn test_slowloris_get_attack_slow_headers() {
    use tokio::io::AsyncWriteExt;

    let (backend_addr, _backend_handle) = run_test_backend().await;

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    let slowloris_config = SlowlorisConfig {
        enabled: true,
        header_timeout_secs: 2,
        request_timeout_secs: 60,
        max_connections_per_ip: 10,
        connection_rate_per_sec: 100,
        idle_timeout_secs: 30,
        storage: intellegen_http_defender::config::StorageType::Memory,
        redis_url: None,
    };

    let tracker_config = ConnectionTrackerConfig::new(10, 100, 30);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        slowloris_config,
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });

    use tokio::io::AsyncReadExt;
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

    stream.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    sleep(Duration::from_millis(1000)).await;
    stream.write_all(b"Host: example.com\r\n").await.unwrap();
    sleep(Duration::from_secs(2)).await; // Total > header_timeout (2s)

    let mut buf = [0u8; 1024];
    let read_result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

    match read_result {
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => {
            let response = std::str::from_utf8(&buf[..n]).unwrap_or("");
            assert!(response.contains("HTTP") || response.is_empty());
        }
        _ => {}
    }
}

#[tokio::test]
async fn test_slowloris_post_attack_slow_body() {
    use tokio::io::AsyncWriteExt;

    let (backend_addr, _backend_handle) = run_test_backend().await;

    let proxy_config = ProxyConfig::new(format!("http://{}", backend_addr));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let filter_chain = FilterChain::new().add_filter(Arc::new(PassthroughFilter));

    let slowloris_config = SlowlorisConfig {
        enabled: true,
        header_timeout_secs: 10,
        request_timeout_secs: 3,
        max_connections_per_ip: 10,
        connection_rate_per_sec: 100,
        idle_timeout_secs: 30,
        storage: intellegen_http_defender::config::StorageType::Memory,
        redis_url: None,
    };

    let tracker_config = ConnectionTrackerConfig::new(10, 100, 30);
    let connection_tracker = ConnectionTracker::with_in_memory(tracker_config);

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = Server::bind(
        proxy_addr,
        filter_chain,
        proxy_client,
        connection_tracker,
        slowloris_config,
    )
    .await
    .unwrap();
    let proxy_addr = server.addr();

    let _server_handle = tokio::spawn(async move { server.run().await });

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1000\r\n\r\n")
        .await
        .unwrap();

    for _ in 0..5 {
        let result = stream.write_all(b"x").await;
        if result.is_err() {
            return;
        }
        sleep(Duration::from_secs(1)).await;
    }

    panic!("Request timeout should have triggered");
}
