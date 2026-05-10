//! Integration tests for the metrics server

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::StatusCode;
use hyper::body::Bytes;
use hyper_util::client::legacy::{Client, connect::HttpConnector};

use intellegen_http_defender::config::SlowlorisConfig;
use intellegen_http_defender::filter::{FilterChain, PassthroughFilter};
use intellegen_http_defender::metrics_server::MetricsServer;
use intellegen_http_defender::proxy::{ProxyClient, ProxyConfig};
use intellegen_http_defender::server::{ConnectionTracker, ConnectionTrackerConfig, Server};

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

fn http_client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(hyper_util::rt::TokioExecutor::new()).build_http()
}

#[tokio::test]
async fn test_metrics_endpoint_returns_prometheus_format() {
    let metrics_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let metrics_server = MetricsServer::bind(metrics_addr).await.unwrap();
    let metrics_addr = metrics_server.addr();
    tokio::spawn(async move { metrics_server.run().await });

    let client = http_client();
    let response = client
        .get(format!("http://{}/metrics", metrics_addr).parse().unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/plain"));

    let body = response.collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("# HELP"));
    assert!(body_str.contains("# TYPE"));
}

#[tokio::test]
async fn test_metrics_unknown_path_returns_404() {
    let metrics_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let metrics_server = MetricsServer::bind(metrics_addr).await.unwrap();
    let metrics_addr = metrics_server.addr();
    tokio::spawn(async move { metrics_server.run().await });

    let client = http_client();
    let response = client
        .get(format!("http://{}/unknown", metrics_addr).parse().unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_metrics_records_requests_after_proxy_traffic() {
    let proxy_config = ProxyConfig::new("http://localhost:19999".to_string());
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
    tokio::spawn(async move { server.run().await });

    // Start metrics server
    let metrics_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let metrics_server = MetricsServer::bind(metrics_addr).await.unwrap();
    let metrics_addr = metrics_server.addr();
    tokio::spawn(async move { metrics_server.run().await });

    let client = http_client();

    client
        .get(format!("http://{}/test", proxy_addr).parse().unwrap())
        .await
        .unwrap();

    let response = client
        .get(format!("http://{}/metrics", metrics_addr).parse().unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(body_str.contains("http_requests_total"));
    assert!(body_str.contains("filter_actions_total"));
    assert!(body_str.contains("upstream_failures_total"));
    assert!(body_str.contains("active_connections"));
}
