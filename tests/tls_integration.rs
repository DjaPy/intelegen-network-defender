#![cfg(feature = "tls")]

use std::net::SocketAddr;
use std::sync::Arc;

use intellegen_http_defender::filter::{FilterChain, FingerprintConfig};
use intellegen_http_defender::proxy::{ProxyClient, ProxyConfig as ProxyClientConfig};
use intellegen_http_defender::server::{ConnectionTracker, ConnectionTrackerConfig, Server};
use intellegen_http_defender::tls::{TlsFingerprint, build_acceptor, parse_clienthello};
use rustls::pki_types::ServerName;

fn generate_test_certs() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    (
        dir,
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

async fn start_backend() -> SocketAddr {
    use hyper::service::service_fn;
    use hyper::{Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(|_req| async {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(http_body_util::Full::new(bytes::Bytes::from("OK")))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    addr
}

async fn start_proxy(cert_path: &str, key_path: &str, backend: SocketAddr) -> SocketAddr {
    let filter_chain = FilterChain::new().add_filter(Arc::new(
        intellegen_http_defender::filter::PassthroughFilter,
    ));

    let proxy_config = ProxyClientConfig::new(format!("http://{}", backend));
    let proxy_client = ProxyClient::new(proxy_config).unwrap();

    let tracker =
        ConnectionTracker::with_in_memory(ConnectionTrackerConfig::new(u32::MAX, 0, u64::MAX));
    let slowloris = intellegen_http_defender::config::SlowlorisConfig {
        enabled: false,
        header_timeout_secs: 30,
        request_timeout_secs: 60,
        max_connections_per_ip: 100,
        connection_rate_per_sec: 100,
        idle_timeout_secs: 300,
        storage: intellegen_http_defender::config::StorageType::Memory,
        redis_url: None,
    };

    let server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        filter_chain,
        proxy_client,
        tracker,
        slowloris,
        None,
    )
    .await
    .unwrap();

    let acceptor = build_acceptor(cert_path, key_path).unwrap();
    let server = server.with_tls(acceptor);
    let addr = server.addr();

    tokio::spawn(async move { server.run().await });

    addr
}

fn make_test_client_config(cert_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let cert = rustls::pki_types::CertificateDer::from(cert_der.to_vec());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert).unwrap();

    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

#[test]
fn test_parse_returns_none_for_non_tls() {
    let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert!(parse_clienthello(http).is_none());
}

#[test]
fn test_parse_returns_none_for_truncated() {
    assert!(parse_clienthello(&[0x16, 0x03, 0x01, 0x00, 0x10]).is_none());
}

#[test]
fn test_tls_fingerprint_compute_is_deterministic() {
    use intellegen_http_defender::tls::fingerprint::ClientHelloInfo;

    let info = ClientHelloInfo {
        client_version: 0x0303,
        cipher_suites: vec![0xC02B, 0xC02F, 0xC00A],
        extension_types: vec![0x0000, 0x000A, 0x000B, 0x0017],
        supported_groups: vec![0x001D, 0x0017],
        ec_point_formats: vec![0x00],
        alpn_first: Some("h2".to_string()),
        sni: Some("example.com".to_string()),
    };

    let fp1 = TlsFingerprint::compute(&info);
    let fp2 = TlsFingerprint::compute(&info);

    assert_eq!(fp1.ja3, fp2.ja3);
    assert_eq!(fp1.ja3_string, fp2.ja3_string);
    assert_eq!(fp1.ja4, fp2.ja4);
    assert_eq!(fp1.sni, Some("example.com".to_string()));
}

#[test]
fn test_ja3_excludes_grease() {
    use intellegen_http_defender::tls::fingerprint::ClientHelloInfo;

    let info = ClientHelloInfo {
        client_version: 0x0303,
        cipher_suites: vec![0x0A0A, 0xC02B, 0xFAFA],
        extension_types: vec![0x0A0A, 0x0017],
        supported_groups: vec![0x0A0A, 0x001D],
        ec_point_formats: vec![0x00],
        alpn_first: None,
        sni: None,
    };

    let fp = TlsFingerprint::compute(&info);
    assert!(
        !fp.ja3_string.contains("2570"),
        "GREASE 0x0A0A should not appear"
    );
    assert!(
        !fp.ja3_string.contains("64250"),
        "GREASE 0xFAFA should not appear"
    );
    assert!(fp.ja3_string.contains("49195"), "0xC02B should appear");
}

#[test]
fn test_ja3_format_parts() {
    use intellegen_http_defender::tls::fingerprint::ClientHelloInfo;

    let info = ClientHelloInfo {
        client_version: 0x0303,
        cipher_suites: vec![0xC02B, 0xC02F],
        extension_types: vec![0x0000, 0x000A, 0x000B],
        supported_groups: vec![0x001D],
        ec_point_formats: vec![0x00],
        alpn_first: None,
        sni: None,
    };

    let fp = TlsFingerprint::compute(&info);
    let parts: Vec<&str> = fp.ja3_string.split(',').collect();

    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0], "771");
    assert_eq!(parts[1], "49195-49199");
    assert_eq!(parts[2], "0-10-11");
    assert_eq!(parts[3], "29");
    assert_eq!(parts[4], "0");
    assert_eq!(fp.ja3.len(), 32, "MD5 hash must be 32 hex chars");
}

#[test]
fn test_ja3_blocklist_scoring() {
    use intellegen_http_defender::tls::fingerprint::ClientHelloInfo;

    let info = ClientHelloInfo {
        client_version: 0x0303,
        cipher_suites: vec![0xC02B],
        extension_types: vec![],
        supported_groups: vec![],
        ec_point_formats: vec![],
        alpn_first: None,
        sni: None,
    };
    let fp = TlsFingerprint::compute(&info);
    let ja3 = fp.ja3.clone();

    let config =
        FingerprintConfig::new(50, 30, vec![], vec![], false, false).with_ja3_blocklist(vec![ja3]);

    assert_eq!(config.deny_threshold, 50);
    assert!(!config.ja3_blocklist.is_empty());
}

#[tokio::test]
async fn test_tls_server_accepts_https_connection() {
    let cert_gen = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert_gen.cert.der().to_vec();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem").to_string_lossy().to_string();
    let key_path = dir.path().join("key.pem").to_string_lossy().to_string();
    std::fs::write(&cert_path, cert_gen.cert.pem()).unwrap();
    std::fs::write(&key_path, cert_gen.key_pair.serialize_pem()).unwrap();

    let backend_addr = start_backend().await;
    let proxy_addr = start_proxy(&cert_path, &key_path, backend_addr).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let client_config = make_test_client_config(&cert_der);
    let connector = tokio_rustls::TlsConnector::from(client_config);

    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .uri("/")
        .header("host", "localhost")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), hyper::StatusCode::OK);
}

#[tokio::test]
async fn test_plain_http_still_works_with_tls_enabled() {
    let (_dir, cert_path, key_path) = generate_test_certs();
    let backend_addr = start_backend().await;
    let proxy_addr = start_proxy(&cert_path, &key_path, backend_addr).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(tcp);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .uri("/")
        .header("host", "localhost")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), hyper::StatusCode::OK);
}

#[tokio::test]
async fn test_build_acceptor_missing_cert_returns_error() {
    let result = build_acceptor("/nonexistent/cert.pem", "/nonexistent/key.pem");
    assert!(result.is_err());
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Failed to open TLS cert"),
        "got: {}",
        err_msg
    );
}
