use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use intellegen_http_defender::filter::{Filter, FilterAction, FilterChain, PassthroughFilter};

struct DenyAllFilter;

#[async_trait::async_trait]
impl Filter for DenyAllFilter {
    async fn filter(&self, _req: &Request<Incoming>, _remote_addr: SocketAddr) -> FilterAction {
        FilterAction::Deny {
            status: 403,
            reason: "Denied by test filter".to_string(),
        }
    }

    fn name(&self) -> &str {
        "deny_all"
    }
}

struct CountingFilter {
    count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Filter for CountingFilter {
    async fn filter(&self, _req: &Request<Incoming>, _remote_addr: SocketAddr) -> FilterAction {
        self.count.fetch_add(1, Ordering::SeqCst);
        FilterAction::Allow
    }

    fn name(&self) -> &str {
        "counting"
    }
}

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
async fn test_passthrough_filter_with_real_http() {
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(PassthroughFilter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    let uri = format!("http://{}/test", addr);

    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    server_handle.abort();
}

#[tokio::test]
async fn test_deny_all_filter_with_real_http() {
    let chain = Arc::new(FilterChain::new().add_filter(Arc::new(DenyAllFilter)));

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    let uri = format!("http://{}/test", addr);

    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    server_handle.abort();
}

#[tokio::test]
async fn test_filter_chain_short_circuit() {
    let count = Arc::new(AtomicUsize::new(0));

    let chain = Arc::new(
        FilterChain::new()
            .add_filter(Arc::new(CountingFilter {
                count: count.clone(),
            }))
            .add_filter(Arc::new(DenyAllFilter))
            .add_filter(Arc::new(CountingFilter {
                count: count.clone(),
            })),
    );

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    let uri = format!("http://{}/test", addr);

    let response = client.get(uri.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(count.load(Ordering::SeqCst), 1);

    server_handle.abort();
}

#[tokio::test]
async fn test_multiple_requests_through_chain() {
    let count = Arc::new(AtomicUsize::new(0));

    let chain = Arc::new(
        FilterChain::new()
            .add_filter(Arc::new(CountingFilter {
                count: count.clone(),
            }))
            .add_filter(Arc::new(PassthroughFilter)),
    );

    let (addr, server_handle) = run_test_server(chain).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    let uri = format!("http://{}/test", addr);
    for _ in 0..3 {
        let response = client.get(uri.parse().unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(count.load(Ordering::SeqCst), 3);

    server_handle.abort();
}
