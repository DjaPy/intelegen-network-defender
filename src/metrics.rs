//! Prometheus metrics for Intellegen HTTP Defender

use lazy_static::lazy_static;
use prometheus::{
    Counter, CounterVec, Encoder, HistogramOpts, HistogramVec, IntGauge, Opts, TextEncoder,
    register_counter, register_counter_vec, register_histogram_vec, register_int_gauge,
};

lazy_static! {
    pub static ref METRICS: AppMetrics = AppMetrics::new();
}

pub struct AppMetrics {
    /// Total HTTP requests by method and status code
    pub http_requests_total: CounterVec,
    /// HTTP request duration in seconds by method
    pub http_request_duration_seconds: HistogramVec,
    /// Currently active TCP connections
    pub active_connections: IntGauge,
    /// Filter actions by type: allow / deny / challenge
    pub filter_actions_total: CounterVec,
    /// Upstream request failures (connection errors, timeouts)
    pub upstream_failures_total: Counter,
    /// Requests rejected by open circuit breaker
    pub circuit_breaker_open_total: Counter,
}

impl AppMetrics {
    fn new() -> Self {
        let http_requests_total = register_counter_vec!(
            Opts::new("http_requests_total", "Total number of HTTP requests"),
            &["method", "status"]
        )
        .expect("failed to register http_requests_total");

        let http_request_duration_seconds = register_histogram_vec!(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0
            ]),
            &["method"]
        )
        .expect("failed to register http_request_duration_seconds");

        let active_connections = register_int_gauge!(Opts::new(
            "active_connections",
            "Number of currently active TCP connections"
        ))
        .expect("failed to register active_connections");

        let filter_actions_total = register_counter_vec!(
            Opts::new("filter_actions_total", "Total filter actions by type"),
            &["action"]
        )
        .expect("failed to register filter_actions_total");

        let upstream_failures_total = register_counter!(Opts::new(
            "upstream_failures_total",
            "Total upstream request failures (timeouts, connection errors)"
        ))
        .expect("failed to register upstream_failures_total");

        let circuit_breaker_open_total = register_counter!(Opts::new(
            "circuit_breaker_open_total",
            "Total requests rejected by open circuit breaker"
        ))
        .expect("failed to register circuit_breaker_open_total");

        Self {
            http_requests_total,
            http_request_duration_seconds,
            active_connections,
            filter_actions_total,
            upstream_failures_total,
            circuit_breaker_open_total,
        }
    }
}

/// Encode all registered metrics in Prometheus text format.
/// Returns (body bytes, content-type string).
pub fn gather_text() -> (Vec<u8>, String) {
    let _ = &*METRICS;
    let encoder = TextEncoder::new();
    let families = prometheus::gather();
    let mut buf = Vec::new();
    encoder
        .encode(&families, &mut buf)
        .expect("failed to encode metrics");
    (buf, encoder.format_type().to_string())
}
