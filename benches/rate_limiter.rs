use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use intellegen_http_defender::filter::rate_limit::{
    InMemoryStorage, RateLimitConfig, RateLimitStorage,
};

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn bench_single_ip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = RateLimitConfig::new(u32::MAX, 1000);
    let storage = InMemoryStorage::new();
    let emission = config.emission_interval_nanos();
    let tolerance = config.delay_tolerance_nanos();

    c.bench_function("rate_limiter/single_ip", |b| {
        b.to_async(&rt).iter(|| async {
            storage
                .check_and_update("192.168.1.1", now_nanos(), emission, tolerance)
                .await
                .unwrap()
        });
    });
}

fn bench_many_ips(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = RateLimitConfig::new(u32::MAX, 1000);
    let emission = config.emission_interval_nanos();
    let tolerance = config.delay_tolerance_nanos();

    let mut group = c.benchmark_group("rate_limiter/N_distinct_ips");
    for n in [10u32, 100, 1000] {
        let storage = Arc::new(InMemoryStorage::new());
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let mut counter: u32 = 0;
            let storage = storage.clone();
            b.to_async(&rt).iter(|| {
                let key = format!(
                    "10.{}.{}.{}",
                    (counter / 65536) % 256,
                    (counter / 256) % 256,
                    counter % 256
                );
                counter = counter.wrapping_add(1) % n;
                let s = storage.clone();
                async move {
                    s.check_and_update(&key, now_nanos(), emission, tolerance)
                        .await
                        .unwrap()
                }
            });
        });
    }
    group.finish();
}

fn bench_concurrent_same_ip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = RateLimitConfig::new(u32::MAX, 1000);
    let emission = config.emission_interval_nanos();
    let tolerance = config.delay_tolerance_nanos();

    let mut group = c.benchmark_group("rate_limiter/concurrent_tasks");
    for n in [10u32, 50, 100] {
        let storage = Arc::new(InMemoryStorage::new());
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let storage = storage.clone();
            b.to_async(&rt).iter(|| {
                let storage = storage.clone();
                async move {
                    let tasks: Vec<_> = (0..n)
                        .map(|i| {
                            let s = storage.clone();
                            let key = format!("10.0.0.{}", i % 256);
                            tokio::spawn(async move {
                                s.check_and_update(&key, now_nanos(), emission, tolerance)
                                    .await
                                    .unwrap()
                            })
                        })
                        .collect();
                    futures::future::join_all(tasks).await
                }
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_single_ip,
    bench_many_ips,
    bench_concurrent_same_ip
);
criterion_main!(benches);
