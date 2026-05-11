use criterion::{Criterion, criterion_group, criterion_main};
use intellegen_http_defender::tls::TlsFingerprint;
use intellegen_http_defender::tls::fingerprint::ClientHelloInfo;

fn typical_chrome_info() -> ClientHelloInfo {
    ClientHelloInfo {
        client_version: 0x0303,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC00A, 0xC014, 0x009C, 0x009D,
        ],
        extension_types: vec![
            0x0000, 0x000A, 0x000B, 0x000D, 0x0017, 0x001B, 0x0023, 0x0029, 0xFF01,
        ],
        supported_groups: vec![0x001D, 0x0017, 0x0018, 0x0019],
        ec_point_formats: vec![0x00],
        alpn_first: Some("h2".to_string()),
        sni: Some("example.com".to_string()),
    }
}

fn bench_compute(c: &mut Criterion) {
    let info = typical_chrome_info();

    c.bench_function("tls_fingerprint/compute_ja3_ja4", |b| {
        b.iter(|| TlsFingerprint::compute(&info));
    });
}

fn bench_compute_no_sni(c: &mut Criterion) {
    let mut info = typical_chrome_info();
    info.sni = None;
    info.alpn_first = None;

    c.bench_function("tls_fingerprint/compute_no_sni", |b| {
        b.iter(|| TlsFingerprint::compute(&info));
    });
}

fn bench_compute_grease_heavy(c: &mut Criterion) {
    let info = ClientHelloInfo {
        client_version: 0x0303,
        cipher_suites: vec![0x0A0A, 0x1A1A, 0x2A2A, 0xC02B, 0xC02F, 0x3A3A, 0x4A4A],
        extension_types: vec![0x0A0A, 0x1A1A, 0x0000, 0x000A, 0x2A2A, 0x000B],
        supported_groups: vec![0x0A0A, 0x001D, 0x1A1A, 0x0017],
        ec_point_formats: vec![0x00],
        alpn_first: None,
        sni: None,
    };

    c.bench_function("tls_fingerprint/compute_grease_heavy", |b| {
        b.iter(|| TlsFingerprint::compute(&info));
    });
}

criterion_group!(
    benches,
    bench_compute,
    bench_compute_no_sni,
    bench_compute_grease_heavy
);
criterion_main!(benches);
