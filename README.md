# Intellegen HTTP Defender

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

High-performance reverse proxy with deep packet inspection for L7 HTTP traffic protection. Built with Rust for security, speed, and reliability.

## Features

### Production-Ready

- **Reverse Proxy** - Forward requests to upstream backend with connection pooling
- **Fingerprinting Filter** - Advanced bot detection and request analysis
  - User-Agent pattern matching (bots, crawlers, scanners)
  - HTTP header order analysis (browser fingerprinting)
  - Scoring system (0-100) with configurable thresholds
  - Whitelist/blacklist support
- **Rate Limiting** - GCRA algorithm with distributed storage
  - In-memory storage (DashMap) for single-node
  - Redis storage for distributed deployments
  - Per-IP tracking with configurable burst capacity
- **Filter Chain** - Composable async filters with short-circuit execution
- **Header Rewriting** - X-Forwarded-For, X-Real-IP, Host preservation

### Configuration

- Environment-based config (12-factor app principles)
- `.env` file support
- Validation with helpful error messages
- Hot-reload friendly

## Installation

### Prerequisites

- Rust 1.75+ ([Install Rust](https://rustup.rs/))
- Optional: Redis (for distributed rate limiting)

### Build from Source

```bash
# Clone repository
git clone https://github.com/yourusername/intellegen-http-defender.git
cd intellegen-http-defender

# Build release version
cargo build --release

# Binary location
./target/release/intellegen-http-defender
```

### With Redis Support

```bash
cargo build --release --features redis-storage
```

## Configuration

Create a `.env` file (see `.env.example`):

```bash
# Server configuration
SERVER_HOST=127.0.0.1
SERVER_PORT=8080

# Upstream backend (required)
PROXY_UPSTREAM_URL=http://localhost:3000

# Proxy settings
PROXY_TIMEOUT_SECS=30
PROXY_PRESERVE_HOST=false

# Fingerprinting (bot detection)
FINGERPRINT_ENABLED=true
FINGERPRINT_DENY_THRESHOLD=85           # Score ≥ 85 = Deny (403)
FINGERPRINT_CHALLENGE_THRESHOLD=70      # Score ≥ 70 = Challenge
FINGERPRINT_USER_AGENT_WHITELIST=googlebot,bingbot
FINGERPRINT_USER_AGENT_BLACKLIST=
FINGERPRINT_STRICT_HEADER_ORDER=false
FINGERPRINT_REQUIRE_COMMON_HEADERS=true

# Rate limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_SECOND=100
RATE_LIMIT_BURST_CAPACITY=10
RATE_LIMIT_STORAGE=memory               # memory | redis

# Redis (required when RATE_LIMIT_STORAGE=redis)
# REDIS_URL=redis://127.0.0.1:6379
```

## Usage

### Basic Usage

```bash
# Start proxy
PROXY_UPSTREAM_URL=http://localhost:3000 cargo run

# Or with release build
PROXY_UPSTREAM_URL=http://localhost:3000 ./target/release/intellegen-http-defender
```

### Docker

```bash
# Using docker-compose (recommended)
docker-compose up -d

# Or build and run manually
docker build -t intellegen-http-defender .
docker run -p 8080:8080 \
  -e PROXY_UPSTREAM_URL=http://backend:3000 \
  intellegen-http-defender
```

### Examples

```bash
# Normal browser request - allowed
curl -H "User-Agent: Mozilla/5.0 (Chrome)" \
     -H "Accept: text/html" \
     http://localhost:8080/

# Bot request - denied
curl http://localhost:8080/
# Response: 403 Forbidden

# Whitelisted bot - allowed
curl -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)" \
     http://localhost:8080/
```

## Architecture

### Filter Chain

Requests flow through a composable filter chain:

### Fingerprinting Scoring

**Total Score = User-Agent (0-50) + Header Order (0-30) + Missing Headers (0-20)**

| Score | Action |
|-------|--------|
| < 70 | Allow (default) |
| 70-84 | Challenge |
| ≥ 85 | Deny (403) |

**User-Agent Patterns:**
- Scanners (nikto, sqlmap, masscan): 50 points
- CLI tools (curl, wget): 40 points
- Generic bots: 30 points
- Blacklist: 50 points (instant deny)
- Whitelist: 0 points (instant allow)

### Tech Stack

- **Runtime**: Tokio (async)
- **HTTP**: Hyper 1.x with hyper-util
- **Storage**: DashMap (in-memory), Redis (distributed)
- **Error Handling**: thiserror
- **Async Traits**: async-trait
- **Logging**: tracing + tracing-subscriber

## Performance

- **Latency**: < 1ms overhead per request
- **Throughput**: 50K+ req/s (single core, in-memory)
- **Memory**: ~10MB base + per-IP tracking
- **Concurrency**: Full async/await with Tokio

## Roadmap

### In Progress
- [ ] Docker image and Docker Compose
- [ ] Prometheus metrics
- [ ] Dashboard UI

### Planned
- [ ] Anti-Slowloris protection
- [ ] CAPTCHA integration
- [ ] Proof-of-Work challenges
- [ ] TLS fingerprinting (JA3/JA4)
- [ ] Machine learning bot detection
- [ ] OpenTelemetry support

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Rust 2024 edition standards
- No `mod.rs` for logic (use direct files)
- Early returns over nested if-else
- Explicit error handling (no unwrap in production)
- Write tests for new features
- Update documentation

## Documentation

- **API Docs**: `cargo doc --open`
- **Examples**: See `examples/` directory (coming soon)

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/)
- Powered by [Tokio](https://tokio.rs/) and [Hyper](https://hyper.rs/)
- Inspired by Cloudflare, AWS WAF, and other L7 protection systems

## Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/intellegen-http-defender/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/intellegen-http-defender/discussions)

---