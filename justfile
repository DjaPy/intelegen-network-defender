# List available commands
default:
    @just --list

# Build release binary
build:
    cargo build --release --all-features

# Build for development
build-dev:
    cargo build

# Run all tests
test:
    cargo test --all-features

# Run tests with output
test-verbose:
    cargo test --all-features -- --nocapture

# Run specific test
test-one TEST:
    cargo test {{TEST}} -- --nocapture

# Run the server locally
run:
    #!/usr/bin/env bash
    [ -f .env ] || cp .env.example .env
    cargo run

# Format code
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt -- --check

# Run clippy
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Check code without building
check:
    cargo check --all-features


# Install binary (requires sudo)
install: build
    sudo cp target/release/intellegen-http-defender /usr/local/bin/

# Generate documentation
docs:
    cargo doc --no-deps --open

# Run security audit
audit:
    cargo audit

# Watch and auto-rebuild on changes
watch:
    cargo watch -x run

# Run benchmarks
bench:
    cargo bench

all-check:
    fmt-check
    fmt
    lint
    audit
    test
    bench