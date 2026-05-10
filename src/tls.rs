//! TLS termination with JA3/JA4 fingerprinting
//!
//! Enabled via the `tls` feature flag. Requires TLS certificate and key paths.
//! JA3/JA4 fingerprints are extracted from the TLS ClientHello before the
//! handshake completes, then injected into request extensions for filters.

pub mod acceptor;
pub mod fingerprint;

pub use acceptor::build_acceptor;
pub use fingerprint::{ClientHelloInfo, TlsFingerprint, parse_clienthello};
