//! Rust Armor L7 - Intelligent HTTP Defender
//!
//! Reverse proxy with deep packet inspection:
//! - Fingerprinting (header order, User-Agent analysis)
//! - Rate limiting (GCRA algorithm)
//! - Anti-Slowloris protection
//! - Challenge-response system

pub mod config;
pub mod error;
pub mod filter;
pub mod proxy;
pub mod server;