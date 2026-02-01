//! Unified error types for Rust Armor L7

use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArmorError {
    #[error("Failed to bind to {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("Connection error from {remote}: {source}")]
    Connection {
        remote: SocketAddr,
        source: hyper::Error,
    },

    #[error("Upstream connection failed: {0}")]
    Upstream(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, ArmorError>;