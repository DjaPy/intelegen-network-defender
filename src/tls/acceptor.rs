//! TLS acceptor builder from PEM certificate and key files

use std::io::BufReader;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::error::{ArmorError, Result};

/// Build a TLS acceptor from PEM certificate and private key files.
pub fn build_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file = std::fs::File::open(cert_path).map_err(|e| {
        ArmorError::Config(format!("Failed to open TLS cert '{}': {}", cert_path, e))
    })?;
    let mut cert_reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ArmorError::Config(format!("Failed to parse TLS cert: {}", e)))?;

    if certs.is_empty() {
        return Err(ArmorError::Config(format!(
            "No certificates found in '{}'",
            cert_path
        )));
    }

    let key_file = std::fs::File::open(key_path)
        .map_err(|e| ArmorError::Config(format!("Failed to open TLS key '{}': {}", key_path, e)))?;
    let mut key_reader = BufReader::new(key_file);

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| ArmorError::Config(format!("Failed to parse TLS key: {}", e)))?
        .ok_or_else(|| ArmorError::Config(format!("No private key found in '{}'", key_path)))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ArmorError::Config(format!("TLS configuration error: {}", e)))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
