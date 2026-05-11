use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::error::{ArmorError, Result};

pub fn build_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| ArmorError::Config(format!("Failed to open TLS cert '{}': {}", cert_path, e)))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ArmorError::Config(format!("Failed to parse TLS cert: {}", e)))?;

    if certs.is_empty() {
        return Err(ArmorError::Config(format!(
            "No certificates found in '{}'",
            cert_path
        )));
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| ArmorError::Config(format!("Failed to open TLS key '{}': {}", key_path, e)))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ArmorError::Config(format!("TLS configuration error: {}", e)))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
