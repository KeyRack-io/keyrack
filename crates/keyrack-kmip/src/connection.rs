// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1

//! KMIP TLS connection management.
//!
//! Manages a TLS connection to a KMIP server, handling the TTLV
//! framing: each KMIP message is length-prefixed by the outer TTLV
//! structure header.

use crate::provider::KmipProviderConfig;
use crate::ttlv;
use bytes::BytesMut;
use keyrack_core::error::{KeyRackError, Result};
use rustls_pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

pub struct KmipConnection {
    stream: TlsStream<TcpStream>,
}

impl KmipConnection {
    /// Establish a TLS connection to the KMIP server.
    pub async fn connect(config: &KmipProviderConfig) -> Result<Self> {
        let (host, port) = parse_endpoint(&config.endpoint)?;

        let tls_config = build_tls_config(config)?;
        let connector = TlsConnector::from(Arc::new(tls_config));

        let tcp = tokio::time::timeout(
            std::time::Duration::from_secs(config.timeout_secs),
            TcpStream::connect((&*host, port)),
        )
        .await
        .map_err(|_| KeyRackError::Provider("KMIP connection timed out".into()))?
        .map_err(|e| KeyRackError::Provider(format!("KMIP TCP connect failed: {e}")))?;

        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| KeyRackError::Provider(format!("invalid KMIP server name: {e}")))?;

        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| KeyRackError::Provider(format!("KMIP TLS handshake failed: {e}")))?;

        Ok(Self { stream })
    }

    /// Send a TTLV-encoded request and receive the response.
    pub async fn round_trip(&mut self, request: &ttlv::TtlvItem) -> Result<ttlv::TtlvItem> {
        let encoded = ttlv::encode(request);
        self.stream
            .write_all(&encoded)
            .await
            .map_err(|e| KeyRackError::Provider(format!("KMIP write failed: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| KeyRackError::Provider(format!("KMIP flush failed: {e}")))?;

        // Read the TTLV header (3 tag + 1 type + 4 length = 8 bytes)
        let mut header = [0u8; 8];
        self.stream
            .read_exact(&mut header)
            .await
            .map_err(|e| KeyRackError::Provider(format!("KMIP read header failed: {e}")))?;

        let content_length =
            u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        let mut body = vec![0u8; content_length];
        self.stream
            .read_exact(&mut body)
            .await
            .map_err(|e| KeyRackError::Provider(format!("KMIP read body failed: {e}")))?;

        let mut full = BytesMut::with_capacity(8 + content_length);
        full.extend_from_slice(&header);
        full.extend_from_slice(&body);

        let mut slice: &[u8] = &full;
        ttlv::decode(&mut slice)
            .map_err(|e| KeyRackError::Provider(format!("KMIP TTLV decode error: {e}")))
    }
}

fn parse_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let stripped = endpoint
        .strip_prefix("kmip://")
        .or_else(|| endpoint.strip_prefix("kmips://"))
        .unwrap_or(endpoint);

    let (host, port_str) = stripped
        .rsplit_once(':')
        .ok_or_else(|| {
            KeyRackError::Provider(format!(
                "invalid KMIP endpoint (expected host:port): {endpoint}"
            ))
        })?;

    let port: u16 = port_str
        .parse()
        .map_err(|e| KeyRackError::Provider(format!("invalid port in KMIP endpoint: {e}")))?;

    Ok((host.to_string(), port))
}

fn build_tls_config(config: &KmipProviderConfig) -> Result<rustls::ClientConfig> {
    use rustls::ClientConfig;

    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = &config.ca_cert_path {
        let ca_data = std::fs::read(ca_path)
            .map_err(|e| KeyRackError::Provider(format!("cannot read CA cert {ca_path}: {e}")))?;
        let mut reader = std::io::BufReader::new(&ca_data[..]);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                KeyRackError::Provider(format!("invalid CA cert PEM: {e}"))
            })?;
        for cert in certs {
            root_store.add(cert).map_err(|e| {
                KeyRackError::Provider(format!("cannot add CA cert to root store: {e}"))
            })?;
        }
    }

    let builder = ClientConfig::builder().with_root_certificates(root_store);

    let tls_config = if let (Some(cert_path), Some(key_path)) =
        (&config.client_cert_path, &config.client_key_path)
    {
        let cert_data = std::fs::read(cert_path).map_err(|e| {
            KeyRackError::Provider(format!("cannot read client cert {cert_path}: {e}"))
        })?;
        let key_data = std::fs::read(key_path).map_err(|e| {
            KeyRackError::Provider(format!("cannot read client key {key_path}: {e}"))
        })?;

        let mut cert_reader = std::io::BufReader::new(&cert_data[..]);
        let certs = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                KeyRackError::Provider(format!("invalid client cert PEM: {e}"))
            })?;

        let mut key_reader = std::io::BufReader::new(&key_data[..]);
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| KeyRackError::Provider(format!("invalid client key PEM: {e}")))?
            .ok_or_else(|| KeyRackError::Provider("no private key found in PEM".into()))?;

        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| KeyRackError::Provider(format!("client auth cert error: {e}")))?
    } else {
        builder.with_no_client_auth()
    };

    Ok(tls_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kmip_endpoint() {
        let (host, port) = parse_endpoint("kmip://hsm.example.com:5696").unwrap();
        assert_eq!(host, "hsm.example.com");
        assert_eq!(port, 5696);
    }

    #[test]
    fn parse_bare_endpoint() {
        let (host, port) = parse_endpoint("192.168.1.100:5696").unwrap();
        assert_eq!(host, "192.168.1.100");
        assert_eq!(port, 5696);
    }

    #[test]
    fn parse_missing_port_fails() {
        assert!(parse_endpoint("hsm.example.com").is_err());
    }
}
