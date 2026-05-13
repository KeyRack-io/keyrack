// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

//! Polling file-watcher for TLS certificate hot-reload.
//!
//! The watcher detects when the server's TLS cert/key files change on disk and
//! broadcasts the new bytes via a `tokio::sync::watch` channel.
//!
//! **V1 limitation:** tonic's `ServerTlsConfig` does not support swapping certs
//! on a running listener. The reloader logs a warning and updates the channel so
//! downstream consumers (e.g. a future `rustls` `ResolvesServerCert` impl) can
//! pick up new certs. For now operators should perform a rolling restart after
//! certificate renewal.

use std::time::{Duration, SystemTime};
use tokio::sync::watch;

pub struct CertReloader {
    cert_path: String,
    key_path: String,
    tx: watch::Sender<(Vec<u8>, Vec<u8>)>,
}

impl CertReloader {
    pub fn new(cert_path: &str, key_path: &str) -> (Self, watch::Receiver<(Vec<u8>, Vec<u8>)>) {
        let cert = std::fs::read(cert_path).unwrap_or_default();
        let key = std::fs::read(key_path).unwrap_or_default();
        let (tx, rx) = watch::channel((cert, key));
        (
            Self {
                cert_path: cert_path.into(),
                key_path: key_path.into(),
                tx,
            },
            rx,
        )
    }

    pub async fn watch_loop(self, interval: Duration) {
        let mut last_modified = SystemTime::UNIX_EPOCH;
        loop {
            tokio::time::sleep(interval).await;
            let meta = tokio::fs::metadata(&self.cert_path).await;
            if let Ok(m) = meta {
                if let Ok(modified) = m.modified() {
                    if modified > last_modified {
                        last_modified = modified;
                        match (
                            tokio::fs::read(&self.cert_path).await,
                            tokio::fs::read(&self.key_path).await,
                        ) {
                            (Ok(cert), Ok(key)) => {
                                tracing::info!("TLS certificates reloaded from disk");
                                tracing::warn!(
                                    "live TLS swap is not yet supported — restart the \
                                     service to apply the new certificates"
                                );
                                let _ = self.tx.send((cert, key));
                            }
                            _ => tracing::warn!("failed to reload TLS certificates"),
                        }
                    }
                }
            }
        }
    }
}
