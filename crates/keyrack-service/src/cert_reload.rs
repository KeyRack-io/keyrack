// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of KeyRack.
//
// KeyRack is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// KeyRack is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with KeyRack. If not, see <https://www.gnu.org/licenses/>.
//
// Alternative commercial licensing is available; contact the Licensor.

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

/// PEM certificate and private key bytes broadcast on renewal.
pub type TlsMaterial = (Vec<u8>, Vec<u8>);

pub struct CertReloader {
    cert_path: String,
    key_path: String,
    tx: watch::Sender<TlsMaterial>,
}

impl CertReloader {
    pub fn new(cert_path: &str, key_path: &str) -> (Self, watch::Receiver<TlsMaterial>) {
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
                        if let (Ok(cert), Ok(key)) = (
                            tokio::fs::read(&self.cert_path).await,
                            tokio::fs::read(&self.key_path).await,
                        ) {
                            tracing::info!("TLS certificates reloaded from disk");
                            tracing::warn!(
                                "live TLS swap is not yet supported — restart the \
                                 service to apply the new certificates"
                            );
                            let _ = self.tx.send((cert, key));
                        } else {
                            tracing::warn!("failed to reload TLS certificates");
                        }
                    }
                }
            }
        }
    }
}
