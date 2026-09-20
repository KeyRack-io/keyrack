// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: Apache-2.0

async fn probe(client: &keyrack::KeyRack) {
    let _: Result<Vec<keyrack::ReEncryptionEvent>, keyrack::KeyRackError> =
        client.poll_data_reencryption_jobs("probe").await;
}

fn main() {}
