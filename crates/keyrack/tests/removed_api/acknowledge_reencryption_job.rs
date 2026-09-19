// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: Apache-2.0

async fn probe(client: &keyrack::KeyRack) {
    let _: Result<(), keyrack::KeyRackError> = client.acknowledge_reencryption_job("probe").await;
}

fn main() {}
