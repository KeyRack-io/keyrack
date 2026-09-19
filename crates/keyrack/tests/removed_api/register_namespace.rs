// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: Apache-2.0

async fn probe(client: &keyrack::KeyRack) {
    let namespace = keyrack::Namespace {
        name: "probe".into(),
        attachment: Default::default(),
        rules: Vec::new(),
    };
    let _: Result<(), keyrack::KeyRackError> = client.register_namespace(namespace).await;
}

fn main() {}
