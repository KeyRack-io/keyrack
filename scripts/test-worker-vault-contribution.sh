#!/usr/bin/env bash
# Worker contribution to docker-vault-ci-lane, owned by the A2 track.
# Consumes its existing fixture; creates no Vault server, parent, token or CI lane.
set -euo pipefail
: "${VAULT_ADDR:?live fixture address required}"
: "${KEYRACK_WORKER_VAULT_TOKEN_FILE:?worker-only token file required}"
: "${KEYRACK_WORKER_VAULT_PARENT:?derived AES-GCM fixture parent required}"
: "${KEYRACK_WORKER_VAULT_COORDINATOR_TOKEN_FILE:?coordinator deny-control token file required}"
: "${KEYRACK_WORKER_VAULT_ADMIN_TOKEN_FILE:?disposable fixture admin token file required}"
cargo test -p keyrack-crypto-worker
cargo test -p keyrack-crypto-worker real_vault_ -- --ignored --test-threads=1
# A2's lane must ALSO retain its four original keyrack-vault provider tests.
