#!/usr/bin/env bash
# Worker contribution to docker-vault-ci-lane, owned by the A2 track.
# Consumes its existing fixture; creates no Vault server or CI lane.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
if [[ $# -gt 0 ]]; then
    if [[ $# != 1 || "$1" != --from-vault-provider-fixture ]]; then
        echo "Usage: bash scripts/test-worker-vault-contribution.sh [--from-vault-provider-fixture]" >&2
        exit 2
    fi
    # Hook for scripts/test-vault-provider.sh at a85272c. It already ran its
    # mandatory provider tests and owns the live demo Vault and its teardown.
    exec python3 scripts/prepare-worker-vault-fixture.py
fi
: "${VAULT_ADDR:?live fixture address required}"
: "${KEYRACK_WORKER_VAULT_TOKEN_FILE:?worker-only token file required}"
: "${KEYRACK_WORKER_VAULT_PARENT:?derived AES-GCM fixture parent required}"
: "${KEYRACK_WORKER_VAULT_COORDINATOR_TOKEN_FILE:?coordinator deny-control token file required}"
: "${KEYRACK_WORKER_VAULT_ADMIN_TOKEN_FILE:?disposable fixture admin token file required}"
available_tests="$(cargo test --locked -p keyrack-crypto-worker -- --ignored --list --color never)"
required_tests=(
    source::tests::real_vault_coordinator_has_no_parent_decrypt_path
    source::tests::real_vault_native_wrapped_only_authenticates_every_v1_context_byte
    source::tests::real_vault_parent_loss_respects_separate_authority_and_residency_bounds
    real_vault_worker_subprocess_round_trip
)
for test_name in "${required_tests[@]}"; do
    if ! grep -Fxq "$test_name: test" <<< "$available_tests"; then
        echo "Required ignored worker Vault test missing: $test_name" >&2
        exit 1
    fi
done
cargo test --locked -p keyrack-crypto-worker
cargo test --locked -p keyrack-crypto-worker real_vault_ -- --ignored --test-threads=1
