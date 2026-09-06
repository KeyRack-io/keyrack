#!/usr/bin/env bash
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run provider integration tests on the existing demo's disposable Vault fixture.
set -euo pipefail

if [[ $# -gt 0 ]]; then
    if [[ "$1" != -- || $# -lt 2 ]]; then
        echo "Usage: bash scripts/test-vault-provider.sh [-- command [arguments...]]" >&2
        exit 2
    fi
    shift
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
command -v docker >/dev/null
command -v cargo >/dev/null
docker compose version

# The fixture is local-only. Never start it on a caller's remote Docker context.
if [[ -n "${DOCKER_CONTEXT:-}" ]]; then
    docker_endpoint="$(docker context inspect "$DOCKER_CONTEXT" --format '{{.Endpoints.docker.Host}}')"
elif [[ -n "${DOCKER_HOST:-}" ]]; then
    docker_endpoint="$DOCKER_HOST"
else
    docker_endpoint="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
fi
case "$docker_endpoint" in
    unix://*) ;;
    *) echo "Refusing nonlocal Docker endpoint: use a local Unix-socket context." >&2; exit 1 ;;
esac
docker info >/dev/null

# Check discovery before booting Vault: a renamed, removed, or un-ignored original
# test must not turn this gate into a successful zero-test run. New ignored
# provider tests are included automatically by the test invocation below.
available_tests="$(cargo test --locked -p keyrack-vault --lib -- --ignored --list --color never)"
required_tests=(
    tests::exportable_round_trip
    tests::loosen_then_export
    tests::tighten_soft_revoke_preserves_data
    tests::non_exportable_has_no_export_path
)
for test_name in "${required_tests[@]}"; do
    if ! grep -Fxq "$test_name: test" <<< "$available_tests"; then
        echo "Required ignored Vault test missing: $test_name" >&2
        exit 1
    fi
done

# mktemp provides a per-run ownership namespace; no checkout or host token/data
# directories are mounted. Cleanup removes only this unique Compose project and
# its own empty temporary directory, never another demo/deployment's resources.
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/keyrack-vault-ci.XXXXXXXX")"
project_name="$(basename "$fixture_dir" | tr '[:upper:].' '[:lower:]-')"
compose=(docker compose --env-file /dev/null --project-name "$project_name"
    --file "$repo_root/demos/01-foss-vault/docker-compose.yml")
fixture_started=0
cleanup() {
    local result=$?
    trap - EXIT INT TERM
    if [[ "$fixture_started" == 1 ]]; then
        if [[ "$result" != 0 ]]; then
            "${compose[@]}" logs --no-color vault >&2 || true
        fi
        if ! "${compose[@]}" down --volumes --timeout 10; then
            echo "Failed to clean owned Vault fixture: $project_name" >&2
            result=1
        fi
    fi
    if ! rmdir -- "$fixture_dir"; then
        echo "Failed to remove owned empty fixture directory: $fixture_dir" >&2
        result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for resource in container network volume; do
    list_args=("$resource" ls --quiet --filter "label=com.docker.compose.project=$project_name")
    if [[ "$resource" == container ]]; then
        list_args+=(--all)
    fi
    existing_resources="$(docker "${list_args[@]}")"
    if [[ -n "$existing_resources" ]]; then
        echo "Refusing an existing Compose project: $project_name" >&2
        exit 1
    fi
done

# Ignore caller Vault credentials/address and the demo's default public port.
# --env-file also prevents an unrelated local .env from configuring this fixture.
export KEYRACK_VAULT_BIND_ADDRESS=127.0.0.1
export KEYRACK_VAULT_PORT=0
export VAULT_TOKEN=demo-root-token
export NO_PROXY=127.0.0.1,localhost
export no_proxy="$NO_PROXY"
unset VAULT_NAMESPACE

fixture_started=1
"${compose[@]}" up --detach --wait --wait-timeout 60 vault
"${compose[@]}" run --rm --no-deps vault-init
published_address="$("${compose[@]}" port vault 8200)"
if [[ ! "$published_address" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
    echo "Expected exactly one loopback-only Vault port, got: $published_address" >&2
    exit 1
fi
export VAULT_ADDR="http://$published_address"
echo "Running mandatory Vault provider tests on disposable fixture $project_name"
cargo test --locked -p keyrack-vault --lib -- --ignored --nocapture --test-threads=1

# A future integration suite can use the same live fixture without replacing the
# provider gate, adding a second Vault stack, or passing deployment credentials.
if [[ $# -gt 0 ]]; then
    echo "Running additional assertions on the same disposable Vault fixture"
    "$@"
fi
