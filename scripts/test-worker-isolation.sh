#!/usr/bin/env bash
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Dedicated acceptance job, reusing the A2 fixture and all provider obligations.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ "$(uname -s)" != Linux ]]; then
    echo "Worker credential isolation FAILED: required gate refuses non-Linux skip" >&2
    exit 1
fi
export KEYRACK_WORKER_ISOLATION=required
log="$(mktemp "${TMPDIR:-/tmp}/keyrack-worker-isolation-gate.XXXXXXXX")"
trap 'rm -f "$log"' EXIT
bash scripts/test-vault-provider.sh -- bash scripts/test-worker-vault-contribution.sh --from-vault-provider-fixture | tee "$log"
if ! grep -Fxq 'Distinct-UID supervisor acceptance PASSED: three native worker launches, six coordinator EACCES probes; unit/users/files cleaned' "$log"; then
    echo "Worker credential isolation FAILED: fixture completion evidence missing" >&2
    exit 1
fi
if grep -Fq 'supervisor acceptance NOT RUN' "$log"; then
    echo "Worker credential isolation FAILED: fixture reported a skip" >&2
    exit 1
fi
echo "Worker credential isolation gate PASSED (fixture executed and cleanup verified)"
