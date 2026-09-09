#!/usr/bin/env bash
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../crates/keyrack-crypto-worker"
corpus="$(mktemp -d "${TMPDIR:-/tmp}/keyrack-worker-fuzz.XXXXXXXX")"
trap 'rm -rf "$corpus"' EXIT
cp fuzz/corpus/ipc_decoder/* "$corpus/"
cargo fuzz run ipc_decoder "$corpus" -- -max_total_time=60 -max_len=70000 -timeout=5 -verbosity=0 -print_final_stats=1
echo "Worker IPC fuzz smoke PASSED: bounded campaign completed"
