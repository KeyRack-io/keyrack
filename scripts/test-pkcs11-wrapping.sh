#!/usr/bin/env bash
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run the native wrapping mechanism probe on a fresh, disposable SoftHSM token.
set -euo pipefail

command -v softhsm2-util >/dev/null || {
    echo "SoftHSM2 is required; use docker/Dockerfile.wrapping-probe if unavailable." >&2
    exit 1
}

if [[ -z "${KMS_PKCS11_LIB:-}" ]]; then
    for candidate in /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
        if [[ -f "$candidate" ]]; then
            export KMS_PKCS11_LIB="$candidate"
            break
        fi
    done
fi
if [[ -z "${KMS_PKCS11_LIB:-}" || ! -f "$KMS_PKCS11_LIB" ]]; then
    echo "Set KMS_PKCS11_LIB to the SoftHSM2 module." >&2
    exit 1
fi

probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/keyrack-wrapping-probe.XXXXXXXX")
cleanup() {
    # The only removal target is the fresh directory created above.
    case "$probe_dir" in
        */keyrack-wrapping-probe.*) rm -rf -- "$probe_dir" ;;
        *) echo "Refusing unexpected probe cleanup path." >&2 ;;
    esac
}
trap cleanup EXIT
mkdir "$probe_dir/tokens"
export SOFTHSM2_CONF="$probe_dir/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
    "$probe_dir/tokens" > "$SOFTHSM2_CONF"

# These are disposable test credentials, never deployment credentials. Ignore any
# caller's token label/PIN so this runner cannot initialize their configured token.
export KMS_PKCS11_TOKEN_LABEL=keyrack-wrapping-probe
export KMS_PKCS11_PIN=12345678
softhsm2-util --version
softhsm2-util --init-token --free --label "$KMS_PKCS11_TOKEN_LABEL" \
    --pin "$KMS_PKCS11_PIN" --so-pin 87654321

cargo test --locked -p keyrack-pkcs11 --features softhsm-tests \
    --test wrapping_probe -- --nocapture --test-threads=1
