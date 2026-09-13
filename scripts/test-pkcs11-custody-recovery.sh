#!/usr/bin/env bash
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Custody loss by permission removal, on a fresh, disposable SoftHSM token.
#
# Custody is removed by taking read permission away from the token directory,
# which is a different fault from moving the directory aside: it can make
# C_Initialize fail during recovery and leave the library finalized. The test
# refuses to run if permissions do not restrict this user, because as root the
# fault cannot be injected and the suite would pass having tested nothing.
set -euo pipefail

command -v softhsm2-util >/dev/null || {
    echo "SoftHSM2 is required for the custody recovery regression." >&2
    exit 1
}

if [[ "$(id -u)" == "0" ]]; then
    echo "Refusing to run as root: chmod does not deny root, so custody loss" >&2
    echo "cannot be injected and the regression would prove nothing." >&2
    exit 1
fi

if [[ -z "${KMS_PKCS11_LIB:-}" ]]; then
    for candidate in /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so \
        /opt/homebrew/lib/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so; do
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

run_dir=$(mktemp -d "${TMPDIR:-/tmp}/keyrack-custody-recovery.XXXXXXXX")
cleanup() {
    # Permissions are removed during the run; restore them so cleanup works.
    chmod -R u+rwX "$run_dir" 2>/dev/null || true
    # The only removal target is the fresh directory created above.
    case "$run_dir" in
        */keyrack-custody-recovery.*) rm -rf -- "$run_dir" ;;
        *) echo "Refusing unexpected cleanup path." >&2 ;;
    esac
}
trap cleanup EXIT

mkdir "$run_dir/tokens"
export SOFTHSM2_CONF="$run_dir/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
    "$run_dir/tokens" > "$SOFTHSM2_CONF"

# Disposable test credentials, never deployment credentials. A caller's own
# label and PIN are ignored so this runner cannot touch their token.
export KMS_PKCS11_TOKEN_LABEL=keyrack-custody-recovery
export KMS_PKCS11_PIN=12345678
softhsm2-util --init-token --free --label "$KMS_PKCS11_TOKEN_LABEL" \
    --pin "$KMS_PKCS11_PIN" --so-pin 87654321 >/dev/null

# The tokendir root, not the token's own subdirectory. SoftHSM scans this at
# C_Initialize, so removing its permissions is what can fail the
# reinitialization itself rather than only the calls that follow — the state
# hosted qualification landed in.
export KEYRACK_TEST_TOKEN_DIR="$run_dir/tokens"

cargo test --locked -p keyrack-pkcs11 --features softhsm-tests \
    --test custody_permission_loss -- --nocapture --test-threads=1
