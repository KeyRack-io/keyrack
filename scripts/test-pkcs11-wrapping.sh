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
    for candidate in /opt/homebrew/lib/softhsm/libsofthsm2.so \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
        if [[ -f "$candidate" ]]; then
            export KMS_PKCS11_LIB="$candidate"
            break
        fi
    done
fi

# Fail before creating a token if the native owner test was removed, renamed or
# ignored. A successful cargo invocation that ran no test is not conformance.
native_test=provider::native_a2::tests::native_a2_soft_hsm
provider_test=provider::context_wrapping::tests::context_wrapped_provider_roundtrip_swap_restart_and_exact_closure
native_policy_tests=(
    provider::context_wrapping::tests::planted_resident_lease_labels_are_refused_before_lookup
    provider::context_wrapping::tests::wrapping_provider_rejects_another_providers_live_lease
    provider::context_wrapping::native::tests::native_provider_envelope_matches_independent_cbc_and_kw
    provider::context_wrapping::native::tests::native_failure_cleanup_precedes_original_session_close
    provider::context_wrapping::native::tests::native_startup_refuses_failed_self_test_and_preserves_inventory
    provider::context_wrapping::native::tests::native_parent_roles_refuse_ordinary_use_and_wrong_parent
    provider::context_wrapping::native::tests::native_destroy_failure_attempts_remaining_objects_and_fences_admission
)
derived_test=context_derived_soft_hsm_strict_policy_and_cleanup
derived_listing=$(cargo test --locked -p keyrack-pkcs11 --features softhsm-tests \
    --test context_derived_probe -- --list)
[[ $(printf '%s\n' "$derived_listing" | grep -Fxc "$derived_test: test") == 1 ]] || {
    echo "Expected context-derived policy test missing." >&2
    exit 1
}
derived_ignored=$(cargo test --locked -p keyrack-pkcs11 --features softhsm-tests \
    --test context_derived_probe -- --ignored --list)
if printf '%s\n' "$derived_ignored" | grep -Fq "$derived_test: test"; then
    echo "Context-derived policy test must not be ignored." >&2
    exit 1
fi
native_listing=$(cargo test --locked -p keyrack-pkcs11 \
    --features softhsm-tests,native-a2-conformance --lib -- --list)
[[ $(printf '%s\n' "$native_listing" | grep -Fxc "$native_test: test") == 1 ]] || {
    echo "Expected native A2 conformance test missing." >&2
    exit 1
}
native_ignored=$(cargo test --locked -p keyrack-pkcs11 \
    --features softhsm-tests,native-a2-conformance --lib -- --ignored --list)
if printf '%s\n' "$native_ignored" | grep -Fq "$native_test: test"; then
    echo "Native A2 conformance test must not be ignored." >&2
    exit 1
fi
[[ $(printf '%s\n' "$native_listing" | grep -Fxc "$provider_test: test") == 1 ]] || {
    echo "Expected context-wrapped provider test missing." >&2
    exit 1
}
if printf '%s\n' "$native_ignored" | grep -Fq "$provider_test: test"; then
    echo "Context-wrapped provider test must not be ignored." >&2
    exit 1
fi
for policy_test in "${native_policy_tests[@]}"; do
    [[ $(printf '%s\n' "$native_listing" | grep -Fxc "$policy_test: test") == 1 ]] || {
        echo "Expected native policy test missing: $policy_test" >&2
        exit 1
    }
    if printf '%s\n' "$native_ignored" | grep -Fq "$policy_test: test"; then
        echo "Native policy test must not be ignored: $policy_test" >&2
        exit 1
    fi
done
service_tests=(
    native_wrapped_grpc_rest_roundtrip_and_envelope_swap_refusal
    native_wrapped_context_fields_and_parent_version_are_bound
    native_wrapped_grpc_rest_cancellation_closes_original_lease
    native_wrapped_provider_reconstruction_retains_child_usability
    native_wrapped_process_restart_retains_child_usability
    native_wrapped_grpc_rest_rewrap_and_reparent_retained_versions
    native_wrapped_grpc_rest_migration_cancellation_retains_journal
)
service_listing=$(cargo test --locked -p keyrack-service --test softhsm_wrapped_service -- --ignored --list)
for service_test in "${service_tests[@]}"; do
    [[ $(printf '%s\n' "$service_listing" | grep -Fxc "$service_test: test") == 1 ]] || {
        echo "Expected ignored native service test missing: $service_test" >&2
        exit 1
    }
done

for cleanup_test in \
    provider::native_a2::adapter::tests::failed_open_preserves_original_error_after_successful_close \
    provider::native_a2::adapter::tests::failed_open_reports_failed_close_and_original_error_without_retry; do
    [[ $(printf '%s\n' "$native_listing" | grep -Fxc "$cleanup_test: test") == 1 ]] || {
        echo "Expected native cleanup regression missing: $cleanup_test" >&2
        exit 1
    }
    if printf '%s\n' "$native_ignored" | grep -Fq "$cleanup_test: test"; then
        echo "Native cleanup regression must not be ignored: $cleanup_test" >&2
        exit 1
    fi
    cargo test --locked -p keyrack-pkcs11 --features softhsm-tests,native-a2-conformance \
        --lib "$cleanup_test" -- --exact
done
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

# Same disposable stack, but a separate test process: no independent C_Initialize
# or token-wide login race with the earlier direct-mechanism probe.
cargo test --locked -p keyrack-pkcs11 --features softhsm-tests,native-a2-conformance \
    --lib "$native_test" -- --exact --nocapture --test-threads=1

# Independent process, same fresh fixture; every object here is session-only.
cargo test --locked -p keyrack-pkcs11 --features softhsm-tests \
    --test context_derived_probe "$derived_test" -- --exact --nocapture --test-threads=1

cargo test --locked -p keyrack-pkcs11 --features softhsm-tests,native-a2-conformance \
    --lib "$provider_test" -- --exact --nocapture --test-threads=1

for policy_test in "${native_policy_tests[@]}"; do
    cargo test --locked -p keyrack-pkcs11 --features softhsm-tests,native-a2-conformance \
        --lib "$policy_test" -- --exact --nocapture --test-threads=1
done

for service_test in "${service_tests[@]}"; do
    cargo test --locked -p keyrack-service --test softhsm_wrapped_service \
        "$service_test" -- --ignored --exact --nocapture --test-threads=1
done

# Mutate an isolated source copy, never production configuration. A direct-parent
# AES-KW counterfactual must fail the exact service envelope-swap assertion.
python3 -B -m unittest discover -s crates/keyrack-pkcs11/tests/support -p test_context_binding_control.py
python3 crates/keyrack-pkcs11/tests/support/context_binding_control.py
