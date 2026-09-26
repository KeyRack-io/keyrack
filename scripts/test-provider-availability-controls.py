#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: Apache-2.0
"""Qualify availability controls by reverting them in an isolated source copy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SERVICE = 'crates/keyrack-service/src/'
MUTATIONS = [
    ('omit_exemption', 'readiness.rs', 'state.custody == ProviderCustody::Customer || state.status == "available"', 'state.status == "available"', 'readiness', 'optional_backend_outage_is_reported_without_gating_readiness', 'optional provider must not gate readiness'),
    ('name_only_exemption', 'readiness.rs', '.optional\n            .get(name)\n            .is_some_and(|configured| Arc::ptr_eq(configured, provider))', '.optional\n            .get(name)\n            .is_some_and(|configured| { let _ = (configured, provider); true })', 'readiness', 'runtime_replacement_cannot_inherit_a_readiness_exemption', 'a replacement provider must default to platform custody'),
    ('omit_platform_gate', 'rest.rs', 'let ready = storage_ok && providers_ok;', 'let ready = storage_ok;', 'readiness', 'nondefault_token_outage_fails_readiness_and_recovery_restores_it', 'healthy storage and default must not hide a named token outage'),
    ('omit_persisted_guard', 'readiness.rs', 'if connection.pkcs11_params().is_some()', 'if false && connection.pkcs11_params().is_some()', 'readiness', 'persisted_token_missing_after_rehydration_fails_readiness', 'left: 200'),
    ('default_only', 'readiness.rs', 'for (name, entry) in entries.iter().cloned() {', 'for (name, entry) in entries.iter().cloned() { if name != *providers.default_ref() { continue; }', 'readiness', 'dynamically_registered_token_participates_in_readiness', 'left: 200'),
    ('omit_probe_bound', 'readiness.rs', 'Duration::from_secs(2)', 'Duration::from_secs(60)', 'readiness', 'hung_token_is_bounded_and_does_not_starve_the_async_executor', 'readiness must finish within its 2-second budget'),
    ('hide_missing_connection', 'readiness.rs', '&& entry.class == ProviderClass::Pkcs11\n                && !custody.is_configured', '&& !custody.is_configured', 'readiness', 'wrong_class_cannot_hide_a_missing_persisted_connection', 'left: 200'),
    ('preserve_backend_denial', 'deferred_provider.rs', 'result.map_err(|_| self.unavailable())', 'result', 'deferred_provider', 'backend_permission_failure_is_unavailable_without_replaying_operations', 'backend permission refusal must map to unavailable'),
    ('omit_live_probe', 'deferred_provider.rs', 'if let Some(probe) = &self.probe {', 'if let Some(probe) = self.probe.as_ref().filter(|_| false) {', 'deferred_provider', 'live_probe_overrides_noop_readiness_and_recovers', 'called `Result::unwrap_err()` on an `Ok` value'),
    ('raise_retry_cap', 'deferred_provider.rs', 'MAX_BACKOFF: Duration = Duration::from_secs(30)', 'MAX_BACKOFF: Duration = Duration::from_secs(60)', 'deferred_provider', 'backoff_doubles_to_cap_and_drop_stops_construction', 'backoff must retry and remain capped'),
    ('omit_constructor_bound', 'deferred_provider.rs', 'ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5)', 'ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60)', 'deferred_provider', 'hung_constructor_times_out_before_retrying', 'hung construction must time out and retry'),
    ('omit_task_cancellation', 'deferred_provider.rs', 'self.initialization.abort();', 'let _ = &self.initialization;', 'deferred_provider', 'backoff_doubles_to_cap_and_drop_stops_construction', 'dropping wrapper must stop constructor task'),
    ('release_native_admission', 'deferred_provider.rs', 'let gate = gate.clone();', 'let gate = Arc::new(tokio::sync::Semaphore::new(gate.available_permits().max(1)));', 'deferred_provider', 'cancelling_native_wait_does_not_release_constructor_admission', 'cancelled native wait must retain admission'),
    ('replay_failed_operation', 'deferred_provider.rs', 'self.backend_result(self.get()?.generate_random(length).await)', 'let result = self.get()?.generate_random(length).await; if result.is_err() { let _ = self.get()?.generate_random(length).await; } self.backend_result(result)', 'deferred_provider', 'backend_permission_failure_is_unavailable_without_replaying_operations', 'failed operations must not be replayed'),
    ('omit_tenant_exemption', 'readiness.rs', 'owner\n                    .strip_prefix("tenant:")', 'owner\n                    .strip_prefix("never:")', 'readiness', 'stored_tenant_connection_that_fails_boot_does_not_gate_readiness', 'left: 503'),
    ('exempt_platform_owner', 'readiness.rs', '.strip_prefix("tenant:")', '.strip_prefix("plat")', 'readiness', 'stored_platform_owner_preserves_readiness_guard', 'left: 200'),
    ('override_configured_custody', 'readiness.rs', 'if !custody.is_configured(&name, &entry.provider) {', 'if true {', 'readiness', 'stored_tenant_outage_does_not_exempt_configured_platform_instance', 'stored tenant ownership must not exempt configured platform provider'),
    ('hide_failed_connection_collision', 'readiness.rs', '&& !custody.is_configured(entry_name, &entry.provider)', '', 'readiness', 'configured_name_collision_cannot_hide_failed_platform_connection', 'configured name collision must not hide failed persisted platform connection'),
    ('native_retry_too_early', 'provider_startup.rs', 'PKCS11_FIRST_RETRY: std::time::Duration = std::time::Duration::from_secs(30)', 'PKCS11_FIRST_RETRY: std::time::Duration = std::time::Duration::from_secs(1)', 'deferred_provider', 'native_constructor_retries_start_at_thirty_seconds_and_remain_bounded', 'backoff must not retry early'),
    ('native_retry_unbounded', 'provider_startup.rs', 'PKCS11_MAX_RETRY: std::time::Duration = std::time::Duration::from_secs(120)', 'PKCS11_MAX_RETRY: std::time::Duration = std::time::Duration::from_secs(240)', 'deferred_provider', 'native_constructor_retries_start_at_thirty_seconds_and_remain_bounded', 'backoff must retry and remain capped'),
    ('ignore_missing_module_symbols', 'provider_startup.rs', '| cryptoki::error::Error::MissingSymbol(_)', '', 'provider_startup', 'loadable_non_pkcs11_library_is_a_local_configuration_error', 'loadable non-PKCS11 library must fail locally'),
    ('omit_service_custody_extension', 'main.rs', '.layer(axum::Extension(custody_readiness))', '.layer(axum::Extension({ let _ = custody_readiness; keyrack_service::readiness::CustodyReadiness::default() }))', 'provider_service_availability', 'unreachable_optional_vault_boots_and_refuses_operations', 'optional backend must not gate readiness'),
    ('omit_service_deferred_construction', 'main.rs', '== keyrack_service::readiness::ProviderCustody::Customer', '== keyrack_service::readiness::ProviderCustody::Customer && false', 'provider_service_availability', 'unreachable_optional_vault_boots_and_refuses_operations', 'service must stay running'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'target/proofs/provider-availability')
    parser.add_argument('--native-library', type=Path)
    parser.add_argument('--target-dir', type=Path, default=ROOT / 'target')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    target = args.target_dir.resolve()
    paths = sorted({SERVICE + item[1] for item in MUTATIONS} | {
        'crates/keyrack-service/src/provider_startup.rs',
        'crates/keyrack-service/tests/readiness.rs',
        'crates/keyrack-service/tests/deferred_provider.rs',
        'crates/keyrack-service/tests/provider_startup.rs',
        'crates/keyrack-service/Cargo.toml', 'Cargo.lock',
        'scripts/test-provider-availability-controls.py',
        'crates/keyrack-pkcs11/src/provider.rs',
        'crates/keyrack-service/tests/provider_availability_live.rs',
        'crates/keyrack-service/tests/provider_service_availability.rs',
    })
    hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
    receipt = {'status': 'running', 'source_sha256': hashes, 'controls': []}
    def save():
        (output / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')
    save()
    env = os.environ | {'CARGO_PROFILE_DEV_DEBUG':'0', 'CARGO_PROFILE_TEST_DEBUG':'0', 'CARGO_INCREMENTAL':'0', 'CARGO_TERM_COLOR':'never'}
    with tempfile.TemporaryDirectory(prefix='keyrack-availability-controls-') as temp:
        copy = Path(temp) / 'source'
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns('.git', 'target', '__pycache__'))
        def run(name, suite=None, test=None):
            command = ['cargo', 'test', '--locked', '-p', 'keyrack-service', '--target-dir', str(target)]
            if suite: command += ['--test', suite, test, '--', '--exact']
            else:
                for item in ['readiness', 'deferred_provider', 'provider_startup', 'provider_service_availability']: command += ['--test', item]
            with (output / (name + '.log')).open('w') as log:
                result = subprocess.run(command, cwd=copy, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
            text = (output / (name + '.log')).read_text()
            if 'error: could not compile' in text or 'error[E' in text:
                raise AssertionError(f'{name}: compilation failure is not a control result')
            return result.returncode, text
        try:
            code, text = run('baseline')
            assert code == 0 and 'test result: ok.' in text, 'foundation baseline must pass'
            for name, file, old, new, suite, test, failure in MUTATIONS:
                path = copy / SERVICE / file
                original = path.read_text()
                assert original.count(old) == 1, f'{name}: expected exactly one mutation anchor'
                path.write_text(original.replace(old, new))
                try:
                    code, text = run(name, suite, test)
                    assert code != 0 and 'running 1 test' in text and f'{test} ... FAILED' in text and failure in text, f'{name}: missing specific expected failure'
                    receipt['controls'].append({'name':name, 'test':test, 'failure':failure, 'exit_code':code})
                    save()
                    print(f'PASS {name}: {failure}', flush=True)
                finally:
                    path.write_text(original)
            if args.native_library:
                def native(name):
                    with tempfile.TemporaryDirectory(prefix='keyrack-native-control-') as fixture:
                        fixture = Path(fixture)
                        (fixture / 'tokens').mkdir()
                        config = fixture / 'softhsm.conf'
                        config.write_text(f'directories.tokendir = {fixture}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n')
                        native_env = env | {'SOFTHSM2_CONF':str(config), 'KEYRACK_AVAILABILITY_PKCS11_LIB':str(args.native_library.resolve())}
                        command = ['cargo','test','--locked','-p','keyrack-service','--target-dir',str(target),'--test','provider_availability_live','--','--ignored','--nocapture']
                        with (output / (name+'.log')).open('w') as log:
                            result = subprocess.run(command,cwd=copy,env=native_env,stdout=log,stderr=subprocess.STDOUT,timeout=300)
                        return result.returncode, (output / (name+'.log')).read_text()
                code, text = native('native_baseline')
                assert code == 0 and '1 passed' in text, 'native baseline must pass'
                path = copy / 'crates/keyrack-pkcs11/src/provider.rs'
                original = path.read_text()
                start = original.index('        let slot = match open() {')
                end = original.index('        tracing::info!(token_label', start)
                path.write_text(original[:start]+'        let _ = generation;\n        let slot = open()?;\n'+original[end:])
                try:
                    code, text = native('omit_native_constructor_recovery')
                    failure = 'deferred native constructor must discover a token without restart'
                    assert code != 0 and failure in text and '1 failed' in text, 'native reversion must fail for late discovery'
                    receipt['controls'].append({'name':'omit_native_constructor_recovery','failure':failure,'exit_code':code})
                    save()
                    print('PASS omit_native_constructor_recovery: '+failure, flush=True)
                finally:
                    path.write_text(original)
                code, text = native('native_restored')
                assert code == 0 and '1 passed' in text, 'restored native baseline must pass'
            code, text = run('restored')
            assert code == 0 and 'test result: ok.' in text, 'restored baseline must pass'
            assert hashes == {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}, 'working source changed'
            receipt['status'] = 'passed'
        except BaseException as error:
            receipt.update(status='failed', error=str(error))
            raise
        finally:
            save()


if __name__ == '__main__':
    main()
