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
    ('name_only_exemption', 'readiness.rs', '.is_some_and(|configured| Arc::ptr_eq(configured, provider))', '.is_some_and(|configured| { let _ = (configured, provider); true })', 'readiness', 'runtime_replacement_cannot_inherit_a_readiness_exemption', 'a replacement provider must default to platform custody'),
    ('omit_platform_gate', 'rest.rs', 'let ready = storage_ok && providers_ok;', 'let ready = storage_ok;', 'readiness', 'nondefault_token_outage_fails_readiness_and_recovery_restores_it', 'healthy storage and default must not hide a named token outage'),
    ('omit_persisted_guard', 'readiness.rs', 'if connection.pkcs11_params().is_some()', 'if false && connection.pkcs11_params().is_some()', 'readiness', 'persisted_token_missing_after_rehydration_fails_readiness', 'left: 200'),
    ('default_only', 'readiness.rs', 'for (name, entry) in entries.iter().cloned() {', 'for (name, entry) in entries.iter().cloned() { if name != *providers.default_ref() { continue; }', 'readiness', 'dynamically_registered_token_participates_in_readiness', 'left: 200'),
    ('omit_probe_bound', 'readiness.rs', 'Duration::from_secs(2)', 'Duration::from_secs(60)', 'readiness', 'hung_token_is_bounded_and_does_not_starve_the_async_executor', 'readiness must finish within its 2-second budget'),
    ('hide_missing_connection', 'readiness.rs', 'if state.status != "missing" {', 'if true {', 'readiness', 'wrong_class_cannot_hide_a_missing_persisted_connection', 'a healthy wrong-class provider must not hide the missing connection'),
    ('preserve_backend_denial', 'deferred_provider.rs', 'result.map_err(|_| self.unavailable())', 'result', 'deferred_provider', 'backend_permission_failure_is_unavailable_without_replaying_operations', 'backend permission refusal must map to unavailable'),
    ('omit_live_probe', 'deferred_provider.rs', 'if let Some(probe) = &self.probe {', 'if let Some(probe) = self.probe.as_ref().filter(|_| false) {', 'deferred_provider', 'live_probe_overrides_noop_readiness_and_recovers', 'called `Result::unwrap_err()` on an `Ok` value'),
    ('raise_retry_cap', 'deferred_provider.rs', 'MAX_BACKOFF: Duration = Duration::from_secs(30)', 'MAX_BACKOFF: Duration = Duration::from_secs(60)', 'deferred_provider', 'backoff_doubles_to_cap_and_drop_stops_construction', 'backoff must retry and remain capped'),
    ('omit_constructor_bound', 'deferred_provider.rs', 'ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5)', 'ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60)', 'deferred_provider', 'hung_constructor_times_out_before_retrying', 'hung construction must time out and retry'),
    ('omit_task_cancellation', 'deferred_provider.rs', 'self.initialization.abort();', 'let _ = &self.initialization;', 'deferred_provider', 'backoff_doubles_to_cap_and_drop_stops_construction', 'dropping wrapper must stop constructor task'),
    ('release_native_admission', 'deferred_provider.rs', 'let gate = gate.clone();', 'let gate = Arc::new(tokio::sync::Semaphore::new(gate.available_permits().max(1)));', 'deferred_provider', 'cancelling_native_wait_does_not_release_constructor_admission', 'cancelled native wait must retain admission'),
    ('replay_failed_operation', 'deferred_provider.rs', 'self.backend_result(self.get()?.generate_random(length).await)', 'let result = self.get()?.generate_random(length).await; if result.is_err() { let _ = self.get()?.generate_random(length).await; } self.backend_result(result)', 'deferred_provider', 'backend_permission_failure_is_unavailable_without_replaying_operations', 'failed operations must not be replayed'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'target/proofs/provider-availability')
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
                for item in ['readiness', 'deferred_provider', 'provider_startup']: command += ['--test', item]
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
