#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: Apache-2.0
"""Revert deferred TLS controls against the runner's owned Vault fixture."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SERVICE = 'crates/keyrack-service/src/'
SUITE = 'provider_service_availability'
TRUST = 'optional_vault_uses_configured_ca_for_construction_and_readiness'
REFUSAL = 'optional_vault_tls_verification_failure_is_reported_without_gating'
LOCAL = 'missing_or_invalid_optional_vault_ca_fails_startup'
MUTATIONS = [
    ('omit_ca_pass_through', 'provider_startup.rs', '                            ca.as_deref(),', '                            { let _ = &ca; None },', TRUST, 'deferred Vault must use configured CA for construction and probes'),
    ('omit_ca_preflight', 'provider_startup.rs', 'validate_vault_ca(ca_cert.as_deref())?;', 'if false { validate_vault_ca(ca_cert.as_deref())?; }', LOCAL, 'missing or invalid CA must fail startup instead of retrying: missing.pem'),
    ('allow_empty_ca_bundle', 'provider_startup.rs', 'if certificates.is_empty() {', 'if false && certificates.is_empty() {', LOCAL, 'missing or invalid CA must fail startup instead of retrying: invalid.pem'),
    ('omit_ca_der_validation', 'provider_startup.rs', 'builder\n            .build()', '{ let _ = builder; reqwest::Client::builder() }\n            .build()', LOCAL, 'missing or invalid CA must fail startup instead of retrying: invalid-der.pem'),
    ('hide_tls_classification', 'deferred_provider.rs', 'message.starts_with("vault health check failed: TLS verification failed:")', 'message.starts_with("not-a-tls-failure:")', REFUSAL, 'TLS verification failure must be reported as readiness reason'),
    ('hide_readiness_reason', 'readiness.rs', 'state.reason = reason;', 'state.reason = None;', REFUSAL, 'TLS verification failure must be reported as readiness reason'),
]


def main():
    for name in ['KEYRACK_VAULT_TLS_ADDR', 'KEYRACK_VAULT_CA_CERT', 'KEYRACK_VAULT_OTHER_CA_CERT', 'KEYRACK_VAULT_CA_BUNDLE', 'VAULT_TOKEN']:
        assert os.environ.get(name), f'{name}: run through scripts/test-vault-provider.sh'
    output = ROOT / 'target/proofs/vault-availability'
    output.mkdir(parents=True, exist_ok=True)
    target = ROOT / 'target'
    paths = {SERVICE+item[1] for item in MUTATIONS} | {'crates/keyrack-service/tests/'+SUITE+'.rs', 'scripts/test-vault-availability-controls.py', 'Cargo.lock'}
    hashes = {p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sorted(paths)}
    receipt = {'status':'running', 'source_sha256':hashes, 'controls':[]}
    def save():
        (output/'results.json').write_text(json.dumps(receipt,indent=2)+'\n')
    save()
    env = os.environ | {'CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0','CARGO_INCREMENTAL':'0','CARGO_TERM_COLOR':'never'}
    with tempfile.TemporaryDirectory(prefix='keyrack-vault-availability-') as temp:
        copy = Path(temp)/'source'
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns('.git','target','run','__pycache__'))
        def run(name, test):
            command = ['cargo','test','--locked','-p','keyrack-service','--target-dir',str(target),'--test',SUITE,test,'--','--ignored','--exact','--nocapture']
            with (output/(name+'.log')).open('w') as log:
                result = subprocess.run(command,cwd=copy,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
            text = (output/(name+'.log')).read_text()
            assert 'error: could not compile' not in text and 'running 1 test' in text, f'{name}: compilation or discovery failure is not control evidence'
            return result.returncode, text
        try:
            for test in [TRUST,REFUSAL,LOCAL]:
                code,text = run('baseline-'+test,test)
                assert code == 0 and '1 passed' in text, f'baseline failed: {test}'
            for name,file,old,new,test,diagnostic in MUTATIONS:
                path = copy/SERVICE/file
                original = path.read_text()
                assert original.count(old)==1, f'{name}: mutation anchor drift'
                path.write_text(original.replace(old,new))
                try:
                    code,text = run(name,test)
                    assert code!=0 and '1 failed' in text and diagnostic in text, f'{name}: missing specific failure'
                    receipt['controls'].append({'name':name,'failure':diagnostic,'exit_code':code})
                    save()
                    print(f'PASS {name}: {diagnostic}',flush=True)
                finally:
                    path.write_text(original)
            for test in [TRUST,REFUSAL,LOCAL]:
                code,text = run('restored-'+test,test)
                assert code==0 and '1 passed' in text, f'restored baseline failed: {test}'
            assert hashes=={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in hashes}, 'working source changed'
            receipt['status']='passed'
        except BaseException as error:
            receipt.update(status='failed',error=str(error))
            raise
        finally:
            save()


if __name__ == '__main__':
    main()
