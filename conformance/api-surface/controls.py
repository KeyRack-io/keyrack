#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Inject exact interface drift and remove guards in isolated copies.

protoc and syn remain the independent source enumerators. Compilation/setup
errors never count as evidence. No working-tree source is modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = 'conformance/api-surface/contract.json'
REST = 'crates/keyrack-service/src/rest.rs'
GRPC = 'crates/keyrack-service/src/grpc.rs'
MAIN = 'crates/keyrack-service/src/main.rs'
CHECKER = 'crates/keyrack-surface-contract/src/main.rs'
PROTO = 'proto/keyrack/v1/key_service.proto'
MARKDOWN = 'docs/generated/api-surface-parity.md'
ARTIFACT = 'docs/generated/api-surface-parity.json'


def replace(root, path, old, new):
    file = root / path
    text = file.read_text()
    assert text.count(old) == 1, f'changed mutation anchor: {path}: {old}'
    file.write_text(text.replace(old, new, 1))


def contract(root, mutate):
    path = root / CONTRACT
    value = json.loads(path.read_text())
    mutate(value)
    path.write_text(json.dumps(value, indent=2) + '\n')


def operation(value, name):
    return next(item for item in value['operations'] if item['rpc'] == name)


def feature_divergence(root):
    # Keep REST's own handler/route declarations internally consistent while
    # removing its feature gate; only cross-interface feature binding rejects it.
    path = root / REST
    path.write_text(path.read_text().replace('#[cfg(feature = "crypto-endpoints")]', ''))
    def ungate(value):
        for item in value['operations']:
            if item['rest'] is not None:
                item['rest']['feature'] = None
    contract(root, ungate)


def cases():
    return [
        ('added-rpc', 'RPC_COVERAGE', lambda r: replace(r, PROTO, 'service KeyService {', 'service KeyService {\n  rpc Unlisted(EncryptRequest) returns (EncryptResponse);')),
        ('removed-rpc', 'RPC_COVERAGE', lambda r: replace(r, PROTO, '  rpc Encrypt(EncryptRequest) returns (EncryptResponse);', '')),
        ('unlisted-service', 'SERVICE_COVERAGE', lambda r: (r / PROTO).write_text((r / PROTO).read_text() + '\nservice UnlistedService { rpc Ping(EncryptRequest) returns (EncryptResponse); }\n')),
        ('omitted-rpc-entry', 'RPC_COVERAGE', lambda r: contract(r, lambda v: v['operations'].remove(operation(v, 'GetKeyMaterial')))),
        ('duplicate-rpc-entry', 'RPC_DUPLICATE', lambda r: contract(r, lambda v: v['operations'].append(dict(operation(v, 'GetKeyMaterial'))))),
        ('missing-gap', 'GAP_REQUIRED', lambda r: contract(r, lambda v: operation(v, 'GetKeyMaterial').update(gap=None))),
        ('empty-gap-reason', 'GAP_REASON', lambda r: contract(r, lambda v: operation(v, 'GetKeyMaterial')['gap'].update(reason=''))),
        ('unknown-gap-kind', 'GAP_KIND', lambda r: contract(r, lambda v: operation(v, 'GetKeyMaterial')['gap'].update(kind='wildcard'))),
        ('empty-operational-reason', 'REST_ONLY_REASON', lambda r: contract(r, lambda v: v['rest_only'][0].update(reason=''))),
        ('feature-surface-divergence', 'FEATURE_BINDING', feature_divergence),
        ('mounted-service-misclassified', 'SERVICE_ROLE', lambda r: contract(r, lambda v: v['services']['keyrack.v1.KeyService'].update(role='external_dependency'))),
        ('unknown-schema-field', 'CONTRACT_SCHEMA', lambda r: contract(r, lambda v: v.update(unrecognized=True))),
        ('wrong-grpc-binding', 'request does not bind descriptor type', lambda r: contract(r, lambda v: operation(v, 'Encrypt').update(grpc_handler='decrypt'))),
        ('unlisted-rest-route', 'REST_COVERAGE', lambda r: replace(r, REST, '.route("/readyz", get(readyz))', '.route("/readyz", get(readyz)).route("/unlisted", get(readyz))')),
        ('removed-rest-route', 'REST_COVERAGE', lambda r: replace(r, REST, '.route("/readyz", get(readyz))', '')),
        ('changed-rest-method', 'REST_COVERAGE', lambda r: replace(r, REST, '.route("/readyz", get(readyz))', '.route("/readyz", post(readyz))')),
        ('changed-rest-path', 'REST_COVERAGE', lambda r: replace(r, REST, '.route("/readyz", get(readyz))', '.route("/readiness", get(readyz))')),
        ('wrong-rest-handler', 'REST_BINDING', lambda r: replace(r, REST, '.route("/readyz", get(readyz))', '.route("/readyz", get(healthz))')),
        ('duplicate-rest-route', 'duplicate', lambda r: replace(r, REST, '.route("/readyz", get(readyz))', '.route("/readyz", get(readyz)).route("/readyz", get(readyz))')),
        ('feature-contract-drift', 'FEATURE_BINDING', lambda r: contract(r, lambda v: operation(v, 'Encrypt')['rest'].update(feature=None))),
        ('removed-crypto-route-gate', 'REST handler/route cfg mismatch', lambda r: replace(r, REST, '#[cfg(feature = "crypto-endpoints")]\n    let r = r', 'let r = r')),
        ('changed-namespace-stub', 'STUB_DRIFT', lambda r: replace(r, GRPC, 'namespace registered (in-memory only)', 'namespace behavior changed')),
        ('hidden-route-composition', 'unsupported service router composition: merge', lambda r: replace(r, REST, '.with_state(state)', '.merge(Router::new()).with_state(state)')),
        ('dynamic-route-path', 'literal', lambda r: replace(r, REST, '.route("/readyz", get(readyz))', '.route(UNREVIEWED_PATH, get(readyz))')),
        ('unmounted-rest-router', 'main no longer constructs the inventoried rest::router', lambda r: replace(r, MAIN, 'keyrack_service::rest::router(Arc::clone(&state))', 'axum::Router::new()')),
        ('altered-markdown-claim', 'GENERATED_DRIFT', lambda r: replace(r, MARKDOWN, '## REST / gRPC surface availability', '## All operations are identical')),
        ('altered-json-artifact', 'GENERATED_DRIFT', lambda r: (r / ARTIFACT).write_text('{}\n')),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error('output directory must be empty; preserve earlier evidence')
    receipt = {'status': 'running', 'cases': [], 'guard_removals': []}

    def save():
        (output / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def run(name, command):
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=600)
        data = result.stdout + result.stderr
        (output / (name + '.log')).write_text(data)
        return result.returncode, data, hashlib.sha256(data.encode()).hexdigest()

    save()
    code, log, _ = run('build', ['cargo', 'build', '--locked', '-p', 'keyrack-surface-contract'])
    if code:
        raise SystemExit('baseline build failed; not control evidence\n' + log)
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version=1'], cwd=ROOT))
    binary = Path(metadata['target_directory']) / 'debug/keyrack-surface-contract'
    code, log, _ = run('baseline', [str(binary), '--check'])
    if code or 'PASS surface contract:' not in log:
        raise SystemExit('baseline contract failed\n' + log)
    paths = [CONTRACT, REST, GRPC, MAIN, PROTO, MARKDOWN, ARTIFACT, CHECKER, "crates/keyrack-surface-contract/src/extract.rs"]
    original = {path: (ROOT / path).read_bytes() for path in paths}
    receipt['source_sha256'] = {path: hashlib.sha256(data).hexdigest() for path, data in original.items()}
    receipt['baseline_passed'] = True
    with tempfile.TemporaryDirectory(prefix='keyrack-surface-controls-') as temporary:
        project = Path(temporary) / 'source'
        shutil.copytree(ROOT, project, copy_function=shutil.copy,
            ignore=shutil.ignore_patterns('.git', 'target', '.aikdb', 'node_modules', '.venv', '__pycache__'))

        def reset():
            for path, data in original.items():
                (project / path).write_bytes(data)

        fixture_cases = cases()
        for name, diagnostic, mutate in fixture_cases:
            reset()
            mutate(project)
            code, log, digest = run(name, [str(binary), '--root', str(project), '--check'])
            if code != 1 or 'FAIL ' not in log or diagnostic not in log:
                raise SystemExit(f'{name}: expected {diagnostic}; unrelated result is not evidence\n{log}')
            receipt['cases'].append(dict(name=name, diagnostic=diagnostic, exit_code=code, log=name+'.log', sha256=digest))
            save()
            print(f'KILLED {name}: {diagnostic}', flush=True)

        # Remove the actual guard, then require the test for its forbidden input
        # to fail. --write isolates source validation from output-staleness checks.
        guards = [
            ('coverage-guard', 'added-rpc', 'if actual == expected', 'if true', '--write'),
            ('reason-guard', 'empty-gap-reason', 'if text.trim().is_empty()', 'if false', '--write'),
            ('rest-binding-guard', 'wrong-rest-handler', 'if routes[&key] != expected', 'if false && routes[&key] != expected', '--write'),
            ('feature-binding-guard', 'feature-surface-divergence', 'if route.feature.as_deref()', 'if false && route.feature.as_deref()', '--write'),
            ('stub-drift-guard', 'changed-namespace-stub', 'if hash == &method.body_sha256', 'if true', '--write'),
            ('generated-claim-guard', 'altered-markdown-claim', 'else if read(&path)? != expected.as_bytes()', 'else if false && read(&path)? != expected.as_bytes()', '--check'),
        ]
        for name, case_name, old, new, mode in guards:
            reset()
            _, diagnostic, mutate = next(case for case in fixture_cases if case[0] == case_name)
            mutate(project)
            code, log, _ = run(name+'-baseline', [str(binary), '--root', str(project), mode])
            if code != 1 or diagnostic not in log:
                raise SystemExit(name+': forbidden input must fail before guard removal\n'+log)
            replace(project, CHECKER, old, new)
            target = ROOT / 'target/surface-control-build'
            code, log, _ = run(name+'-build', ['cargo', 'build', '--locked', '--manifest-path', str(project/'Cargo.toml'), '-p', 'keyrack-surface-contract', '--target-dir', str(target)])
            if code:
                raise SystemExit(name+': mutant compilation is not evidence\n'+log)
            mutant = target/'debug/keyrack-surface-contract'
            code, log, digest = run(name, [str(mutant), '--root', str(project), mode])
            if code != 0 or 'PASS surface contract:' not in log:
                raise SystemExit(name+': removed guard did not admit the exact forbidden input\n'+log)
            failure = f'CONTROL_{name}: expected rejection of {case_name}; removed guard admitted it'
            receipt['guard_removals'].append(dict(name=name, forbidden_input=case_name, expected_failure=failure, actual_exit_code=code, log=name+'.log', sha256=digest))
            save()
            print('KILLED '+failure, flush=True)
        reset()
    for path, data in original.items():
        assert (ROOT/path).read_bytes() == data, 'working-tree source changed during controls: '+path
    receipt['status'] = 'passed'
    save()
    print(f"PASS {len(receipt['cases'])} interface/claim mutations and {len(receipt['guard_removals'])} guard removals", flush=True)


if __name__ == '__main__':
    main()
