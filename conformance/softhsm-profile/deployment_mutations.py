#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Revert profile constraints in disposable copies, then run the same Rust tests.

No deployment or working-tree mutation occurs. The test binary is compiled once;
each negative must fail the named assertion, not compilation or fixture loading.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / 'deploy' / 'softhsm'
TOPOLOGY = 'persistent_token_has_one_replica_recreate_and_rwo'
SECRETS = 'initializer_and_service_are_nonroot_and_use_secret_files'
READINESS = 'readiness_uses_live_endpoint_with_sufficient_timeout'
CONFIG = 'shipped_config_has_persistent_pkcs11_and_no_inline_credentials'


def cases():
    """name, source, exact before/after, occurrence, test, assertion diagnostic."""
    manifest = 'deployment.yaml'
    config = 'keyrack.yaml'
    yield ('replicas', manifest, 'replicas: 1', 'replicas: 2', 0, TOPOLOGY, 'token requires one replica')
    yield ('recreate', manifest, 'type: Recreate', 'type: RollingUpdate', 0, TOPOLOGY, 'token requires Recreate')
    yield ('rwo', manifest, '[ReadWriteOnce]', '[ReadWriteMany]', 0, TOPOLOGY, 'token requires RWO')
    yield ('pvc-reference', manifest, 'claimName: keyrack-softhsm-data', 'claimName: another-pvc', 0, TOPOLOGY, 'token data must use the claimed PVC')
    for index, name in enumerate(['init', 'service']):
        yield (f'{name}-persistent-mount', manifest, 'mountPath: /var/lib/keyrack', 'mountPath: /tmp/keyrack', index, TOPOLOGY, 'initializer and service must share the persistent data directory')
    for kind in ['initContainers', 'containers']:
        yield (f'{kind}-extra-writer', manifest, f'      {kind}:\n', f'      {kind}:\n        - name: extra-writer\n', 0, TOPOLOGY, 'one initializer and one service container required')
    for key, old, new, message in [
        ('runAsNonRoot', 'true', 'false', 'pod must require nonroot'),
        ('runAsUser', '10001', '0', 'pod must use nonroot UID'),
        ('runAsGroup', '10001', '0', 'pod must use nonroot GID'),
        ('fsGroup', '10001', '0', 'PVC must use service file group'),
    ]:
        yield (key, manifest, f'{key}: {old}', f'{key}: {new}', 0, SECRETS, message)
    for index, name in enumerate(['init', 'service']):
        for key, old, new, message in [
            ('allowPrivilegeEscalation', 'false', 'true', 'privilege escalation must be disabled'),
            ('readOnlyRootFilesystem', 'true', 'false', 'image root filesystem must be read only'),
            ('drop', '[ALL]', '[NET_RAW]', 'all capabilities must be dropped'),
        ]:
            yield (f'{name}-{key}', manifest, f'{key}: {old}', f'{key}: {new}', index, SECRETS, message)
        args = 'init' if name == 'init' else 'serve'
        yield (f'{name}-entrypoint-bypass', manifest, f'args: [{args}]', f'args: [{args}]\n          command: [/bin/sh]', 0, SECRETS, 'do not bypass the locked image entrypoint')
        yield (f'{name}-mode', manifest, f'args: [{args}]', 'args: [other]', 0, SECRETS, 'entrypoint mode must be exact')
        yield (f'{name}-root-override', manifest, f'args: [{args}]\n          securityContext:', f'args: [{args}]\n          securityContext:\n            runAsUser: 0', 0, SECRETS, 'container must not override nonroot identity')
        yield (f'{name}-environment-secret', manifest, f'args: [{args}]', f'args: [{args}]\n          env: [{{name: PIN, value: synthetic-test-only}}]', 0, SECRETS, 'secrets must enter only through files')
        secret = 'init-secrets' if name == 'init' else 'service-secrets'
        yield (f'{name}-secret-mount-path', manifest, f'{{name: {secret}, mountPath: /run/secrets/keyrack, readOnly: true}}', f'{{name: {secret}, mountPath: /run/other, readOnly: true}}', 0, SECRETS, 'secret files must use the expected mount path')
        yield (f'{name}-writable-secret-files', manifest, f'{{name: {secret}, mountPath: /run/secrets/keyrack, readOnly: true}}', f'{{name: {secret}, mountPath: /run/secrets/keyrack, readOnly: false}}', 0, SECRETS, 'secret files must be read only')
        yield (f'{name}-secret-source', manifest, 'secretName: keyrack-softhsm-secrets', 'secretName: another-secret', index, SECRETS, 'credentials must come from the declared Secret')
        yield (f'{name}-secret-permissions', manifest, 'defaultMode: 288', 'defaultMode: 292', index, SECRETS, 'secret files must use restricted permissions')
        yield (f'{name}-secret-file-path', manifest, '{key: user-pin, path: user-pin}', '{key: user-pin, path: other-pin}', index, SECRETS, 'secret key and path projection must exclude SO PIN from service')
    yield ('service-extra-secret-mount', manifest, '            - {name: service-secrets, mountPath: /run/secrets/keyrack, readOnly: true}', '            - {name: service-secrets, mountPath: /run/secrets/keyrack, readOnly: true}\n            - {name: init-secrets, mountPath: /run/other, readOnly: true}', 0, SECRETS, 'container must not mount extra secret sources')
    yield ('service-mounts-so-secret', manifest, '{name: service-secrets, mountPath: /run/secrets/keyrack, readOnly: true}', '{name: init-secrets, mountPath: /run/secrets/keyrack, readOnly: true}', 0, SECRETS, 'service must mount only its restricted secret projection')
    yield ('service-projects-so-pin', manifest, '              - {key: user-pin, path: user-pin}', '              - {key: user-pin, path: user-pin}\n              - {key: so-pin, path: so-pin}', 1, SECRETS, 'secret key and path projection must exclude SO PIN from service')
    yield ('init-missing-so-pin', manifest, '              - {key: so-pin, path: so-pin}\n', '', 0, SECRETS, 'secret key and path projection must exclude SO PIN from service')
    for name, old, new, message in [
        ('endpoint', 'path: /readyz', 'path: /healthz', 'readiness must use live readyz endpoint'),
        ('port', 'httpGet: {path: /readyz, port: rest}', 'httpGet: {path: /readyz, port: grpc}', 'readiness must probe the REST listener'),
        ('timeout', 'timeoutSeconds: 5', 'timeoutSeconds: 1', 'readiness timeout must exceed provider probe budget'),
        ('failure-threshold', 'failureThreshold: 1', 'failureThreshold: 3', 'readiness must withdraw on first failure'),
    ]:
        yield (f'readiness-{name}', manifest, old, new, 0, READINESS, message)
    for name, old, new, message in [
        ('storage', 'type: sqlite', 'type: memory', 'profile metadata must persist in SQLite'),
        ('metadata-path', '/var/lib/keyrack/metadata/keyrack.db', '/tmp/keyrack.db', 'metadata must use the persistent directory'),
        ('provider', 'type: pkcs11', 'type: software', 'profile must use PKCS11 custody'),
        ('module-path', '/usr/lib/softhsm/libsofthsm2.so', '/usr/lib/arch-specific/softhsm.so', 'profile must use the stable module path'),
        ('pin-ref', 'pin_ref: file:user-pin', 'pin_ref: file:wrong-pin', 'user PIN must be a file reference'),
        ('label-ref', 'token_label_ref: file:token-label', 'token_label_ref: file:wrong-label', 'token label must be a file reference'),
        ('inline-pin', 'pin_ref: file:user-pin', 'pin_ref: file:user-pin\n  pin: synthetic-test-only', 'inline token credentials are forbidden'),
        ('inline-label', 'token_label_ref: file:token-label', 'token_label_ref: file:token-label\n  token_label: baked-label', 'inline token credentials are forbidden'),
        ('default-authorization', 'type: always_deny', 'type: always_allow', 'shipped profile must deny until authorization is configured'),
    ]:
        yield (f'config-{name}', config, old, new, 0, CONFIG, message)


def mutate(text, before, after, occurrence):
    start = 0
    for _ in range(occurrence + 1):
        position = text.find(before, start)
        if position < 0:
            raise AssertionError(f'mutation target missing: {before!r}, occurrence {occurrence}')
        start = position + len(before)
    return text[:position] + after + text[position + len(before):]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    build_command = ['cargo', 'test', '-p', 'keyrack-service', '--test', 'softhsm_deployment', '--locked', '--no-run', '--message-format=json']
    build = subprocess.run(build_command, cwd=ROOT, capture_output=True, text=True, timeout=900)
    (args.output_dir / 'build.log').write_text(build.stdout + build.stderr)
    if build.returncode:
        raise AssertionError('fixture test failed to build; this is not a successful mutation result')
    executables = []
    for line in build.stdout.splitlines():
        message = json.loads(line)
        if message.get('reason') == 'compiler-artifact' and message.get('target', {}).get('name') == 'softhsm_deployment' and message.get('executable'):
            executables.append(message['executable'])
    if len(executables) != 1:
        raise AssertionError(f'expected one fixture test binary, found {executables}')
    binary = executables[0]
    env = dict(os.environ)
    env.pop('KEYRACK_SOFTHSM_PROFILE_FIXTURE', None)
    baseline = subprocess.run([binary, '--nocapture'], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    (args.output_dir / 'baseline.log').write_text(baseline.stdout + baseline.stderr)
    if baseline.returncode or '4 passed; 0 failed' not in baseline.stdout:
        raise AssertionError('checked-in deployment baseline must pass all four tests')
    originals = {name: (PROFILE / name).read_text() for name in ['deployment.yaml', 'keyrack.yaml']}
    records = []
    for name, source, before, after, occurrence, test, diagnostic in cases():
        with tempfile.TemporaryDirectory(prefix='keyrack-deployment-mutant-') as temp:
            fixture = Path(temp)
            for filename, contents in originals.items():
                (fixture / filename).write_text(mutate(contents, before, after, occurrence) if filename == source else contents)
            mutant_env = {**env, 'KEYRACK_SOFTHSM_PROFILE_FIXTURE': str(fixture)}
            command = [binary, test, '--exact', '--nocapture']
            result = subprocess.run(command, cwd=ROOT, env=mutant_env, capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
            (args.output_dir / f'{name}.log').write_text(output)
            failed_assertion = result.returncode == 101 and f'test {test} ... FAILED' in result.stdout and diagnostic in output
            records.append({'case': name, 'file': source, 'before': before, 'after': after, 'occurrence': occurrence, 'test': test, 'command': command, 'expected_assertion': diagnostic, 'exit_code': result.returncode, 'detected': failed_assertion})
            receipt = {'source_sha256': {path: hashlib.sha256(contents.encode()).hexdigest() for path, contents in originals.items()}, 'build_command': build_command, 'baseline_passed': True, 'cases': records}
            (args.output_dir / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')
            if not failed_assertion:
                raise AssertionError(f'{name}: expected named assertion failure, got:\n{output}')
            print(f'PASS {name}: {diagnostic}')
    print(f'PASS: {len(records)} isolated profile mutations detected; working tree unchanged')


if __name__ == '__main__':
    main()
