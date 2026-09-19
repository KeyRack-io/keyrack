#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: Apache-2.0
"""Check removed SDK methods with rustc, then reverse each deletion in isolation.

The same downstream probe must produce precisely E0599 against the actual SDK
and compile successfully after its original no-op is restored. An unrelated
compiler, dependency, or fixture failure does not count as control evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / 'crates/keyrack'
ORIGINAL_METHODS = {
    'register_namespace': '''    pub async fn register_namespace(&self, _ns: Namespace) -> Result<(), KeyRackError> {
        // TODO: wire to gRPC RegisterNamespace
        Ok(())
    }
''',
    'acknowledge_reencryption_job': '''    pub async fn acknowledge_reencryption_job(&self, _job_id: &str) -> Result<(), KeyRackError> {
        Ok(())
    }
''',
    'complete_reencryption_job': '''    pub async fn complete_reencryption_job(&self, _job_id: &str) -> Result<(), KeyRackError> {
        Ok(())
    }
''',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=600)


def library_from(build):
    if build.returncode:
        raise AssertionError('SDK build failed; dependency/setup failures cannot satisfy this control')
    artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith('{')]
    libraries = [path for artifact in artifacts
                 if artifact.get('reason') == 'compiler-artifact' and artifact.get('target', {}).get('name') == 'keyrack'
                 for path in artifact.get('filenames', []) if path.endswith('.rlib')]
    if len(libraries) != 1:
        raise AssertionError(f'expected one compiled keyrack library, found {libraries}')
    return Path(libraries[0])


def absence_failure(result, method):
    if result.returncode == 0:
        return f'REMOVED_SDK_METHOD_REINTRODUCED: {method} downstream probe compiled successfully'
    diagnostics = [json.loads(line) for line in result.stderr.splitlines() if line.startswith('{')]
    errors = [item for item in diagnostics if item.get('level') == 'error' and not item['message'].startswith('aborting due to ')]
    if result.returncode != 1 or len(errors) != 1 or (errors[0].get('code') or {}).get('code') != 'E0599' or f'no method named `{method}`' not in errors[0]['message']:
        return f'UNEXPECTED_COMPILER_FAILURE: expected only E0599 naming {method}'
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'target/proofs/sdk-removed-api')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    target = ROOT / 'target/sdk-removed-api'
    original = (SDK / 'src/lib.rs').read_text()
    inputs = [SDK / 'src/lib.rs', SDK / 'Cargo.toml', ROOT / 'Cargo.lock']
    inputs.extend(SDK / 'tests/removed_api' / f'{name}.rs' for name in ORIGINAL_METHODS)
    source_hashes = {str(path.relative_to(ROOT)): sha(path) for path in inputs}
    receipt = {'status': 'running', 'source_sha256': source_hashes, 'cases': []}

    def save():
        (args.output_dir / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def log(name, result):
        (args.output_dir / f'{name}.log').write_text(result.stdout + result.stderr)

    def probe(method, library, output):
        dependencies = library.parent if library.parent.name == 'deps' else library.parent / 'deps'
        return run(['rustc', '--edition=2021', '--error-format=json', '--crate-name', f'probe_{method}',
                    '--extern', f'keyrack={library}', '-L', f'dependency={dependencies}',
                    '--emit=metadata', '-o', str(output), str(SDK / 'tests/removed_api' / f'{method}.rs')])

    save()
    baseline_command = ['cargo', 'build', '--locked', '-p', 'keyrack', '--target-dir', str(target), '--message-format=json']
    baseline = run(baseline_command)
    log('baseline-build', baseline)
    library = library_from(baseline)
    receipt['baseline_build_command'] = baseline_command
    receipt['baseline_library_sha256'] = sha(library)
    with tempfile.TemporaryDirectory(prefix='keyrack-sdk-removal-controls-') as temp:
        project = Path(temp)
        for method in ORIGINAL_METHODS:
            result = probe(method, library, project / f'{method}.rmeta')
            log(f'{method}-removed', result)
            failure = absence_failure(result, method)
            if failure:
                raise AssertionError(f'{failure}\n{result.stderr}')
            receipt['cases'].append({'method': method, 'baseline_exit_code': result.returncode, 'baseline_error': 'E0599'})
            save()
            print(f'PASS removed {method}: sole E0599 names the absent method', flush=True)
        (project / 'src').mkdir()
        (project / 'Cargo.toml').write_text((SDK / 'Cargo.toml').read_text() + '\n[workspace]\n')
        (project / 'Cargo.lock').write_bytes((ROOT / 'Cargo.lock').read_bytes())
        for record in receipt['cases']:
            method = record['method']
            restored = original + '\nimpl KeyRack {\n' + ORIGINAL_METHODS[method] + '}\n'
            (project / 'src/lib.rs').write_text(restored)
            command = ['cargo', 'build', '--offline', '--manifest-path', str(project / 'Cargo.toml'),
                       '--target-dir', str(target), '--message-format=json']
            build = run(command)
            log(f'{method}-restored-build', build)
            restored_library = library_from(build)
            result = probe(method, restored_library, project / f'{method}-restored.rmeta')
            log(f'{method}-restored', result)
            failure = absence_failure(result, method)
            expected = f'REMOVED_SDK_METHOD_REINTRODUCED: {method} downstream probe compiled successfully'
            record.update({'restored_exit_code': result.returncode, 'restored_source_sha256': hashlib.sha256(restored.encode()).hexdigest(),
                           'restored_library_sha256': sha(restored_library), 'control_failure': failure, 'detected': failure == expected})
            (args.output_dir / f'{method}-control-failure.log').write_text((failure or 'CONTROL DID NOT FAIL') + '\n')
            save()
            if failure != expected:
                raise AssertionError(f'restoring {method} must make the same downstream probe compile, got {failure}\n{result.stderr}')
            print(f'PASS restored control: {failure}', flush=True)
    if source_hashes != {str(path.relative_to(ROOT)): sha(path) for path in inputs}:
        raise AssertionError('working SDK or probe sources changed during the proof')
    receipt['status'] = 'passed'
    receipt['working_sources_unchanged'] = True
    save()
    print('PASS three compiler-backed absence checks and three exact-method restoration controls')


if __name__ == '__main__':
    main()
