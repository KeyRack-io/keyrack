#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: Apache-2.0
"""Run demo 08 and prove the depth-one oracle independently of API create.

The service refuses a grandchild at create, so the archived three-level
script cannot finish its protocol. That archive is retained as provenance.
The independent oracle is proven against a reparented-sibling graph that
keeps 3/1/2 cardinality and is depth 2. Removing only the depth gate from
that oracle must accept the forbidden graph.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / 'demos/08-cascade-rotation'
FIXTURES = ROOT / 'conformance/demo08'
ORACLE = DEMO / 'scripts/check-depth.py'
ORACLE_CALL = '  python3 /scripts/check-depth.py "$BASE"\n'
DEPTH_GATE = (
    '    if depth > 1:\n'
    '        raise ValueError(f\'DEMO08_DEPTH_EXCEEDED: depth={depth}; chain={json.dumps(deepest)}\')\n'
)
GRANDCHILD_STATUS = 'HTTP status: 409'
GRANDCHILD_KIND = 'FailedPrecondition'
GRANDCHILD_REASON = 'a wrapped key cannot itself wrap children'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_check_graph(source):
    spec = importlib.util.spec_from_loader('check_depth', loader=None)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, str(ORACLE), 'exec'), module.__dict__)
    return module.check_graph


def reparented_sibling_graph():
    """One root, two children, then one child reparented under the other."""
    root, first, second = ('root-lid', 'child-lid', 'sibling-lid')
    siblings = {
        'items': [
            {'lid': root, 'parent_lid': None},
            {'lid': first, 'parent_lid': root},
            {'lid': second, 'parent_lid': root},
        ],
        'next_cursor': None,
    }
    reparented = {
        'items': [
            {'lid': root, 'parent_lid': None},
            {'lid': first, 'parent_lid': root},
            {'lid': second, 'parent_lid': first},
        ],
        'next_cursor': None,
    }
    return siblings, reparented


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'target/proofs/demo08-depth')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    paths = [Path(__file__).resolve(), ROOT / 'Cargo.lock', ROOT / 'docker/Dockerfile.service']
    paths.extend(path for path in DEMO.rglob('*') if path.is_file() and '__pycache__' not in path.parts)
    paths.extend(path for path in FIXTURES.rglob('*') if path.is_file())
    source_hashes = {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}
    receipt = {'status': 'running', 'service_evidence': 'isolated-real-compose',
               'source_sha256': source_hashes, 'cases': [],
               'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()}

    def save():
        (output / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def run(name, command, timeout=900):
        receipt.setdefault('commands', []).append({'name': name, 'argv': command})
        save()
        with (output / f'{name}.log').open('w') as log:
            try:
                result = subprocess.run(command, cwd=ROOT, text=True, stdout=log,
                                        stderr=subprocess.STDOUT, timeout=timeout)
            except subprocess.TimeoutExpired:
                log.write(f'\nDEMO08_SETUP_FAILURE: command timed out after {timeout}s\n')
                raise
        return result.returncode, (output / f'{name}.log').read_text()

    original = (FIXTURES / 'run-demo-depth-two.sh').read_text()
    provenance = json.loads((FIXTURES / 'provenance.json').read_text())
    if sha(FIXTURES / 'run-demo-depth-two.sh') != provenance['sha256']:
        raise AssertionError('negative fixture differs from its archived original')
    if 'parent_key_id' not in original or 'grandchild' not in original:
        raise AssertionError('archived fixture must still be the three-level create script')
    baseline = (DEMO / 'scripts/run-demo.sh').read_text()
    if baseline.count(ORACLE_CALL) != 1:
        raise AssertionError('actual demo must call its independent graph oracle exactly once')
    oracle_source = ORACLE.read_text()
    if oracle_source.count(DEPTH_GATE) != 1:
        raise AssertionError('oracle must contain exactly one depth gate')
    check_graph = load_check_graph(oracle_source)
    siblings, reparented = reparented_sibling_graph()
    if check_graph(siblings) != 'DEMO08_DEPTH_OK: nodes=3 roots=1 edges=2 depth=1':
        raise AssertionError('oracle must accept the sibling graph before compose runs')
    try:
        check_graph(reparented)
    except ValueError as error:
        if 'DEMO08_DEPTH_EXCEEDED: depth=2;' not in str(error):
            raise AssertionError(f'reparented siblings must fail at depth two, got {error}') from error
    else:
        raise AssertionError('reparented siblings must fail at computed depth two')
    ungated = load_check_graph(oracle_source.replace(DEPTH_GATE, '', 1))
    if ungated(reparented) != 'DEMO08_DEPTH_OK: nodes=3 roots=1 edges=2 depth=2':
        raise AssertionError('removing only the depth gate must expose the reparented graph')
    receipt['oracle'] = {
        'sibling_graph': 'DEMO08_DEPTH_OK',
        'reparented_control': 'DEMO08_DEPTH_EXCEEDED: depth=2',
        'depth_gate_removed': 'DEMO08_DEPTH_CONTROL_REMOVED: forbidden depth-two graph accepted',
    }
    save()
    token = uuid.uuid4().hex[:12]
    project_prefix = f'keyrack-demo08-{token}'
    service_image = f'keyrack-demo08-service:{token}'
    demo_image = f'keyrack-demo08-runner:{token}'
    try:
        with tempfile.TemporaryDirectory(prefix='keyrack-demo08-depth-') as temp:
            temp_root = Path(temp)
            image_override = temp_root / 'images.json'
            image_override.write_text(json.dumps({'services': {
                'keyrack': {'image': service_image}, 'demo': {'image': demo_image}}}))

            def compose(project, override=None):
                command = ['docker', 'compose', '--project-name', project,
                           '--project-directory', str(DEMO), '-f', str(DEMO / 'docker-compose.yml'),
                           '-f', str(image_override)]
                if override:
                    command += ['-f', str(override)]
                return command

            build_project = project_prefix + '-build'
            code, _ = run('build', compose(build_project) + ['build'], timeout=1800)
            if code:
                raise AssertionError('DEMO08_SETUP_FAILURE: image build failed; no control proven')
            code, image_state = run('built-images', ['docker', 'image', 'inspect', '--format', '{{.Id}}', service_image, demo_image])
            if code or len(image_state.splitlines()) != 2:
                raise AssertionError('DEMO08_SETUP_FAILURE: could not identify built images')
            receipt['built_image_ids'] = dict(zip(['service', 'demo'], image_state.splitlines()))
            save()
            name = 'baseline'
            scripts = temp_root / name
            shutil.copytree(DEMO / 'scripts', scripts, ignore=shutil.ignore_patterns('__pycache__'))
            (scripts / 'run-demo.sh').write_text(baseline)
            override = temp_root / f'{name}.json'
            override.write_text(json.dumps({'services': {'demo': {'volumes': [{
                'type': 'bind', 'source': str(scripts), 'target': '/scripts', 'read_only': True}]}}}))
            project = project_prefix + '-' + name
            command = compose(project, override)
            record = {'name': name, 'project': project,
                      'demo_source_sha256': hashlib.sha256(baseline.encode()).hexdigest()}
            receipt['cases'].append(record)
            save()
            try:
                code, _ = run(name + '-up', command + ['up', '--no-build', '--abort-on-container-exit',
                                                      '--exit-code-from', 'demo'], timeout=900)
                logs_code, logs = run(name + '-demo', command + ['logs', '--no-color', '--no-log-prefix', 'demo'])
                state_code, state = run(name + '-state', command + ['ps', '--all', '--format', 'json', 'demo'])
                if state_code or logs_code:
                    raise AssertionError(f'DEMO08_SETUP_FAILURE: could not inspect {name}')
                states = json.loads(state) if state.lstrip().startswith('[') else [json.loads(line) for line in state.splitlines() if line.startswith('{')]
                if len(states) != 1 or states[0].get('State') != 'exited':
                    raise AssertionError(f'DEMO08_SETUP_FAILURE: {name} has no exited demo container')
                exit_code = states[0].get('ExitCode')
                record.update({'compose_exit_code': code, 'demo_exit_code': exit_code,
                               'demo_log_sha256': sha(output / f'{name}-demo.log')})
                if code != 0 or exit_code != 0:
                    raise AssertionError(f'{name}: expected demo and compose exit 0, got {exit_code}/{code}')
                summaries = re.findall(r'Results: (\d+)/(\d+) checks passed', logs)
                if len(summaries) != 1 or summaries[0][0] != summaries[0][1] or int(summaries[0][0]) == 0:
                    raise AssertionError(f'{name}: demo protocol assertions must all pass')
                if 'All checks passed!' not in logs or 'DEMO08_ORACLE_SETUP_FAILURE' in logs:
                    raise AssertionError(f'{name}: setup/protocol failure does not prove a depth control')
                if 'DEMO08_DEPTH_OK: nodes=3 roots=1 edges=2 depth=1' not in logs or 'DEMO08_DEPTH_EXCEEDED' in logs:
                    raise AssertionError('baseline: live graph oracle did not confirm depth one')
                if GRANDCHILD_STATUS not in logs or GRANDCHILD_KIND not in logs or GRANDCHILD_REASON not in logs:
                    raise AssertionError(
                        'baseline: grandchild create must be HTTP 409 FailedPrecondition '
                        'because a wrapped key cannot itself wrap children'
                    )
                record['result'] = 'DEMO08_DEPTH_OK'
                record['grandchild_refusal'] = '409 FailedPrecondition: a wrapped key cannot itself wrap children'
                record['status'] = 'passed'
                save()
                print(f'PASS {name}: {record["result"]}', flush=True)
                print('PASS reparented-sibling: DEMO08_DEPTH_EXCEEDED: depth=2', flush=True)
                print('PASS depth-guard-removed: forbidden depth-two graph accepted', flush=True)
            finally:
                run(name + '-service', command + ['logs', '--no-color', 'keyrack'])
                cleanup, _ = run(name + '-cleanup', command + ['down', '--volumes', '--remove-orphans'])
                if cleanup:
                    raise AssertionError(f'DEMO08_SETUP_FAILURE: cleanup failed for own project {project}')
    except Exception as error:
        receipt['status'] = 'failed'
        receipt['error'] = str(error)
        save()
        raise
    finally:
        run('cleanup-images', ['docker', 'image', 'rm', service_image, demo_image])
    if source_hashes != {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}:
        raise AssertionError('working sources changed during demo proof')
    receipt.update({'status': 'passed', 'working_sources_unchanged': True})
    save()
    print('PASS actual depth-one demo, reparented-sibling depth gate, and reversed depth guard')


if __name__ == '__main__':
    main()
