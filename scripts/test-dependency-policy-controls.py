#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify policy refusals and individually justify every baseline exception."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BIN = os.environ.get('CARGO_DENY', 'cargo-deny')


def main():
    original = (ROOT / 'deny.toml').read_text()
    config = tomllib.loads(original)
    output = ROOT / 'target/proofs/dependency-policy'
    output.mkdir(parents=True, exist_ok=True)
    receipt = {'status': 'running', 'policy_sha256': hashlib.sha256(original.encode()).hexdigest(), 'lock_sha256': hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest(), 'controls': []}
    with tempfile.TemporaryDirectory(prefix='keyrack-dependency-policy-') as temp:
        temp = Path(temp)
        policy = temp / 'deny.toml'
        policy.write_text(original)
        def run(name, check, manifest=ROOT / 'Cargo.toml', offline=True):
            command = [BIN, '--locked', '--format', 'json', '--manifest-path', str(manifest)]
            if offline:
                command += ['--offline']
            command += ['--config', str(policy), 'check', check]
            result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
            (output / (name + '.jsonl')).write_text(result.stdout)
            diagnostics = []
            for line in result.stdout.splitlines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get('type') == 'diagnostic' and row['fields'].get('severity') == 'error':
                    diagnostics.append(row['fields'])
            return result.returncode, diagnostics
        def require_refusal(name, check, code, manifest=ROOT / 'Cargo.toml', identity=None):
            status, errors = run(name, check, manifest)
            matching = [e for e in errors if e['code'] == code and (identity is None or identity in json.dumps(e))]
            assert status != 0 and matching, f'{name}: expected {code} {identity}, not tooling failure'
            receipt['controls'].append({'name': name, 'diagnostic': code, 'identity': identity, 'exit_code': status})
            print(f'PASS {name}: {code}', flush=True)
        def without_entry(key, value):
            needle = key + ' = ' + json.dumps(value)
            lines = original.splitlines(keepends=True)
            selected = [line for line in lines if needle in line and line.lstrip().startswith('{')]
            assert len(selected) == 1, f'unique exception required: {needle}'
            return original.replace(selected[0], '')
        try:
            assert run('baseline', 'all', offline=False)[0] == 0, 'baseline must pass'
            for item in config['advisories']['ignore']:
                key = 'id' if 'id' in item else 'crate'
                identity = item[key]
                policy.write_text(without_entry(key, identity))
                # Exact advisory IDs and exact yanked versions each need a real refusal.
                status, errors = run('remove-' + identity, 'advisories')
                matching = [e for e in errors if (e.get('advisory', {}).get('id') == identity if key == 'id' else e['code'] == 'yanked' and identity.split('@')[0] in json.dumps(e))]
                assert status != 0 and matching, f'{identity}: removing exception must expose that finding'
                receipt['controls'].append({'name': 'remove-' + identity, 'diagnostic': matching[0]['code'], 'exit_code': status})
                print(f'PASS remove-{identity}: {matching[0]["code"]}', flush=True)
            for item in config['bans']['skip']:
                line = '{ name = ' + json.dumps(item['name']) + ', version = ' + json.dumps(item['version']) + ' },'
                assert original.count(line) == 1
                policy.write_text(original.replace(line, ''))
                require_refusal('remove-' + item['name'] + item['version'], 'bans', 'duplicate', identity=item['name'])
            policy.write_text(original.replace('allow-registry = ["https://github.com/rust-lang/crates.io-index"]', 'allow-registry = []'))
            require_refusal('unlisted_registry', 'sources', 'source-not-allowed')
            policy.write_text(policy.read_text().replace('unknown-registry = "deny"', 'unknown-registry = "allow"'))
            assert run('reverted_registry_guard', 'sources')[0] == 0, 'reverting registry guard must expose unlisted registry'
            # Synthetic packages exercise otherwise absent bad licenses and git sources.
            fixture = temp / 'fixture'
            fixture.mkdir()
            (fixture / 'src').mkdir()
            (fixture / 'src/lib.rs').write_text('pub fn value() -> u8 { 1 }\n')
            (fixture / 'Cargo.toml').write_text('[package]\nname="policy-fixture"\nversion="0.1.0"\nedition="2021"\nlicense="LicenseRef-Unapproved"\n[workspace]\n')
            subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=fixture, check=True, capture_output=True)
            policy.write_text(original)
            require_refusal('unapproved_license', 'licenses', 'rejected', fixture / 'Cargo.toml')
            policy.write_text(original.replace('allow = [', 'allow = ["LicenseRef-Unapproved",', 1))
            assert run('reverted_license_guard', 'licenses', fixture / 'Cargo.toml')[0] == 0, 'allowing unapproved license must expose fixture'
            # Create a local Git dependency; no external code or credentials are used.
            dependency = temp / 'git-dependency'
            dependency.mkdir()
            (dependency / 'src').mkdir()
            (dependency / 'src/lib.rs').write_text('pub fn value() -> u8 { 2 }\n')
            (dependency / 'Cargo.toml').write_text('[package]\nname="git-fixture"\nversion="0.1.0"\nedition="2021"\nlicense="MIT"\n')
            for args in [['init', '--quiet'], ['add', '.'], ['-c', 'user.name=Policy fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'Create source fixture']]:
                subprocess.run(['git', *args], cwd=dependency, check=True, capture_output=True)
            url = dependency.as_uri()
            with (fixture / 'Cargo.toml').open('a') as f:
                f.write('\n[dependencies]\ngit-fixture = { git = ' + json.dumps(url) + ' }\n')
            subprocess.run(['cargo', 'generate-lockfile'], cwd=fixture, check=True, capture_output=True)
            policy.write_text(original)
            require_refusal('unapproved_git_source', 'sources', 'source-not-allowed', fixture / 'Cargo.toml')
            policy.write_text(original.replace('unknown-git = "deny"', 'unknown-git = "allow"'))
            assert run('reverted_git_guard', 'sources', fixture / 'Cargo.toml')[0] == 0, 'reverting Git guard must expose fixture'
            policy.write_text(original)
            assert run('restored', 'all')[0] == 0, 'restored baseline must pass'
            assert (ROOT / 'deny.toml').read_text() == original, 'working policy changed'
            receipt['status'] = 'passed'
        except BaseException:
            receipt['status'] = 'failed'
            raise
        finally:
            (output / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
