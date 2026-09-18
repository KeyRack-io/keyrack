#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check the real Compose quickstart and revert each field/assertion correction.

Requires an already running isolated development service. A local forwarding
proxy changes one response only for assertion controls; all API requests still
reach that real service. Only temporary script copies are mutated.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'examples/quickstart.sh'
SUCCESS = 'All checks passed.'
LIST_ERROR = 'List response must contain an items array including the created key'
DESCRIBE_ERROR = 'Describe response must report enabled AES256 key'


class ResponseFault:
    def __init__(self, upstream, mode):
        self.upstream, self.mode, self.hits, self.requests = upstream.rstrip('/'), mode, 0, []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                request = urllib.request.Request(owner.upstream + self.path,
                    data=body if self.command == 'POST' else None,
                    headers={'Content-Type': 'application/json'}, method=self.command)
                try:
                    response = urllib.request.urlopen(request, timeout=20)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    payload = response.read()
                    status = response.status
                owner.requests.append({'method': self.command, 'path': self.path, 'status': status})
                if status == 200 or status == 201:
                    value = json.loads(payload)
                    changed = False
                    if owner.mode.startswith('list-') and self.command == 'GET' and self.path == '/v1/keys':
                        if owner.mode == 'list-missing-array':
                            value.pop('items', None)
                        else:
                            value['items'] = []
                        changed = True
                    elif owner.mode.startswith('describe-') and self.path.endswith('/describe'):
                        value['state' if owner.mode == 'describe-state' else 'key_spec'] = 'wrong'
                        changed = True
                    elif owner.mode == 'signing-key-lid' and self.command == 'POST' and self.path == '/v1/keys' and json.loads(body).get('key_spec') == 'ED25519':
                        value.pop('lid', None)
                        changed = True
                    elif owner.mode == 'signature' and self.path.endswith('/actions-sign'):
                        value.pop('signature', None)
                        changed = True
                    if changed:
                        owner.hits += 1
                        payload = json.dumps(value).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def execute(script, url):
    env = {**os.environ, 'KEYRACK_REST_URL': url}
    return subprocess.run(['bash', str(script)], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=90)


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise AssertionError(f'control needs exactly one source match: {old!r}')
    return source.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default=os.environ.get('KEYRACK_REST_URL', 'http://127.0.0.1:8080'))
    parser.add_argument('--service-evidence', default='existing-live-service', help='Evidence label, e.g. documented-compose or native-diagnostic')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'target/proofs/quickstart/controls')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    source = SCRIPT.read_text()
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    receipt = {'source_sha256': source_hash, 'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'service_evidence': args.service_evidence, 'base_url': args.base_url, 'baseline_passed': False, 'cases': []}

    def save():
        (args.output_dir / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def log(name, result):
        (args.output_dir / f'{name}.log').write_text(result.stdout + result.stderr)

    save()
    baseline = execute(SCRIPT, args.base_url)
    log('baseline', baseline)
    required = ['Key created:', 'Encrypted (', "Decrypted: 'hello keyrack'", 'key(s) in the system',
                'State: enabled, Spec: AES256', 'Signing key:', 'Signature:', 'Signature valid', SUCCESS]
    if baseline.returncode or not all(marker in baseline.stdout for marker in required):
        raise AssertionError('real quickstart baseline failed or omitted a required assertion result')
    receipt['baseline_passed'] = True
    save()
    request_lines = [line for line in source.splitlines() if line.startswith('    -d ') and 'signing_algorithm' in line]
    assert len(request_lines) == 2
    fields = [
        ('signing-request-field', replace_once(source, request_lines[0], request_lines[0].replace('signing_algorithm', 'algorithm', 1)), 'Signing request failed:'),
        ('verification-request-field', replace_once(source, request_lines[1], request_lines[1].replace('signing_algorithm', 'algorithm', 1)), 'Verification request failed:'),
        ('verification-response-field', replace_once(source, "jq -r '.signature_valid'", "jq -r '.valid'"), 'Signature verification response must report signature_valid=true'),
        ('list-response-field', source.replace('.items', '.keys'), LIST_ERROR),
    ]
    with tempfile.TemporaryDirectory(prefix='keyrack-quickstart-controls-') as temp:
        mutant_path = Path(temp) / 'quickstart.sh'
        for name, mutant, message in fields:
            mutant_path.write_text(mutant)
            result = execute(mutant_path, args.base_url)
            log(name, result)
            detected = result.returncode != 0 and message in result.stdout and SUCCESS not in result.stdout
            if name in ['signing-request-field', 'verification-request-field']:
                detected &= 'unknown signing_algorithm:' in result.stdout
            receipt['cases'].append({'name': name, 'kind': 'field-regression', 'mutant_sha256': hashlib.sha256(mutant.encode()).hexdigest(),
                'expected_failure': message, 'exit_code': result.returncode, 'detected': detected})
            save()
            if not detected:
                raise AssertionError(f'{name} did not fail its expected assertion')
            print(f'PASS {name}: {message}', flush=True)
        list_guard = source[source.index('if ! echo "$LIST_RESPONSE"'):source.index('KEY_COUNT=')]
        describe_guard = source[source.index('if [ "$STATE"'):source.index('ok "State:')]
        lid_guard = source[source.index('if [ -z "$SIGN_KEY_ID"'):source.index('ok "Signing key:')]
        signature_guard = source[source.index('if [ -z "$SIGNATURE"'):source.index('ok "Signature:')]
        controls = [
            ('list-missing-array', list_guard, LIST_ERROR),
            ('list-missing-created-key', list_guard, LIST_ERROR),
            ('describe-state', describe_guard, DESCRIBE_ERROR),
            ('describe-spec', describe_guard, DESCRIBE_ERROR),
            ('signing-key-lid', lid_guard, 'Signing-key creation returned no lid'),
            ('signature', signature_guard, 'Signing response returned no signature'),
        ]
        for name, guard, message in controls:
            proxy = ResponseFault(args.base_url, name)
            try:
                positive = execute(SCRIPT, proxy.url)
                log(f'{name}-guard-present', positive)
                if proxy.hits != 1 or positive.returncode == 0 or message not in positive.stdout:
                    raise AssertionError(f'{name}: corrected script must reject the targeted faulty response')
                mutant = replace_once(source, guard, '')
                mutant_path.write_text(mutant)
                result = execute(mutant_path, proxy.url)
                log(f'{name}-guard-reverted', result)
                detected = proxy.hits == 2 and message not in result.stdout
                if name.startswith(('list-', 'describe-')):
                    detected &= result.returncode == 0 and SUCCESS in result.stdout
                elif name == 'signing-key-lid':
                    detected &= result.returncode != 0 and 'Signing request failed:' in result.stdout and 'invalid key_id: null' in result.stdout
                    detected &= any(item['path'] == '/v1/keys/null/actions-sign' and item['status'] == 400 for item in proxy.requests)
                elif name == 'signature':
                    detected &= result.returncode != 0 and 'Verification request failed:' in result.stdout and 'invalid Ed25519 sig' in result.stdout
                    detected &= any(item['path'].endswith('/actions-verify') and item['status'] >= 400 for item in proxy.requests)
                receipt['cases'].append({'name': name, 'kind': 'assertion-removal', 'mutant_sha256': hashlib.sha256(mutant.encode()).hexdigest(),
                    'expected_assertion': message, 'guard_present_exit_code': positive.returncode,
                    'guard_reverted_exit_code': result.returncode, 'guard_reverted_claimed_success': SUCCESS in result.stdout,
                    'fault_injections': proxy.hits, 'requests': proxy.requests, 'detected': detected})
                save()
                if not detected:
                    raise AssertionError(f'{name}: removing the assertion did not produce the expected control failure')
                print(f'PASS {name}: reverted script omits required rejection: {message}', flush=True)
            finally:
                proxy.close()
    assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest() == source_hash, 'working script changed during controls'
    receipt['working_source_unchanged'] = True
    receipt['status'] = 'passed'
    save()
    print(f'PASS real baseline and {len(receipt["cases"])} reverted controls; source unchanged')


if __name__ == '__main__':
    main()
