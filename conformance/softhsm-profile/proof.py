#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the packaged image, using only disposable volumes and synthetic secrets.

No host token configuration or existing data is used. --case permits the same
assertion to be run against a reverted packaging layer by mutations.py.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


class Proof:
    def __init__(self, image, case):
        self.image, self.case = image, case
        self.prefix = 'keyrack-softhsm-proof-' + uuid.uuid4().hex[:12]
        self.volumes, self.containers, self.passed = [], [], []
        self.container, self.base = None, None
        self.temp = tempfile.TemporaryDirectory(prefix=self.prefix)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.secret_dir = self.root / 'secrets'
        self.secret_dir.mkdir(mode=0o755)
        for key, value in [('token-label', 'profile-proof'), ('user-pin', secrets.token_hex(16)),
                           ('so-pin', secrets.token_hex(16))]:
            path = self.secret_dir / key
            path.write_text(value)
            path.chmod(0o444)
        self.service_secret_dir = self.root / 'service-secrets'
        self.service_secret_dir.mkdir(mode=0o755)
        for key in ('token-label', 'user-pin'):
            projected = self.service_secret_dir / key
            projected.write_bytes((self.secret_dir / key).read_bytes())
            projected.chmod(0o444)
        self.config = self.root / 'keyrack.yaml'
        self.config.write_text('''grpc_addr: "0.0.0.0:50051"
rest_addr: "0.0.0.0:8080"
storage: {type: sqlite, path: /var/lib/keyrack/metadata/keyrack.db}
provider:
  type: pkcs11
  lib_path: /usr/lib/softhsm/libsofthsm2.so
  token_label_ref: file:token-label
  pin_ref: file:user-pin
# Explicit isolated-test authorization; shipped deployment starts always_deny.
pdp: {type: always_allow}
authn: {type: insecure}
audit: {type: stdout}
''')
        self.config.chmod(0o444)

    @staticmethod
    def docker(*args, check=True):
        result = subprocess.run(['docker', *map(str, args)], capture_output=True, text=True, timeout=120)
        if check and result.returncode:
            raise AssertionError(f'docker operation failed ({result.returncode}): {result.stderr.strip()}')
        return result

    def volume(self):
        name = f'{self.prefix}-{len(self.volumes)}'
        self.docker('volume', 'create', name)
        self.volumes.append(name)
        return name

    def args(self, data, backup=None, *, init=False):
        secret_dir = self.secret_dir if init else self.service_secret_dir
        args = ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
                '-v', f'{data}:/var/lib/keyrack',
                '-v', f'{secret_dir}:/run/secrets/keyrack:ro',
                '-v', f'{self.config}:/etc/keyrack/config.yaml:ro']
        if backup:
            args += ['-v', f'{backup}:/backup']
        return args

    def mark(self, name, condition, detail=''):
        if not condition:
            raise AssertionError(f'{name}: {detail or "required condition failed"}')
        self.passed.append(name)
        print(f'PASS {name}', flush=True)

    def init(self, data):
        return self.docker('run', '--rm', *self.args(data, init=True), self.image, 'init', check=False)

    def start(self, data):
        name = f'{self.prefix}-service-{len(self.containers)}'
        self.docker('run', '-d', '--name', name, '-p', '127.0.0.1::8080',
                    *self.args(data), self.image, 'serve')
        self.containers.append(name)
        self.container = name
        port = self.docker('inspect', '--format', '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}', name).stdout.strip()
        self.base = f'http://127.0.0.1:{port}'
        self.wait_status('/readyz', 200, 'service_ready')

    def stop(self):
        if self.container:
            self.docker('stop', '--time', '40', self.container)
            self.container = None

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(self.base + path, data=body, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=6) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            return 0, {}

    def wait_status(self, path, expected, assertion):
        end, last = time.monotonic() + 40, 0
        while time.monotonic() < end:
            last, _ = self.request(path)
            if last == expected:
                self.mark(assertion, True)
                return
            time.sleep(.25)
        self.mark(assertion, False, f'expected HTTP {expected}, got {last}')

    def image_contract(self):
        meta = json.loads(self.docker('image', 'inspect', self.image).stdout)[0]
        self.mark('image_non_root', meta['Config']['User'] == '10001:10001')
        self.mark('image_architecture', meta['Architecture'] in ('amd64', 'arm64'))
        env = meta['Config'].get('Env', [])
        self.mark('image_no_pin_environment', not any(item.split('=', 1)[0].endswith(('_PIN', '_PASSWORD')) for item in env))
        self.mark('image_stable_library', self.docker('run', '--rm', '--entrypoint', '/bin/sh', self.image,
                  '-c', 'test -r /usr/lib/softhsm/libsofthsm2.so', check=False).returncode == 0)
        self.mark('image_no_baked_token_or_secret', self.docker('run', '--rm', '--entrypoint', '/bin/sh', self.image,
                  '-c', 'test -z "$(find /var/lib/keyrack/tokens -type f -print -quit)" && test ! -d /run/secrets/keyrack', check=False).returncode == 0)
        print(json.dumps({'image_id': meta['Id'], 'architecture': meta['Architecture']}), flush=True)

    def run(self):
        self.image_contract()
        if self.case == 'image':
            return
        data, backup = self.volume(), self.volume()
        initialized = self.init(data)
        self.mark('initializer_succeeds', initialized.returncode == 0, initialized.stderr)
        self.mark('initializer_retry_succeeds', self.init(data).returncode == 0)
        self.start(data)
        if self.case in ('all', 'writer'):
            self.mark('single_writer_rejected', self.init(data).returncode == 75,
                      'a second init process acquired the active service store')
        if self.case in ('all', 'quiescence'):
            result = self.docker('run', '--rm', *self.args(data, backup), self.image, 'backup', '/backup/live.tar', check=False)
            self.mark('live_backup_rejected', result.returncode == 75, 'backup ran while service held store lock')
        if self.case in ('writer', 'quiescence'):
            return
        code, key = self.request('/v1/keys', {'key_spec': 'AES_256', 'description': 'disposable persistence proof'})
        self.mark('create_in_token', code in (200, 201) and key.get('lid', '').startswith('lid_'))
        lid = key['lid']
        plaintext = base64.b64encode(secrets.token_bytes(64)).decode()
        code, encrypted = self.request(f'/v1/keys/{lid}/actions-encrypt', {'plaintext': plaintext})
        self.mark('encrypt_before_restart', code == 200 and bool(encrypted.get('ciphertext_blob')))
        ciphertext = encrypted['ciphertext_blob']
        def decrypt(assertion):
            code, result = self.request(f'/v1/keys/{lid}/actions-decrypt', {'ciphertext_blob': ciphertext})
            self.mark(assertion, code == 200 and result.get('plaintext') == plaintext,
                      f'original ciphertext did not decrypt exactly (HTTP {code})')
        decrypt('baseline_decrypt')
        if self.case in ('all', 'readiness'):
            self.docker('exec', self.container, '/bin/sh', '-c',
                        'mv /var/lib/keyrack/tokens /var/lib/keyrack/tokens-away && mkdir /var/lib/keyrack/tokens')
            self.wait_status('/readyz', 503, 'token_loss_not_ready')
            self.docker('exec', self.container, '/bin/sh', '-c',
                        'rmdir /var/lib/keyrack/tokens && mv /var/lib/keyrack/tokens-away /var/lib/keyrack/tokens')
            self.wait_status('/readyz', 200, 'token_return_ready')
            decrypt('decrypt_after_token_return')
        if self.case == 'readiness':
            return
        old_container = self.container
        self.stop()
        if self.case == 'restart-token-loss':
            # Negative control: retain SQLite but remove durable token material.
            self.docker('run', '--rm', '--entrypoint', '/bin/sh', *self.args(data), self.image,
                        '-c', 'rm -rf /var/lib/keyrack/tokens/*')
        self.mark('initializer_after_restart_preserves_token', self.init(data).returncode == 0)
        self.start(data)
        self.mark('fresh_container', old_container != self.container)
        decrypt('decrypt_after_process_restart')
        self.stop()
        result = self.docker('run', '--rm', *self.args(data, backup), self.image, 'backup', '/backup/snapshot.tar', check=False)
        self.mark('quiesced_backup_succeeds', result.returncode == 0, result.stderr)
        restored = self.volume()
        result = self.docker('run', '--rm', *self.args(restored, backup), self.image, 'restore', '/backup/snapshot.tar', check=False)
        self.mark('restore_to_empty_volume', result.returncode == 0, result.stderr)
        self.mark('initializer_after_restore_preserves_token', self.init(restored).returncode == 0)
        self.start(restored)
        decrypt('decrypt_after_quiesced_restore')
        self.stop()
        result = self.docker('run', '--rm', *self.args(restored, backup), self.image, 'restore', '/backup/snapshot.tar', check=False)
        self.mark('restore_refuses_existing_data', result.returncode != 0)
        self.start(restored)
        decrypt('decrypt_after_refused_restore')

    def close(self):
        for container in reversed(self.containers):
            self.docker('rm', '-f', container, check=False)
        for volume in reversed(self.volumes):
            self.docker('volume', 'rm', volume, check=False)
        self.temp.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--case', default='all', choices=['all', 'image', 'writer', 'quiescence', 'readiness', 'restart-token-loss'])
    args = parser.parse_args()
    proof = Proof(args.image, args.case)
    try:
        proof.run()
        expected = {'all': 28, 'image': 5, 'writer': 9, 'quiescence': 9, 'readiness': 14, 'restart-token-loss': 0}
        # Counts bind the full path; a skipped assertion cannot produce a pass.
        assert len(proof.passed) == expected[args.case], f'assertion count: {len(proof.passed)} != {expected[args.case]}'
        print(json.dumps({'result': 'PASS', 'case': args.case, 'assertions': proof.passed}), flush=True)
    except Exception as error:
        print(f'FAIL {error}', flush=True)
        raise SystemExit(1) from error
    finally:
        proof.close()


if __name__ == '__main__':
    main()
