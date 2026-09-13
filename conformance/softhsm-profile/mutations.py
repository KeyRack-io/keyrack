#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Revert packaging guarantees in disposable derived images; require exact failures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', default='proof-results')
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    entrypoint = (ROOT / 'docker/softhsm/entrypoint.sh').read_text()
    archive = (ROOT / 'docker/softhsm/archive.sh').read_text()
    lock = 'exec flock --nonblock --conflict-exit-code 75 --no-fork /var/lib/keyrack/.writer.lock "$@"'
    assert entrypoint.count(lock) == 1, 'review changed lock before mutating'
    unlocked = entrypoint.replace(lock, 'exec "$@"')
    assert archive.count('metadata tokens') == 1
    overwrite_guard = '[ -z "$(find /var/lib/keyrack/metadata /var/lib/keyrack/tokens -mindepth 1 -print -quit)" ]'
    assert archive.count(overwrite_guard) == 1
    mutants = [
        ('root_image', 'image', 'image_non_root', 'USER 0:0\n', {}),
        ('missing_library', 'image', 'image_stable_library', 'USER 0\nRUN rm -f /usr/lib/softhsm/libsofthsm2.so\nUSER 10001:10001\n', {}),
        ('baked_token', 'image', 'image_no_baked_token_or_secret', 'USER 0\nRUN touch /var/lib/keyrack/tokens/synthetic-baked-token\nUSER 10001:10001\n', {}),
        ('baked_pin_environment', 'image', 'image_no_pin_environment', 'ENV SYNTHETIC_USER_PIN=not-a-real-pin\n', {}),
        ('configuration_unreadable', 'writer', 'initializer_succeeds', 'USER 0\nRUN chmod 0750 /etc/softhsm\nUSER 10001:10001\n', {}),
        ('writer_lock_removed', 'writer', 'single_writer_rejected', 'COPY --chmod=0555 entrypoint /usr/local/bin/keyrack-softhsm\n', {'entrypoint': unlocked}),
        ('backup_lock_removed', 'quiescence', 'live_backup_rejected', 'COPY --chmod=0555 entrypoint /usr/local/bin/keyrack-softhsm\n', {'entrypoint': unlocked}),
        ('token_backup_omitted', 'all', 'decrypt_after_quiesced_restore', 'COPY --chmod=0555 archive /usr/local/bin/keyrack-softhsm-archive\n', {'archive': archive.replace('metadata tokens', 'metadata')}),
        ('restore_overwrite_allowed', 'all', 'restore_refuses_existing_data', 'COPY --chmod=0555 archive /usr/local/bin/keyrack-softhsm-archive\n', {'archive': archive.replace(overwrite_guard, 'true')}),
        ('token_persistence_removed', 'restart-token-loss', 'decrypt_after_process_restart', None, {}),
    ]
    results = []
    for name, case, assertion, layer, files in mutants:
        tag = f'keyrack-softhsm-mutant:{uuid.uuid4().hex}' if layer else args.image
        try:
            if layer:
                with tempfile.TemporaryDirectory(prefix='keyrack-image-mutation-') as temporary:
                    directory = Path(temporary)
                    (directory / 'Dockerfile').write_text(f'FROM {args.image}\n' + layer)
                    for path, data in files.items():
                        (directory / path).write_text(data)
                    build = subprocess.run(['docker', 'build', '-t', tag, str(directory)], text=True, capture_output=True)
                    if build.returncode:
                        raise SystemExit(f'{name}: mutant did not build; not evidence\n{build.stderr}')
            result = subprocess.run([sys.executable, str(ROOT / 'conformance/softhsm-profile/proof.py'), '--image', tag, '--case', case], text=True, capture_output=True)
            log = result.stdout + result.stderr
            path = output / f'{name}.log'
            path.write_text(log)
            expected = f'FAIL {assertion}:'
            if result.returncode == 0 or expected not in log:
                raise SystemExit(f'{name}: expected {expected}, got unrelated result; not proven\n{log}')
            results.append(dict(control=name, failure=assertion, log=path.name, sha256=hashlib.sha256(log.encode()).hexdigest()))
            print(f'KILLED {name}: {assertion}', flush=True)
        finally:
            if layer:
                subprocess.run(['docker', 'image', 'rm', '-f', tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    (output / 'packaging-controls.json').write_text(json.dumps(results, indent=2) + '\n')
    assert len(results) == 10
    print('PASS all ten packaging reversions failed their specific assertions', flush=True)


if __name__ == '__main__':
    main()
