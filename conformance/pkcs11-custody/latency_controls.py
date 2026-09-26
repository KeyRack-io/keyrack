#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check percentile arithmetic and revert each evidence admission guard."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(__file__).with_name('latency.py').read_text()
with tempfile.TemporaryDirectory(prefix='keyrack-latency-controls-') as temp:
    root = Path(temp)
    samples = root / 'samples'
    samples.mkdir()
    script = root / 'latency.py'
    script.write_text(source)

    def reset():
        for path in samples.iterdir():
            path.unlink()
        # 80 independently known, uniformly spaced observations: p50=40, p99=80ms.
        for worker in range(8):
            (samples / str(worker)).write_text(''.join(
                f'10 200 {value/1000:.3f}\n' for value in range(worker*10+1, worker*10+11)))

    def run(end='60'):
        return subprocess.run([sys.executable, str(script), str(samples), '0', end], capture_output=True, text=True)

    reset()
    result = run()
    assert result.returncode == 0, result.stderr
    baseline = json.loads(result.stdout)
    assert baseline['p50_ms'] == 40 and baseline['p99_ms'] == 80
    print('PASS independently known p50/p99')
    cases = [
        ('sibling_failure', 'assert failures == 0,', 'if False: assert failures == 0,', 'sibling failed', '60'),
        ('short_window', 'assert end - start >= 60,', 'if False: assert end - start >= 60,', 'outage must last', '59'),
        ('missing_worker', 'assert workers == 8 and len(samples) >= 40,', 'if False: assert workers == 8 and len(samples) >= 40,', 'all workers must contribute', '60'),
    ]
    for name, old, new, diagnostic, end in cases:
        reset()
        if name == 'sibling_failure':
            path = samples / '0'
            path.write_text(path.read_text().replace('200', '503', 1))
        if name == 'missing_worker':
            (samples / '0').unlink()
        result = run(end)
        assert result.returncode != 0 and diagnostic in result.stderr, name
        script.write_text(source.replace(old, new))
        assert run(end).returncode == 0, f'{name}: removing guard must expose bad evidence'
        script.write_text(source)
        assert run(end).returncode != 0, f'{name}: restored guard must refuse'
        print(f'PASS {name}: {diagnostic}')
    reset()
    for percentile, wrong in [('.50', '.40'), ('.99', '.90')]:
        script.write_text(source.replace(f'*{percentile}', f'*{wrong}'))
        mutated = json.loads(run().stdout)
        assert (mutated['p50_ms'], mutated['p99_ms']) != (40, 80), 'arithmetic mutation must disagree with independent values'
        print(f'PASS percentile {percentile} mutation disagrees with independent values')
    script.write_text(source)
    assert json.loads(run().stdout) == baseline
