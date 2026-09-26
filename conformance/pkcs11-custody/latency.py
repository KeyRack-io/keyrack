#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Nearest-rank latency statistics for requests completed in the outage window."""
from decimal import Decimal
import json
import math
import pathlib
import sys

source, start, end = pathlib.Path(sys.argv[1]), Decimal(sys.argv[2]), Decimal(sys.argv[3])
samples = []
failures = 0
workers = 0
for path in source.iterdir():
    count = 0
    for line in path.read_text().splitlines():
        completed, status, latency = line.split()
        if start <= Decimal(completed) <= end:
            samples.append(float(latency) * 1000)
            failures += status != "200"
            count += 1
    workers += count > 0
assert end - start >= 60, "outage must last at least 60 seconds"
assert workers == 8 and len(samples) >= 40, "all workers must contribute outage samples"
assert failures == 0, f"sibling failed {failures} requests during sustained outage"
samples.sort()
print(json.dumps(dict(seconds=float(end-start), requests=len(samples), failures=failures,
                     workers=workers, p50_ms=samples[math.ceil(len(samples)*.50)-1],
                     p99_ms=samples[math.ceil(len(samples)*.99)-1])))
