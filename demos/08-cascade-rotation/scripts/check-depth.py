#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: Apache-2.0
"""Independently check the persisted demo graph through the live REST API."""
import json
import sys
import urllib.request


def check_graph(document):
    if not isinstance(document, dict) or not isinstance(document.get('items'), list):
        raise ValueError('DEMO08_INVALID_GRAPH: expected a key-list items array')
    if document.get('next_cursor') is not None:
        raise ValueError('DEMO08_INVALID_GRAPH: incomplete key listing')
    parents = {}
    for key in document['items']:
        if not isinstance(key, dict):
            raise ValueError('DEMO08_INVALID_GRAPH: key must be an object')
        lid, parent = key.get('lid'), key.get('parent_lid')
        if not isinstance(lid, str) or not lid or lid in parents:
            raise ValueError('DEMO08_INVALID_GRAPH: missing or duplicate key identity')
        if parent is not None and (not isinstance(parent, str) or not parent):
            raise ValueError('DEMO08_INVALID_GRAPH: invalid parent identity')
        parents[lid] = parent
    deepest = []
    for lid in parents:
        chain = []
        current = lid
        while current is not None:
            if current not in parents:
                raise ValueError('DEMO08_INVALID_GRAPH: parent is absent from the key listing')
            if current in chain:
                raise ValueError('DEMO08_INVALID_GRAPH: cycle in parent relationships')
            chain.append(current)
            current = parents[current]
        if len(chain) > len(deepest):
            deepest = chain
    depth = len(deepest) - 1
    # Depth comes before cardinality: restoring the original three-key demo
    # must fail for its forbidden edge, not merely because its count changed.
    if depth > 1:
        raise ValueError(f'DEMO08_DEPTH_EXCEEDED: depth={depth}; chain={json.dumps(deepest)}')
    roots = sum(parent is None for parent in parents.values())
    edges = len(parents) - roots
    if (len(parents), roots, edges, depth) != (2, 1, 1, 1):
        raise ValueError(f'DEMO08_GRAPH_SHAPE: nodes={len(parents)} roots={roots} edges={edges} depth={depth}; expected 2/1/1/1')
    return f'DEMO08_DEPTH_OK: nodes=2 roots=1 edges=1 depth={depth}'


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: check-depth.py REST_BASE_URL')
    try:
        with urllib.request.urlopen(sys.argv[1].rstrip('/') + '/v1/keys', timeout=15) as response:
            document = json.load(response)
    except Exception as error:
        raise SystemExit(f'DEMO08_ORACLE_SETUP_FAILURE: could not read live key records: {error}') from error
    try:
        print(check_graph(document), flush=True)
    except ValueError as error:
        raise SystemExit(str(error)) from error


if __name__ == '__main__':
    main()
