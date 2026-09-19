#!/usr/bin/env python3
"""Reintroduce retired claims, then remove each guard and record the outcome."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CORE = 'crates/keyrack-core/tests/doc_claims.rs'
SERVICE = 'crates/keyrack-service/tests/doc_config_claims.rs'
CASES = [
    ('fips-achievement', CORE, 'release_claims_do_not_overstate_shipped_capabilities', 'FIPS_ACHIEVEMENT', 'FIPS 140-3 compliance is achieved through the HSM provider path.'),
    ('competitor-audit', CORE, 'release_claims_do_not_overstate_shipped_capabilities', 'COMPETITOR_AUDIT', 'Cloud KMS providers generate audit logs, but you cannot independently verify their integrity.'),
    ('community-governance', CORE, 'release_claims_do_not_overstate_shipped_capabilities', 'COMMUNITY_GOVERNANCE', 'The core engine is community-driven.'),
    ('wasm-export', CORE, 'release_claims_do_not_overstate_shipped_capabilities', 'WASM_EXPORT', 'Use WasmProvider for browser crypto.'),
    ('benchmark-methodology', CORE, 'release_claims_do_not_overstate_shipped_capabilities', 'BENCHMARK_METHODOLOGY', 'NFR numbers from a pinned reference platform — methodology published for reproducibility.'),
    ('benchmark-ghz', CORE, 'release_claims_do_not_overstate_shipped_capabilities', 'BENCHMARK_TOOLS', '- gRPC load via `ghz`'),
    ('benchmark-k6', CORE, 'release_claims_do_not_overstate_shipped_capabilities', 'BENCHMARK_TOOLS', '- REST/HTTP via `k6`'),
    ('export-bound', CORE, 'release_claims_do_not_overstate_shipped_capabilities', 'KEY_EXPORT_BOUND', 'When backed by an HSM or Vault provider, raw key material never leaves the backend.'),
    ('service-boundary', SERVICE, 'service_boundary_claims_match_real_defaults', 'SERVICE_BOUNDARY', 'TLS-encrypted gRPC/REST. Clients authenticate via bearer tokens.'),
    ('audit-full-rewrite', CORE, 'keyless_audit_claims_state_their_bounds', 'full-log rewrite', 'Audit edits are detectable without a key. Tail-truncation needs an external anchor.'),
    ('audit-tail-truncation', CORE, 'keyless_audit_claims_state_their_bounds', 'tail-truncation', 'Audit edits are detectable without a key. Full-log rewrite can recompute the chain.'),
    ('ephemeral-default', SERVICE, 'documented_config_defaults_match_config_rs', 'documented configuration default(s)', 'The audit signing key is ephemeral by default.'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'target/proofs/release-docs')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    originals = {name: (ROOT / name).read_text() for name in (CORE, SERVICE)}
    evidence = {'status': 'running', 'source_sha256': {p: hashlib.sha256(s.encode()).hexdigest() for p, s in originals.items()}, 'cases': []}

    def save():
        (args.output_dir / 'results.json').write_text(json.dumps(evidence, indent=2) + '\n')

    with tempfile.TemporaryDirectory(prefix='keyrack-doc-claims-') as tmp:
        fixture = Path(tmp)
        security = fixture / 'src/content/docs/docs/security/index.md'
        security.parent.mkdir(parents=True)
        security.write_text((ROOT / 'docs/SECURITY.md').read_text())
        env = {**os.environ, 'KEYRACK_DOC_ROOT': str(fixture)}

        def run(name, source, test):
            package = 'keyrack-core' if source == CORE else 'keyrack-service'
            command = ['cargo', 'test', '--locked', '-p', package, '--test', Path(source).stem, test, '--', '--exact']
            result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=900)
            output = result.stdout + result.stderr
            (args.output_dir / f'{name}.log').write_text(output)
            if 'running 1 test' not in output:
                raise AssertionError(f'{name}: setup/compilation/zero-test failure is not a control result')
            return result.returncode, output

        try:
            for source, test in sorted({(c[1], c[2]) for c in CASES}):
                rc, _ = run('baseline-' + test, source, test)
                assert rc == 0, f'baseline {test} failed'
            for name, source, test, diagnostic, claim in CASES:
                bad = fixture / 'retired-claim.md'
                bad.write_text('# Reintroduced claim\n\n' + claim + '\n')
                rc, output = run(name, source, test)
                assert rc != 0 and diagnostic in output, f'{name}: expected specific failure {diagnostic}'
                evidence['cases'].append({'name': name, 'error': diagnostic, 'exit_code': rc})
                bad.unlink()
                save()
            # Bind the copied default block to actual ServiceConfig, not a second
            # handwritten constant table. Change each documented value separately.
            for name, old, new in [('tls-default', 'tls: null', 'tls: {}'), ('authn-default', 'type: mtls', 'type: jwt')]:
                original = security.read_text()
                security.write_text(original.replace(old, new))
                rc, output = run(name, SERVICE, 'service_boundary_claims_match_real_defaults')
                assert rc != 0 and 'SERVICE_DEFAULTS' in output, name
                evidence['cases'].append({'name': name, 'error': 'SERVICE_DEFAULTS', 'exit_code': rc})
                security.write_text(original)
                save()
            # Remove each new guard in source, compile that version, and show the
            # same input which failed now passes the actual test. Restore always.
            for name, source, test, claim, anchor, replacement in [
                ('release-claim-guard', CORE, 'release_claims_do_not_overstate_shipped_capabilities', CASES[0][4], 'violations.is_empty(),\n        "release claim violation(s):', 'true,\n        "release claim violation(s):'),
                ('boundary-guard', SERVICE, 'service_boundary_claims_match_real_defaults', CASES[8][4], '!flat.contains("tls-encrypted grpc/rest. clients authenticate via bearer tokens")', 'true || !flat.is_empty()'),
                ('defaults-guard', SERVICE, 'service_boundary_claims_match_real_defaults', '', 'read(&path).contains(&expected)', 'true || read(&path).contains(&expected)'),
            ]:
                original = originals[source]
                assert original.count(anchor) == 1, f'{name}: guard anchor drift'
                bad = fixture / 'retired-claim.md'
                bad.write_text(claim)
                if name == 'defaults-guard':
                    security.write_text(security.read_text().replace('type: mtls', 'type: jwt'))
                (ROOT / source).write_text(original.replace(anchor, replacement))
                rc, output = run(name, source, test)
                assert rc == 0, f'{name}: removed guard must admit forbidden claim, not fail for another reason'
                failure = f'CONTROL_REMOVED: {name} admits the previously rejected claim'
                (args.output_dir / f'{name}-failure.log').write_text(failure + '\n')
                evidence['cases'].append({'name': name, 'error': failure, 'exit_code': rc})
                (ROOT / source).write_text(original)
                bad.unlink()
                security.write_text((ROOT / 'docs/SECURITY.md').read_text())
                save()
        finally:
            for path, original in originals.items():
                (ROOT / path).write_text(original)
        for source, test in sorted({(c[1], c[2]) for c in CASES}):
            rc, _ = run('restored-' + test, source, test)
            assert rc == 0, f'restored baseline {test}'
    evidence['status'] = 'passed'
    evidence['working_sources_restored'] = True
    save()
    print(f'PASS {len(evidence["cases"])} specific documentation mutation/reversion controls')


if __name__ == '__main__':
    main()
