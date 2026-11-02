#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Revert delegated peer identity controls; compiler failures are not evidence."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'crates/keyrack-core/src/authn.rs'
MUTATIONS = [
    ('discard_matched_san', '.matched_san\n                    .unwrap_or', '.matched_san.filter(|_| false)\n                    .unwrap_or', 'delegated_peer_ignores_unlisted_sans_and_certificate_order', 'delegating peer must be the matched SAN'),
    ('reverse_allowlist_priority', 'for value in required {', 'for value in required.iter().rev() {', 'delegated_peer_uses_allowlist_order_for_multiple_matches', 'delegating peer must be the matched SAN'),
    ('reject_extra_sans', 'for name in &san.0 {\n                    let candidate', 'if san.0.len() > 1 { return SanRequirement::Unmatched; }\n                for name in &san.0 {\n                    let candidate', 'delegated_peer_ignores_unlisted_sans_and_certificate_order', 'called `Result::unwrap()` on an `Err` value'),
    ('case_insensitive_match', 'if candidate == value {', 'if candidate.eq_ignore_ascii_case(value) {', 'delegated_peer_san_matching_is_case_sensitive', 'ineligible SAN must refuse delegation without fallback'),
    ('accept_email_san', 'GeneralName::DnsName(dns) => dns.as_str(),', 'GeneralName::DnsName(dns) | GeneralName::Rfc822Name(dns) => dns.as_str(),', 'delegated_peer_email_and_ip_sans_are_ineligible', 'ineligible SAN must refuse delegation without fallback'),
    ('accept_ip_san', 'let candidate = match name {', 'if let GeneralName::IpAddress(ip) = name { if let Ok(bytes) = <[u8; 4]>::try_from(ip.as_bytes()) { if std::net::Ipv4Addr::from(bytes).to_string() == *value { return SanRequirement::Matched(value.clone()); } } }\n                    let candidate = match name {', 'delegated_peer_email_and_ip_sans_are_ineligible', 'ineligible SAN must refuse delegation without fallback'),
    ('omit_dns_san', 'GeneralName::DnsName(dns) => dns.as_str(),', 'GeneralName::DnsName(_) => continue,', 'delegated_peer_same_string_dns_and_uri_are_equivalent', 'called `Result::unwrap()` on an `Err` value'),
    ('omit_uri_san', 'GeneralName::UniformResourceIdentifier(uri) => uri.as_str(),', 'GeneralName::UniformResourceIdentifier(_) => continue,', 'delegated_peer_same_string_dns_and_uri_are_equivalent', 'called `Result::unwrap()` on an `Err` value'),
    ('refuse_unpinned_san', 'return SanRequirement::Unrestricted;', 'return { let _ = SanRequirement::Unrestricted; SanRequirement::Unmatched };', 'delegated_peer_unrestricted_san_keeps_existing_identity', 'called `Result::unwrap()` on an `Err` value'),
    ('change_standalone_principal', '.map(|peer| peer.authentication)', '.map(|mut peer| { if let Some(san) = peer.matched_san { peer.authentication.principal.id = san; } peer.authentication })', 'trusted_peer_san_pin_preserves_standalone_principal', 'standalone principal must remain unchanged'),
]


def main():
    target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')).resolve()
    output = ROOT / 'target/proofs/delegating-peer'
    output.mkdir(parents=True, exist_ok=True)
    original = (ROOT / SOURCE).read_text()
    receipt = {'status': 'running', 'source_sha256': hashlib.sha256(original.encode()).hexdigest(), 'controls': []}
    env = os.environ | {'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0', 'CARGO_TERM_COLOR': 'never'}
    with tempfile.TemporaryDirectory(prefix='keyrack-delegating-peer-') as temp:
        copy = Path(temp) / 'source'
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns('.git', 'target', '__pycache__'))
        def run(name, test='authn::tests'):
            command = ['cargo', 'test', '--locked', '-p', 'keyrack-core', '--target-dir', str(target), '--lib', test]
            if test != 'authn::tests':
                command += ['--', '--exact']
            result = subprocess.run(command, cwd=copy, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
            (output / (name + '.log')).write_text(result.stdout)
            assert 'error: could not compile' not in result.stdout and 'error[E' not in result.stdout, f'{name}: compilation failure is not evidence'
            return result.returncode, result.stdout
        try:
            assert run('baseline')[0] == 0, 'baseline must pass'
            for name, old, new, test, diagnostic in MUTATIONS:
                assert original.count(old) == 1, f'{name}: mutation anchor drift'
                (copy / SOURCE).write_text(original.replace(old, new))
                try:
                    code, text = run(name, 'authn::tests::' + test)
                    assert code != 0 and 'running 1 test' in text and '1 failed' in text and diagnostic in text, f'{name}: expected specific failure'
                    receipt['controls'].append({'name': name, 'test': test, 'diagnostic': diagnostic, 'exit_code': code})
                    print(f'PASS {name}: {diagnostic}', flush=True)
                finally:
                    (copy / SOURCE).write_text(original)
            assert run('restored')[0] == 0, 'restored baseline must pass'
            assert (ROOT / SOURCE).read_text() == original, 'working source changed'
            receipt['status'] = 'passed'
        finally:
            (output / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
