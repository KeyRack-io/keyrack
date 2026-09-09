// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Independent reference encoder: Node built-ins only; never invokes Rust or
// reads Rust-produced expected bytes. All identifiers, digests and keys below
// are PUBLIC TEST DATA. These vectors qualify bytes, not any custody provider.
// Emit JSON: node scripts/custody-contract-vectors.mjs
// Compare:  node scripts/custody-contract-vectors.mjs --check [fixture.json]
// This script never writes files, including in --check mode.

import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const kinds = {
  CustodyProfile: 1, CustodyContext: 2, CustodyMaterialDescriptor: 3,
  RequestBinding: 4, AuthorityIdentity: 5, AuthorityGrant: 6,
  LeaseIdentity: 7, LeaseRecord: 8, CreationResult: 9,
  LeaseCleanupResult: 10, RevocationCommand: 11, RevocationResult: 12, Evidence: 13,
};
const tags = {
  boundary: { ProviderSessionObject: 1, ProviderJournaledTemporaryObject: 2, TrustedHostWorkerMemory: 3 },
  spec: { Aes256: 1, Aes128: 2, Ed25519: 3, RsaPkcs1v15Sha256: 4, RsaPssSha256: 5, EcdsaP256Sha256: 6, EcdsaP384: 7, Hmac256: 8 },
  format: { RawSecret: 1, Pkcs8Der: 2, ProviderNative: 3 },
  purpose: { EncryptDecrypt: 1, SignVerify: 2, GenerateVerifyMac: 3, WrapUnwrap: 4 },
  scope: { Context: 1, SecurityDomain: 2 },
  operation: { GenerateWrapped: 1, Encrypt: 2, Decrypt: 3 },
  clock: { UnixMilliseconds: 1, ExecutorMonotonicMilliseconds: 2 },
  outcome: { ProviderSessionClosed: 1, ProviderTemporaryObjectDestroyed: 2, NativeWrappedOnlyGenerated: 3 },
  reason: { Released: 1, ResidencyExpired: 2, AuthorityFenced: 3 },
  in_flight: { Drained: 1, FurtherReleaseBlocked: 2 },
};
const exercisedTags = new Set();
const domain = Buffer.from('KeyRack:CustodyContract\0', 'ascii');
const signatureDomain = Buffer.from('KeyRack:CustodyEvidenceSignature\0', 'ascii');
const wrappingDomain = Buffer.from('KeyRack:ParentWrappedContext\0', 'ascii');
const concat = (...parts) => Buffer.concat(parts);
const repeat = (byte, count) => byte.toString(16).padStart(2, '0').repeat(count);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const ref = (name) => ({ $ref: name });

function uint(value, width) {
  assert.equal(typeof value === 'string' || Number.isSafeInteger(value), true);
  const number = BigInt(value);
  assert(number >= 0n && number < (1n << BigInt(width * 8)));
  const bytes = Buffer.alloc(width);
  for (let i = width - 1, remaining = number; i >= 0; i--, remaining >>= 8n) {
    bytes[i] = Number(remaining & 255n);
  }
  return bytes;
}
const u8 = (v) => uint(v, 1);
const u16 = (v) => uint(v, 2);
const u32 = (v) => uint(v, 4);
const u64 = (v) => uint(v, 8);
function nonzero(value) { assert(BigInt(value) > 0n); return u64(value); }
function fixed(hex, size) {
  assert.equal(typeof hex, 'string');
  assert.match(hex, new RegExp(`^[0-9a-f]{${size * 2}}$`));
  return Buffer.from(hex, 'hex');
}
function identity(hex, size) {
  const bytes = fixed(hex, size);
  assert(bytes.some((byte) => byte !== 0));
  return bytes;
}
function identifier(value) {
  assert.equal(typeof value, 'string');
  assert.match(value, /^[\x21-\x7e]{1,256}$/);
  const bytes = Buffer.from(value, 'ascii');
  return concat(u16(bytes.length), bytes);
}
function tagged(group, name) {
  assert(Object.hasOwn(tags[group], name), `unknown ${group} ${name}`);
  exercisedTags.add(`${group}:${name}`);
  return u8(tags[group][name]);
}
function blob(bytes) {
  assert(bytes.length <= 65_536);
  return concat(u32(bytes.length), bytes);
}
function frame(type, body) {
  assert(Object.hasOwn(kinds, type));
  const bytes = concat(domain, u16(1), u8(kinds[type]), body);
  assert(bytes.length <= 65_536);
  return bytes;
}
function key(value) {
  return concat(fixed(value.lid_hex, 32), nonzero(value.version));
}
function spec(value) {
  const tag = tagged('spec', value.name);
  if (value.name === 'RsaPkcs1v15Sha256' || value.name === 'RsaPssSha256') {
    assert([2048, 3072, 4096].includes(value.key_size));
    return concat(tag, u32(value.key_size));
  }
  return tag;
}
function wrapping(value) {
  assert.equal(value.version, 1);
  assert(['Aes128', 'Aes256'].includes(value.parent_spec.name));
  const asymmetric = !['Aes128', 'Aes256', 'Hmac256'].includes(value.child_spec.name);
  assert.equal(asymmetric, value.public_material_sha256 !== null);
  const allowedPurposes = asymmetric ? ['SignVerify']
    : value.child_spec.name === 'Hmac256' ? ['GenerateVerifyMac'] : ['EncryptDecrypt', 'WrapUnwrap'];
  assert(allowedPurposes.includes(value.purpose));
  assert(value.key_format.name !== 'RawSecret' || !asymmetric);
  assert(value.key_format.name !== 'Pkcs8Der' || asymmetric);
  const format = concat(tagged('format', value.key_format.name),
    value.key_format.name === 'ProviderNative' ? identifier(value.key_format.id) : Buffer.alloc(0));
  return concat(wrappingDomain, u16(1), key(value.child), key(value.parent),
    spec(value.parent_spec), spec(value.child_spec), format, tagged('purpose', value.purpose),
    identifier(value.provider_ref), identifier(value.security_domain), identifier(value.mechanism),
    value.public_material_sha256 === null ? u8(0) : concat(u8(1), fixed(value.public_material_sha256, 32)));
}
function scope(value) {
  return concat(tagged('scope', value.kind), value.kind === 'Context'
    ? fixed(value.context_sha256, 32)
    : concat(identifier(value.provider_ref), identifier(value.security_domain)));
}
function validity(value, executor) {
  assert(BigInt(value.not_before) < BigInt(value.not_after));
  const clock = tagged('clock', value.clock.kind);
  if (value.clock.kind === 'ExecutorMonotonicMilliseconds') {
    assert.equal(value.clock.executor_hex, executor);
    return concat(clock, identity(value.clock.executor_hex, 32), u64(value.not_before), u64(value.not_after));
  }
  return concat(clock, u64(value.not_before), u64(value.not_after));
}
function transcript(value) {
  assert(['AuthorityGrant', 'CreationResult', 'LeaseCleanupResult', 'RevocationCommand', 'RevocationResult'].includes(value.claims_type));
  if (['AuthorityGrant', 'RevocationCommand'].includes(value.claims_type)) {
    assert.equal(value.issuer, value.claims.authority.issuer);
  }
  const bytes = concat(signatureDomain, u16(1), u8(1), identifier(value.issuer),
    identifier(value.key_id), blob(encode(value.claims_type, value.claims)));
  assert(bytes.length <= 65_536);
  return bytes;
}
function encode(type, value) {
  const nested = (nestedType, input) => blob(encode(nestedType, input));
  let body;
  switch (type) {
    case 'CustodyProfile':
      body = concat(tagged('boundary', value.boundary), identifier(value.id)); break;
    case 'CustodyContext':
      assert.notEqual(value.wrapping.child.lid_hex, value.wrapping.parent.lid_hex);
      body = concat(blob(wrapping(value.wrapping)), nested('CustodyProfile', value.profile)); break;
    case 'CustodyMaterialDescriptor':
      body = concat(nested('CustodyContext', value.context), identifier(value.envelope_ref), fixed(value.envelope_sha256, 32)); break;
    case 'RequestBinding':
      body = concat(identity(value.operation_hex, 16), identity(value.attempt_hex, 16), identity(value.executor_hex, 32),
        fixed(value.context_sha256, 32), fixed(value.request_sha256, 32)); break;
    case 'AuthorityIdentity':
      body = concat(identifier(value.issuer), scope(value.scope), nonzero(value.generation)); break;
    case 'AuthorityGrant':
      assert(BigInt(value.ancestor_not_after) > BigInt(value.validity.not_before));
      body = concat(nested('AuthorityIdentity', value.authority), nested('RequestBinding', value.request),
        identifier(value.principal), tagged('operation', value.operation), nonzero(value.sequence),
        validity(value.validity, value.request.executor_hex), u64(value.ancestor_not_after)); break;
    case 'LeaseIdentity':
      body = concat(identity(value.executor_hex, 32), nonzero(value.counter)); break;
    case 'LeaseRecord':
      if (value.authority.scope.kind === 'Context') assert.equal(value.authority.scope.context_sha256, value.context_sha256);
      body = concat(nested('LeaseIdentity', value.lease), fixed(value.context_sha256, 32),
        nested('AuthorityIdentity', value.authority), validity(value.residency, value.lease.executor_hex)); break;
    case 'CreationResult': {
      const outcome = tagged('outcome', value.outcome.kind);
      const target = value.outcome.kind === 'ProviderSessionClosed' ? identifier(value.outcome.session)
        : value.outcome.kind === 'ProviderTemporaryObjectDestroyed' ? identifier(value.outcome.object) : Buffer.alloc(0);
      body = concat(nested('RequestBinding', value.request), identity(value.owner.instance_hex, 16),
        nonzero(value.owner.generation), fixed(value.material_sha256, 32), outcome, target); break;
    }
    case 'LeaseCleanupResult':
      body = concat(nested('LeaseRecord', value.record), tagged('reason', value.reason)); break;
    case 'RevocationCommand':
      body = concat(identity(value.fence_hex, 16), identity(value.executor_hex, 32),
        nested('AuthorityIdentity', value.authority), validity(value.validity, value.executor_hex)); break;
    case 'RevocationResult': {
      assert(value.observed_leases.length <= 128);
      let previous = 0n;
      for (const lease of value.observed_leases) {
        assert.equal(lease.executor_hex, value.executor_hex);
        assert(BigInt(lease.counter) > previous);
        previous = BigInt(lease.counter);
      }
      body = concat(identity(value.fence_hex, 16), identity(value.executor_hex, 32),
        nested('AuthorityIdentity', value.authority), fixed(value.command_sha256, 32),
        tagged('in_flight', value.in_flight), u16(value.observed_leases.length),
        ...value.observed_leases.map((lease) => nested('LeaseIdentity', lease))); break;
    }
    case 'Evidence':
      transcript(value);
      body = concat(u8(1), identifier(value.issuer), identifier(value.key_id),
        nested(value.claims_type, value.claims), fixed(value.signature_hex, 64)); break;
    default: throw new Error(`unknown message type ${type}`);
  }
  return frame(type, body);
}

const seed = Buffer.alloc(32, 0x42); // PUBLIC TEST ONLY: never a deployment key.
// RFC 8410 PKCS#8 Ed25519 seed wrapper; no private key file is read or written.
const privateKey = createPrivateKey({ key: concat(Buffer.from('302e020100300506032b657004220420', 'hex'), seed), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
const spki = publicKey.export({ format: 'der', type: 'spki' });
assert.equal(spki.subarray(0, 12).toString('hex'), '302a300506032b6570032100');
const verifyingKeyHex = spki.subarray(12).toString('hex');
const vectors = [];
const resolved = new Map();
function resolve(value) {
  if (Array.isArray(value)) return value.map(resolve);
  if (value !== null && typeof value === 'object') {
    if (Object.hasOwn(value, '$ref')) {
      assert.deepEqual(Object.keys(value), ['$ref']);
      assert(resolved.has(value.$ref), `unknown or forward reference ${value.$ref}`);
      return resolved.get(value.$ref);
    }
    return Object.fromEntries(Object.entries(value).map(([name, field]) => [name, resolve(field)]));
  }
  return value;
}
function add(name, type, input, extra = {}) {
  assert(!resolved.has(name));
  const value = resolve(input);
  const bytes = encode(type, value);
  const vector = { name, kind: kinds[type], type, input, hex: bytes.toString('hex'), sha256: sha256(bytes), ...extra };
  vectors.push(vector);
  resolved.set(name, value);
  return vector;
}
function evidence(name, claimsName, issuer) {
  const claimsVector = vectors.find((vector) => vector.name === claimsName);
  const input = { issuer, key_id: 'key-1', claims_type: claimsVector.type, claims: ref(claimsName) };
  const signingBytes = transcript(resolve(input));
  const signature = sign(null, signingBytes, privateKey);
  assert.equal(signature.length, 64);
  assert(verify(null, signingBytes, publicKey, signature));
  assert.deepEqual(sign(null, signingBytes, privateKey), signature);
  const altered = Buffer.from(signingBytes);
  altered[0] ^= 1;
  assert(!verify(null, altered, publicKey, signature));
  input.signature_hex = signature.toString('hex');
  return add(name, 'Evidence', input, { signing_hex: signingBytes.toString('hex'), signature_hex: input.signature_hex });
}

const baseWrapping = {
  version: 1,
  child: { lid_hex: repeat(0x11, 32), version: '2' },
  parent: { lid_hex: repeat(0x22, 32), version: '3' },
  parent_spec: { name: 'Aes256' }, child_spec: { name: 'Aes256' },
  key_format: { name: 'RawSecret' }, purpose: 'EncryptDecrypt',
  provider_ref: 'vault-a', security_domain: 'tenant-a', mechanism: 'fixture-wrap-v1',
  public_material_sha256: null,
};
const executor = repeat(0x44, 32);
const clock = { kind: 'ExecutorMonotonicMilliseconds', executor_hex: executor };
const baseValidity = { clock, not_before: '100', not_after: '200' };
const owner = { instance_hex: repeat(0x88, 16), generation: '13' };

add('profile_worker', 'CustodyProfile', { boundary: 'TrustedHostWorkerMemory', id: 'fixture-worker-v1' });
const context = add('context_worker', 'CustodyContext', { wrapping: baseWrapping, profile: ref('profile_worker') });
const material = add('material_worker', 'CustodyMaterialDescriptor', {
  context: ref('context_worker'), envelope_ref: 'envelope-1', envelope_sha256: repeat(0x33, 32),
});
const baseRequest = {
  operation_hex: repeat(0x55, 16), attempt_hex: repeat(0x66, 16), executor_hex: executor,
  context_sha256: context.sha256, request_sha256: repeat(0x77, 32),
};
add('request_worker', 'RequestBinding', baseRequest);
const baseAuthority = { issuer: 'authority-a', scope: { kind: 'Context', context_sha256: context.sha256 }, generation: '7' };
add('authority_context', 'AuthorityIdentity', baseAuthority);
const baseGrant = {
  authority: ref('authority_context'), request: ref('request_worker'), principal: 'principal-a',
  operation: 'Encrypt', sequence: '9', validity: baseValidity, ancestor_not_after: '180',
};
add('grant_encrypt', 'AuthorityGrant', baseGrant);
add('lease_identity', 'LeaseIdentity', { executor_hex: executor, counter: '11' });
add('lease_record', 'LeaseRecord', {
  lease: ref('lease_identity'), context_sha256: context.sha256, authority: ref('authority_context'),
  residency: { clock, not_before: '100', not_after: '500' },
});
add('creation_worker', 'CreationResult', {
  request: ref('request_worker'), owner, material_sha256: material.sha256, outcome: { kind: 'NativeWrappedOnlyGenerated' },
});
add('cleanup_released', 'LeaseCleanupResult', { record: ref('lease_record'), reason: 'Released' });
const baseCommand = { fence_hex: repeat(0x99, 16), executor_hex: executor,
  authority: { ...baseAuthority, generation: '8' }, validity: baseValidity };
const command = add('revocation_command', 'RevocationCommand', baseCommand);
const baseResult = { fence_hex: baseCommand.fence_hex, executor_hex: executor, authority: baseCommand.authority,
  command_sha256: command.sha256, in_flight: 'Drained', observed_leases: [ref('lease_identity')] };
add('revocation_drained', 'RevocationResult', baseResult);
evidence('evidence_grant', 'grant_encrypt', 'authority-a');
evidence('evidence_creation', 'creation_worker', 'executor-a');
evidence('evidence_cleanup', 'cleanup_released', 'executor-a');
evidence('evidence_command', 'revocation_command', 'authority-a');
evidence('evidence_revocation', 'revocation_drained', 'executor-a');

// Complete, mutually matching profile/context/descriptor/request/creation chains
// for both provider-object boundaries, in addition to the main worker chain.
for (const [suffix, boundary, outcome] of [
  ['session', 'ProviderSessionObject', { kind: 'ProviderSessionClosed', session: 'session-1' }],
  ['temporary', 'ProviderJournaledTemporaryObject', { kind: 'ProviderTemporaryObjectDestroyed', object: 'temporary-1' }],
]) {
  add(`profile_${suffix}`, 'CustodyProfile', { boundary, id: `fixture-${suffix}-v1` });
  const alternateContext = add(`context_${suffix}`, 'CustodyContext', { wrapping: baseWrapping, profile: ref(`profile_${suffix}`) });
  const alternateMaterial = add(`material_${suffix}`, 'CustodyMaterialDescriptor', {
    context: ref(`context_${suffix}`), envelope_ref: `envelope-${suffix}`, envelope_sha256: repeat(0x33, 32),
  });
  add(`request_${suffix}`, 'RequestBinding', { ...baseRequest, context_sha256: alternateContext.sha256 });
  add(`creation_${suffix}`, 'CreationResult', { request: ref(`request_${suffix}`), owner,
    material_sha256: alternateMaterial.sha256, outcome });
}

add('authority_domain', 'AuthorityIdentity', { ...baseAuthority,
  scope: { kind: 'SecurityDomain', provider_ref: 'vault-a', security_domain: 'tenant-a' } });
add('grant_generate', 'AuthorityGrant', { ...baseGrant, operation: 'GenerateWrapped' });
add('grant_decrypt_unix_domain', 'AuthorityGrant', { ...baseGrant, authority: ref('authority_domain'), operation: 'Decrypt',
  validity: { clock: { kind: 'UnixMilliseconds' }, not_before: '100', not_after: '200' } });
add('cleanup_expired', 'LeaseCleanupResult', { record: ref('lease_record'), reason: 'ResidencyExpired' });
add('cleanup_fenced', 'LeaseCleanupResult', { record: ref('lease_record'), reason: 'AuthorityFenced' });
add('revocation_suppressed', 'RevocationResult', { ...baseResult, in_flight: 'FurtherReleaseBlocked',
  observed_leases: [ref('lease_identity'), { executor_hex: executor, counter: '12' }] });
add('revocation_empty', 'RevocationResult', { ...baseResult, observed_leases: [] });

// Exercise every frozen V1 spec, format, purpose and public-digest alternative
// inside the new context frame, including RSA's explicit u32 parameter.
add('context_aes128_native_wrap', 'CustodyContext', { profile: ref('profile_worker'), wrapping: {
  ...baseWrapping, parent_spec: { name: 'Aes128' }, child_spec: { name: 'Aes128' },
  key_format: { name: 'ProviderNative', id: 'native-format-v1' }, purpose: 'WrapUnwrap',
} });
for (const [suffix, childSpec] of [
  ['ed25519', { name: 'Ed25519' }],
  ['rsa_pkcs1_2048', { name: 'RsaPkcs1v15Sha256', key_size: 2048 }],
  ['rsa_pss_3072', { name: 'RsaPssSha256', key_size: 3072 }],
  ['ecdsa_p256', { name: 'EcdsaP256Sha256' }],
  ['ecdsa_p384', { name: 'EcdsaP384' }],
]) {
  add(`context_${suffix}`, 'CustodyContext', { profile: ref('profile_worker'), wrapping: {
    ...baseWrapping, child_spec: childSpec, key_format: { name: 'Pkcs8Der' }, purpose: 'SignVerify',
    public_material_sha256: repeat(0xaa, 32),
  } });
}
add('context_hmac', 'CustodyContext', { profile: ref('profile_worker'), wrapping: {
  ...baseWrapping, child_spec: { name: 'Hmac256' }, purpose: 'GenerateVerifyMac',
} });
add('profile_identifier_min', 'CustodyProfile', { boundary: 'TrustedHostWorkerMemory', id: '*' });
add('profile_identifier_max', 'CustodyProfile', { boundary: 'TrustedHostWorkerMemory', id: 'x'.repeat(256) });
add('lease_counter_max', 'LeaseIdentity', { executor_hex: executor, counter: '18446744073709551615' });
add('authority_generation_max', 'AuthorityIdentity', { ...baseAuthority, generation: '18446744073709551615' });
add('grant_u64_clock_boundary', 'AuthorityGrant', { ...baseGrant, sequence: '18446744073709551615',
  validity: { clock: { kind: 'UnixMilliseconds' }, not_before: '18446744073709551613', not_after: '18446744073709551615' },
  ancestor_not_after: '18446744073709551614' });

assert.deepEqual([...new Set(vectors.map((vector) => vector.kind))].sort((a, b) => a - b),
  Array.from({ length: 13 }, (_, i) => i + 1));
for (const [group, alternatives] of Object.entries(tags)) {
  for (const name of Object.keys(alternatives)) {
    assert(exercisedTags.has(`${group}:${name}`), `missing enum vector for ${group}:${name}`);
  }
}
assert.equal(new Set(vectors.filter((vector) => vector.type === 'Evidence')
  .map((vector) => vector.input.claims_type)).size, 5);
const output = {
  format_version: 1,
  description: 'Independent Node reference vectors; public synthetic fixtures only. Encoding/signature evidence is not authorization, provider qualification, freshness or erasure evidence.',
  test_only_seed_hex: seed.toString('hex'),
  verifying_key_hex: verifyingKeyHex,
  field_definitions: {
    representation: 'input records use Rust field meanings. A sole {$ref:name} object expands to that earlier vector input. No reference marker is serialized on the wire.',
    integers: 'u64 fields are decimal strings, including versions, generations, counters, sequences and clock readings. This avoids JavaScript number rounding. Wire integers are unsigned big endian.',
    fixed_hex: 'Fields named *_hex contain lowercase fixed-width bytes: LID/executor/hash 32 bytes; operation/attempt/instance/fence UUID 16 bytes; signature 64 bytes. UUID bytes are not textual UUID encodings.',
    sha256: 'All *_sha256 fields and vector.sha256 are lowercase 32-byte digests; vector.sha256 hashes its complete canonical message. Fixtures 0x33/0x77/0xaa are synthetic, not claims about external material.',
    identifiers: 'Printable non-whitespace ASCII, 1..256 bytes, encoded as u16 byte length followed by exact bytes; no normalization or wildcard semantics.',
    enums: 'Symbolic alternatives in input use the Rust names; explicitly assigned byte tags are recorded in enum_tags. Parameterized alternatives use kind/name plus their payload fields.',
    nested: 'Nested contract messages are u32 byte length plus the COMPLETE domain/version/kind/body. CustodyContext.wrapping is u32 length plus frozen WrappingContext V1 bytes.',
    header: 'KeyRack:CustodyContract followed by NUL, u16BE 1, u8 message kind. Frozen wrapping header is KeyRack:ParentWrappedContext followed by NUL and u16BE 1.',
    signing: 'KeyRack:CustodyEvidenceSignature followed by NUL, u16BE 1, u8 algorithm 1 (Ed25519), issuer identifier, key_id identifier, then a length-prefixed full typed claim. No prehash.',
    evidence: 'Evidence input names claims_type for independent construction only; the nested claim carries its own wire kind. Outer kind 13 body is algorithm 1, issuer, key_id, nested claims, raw 64-byte signature.',
    validity: 'Clock is tagged UnixMilliseconds or ExecutorMonotonicMilliseconds plus 32-byte executor. Then u64 not_before and not_after encode a half-open interval. Fixture timing is not a production default.',
    lists: 'RevocationResult.observed_leases is u16 count followed by complete length-prefixed LeaseIdentity messages; counters are strictly increasing and every executor matches the result.',
    fixtures: 'Main worker chain uses the supplied synthetic constants. Session and temporary chains are internally hash-bound alternatives, not advertised provider profiles. Every Ed25519 signature uses the explicitly public 0x42 seed.',
  },
  message_kinds: kinds,
  enum_tags: tags,
  vectors,
};

if (process.argv[2] === '--check' && process.argv.length <= 4) {
  const fixture = process.argv[3] ?? fileURLToPath(new URL('../crates/keyrack-core/tests/vectors/custody-contract-v1.json', import.meta.url));
  assert.deepEqual(JSON.parse(readFileSync(fixture, 'utf8')), output, 'committed fixture differs from independent reference encoder');
  process.stdout.write(`Verified ${vectors.length} custody-contract vectors.\n`);
} else if (process.argv.length === 2) {
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
} else {
  throw new Error('usage: node scripts/custody-contract-vectors.mjs [--check [fixture.json]]');
}
