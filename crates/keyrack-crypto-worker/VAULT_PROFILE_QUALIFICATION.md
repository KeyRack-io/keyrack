# Vault derived-parent construction — qualification evidence

Recorded 2026-09-07. **The worker-owned API/cryptographic construction investigation
is verified for the exact build and fresh-parent conditions below.** Full canonical
custody-context bytes affect native wrapping through HKDF-SHA256 key derivation;
they are not AES-GCM additional authenticated data. Source inspection, independent
decryption and live negative controls agree. This closes the construction
investigation for this fixture, not production profile approval. The identifier
`UNQUALIFIED-vault-derived-worker-fixture-v1` remains unchanged and unadvertised;
A2 owns acceptance of the proposed profile/transcript and integration contracts.

## Artifact and scope

| Item | Observed value / scope |
|---|---|
| Existing A2 fixture | `demos/01-foss-vault`; no second maintained stack |
| Compose image reference | `hashicorp/vault:1.17` — a mutable minor tag, **not a repository digest pin** |
| Tested Vault version | `1.17.6`; the live qualification now fails on version drift |
| Locally inspected image ID and repository digest | `sha256:74a4ab138ab5d64725e89cd9a9c73f7040c7fe49e98b71697b275ca9a69919df` |
| Image revision and official `v1.17.6` source commit | `69a720d5d940bfcd590d7c24f3c98f178673d796` |
| Parent | Freshly created `aes256-gcm96`, derived, non-convergent, version 1; runtime parent non-exportable and plaintext backup disabled |
| Child | Native `datakey/wrapped`, explicit `bits=256`, `key_version=1`; no caller-generated child or imported independently usable child object |
| Semantic context | Exact canonical `keyrack_core::custody::CustodyContext` bytes, including unchanged V1 wrapping fields and explicit worker-memory profile |

The image/source association is checked release metadata, not a reproducible-build
proof or runtime attestation. Fresh creation matters: the source still implements
a legacy counter-mode KDF. The public `derived=true` metadata check alone does not
prove which KDF an old/imported/restored parent uses. No qualification of those
parents, other versions, convergent encryption or arbitrary hierarchy follows.

## What the pinned implementation actually authenticates

Let `P_v` be the 32-byte parent key at the selected version and `C` the complete
decoded custody frame. For a fresh derived parent, the construction reconstructed
from source and matched independently is:

```text
K_C = HKDF-SHA256(IKM=P_v, salt=absent, info=C, output_length=32)
payload = nonce[12] || AES-256-GCM(K_C, nonce, child[32], AAD=empty)
wire = "vault:v1:" || base64(payload)       # 60 decoded payload bytes
```

Fresh derived policies select HKDF-SHA256 in the
[policy constructor](https://github.com/hashicorp/vault/blob/69a720d5d940bfcd590d7c24f3c98f178673d796/sdk/helper/keysutil/lock_manager.go#L411-L430).
The data-key handler decodes `context`, generates random child bytes internally,
and calls encryption without an AAD factory. Only the plaintext variant returns
those bytes in its response.
[Native data-key handler](https://github.com/hashicorp/vault/blob/69a720d5d940bfcd590d7c24f3c98f178673d796/builtin/logical/transit/path_datakey.go#L77-L200).

The key-selection code supplies context as HKDF info with absent salt. Non-derived
keys bypass this derivation. GCM encrypts with a random nonce; decrypt selects the
parent version and recomputes the key. The textual version parser accepts aliases.
[Key derivation](https://github.com/hashicorp/vault/blob/69a720d5d940bfcd590d7c24f3c98f178673d796/sdk/helper/keysutil/policy.go#L823-L883),
[decrypt path](https://github.com/hashicorp/vault/blob/69a720d5d940bfcd590d7c24f3c98f178673d796/sdk/helper/keysutil/policy.go#L942-L1035),
[GCM implementation](https://github.com/hashicorp/vault/blob/69a720d5d940bfcd590d7c24f3c98f178673d796/sdk/helper/keysutil/policy.go#L1900-L2030).

**Inference under HKDF pseudorandomness and AES-GCM integrity assumptions:** a
different complete frame derives a different wrapping key, so the original tag
does not verify. The trusted worker constructs the frame before calling Vault and
retains it for open; the coordinator cannot substitute adjacent unsigned context.
This is derived-key binding, not a claim that Vault accepts this frame as GCM AAD,
nor a formal proof of multi-user security or nonce limits.

The versioned API documents `associated_data` for ordinary encrypt/decrypt but not
native data-key generation. The live controls confirm that a nonempty field on
`datakey/wrapped` is ignored: decrypt succeeds without AAD and fails with that AAD.
Ordinary encrypt/decrypt with the same field supplies the positive control.
[Vault 1.17 Transit API](https://developer.hashicorp.com/vault/api-docs/v1.17.x/secret/transit#generate-data-key).

## Executable qualification controls

[The qualification helper](src/source/tests/qualification.rs) runs inside the
existing ignored `real_vault_native_wrapped_only_authenticates_every_v1_context_byte`
test. Its historical name remains for the discovery guard; its input is the full
custody frame. The worker contribution still contains exactly four live tests.

| Control | Observed result and implication |
|---|---|
| Independent Rust HKDF/AES-GCM decryptor, with a separately created exportable **control** parent | Matches Vault's native plaintext; empty AAD succeeds and nonempty AAD fails. Production fixture parent is never made exportable. |
| Flip each byte of the complete frame | Existing live Vault check and independent decryptor reject every changed frame, including profile bytes. |
| Missing, empty or invalid-base64 context on derived parent | Vault rejects. |
| Change nonce, encrypted child or tag | Vault rejects representative mutations in all three regions. |
| Native data-key `associated_data` versus ordinary encrypt AAD | Native field ignored; ordinary encrypt/decrypt requires matching AAD. Unsigned extra fields cannot supply missing authentication. |
| Base64 context display containing CR/LF | Same decoded bytes decrypt; the display spelling is not bound. |
| `vault:v01:` and `vault:v0:` aliases for version 1 | Same plaintext, different exact ciphertext digest. Version selection is not authentication of literal envelope text. |
| Two native generations under one context | Both decrypt; context alone is neither a unique generation attempt nor a ciphertext commitment. |
| Rotate control parent | Explicit version 1 remains version 1; omitted version generates version 2, which the old derived key cannot open. Relabeling version 1 as version 2 is rejected. |
| Non-derived control parent | Missing/different context still decrypts. Runtime preparation rejects this parent. |
| Exportable control parent | Runtime preparation rejects it. Root export is restricted to the test-admin algorithm control. |
| Worker token on plaintext data-key and parent export paths | Both denied by Vault. Coordinator parent-decrypt denial remains a separate existing live test. |

Control parents have fresh random names and explicit deletion checks. The existing
A2 fixture owns final container teardown. Test-admin credentials never enter the
worker subprocess. Decoded control secrets use owned zeroizing buffers, with no
secret-value assertion output; this does not demonstrate comprehensive memory
erasure in the test process or Vault.

## Required integration interpretation

1. Authenticate the complete canonical frame, including the explicit profile,
   through a reviewed parent resolver and the native context path. Preserve V1
   bytes; never reinterpret historical V1-only records as this profile.
2. Keep exact ciphertext SHA-256 and envelope reference in the canonical material
   descriptor, then bind that descriptor to the authenticated creation result and
   trusted request/attempt/owner. Native context binding does not replace those
   provenance and exact-envelope commitments.
3. Qualify parent creation history, version selection, immutable provider identity
   and policy controls. The synthetic fixture mapping and `derived=true` response
   are not sufficient production provenance. A2 owns fixture image pinning; the
   new exact-version assertion detects drift but is not an image attestation.
4. The worker and Vault are inside this profile's trusted secret boundary. Vault
   generates plaintext child bytes internally. A wrapped-only response is neither
   a provider-object closure receipt nor proof that every allocator copy vanished.
5. Obtain A2 acceptance of the proposal and profile, trusted authority/observer-key
   provisioning, durable creation/restart reconciliation and the A3 adapter before
   activation. The [two-user supervisor fixture](SUPERVISOR_ISOLATION.md) separately demonstrates
   credential-file isolation; production deployments must preserve its controls. No native
   creation result is converted to `VerifiedA2Closure` by this crate.

## Reproduction and evidence limits

```sh
bash scripts/test-vault-provider.sh -- bash scripts/test-worker-vault-contribution.sh --from-vault-provider-fixture
cargo clippy --locked -p keyrack-crypto-worker --all-targets -- -D warnings
cargo fmt --all -- --check
```

2026-09-07 local result: the original four provider tests passed; 38 ordinary worker
tests passed with exactly four live tests ignored; explicit live execution passed
3 unit tests plus 1 subprocess test with none skipped. Clippy passed on Rust 1.92.0 and 1.98.0; formatting passed. Test secret
comparisons retain redacted failure output while satisfying the Rust 1.98 lint.
The qualification controls above executed in that live unit run. No mock fallback,
runtime change, shared-contract edit, fixture edit or workflow edit was required.

This is hand-reproducible evidence on the recorded artifact, not evidence of a PR
CI run or required branch-protection gate. A2 retains ownership of the existing
lane, trigger ancestry and immutable fixture pinning. No production capability is
enabled by this report.
