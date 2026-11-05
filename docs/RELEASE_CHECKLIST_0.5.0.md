# KeyRack 0.5.0 release checklist

Release preparation on [#75](https://github.com/KeyRack-io/keyrack/pull/75),
updated 2026-11-05. An unchecked item is work still to verify, not
evidence of a passing gate. This document does not cut a release, create a tag,
or qualify an experimental provider profile. Follow [Releasing KeyRack](RELEASING.md)
for the release workflow.

## Pin the scope

The starting baseline for this checklist is main
[`2c93cfaaceb26b22802989fd9bcab37d9ef1c04d`](https://github.com/KeyRack-io/keyrack/commit/2c93cfaaceb26b22802989fd9bcab37d9ef1c04d),
the merge of [#66](https://github.com/KeyRack-io/keyrack/pull/66). It includes
all-version wrapped-key migration, the lifecycle/history metadata addition and
the earlier schedule-time dependency refusal. It is a source baseline, not a
0.5.0 release pin or native wrapping qualification.

Later main merges must be tracked separately from that baseline:

| Change | Merge commit | Release evidence to retain |
| --- | --- | --- |
| [#68: wrapped-child rotation](https://github.com/KeyRack-io/keyrack/pull/68) | `994dfc0c3341260adc6ded8ac3764b29fcbf3ddf` | Creation-journal rotation, retained-version behavior, migration fences and `rotation-fence-controls`. |
| [#69: dependency-aware deletion](https://github.com/KeyRack-io/keyrack/pull/69) | `07f65ec918a443b3d9cf8ab2e14a78d67bed33b1` | Persisted explicit data-loss approval, claim-time rechecks, destruction recovery and `deletion-refusal-controls`. |

The release branch now includes main at
[`01347a4f771260bc13322de386e7460fb938325b`](https://github.com/KeyRack-io/keyrack/commit/01347a4f771260bc13322de386e7460fb938325b),
the merge of [#65](https://github.com/KeyRack-io/keyrack/pull/65). It includes
#63–#71, #73 and #74. Draft #72 remains excluded and held until after the tag.
The final PR head, tree, check runs and manual receipts are recorded on #75;
this source document does not claim that its own commit is the eventual tag.

- [x] Verify ancestry from `2c93cfa`, including the distinct #68/#69 merges.
- [x] Resolve native inclusion: #65 is merged. The explicit experimental
  `pkcs11:aes256-cbc-sha256-kw:v1` profile is in scope with its qualification
  limits; it is not hardware custody or formal verification.
- [x] Review final source and public support claims together, distinguishing
  software wrapping, experimental native wrapping, the worker harness and
  unimplemented cross-provider managed-key migration.
- [ ] Record the final release commit/tree and exact-source evidence after merge.

## Consolidate the changelog and upgrade guidance

- [x] Consolidate `[Unreleased]` into a readable 0.5.0 account of final behavior.
  Group overlapping implementation entries; remove intermediate descriptions that
  the final merged code supersedes. Set the release date only when cutting the
  release and retain an empty `[Unreleased]` section for subsequent changes.
- [x] Account for [#70](https://github.com/KeyRack-io/keyrack/pull/70) through
  [#74](https://github.com/KeyRack-io/keyrack/pull/74) explicitly in the
  consolidation: #70 clarifies destruction recovery audit outcomes;
  [#71](https://github.com/KeyRack-io/keyrack/pull/71) guards resident rotation,
  audits panics and cleans up unpublished keys after a known OCC refusal;
  #74 fixes custody-proof initialization retries and stops on prerequisite
  failure without reducing its assertions. Verify the included merge commits.
- [x] Keep [draft #72](https://github.com/KeyRack-io/keyrack/pull/72),
  disabled-source wrapped-key maintenance, out of the 0.5.0 changelog's delivered
  features and out of the release commit. It is implemented for the first release
  after 0.5.0 and held until after the tag; do not suggest temporary re-enablement
  as a maintenance workaround.
- [x] Document [#73](https://github.com/KeyRack-io/keyrack/pull/73)'s temporary
  `RUSTSEC-2026-0441` exception: the unmaintained `pin-utils@0.1.0` dependency is
  transitive through the AWS SDK (`aws-config`/Smithy) in `keyrack-aws-proxy`.
  Record the advisory-specific scope and removal condition. After 0.5.0, check
  for a contained AWS SDK upgrade that removes `pin-utils`, then remove the
  exception and rerun dependency-policy controls. Do not present the exception
  as an advisory fix or a global policy relaxation.
- [x] Describe wrapped-child creation, all-version `RewrapKey`/reparenting,
  wrapped-child rotation and dependency-aware deletion separately. Explain that
  parent rotation does not itself migrate old child envelopes. Replace the
  earlier unconditional schedule-refusal description with the final #69 approval
  and snapshot contract if that merge is included.
- [x] Retain the explicit `lifecycle_state` and `has_compromise_history` addition,
  the deprecated version `state` compatibility meaning, and the unchanged
  enforcement rules. Link [SPEC §7.2](SPEC.md#72-valid-transitions), including the
  distinction between verification, decrypt and raw export.
- [x] Retain actionable breaking-change guidance for Vault AAD and the bounded
  connection/request timeouts. Reconcile dependency updates, TLS trust changes,
  and ECDSA compatibility evidence with the final lockfile and security checks.
- [x] State supported storage/provider combinations, experimental-journal upgrade
  constraints, recovery limits and unsupported combinations. Do not describe
  software wrapping as token custody or worker code as service integration.
  Cross-provider unwrap remains outside 0.5.0.
- [x] Verify the eighteen intended workspace crates are already at 0.5.0;
  preserve six unpublished tooling/example exceptions. Align all four lockfiles,
  including the E2E lockfile's stale package entry. No second version bump is needed.
- [ ] Recompile commercial consumers of the final protobuf definitions before tagging.
- [ ] Retain exact-head documentation/source claim and SDK contract checks from
  [`release-doc-sdk.yml`](../.github/workflows/release-doc-sdk.yml), and regenerate
  the API inventory through the existing surface-parity workflow. Review public
  text for names or details that belong only in private integration records.

## Document the experimental native opt-in

The implementation merged in #65 at `01347a4` is included. The
[operator guide](OPERATOR.md#experimental-context-derived-wrapping-profile)
documents the runtime configuration opt-in; there is no separate experimental
Cargo feature. Qualification is restricted to SoftHSM 2.7.0. The pinned native
fixture and its negative controls are distinct from the ordinary distribution
SoftHSM persistence image, which does not establish native-profile qualification.

- [x] Record the reviewed native implementation merge (#65, `01347a4`);
  require fresh exact-candidate qualification evidence in the validation gates.
  Publish its experimental status, supported
  token/module/version and algorithms, and unresolved limitations. SoftHSM is a
  software token; its qualification does not establish hardware custody or
  qualify another token.
- [x] Check every 0.5.0 document, changelog entry, example and support claim for
  assertions that the experimental native profile is formally verified or
  hardware-custodied. Neither claim is supported by this release: formal proof
  work continues after 0.5.0, and SoftHSM qualification does not establish
  hardware custody. Keep functional conformance results distinct from those
  claims.
- [x] Document every actual build and runtime gate. If the final implementation
  adds a Cargo feature, record its exact name, default status and image build
  setting. Do not invent a feature flag or imply that compiling the provider
  enables native wrapping automatically.
- [x] Verify the opt-in example selects the exact mechanism
  `pkcs11:aes256-cbc-sha256-kw:v1` in a `wrapping:` entry with an explicit
  `security_domain`, bound to a dedicated named PKCS#11 provider. The implementation
  requires that provider to be non-default; ordinary keys use a separate provider
  entry even on the same token. Document refusal of explicit/implicit default and
  legacy single-provider configurations that violate this constraint.
- [x] Document the implementation's AES-256 derive-only resident roots and AES-128/256
  children, same-provider/security-domain restriction, context-derived KEK and
  no-fallback behavior. Do not broaden these into generic PKCS#11 or asymmetric
  wrapping support without new evidence.
- [x] Require startup qualification to succeed for the configured token: native
  derive/wrap/unwrap, wrong-context rejection, and sensitive/non-extractable
  derived KEKs and opened children. Record refusal behavior when qualification
  fails; keep the self-test's temporary objects session-only.
- [x] Retain the construction assumptions and limits from the reviewed design:
  context binding is supplied by derivation, not plain AES-KW AAD; it is not an
  SP 800-108 or 256-bit PRF claim. Retain the raw-token-PIN trust assumption and
  absence of qualified hardware tokens.
- [x] Verify and document operational limits from the final code: finite ownership
  ledger capacity and restart behavior, module-wide refusal after unconfirmed
  session closure, bounded leases, and unresolved creation evidence. Restart
  must not be described as reconstructing verified closure.
- [x] Update changelog, operator guide, configuration examples and support matrix
  together. Preserve ordinary SoftHSM key support while accurately distinguishing
  the experimental child-wrapping profile from the existing mechanism probe and
  persistent SoftHSM deployment profile.

## Validate the release candidate

The first full release E2E run exposed Demo 02's obsolete lineage-only child
creation. Its ordinary distribution SoftHSM configuration has no wrapping
profile. The demo now creates independent resident PKCS#11 keys, verifies provider
selection and rotation, and retains its old-ciphertext round trip. It does not
activate or qualify the experimental native profile. Require the full E2E gate
again on the corrected head; the earlier seven-of-eight result is not a pass.

Preparation checks run locally: full locked workspace tests, Format and Clippy.
The SDK removal controls must reject all four absent methods and accept all four
restoration controls. The documentation controls deliberately reintroduce retired
claims and remove their guards. Environment-dependent native and PostgreSQL tests
require the corresponding CI lanes; ignored local tests are not qualified results.
CI status and run URLs for the exact head belong in #75's execution receipt below
its description; all pre-merge gates must pass before merge. Remaining main/tag
steps are intentionally unchecked until owner-authorized release work.

- [ ] Record successful Check, Test, Clippy and Format jobs, dependency/security
  checks, release documentation/SDK checks and REST/gRPC surface parity for the
  exact candidate. Record skipped tests and environment-dependent exclusions;
  a zero-test invocation or skipped job is not passing feature evidence.
- [ ] Retain migration PostgreSQL conformance, reconnect/recovery and reverted
  fence controls from [`wrapped-migration.yml`](../.github/workflows/wrapped-migration.yml).
  For included #68/#69 changes, also retain rotation PostgreSQL/SQLite/service
  coverage and deletion approval, scheduling and recovery controls. Require each
  deliberate regression to fail for its intended reason and the restored source
  to pass.
- [ ] Record the experimental native profile's own qualification and integration
  results on the final candidate. General CI, a pre-#65 mechanism-only probe, software
  migration tests and ordinary-key SoftHSM persistence tests do not substitute
  for that profile's evidence. In current CI the expanded native lane is still
  named **SoftHSM wrapping mechanism probe**: retain its pinned build manifest,
  seven native service tests and context-binding negative control.
- [ ] Use the `release` label on the release PR and retain the full demo E2E and
  native amd64/arm64 image-build results. Complete the manual Demo 07 check
  described in [Releasing KeyRack](RELEASING.md#demo-coverage-model).
- [ ] On the merged release commit, retain successful main image publication and
  the exact-commit `softhsm-profile.yml` result/source artifact. The tag workflow
  promotes these existing images after E2E; it does not rebuild release images.

## Re-pin #66 evidence to the eventual release

Complete this handoff only after owner authorization and an existing `v0.5.0`
tag. Do not create a tag as part of #75 preparation. Preserve
the `2c93cfa` baseline and historical receipts; do not replace their commit or run
identifiers with release identifiers.

- [ ] Resolve the annotated tag to its full peeled commit, for example with
  `git rev-parse 'v0.5.0^{commit}'`, and record its tree SHA. Verify the tagged
  commit contains the reviewed migration, rotation/deletion changes and the
  agreed final native-profile scope. Link the migration contract at `v0.5.0`.
- [ ] Record successful full CI, surface parity and migration conformance run
  URLs for that release commit. Record each run's event, head SHA, attempt and
  actual checkout SHA. For a differing PR merge checkout, prove and record tree
  identity; a similarly named run or ancestor result is insufficient. Obtain
  missing release-commit evidence before claiming coverage.
- [ ] Download and preserve `migration-fence-controls` logs and `results.json`;
  record run/artifact IDs, archive SHA-256, source-file hashes, control names and
  results. Carry equivalent receipts for the included rotation, deletion and
  native qualification gates. Preserve receipts independently of CI retention.
- [ ] Record the release workflow result, E2E result, published image manifest
  digests and platform descriptors. Confirm the standard image matches its
  tested source and the SoftHSM manifest matches the exact-commit tested source
  artifact; mutable `:main`, `:latest` and short-SHA tags are not digest receipts.
- [ ] Add a new release conformance receipt and update the active pin in
  [Wrapped-key migration](WRAPPED_KEY_MIGRATION.md#pinned-revision-and-ci-results)
  and the release handoff. Keep the `4c0822e` and `558bd6a` receipts historical,
  and retain any `2c93cfa` integration receipt. Never move the release tag or
  relabel pre-release CI results to fill a missing gate.

The completed handoff should identify the release tag, peeled commit and tree,
included merges, exact CI runs/checkouts, archived control receipts, image
digests/platforms, tested native profile and remaining limitations.
