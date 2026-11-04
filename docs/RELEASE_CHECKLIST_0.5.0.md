# KeyRack 0.5.0 release checklist

Draft prepared on 2026-11-04. An unchecked item is work still to verify, not
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

- [ ] Record the full proposed release commit and tree SHA, included PRs and
  remaining dependencies. Verify ancestry from `2c93cfa`, and explicitly verify
  inclusion of #68 and #69 rather than attributing them to #66.
- [ ] Resolve the experimental native wrapping inclusion gate before release.
  At `2c93cfa`, service wrapping supports the software mechanism only. A probe,
  branch implementation or planned qualification is not merged release support.
- [ ] Recheck the final source, generated API inventory and public docs together
  after the remaining merges. Preserve the distinctions between software wrapping,
  experimental native wrapping, the worker harness and cross-provider unwrap.

## Consolidate the changelog and upgrade guidance

- [ ] Consolidate `[Unreleased]` into a readable 0.5.0 account of final behavior.
  Group overlapping implementation entries; remove intermediate descriptions that
  the final merged code supersedes. Set the release date only when cutting the
  release and retain an empty `[Unreleased]` section for subsequent changes.
- [ ] Describe wrapped-child creation, all-version `RewrapKey`/reparenting,
  wrapped-child rotation and dependency-aware deletion separately. Explain that
  parent rotation does not itself migrate old child envelopes. Replace the
  earlier unconditional schedule-refusal description with the final #69 approval
  and snapshot contract if that merge is included.
- [ ] Retain the explicit `lifecycle_state` and `has_compromise_history` addition,
  the deprecated version `state` compatibility meaning, and the unchanged
  enforcement rules. Link [SPEC §7.2](SPEC.md#72-valid-transitions), including the
  distinction between verification, decrypt and raw export.
- [ ] Retain actionable breaking-change guidance for Vault AAD and the bounded
  connection/request timeouts. Reconcile dependency updates, TLS trust changes,
  and ECDSA compatibility evidence with the final lockfile and security checks.
- [ ] State supported storage/provider combinations, experimental-journal upgrade
  constraints, recovery limits and unsupported combinations. Do not describe
  software wrapping as token custody or worker code as service integration.
  Cross-provider unwrap remains outside 0.5.0.
- [ ] Verify the eighteen intended workspace crates remain at 0.5.0 and preserve
  the intentional unpublished-package exceptions recorded in the changelog.
  Check lockfiles, image examples, SDK examples and vendored protos against the
  final source; recompile consumers of changed protobuf definitions.
- [ ] Run the documentation/source claim and SDK contract checks from
  [`release-doc-sdk.yml`](../.github/workflows/release-doc-sdk.yml), and regenerate
  the API inventory through the existing surface-parity workflow. Review public
  text for names or details that belong only in private integration records.

## Document the experimental native opt-in

This section is a release dependency, not an announcement that the profile has
shipped. The inspected candidate is
[`078f8f5c4ba4f55979f85065fc381a63a1298cbd`](https://github.com/KeyRack-io/keyrack/commit/078f8f5c4ba4f55979f85065fc381a63a1298cbd)
on `feat/softhsm-context-wrapping`. Its
[operator documentation](https://github.com/KeyRack-io/keyrack/blob/078f8f5c4ba4f55979f85065fc381a63a1298cbd/docs/OPERATOR.md#experimental-context-derived-wrapping-profile)
describes a configuration opt-in. Its service manifest does not define a
separate experimental Cargo feature. Recheck the merged implementation before
publishing build or configuration instructions.

- [ ] Record the reviewed native implementation merge and qualification evidence
  for the exact release candidate. Publish its experimental status, supported
  token/module/version and algorithms, and unresolved limitations. SoftHSM is a
  software token; its qualification does not establish hardware custody or
  qualify another token.
- [ ] Document every actual build and runtime gate. If the final implementation
  adds a Cargo feature, record its exact name, default status and image build
  setting. Do not invent a feature flag or imply that compiling the provider
  enables native wrapping automatically.
- [ ] Verify the opt-in example selects the exact mechanism
  `pkcs11:aes256-cbc-sha256-kw:v1` in a `wrapping:` entry with an explicit
  `security_domain`, bound to a dedicated named PKCS#11 provider. The candidate
  requires that provider to be non-default; ordinary keys use a separate provider
  entry even on the same token. Document refusal of explicit/implicit default and
  legacy single-provider configurations that violate this constraint.
- [ ] Document the candidate's AES-256 derive-only resident roots and AES-128/256
  children, same-provider/security-domain restriction, context-derived KEK and
  no-fallback behavior. Do not broaden these into generic PKCS#11 or asymmetric
  wrapping support without new evidence.
- [ ] Require startup qualification to succeed for the configured token: native
  derive/wrap/unwrap, wrong-context rejection, and sensitive/non-extractable
  derived KEKs and opened children. Record refusal behavior when qualification
  fails; keep the self-test's temporary objects session-only.
- [ ] Retain the construction assumptions and limits from the reviewed design:
  context binding is supplied by derivation, not plain AES-KW AAD; it is not an
  SP 800-108 or 256-bit PRF claim. Retain the raw-token-PIN trust assumption and
  absence of qualified hardware tokens.
- [ ] Verify and document operational limits from the final code: finite ownership
  ledger capacity and restart behavior, module-wide refusal after unconfirmed
  session closure, bounded leases, and unresolved creation evidence. Restart
  must not be described as reconstructing verified closure.
- [ ] Update changelog, operator guide, configuration examples and support matrix
  together. Preserve ordinary SoftHSM key support while accurately distinguishing
  the experimental child-wrapping profile from the existing mechanism probe and
  persistent SoftHSM deployment profile.

## Validate the release candidate

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
  results on the final candidate. General CI, the old mechanism probe, software
  migration tests and ordinary-key SoftHSM persistence tests do not substitute
  for that profile's evidence.
- [ ] Use the `release` label on the release PR and retain the full demo E2E and
  native amd64/arm64 image-build results. Complete the manual Demo 07 check
  described in [Releasing KeyRack](RELEASING.md#demo-coverage-model).
- [ ] On the merged release commit, retain successful main image publication and
  the exact-commit `softhsm-profile.yml` result/source artifact. The tag workflow
  promotes these existing images after E2E; it does not rebuild release images.

## Re-pin #66 evidence to the eventual release

Complete this handoff when the release is authorized and the tag exists. Preserve
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
