# Releasing KeyRack

KeyRack uses tag-driven releases with the end-to-end demo suite as a hard gate.

## CI lanes

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | every PR + push to `main` | fast lane: check / test / clippy / fmt / docker build |
| `docker.yml` | push to `main`, PRs | `:edge` / `:main` / `:sha-...` images (no version tags) |
| `e2e.yml` | reusable (`workflow_call`) + manual | the demo-stack E2E suite (`scripts/run-demos-ci.sh`) |
| `release-pr.yml` | PR labeled `release` | full E2E + multi-arch image build (no push) before merge |
| `release.yml` | push tag `v*` | re-runs E2E, then publishes the multi-arch image **only if E2E passes** |

E2E is intentionally kept off the per-PR fast lane; it runs as a gate on release
PRs and on the release tag.

## Release steps

1. **Open a release PR** with the version bump and `CHANGELOG.md` section
   (move `[Unreleased]` into `[X.Y.Z] — <date>`). Add the **`release`** label.
2. `release-pr.yml` runs the full E2E suite and a multi-arch image build (no
   push). **Merge only when green.**
3. **Tag the merged commit** and push:
   ```bash
   git tag -a vX.Y.Z -m "KeyRack X.Y.Z — <summary>"
   git push origin main
   git push origin vX.Y.Z      # use `pgit push` in this environment
   ```
4. `release.yml` runs the E2E suite again as the gate, then builds and pushes
   the multi-arch image to `ghcr.io/keyrack-io/keyrack-service:X.Y.Z` (+ `:X.Y`).
   A failed E2E **blocks** the publish.

## Notes

- **Prereleases** (e.g. `vX.Y.Z-beta.N`) never move `:latest` (`latest=auto`).
- Tag the **merged** commit, so the tag tree contains `release.yml`.
- **Manual validation** any time: run `e2e.yml` via *Actions → E2E demos → Run
  workflow*, or locally with `./scripts/run-demos-ci.sh` (optionally a subset,
  e.g. `./scripts/run-demos-ci.sh 10-mtls-identity`).
- Commercial shims (`keyrack-commercial`) that vendor the proto must be
  recompiled against any proto change before the release tag.
