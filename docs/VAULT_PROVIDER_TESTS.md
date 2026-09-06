# Live Vault provider tests

Run from a checkout with Rust, Docker, and a Docker Compose version supporting
`up --wait --wait-timeout`:

```bash
bash scripts/test-vault-provider.sh
```

The runner reuses the `vault` and `vault-init` services from
`demos/01-foss-vault/docker-compose.yml`. It starts only those services, with a
unique Compose project, an ephemeral loopback-only port, disposable development
credentials, and no host data mounts. It ignores caller Vault credentials and
refuses remote Docker endpoints. Its exit/signal cleanup tears down only its own
project, including anonymous volumes. A force-killed runner or failed Docker
daemon can prevent cleanup; the project name is printed in the run output.

The CI job **Vault provider export tests** verifies that these four original
ignored tests are discoverable and runs them, plus any additional ignored tests
in the provider library:

- `exportable_round_trip`
- `loosen_then_export`
- `tighten_soft_revoke_preserves_data`
- `non_exportable_has_no_export_path`

Missing tests, an unavailable Vault, initialization failures, failed assertions,
and cleanup failures fail the lane. Ordinary `cargo test --workspace` still leaves
these live tests ignored. Existing demo-01 PR canary and release coverage remain
unchanged; this lane adds provider export-policy coverage, not the first Vault E2E.

Additional integration assertions can share this fixture:

```bash
bash scripts/test-vault-provider.sh -- path/to/additional-test-runner
```

The extra command runs only after the mandatory provider tests pass and inherits
`VAULT_ADDR` and `VAULT_TOKEN`. Add future worker assertions through this extension
in the same CI job; they are not implemented or claimed here.

These tests exercise real Vault export and soft-revoke semantics. In particular,
soft revocation does not unset Vault's one-way exportable flag: the KeyRack
service remains responsible for its own export-policy gate. Passing this lane
does not qualify parent-wrapped hierarchy, a trusted worker, or custody-preserving
cross-provider transport. The fixture follows demo-01's Vault image version and
is not a production Vault configuration.
