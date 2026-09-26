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

The CI job **Vault provider export tests** verifies that all ten required ignored tests are
discoverable and runs them serially, plus any additional ignored tests in the
provider library. The four original export-policy tests remain required:

- `exportable_round_trip`
- `loosen_then_export`
- `tighten_soft_revoke_preserves_data`
- `non_exportable_has_no_export_path`

Six additional required tests cover authenticated encryption and availability:

| Test (under `live_tests::`) | Assertion |
| --- | --- |
| `matching_associated_data_round_trips` | Matching binary AAD decrypts to the original plaintext. |
| `tampered_associated_data_is_authentication_failure` | Changed AAD returns HTTP 400 and `cipher: message authentication failed`. |
| `omitted_associated_data_is_authentication_failure` | Missing AAD on bound ciphertext returns the same authentication failure. |
| `legacy_ciphertext_without_associated_data_is_authentication_failure` | Both absent-AAD and old context-only ciphertext are valid without AAD, but fail authentication with the required AAD; the key is non-derived. |
| `sealed_vault_is_unavailable_and_restores_existing_ciphertext` | Sealed Vault returns HTTP 503; both decrypt and the construction-time health check report `ProviderUnavailable` with `Vault is sealed`. The same instance is unsealed and its pre-seal ciphertext decrypts. |
| `unreachable_vault_is_unavailable_within_timeout` | A refused loopback connection reports `ProviderUnavailable` with a connection-failure cause within the request deadline, including during construction. |

The seal test requires `KEYRACK_VAULT_TEST_UNSEAL_KEY`, obtained by the runner from
its own disposable instance. It refuses to seal without that capability. Do not
run it concurrently with any Vault tests. A guard is armed before sealing and
only disarmed after Vault confirms it is unsealed. On panic, its destructor joins
a separate cleanup thread/runtime to attempt unseal with bounded HTTP timeouts,
without depending on the unwinding test runtime. Cleanup errors are reported
without causing a second panic; the runner still tears down its owned fixture.
The live test injects a panic after confirming HTTP 503 and verifies that the
original ciphertext decrypts after the guard runs. Normal execution also unseals
before asserting the observations collected while sealed. The runner also checks
that Vault is unsealed before invoking an additional test runner, and does not
pass the unseal key to that command. Restarting Vault is not a substitute for unsealing: the
existing ciphertext must remain decryptable.

Ordinary provider unit tests capture encrypt/decrypt HTTP requests to verify
base64 `associated_data` and absence of `context`. They also exercise stalled
headers and bodies with shorter test-only deadlines, HTTP error classification
across all request helpers, and malformed JSON responses.

Missing tests, an unavailable Vault, initialization failures, failed assertions,
and cleanup failures fail the lane. Ordinary `cargo test --workspace` still leaves
these live tests ignored. Existing demo-01 PR canary and release coverage remain
unchanged; this lane adds provider export-policy coverage, not the first Vault E2E.

As of the 2026-09-07 owner review, this job and **SoftHSM wrapping mechanism probe**
run but do not gate merges: neither is a required branch-protection context on
`main`. The owner plans to add both after integration. Workflow presence alone
does not make a job a merge gate; re-check the required-context list before
reporting otherwise. The workflow triggers on pushes to `main` and PRs targeting
`main`, `feat/**`, `fix/**` or `handback/**`, not every feature-branch push. Existing
PRs still need a qualifying event; branch eligibility alone is not a completed run.

Additional integration assertions can share this fixture:

```bash
bash scripts/test-vault-provider.sh -- path/to/additional-test-runner
```

The extra command runs only after the mandatory provider tests pass and inherits
`VAULT_ADDR` and `VAULT_TOKEN`. The existing CI job now uses this extension for the
[provisional worker](../crates/keyrack-crypto-worker/README.md):

```bash
bash scripts/test-vault-provider.sh -- bash scripts/test-worker-vault-contribution.sh --from-vault-provider-fixture
```

Both suites run from one checkout against the same fixture. The worker helper
guards four explicitly ignored live tests and provisions restricted test tokens;
it does not create a second maintained Vault stack. This adopts the provisional
worker contribution, not production A3 qualification or a branch-protection gate.

These tests exercise real Vault export and soft-revoke semantics. In particular,
soft revocation does not unset Vault's one-way exportable flag: the KeyRack
service remains responsible for its own export-policy gate. Passing this lane
does not qualify parent-wrapped hierarchy, a trusted worker, or custody-preserving
cross-provider transport. Both fixture services pin Vault 1.17.6 by image digest:
`sha256:74a4ab138ab5d64725e89cd9a9c73f7040c7fe49e98b71697b275ca9a69919df`.
This is not a production Vault configuration.

## AAD compatibility and HTTP failures

Encrypt and decrypt send AAD as base64 `associated_data`. Non-derived Vault keys
ignore `context`, so the previous requests did not authenticate KeyRack's header
or encryption context. **Breaking change:** Vault ciphertext created before this
fix no longer decrypts with the required header and encryption context; create
fresh keys. There is no retry without AAD, compatibility switch, or change to
derived keys. An explicitly empty AAD still means empty AAD; this does not bypass
authentication for ciphertext created with nonempty AAD.

The HTTP client has a fixed 5-second connection timeout and 15-second total
request timeout, including response-body reads. Only tests override them; there
is no configuration field or constructor signature change. The existing
construction-time mount health check remains in place.

| Failure | Error class |
| --- | --- |
| Connection failure | `KeyRackError::ProviderUnavailable` |
| Connection or request/body timeout | `KeyRackError::ProviderUnavailable` |
| HTTP 503, including sealed Vault | `KeyRackError::ProviderUnavailable` |
| Every other HTTP failure, including AAD authentication failure (400) | Existing `KeyRackError::Provider` |
| Other transport, JSON, and response-decoding failures | Existing error behavior preserved |

Same-provider re-encryption uses Core's decrypt-then-encrypt path because this
provider advertises `supports_atomic_re_encrypt: false`, so it receives the same
AAD handling.
