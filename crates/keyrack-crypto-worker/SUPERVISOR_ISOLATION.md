# Two-user supervisor acceptance fixture

This fixture implements the worker/coordinator credential-isolation acceptance
bar using **two real Linux OS users and systemd**, with actual coordinator reads
returning `EACCES` across worker restart and credential rotation. Containers are
used only by the pre-existing A2 Vault service fixture, not as the identity boundary.
A local macOS run cannot establish this acceptance result.

The stable **Worker credential isolation** check is job `isolation` in
`.github/workflows/worker.yml`. It runs `scripts/test-worker-isolation.sh`, which
requires Linux, sets `KEYRACK_WORKER_ISOLATION=required`, and invokes the existing
A2 fixture through `test-vault-provider.sh -- bash
test-worker-vault-contribution.sh --from-vault-provider-fixture`. The preparation
script runs the worker suite and then `worker-supervisor-isolation.py`.

The job fails on unsupported platforms, missing sudo/systemd/user tools, failed
identity evidence, missing completion evidence, or a NOT RUN message. Fixture
success is reported only after cleanup. Repository protection must separately
require this stable check; the workflow does not change branch protection.

Ordinary Vault-provider contributions default to isolation mode `off` and print
**NOT RUN** for the supervisor rather than implying isolation passed. Explicit
`auto` mode supports laptop development (Linux executes, other platforms report
NOT RUN); `required` mode rejects unsupported platforms. The dedicated check
always selects `required`. This uses the existing Vault service and original
provider acceptance tests; it introduces no second maintained Vault stack.

The trusted provisioning controller uses root only for creating/removing the two
unique accounts, installing a temporary unit, placing credentials and rotating/
revoking the fixture token. **Root performs no permission-denial probe.** Root and
the host administrator remain trusted; this is not a claim of resistance to them.

The systemd unit runs the existing real-Vault subprocess test under the worker
user, with no effective/ambient capabilities and `NoNewPrivileges=yes`. That test
starts the actual worker executable under the same non-root identity and performs
canonical wrapped-only generation, application encryption/decryption and local
fencing. The test verifies its own real/effective UID, the actual child PID, all
four child UID values in `/proc`, and zero child effective capabilities. The
unit's exit status and fresh worker identity report are required, so running zero
tests or merely reaching a startup message cannot pass.

A separate Python probe starts through `runuser` as the coordinator user with an
explicitly clean environment. It refuses real/effective/saved UID 0, the wrong UID,
the worker UID, effective capabilities and inherited credential variables. It
first reads a public control file successfully, then actually calls `open` for
reading on the worker token path. Only `EACCES` is accepted: successful open,
`ENOENT`, another error or inability to read the positive control fails. Expected
check failures print their static description to stderr; unexpected exceptions
retain a generic diagnostic so paths and credential data cannot enter the log.

The controller performs three phases:

1. Provision token 1; coordinator read denial; systemd worker execution; coordinator
   read denial again.
2. Keep token 1 and restart the same systemd unit; require a different worker PID
   and incarnation, a successful native Vault round trip, and read denial on both
   sides of the restart.
3. Atomically replace the file with independently issued token 2, revoke token 1
   through the fixture admin, and restart the unit again. Require a new worker
   identity and successful native Vault round trip, plus before/after read denial.

That gives **three real worker executions and six unprivileged `EACCES` probes**.
The systemd service is a oneshot test driver with `RemainAfterExit=yes`; probes
bracket its execution. This fixture does not claim to test live process-memory
inspection or execute a coordinator read while a particular crypto call is active.
Its acceptance property is credential-file isolation across the three phases.

Temporary binaries/configuration are root-owned; the worker token directory is
owned by the dedicated worker user, and the coordinator has a separate UID/group.
Only paths, not token values, appear in process arguments, unit environment or
logs. The coordinator receives no Vault-admin environment. Worker and coordinator
assertions execute non-root even though the trusted provisioning controller needs
sudo. This distinction is explicit in the logged UID evidence.

Cleanup handles termination, attempts all owned resources despite individual
failures, checks service stop state, removes/reloads the unit, deletes both users
and any remaining private groups, and removes the private directory. Success is
printed only after cleanup succeeds. The existing A2 fixture then revokes its
remaining temporary credentials/policies and tears down Vault. SIGKILL or loss of
the host cannot be handled by application cleanup; GitHub's disposable runner is
the final host boundary.

Run through the existing lane on a Linux systemd host:

```sh
bash scripts/test-worker-isolation.sh
```

Before a deployment makes the same claim, preserve the demonstrated identity,
supervisor, credential-path and clean-environment controls in that deployment.
This fixture does not approve the production custody profile, pin a provider,
replace the external authority, or change required repository checks.


The corrected fixture passed on Ubuntu 24.04 in [CI run 34103419226](https://github.com/KeyRack-io/keyrack/actions/runs/34103419226/job/101682857423),
commit `049c5b8ec0ea621d74c2504c4538fa2137609522`: worker UID 999, coordinator real/
effective/saved UID 997, zero effective capabilities, three native-Vault executions
and six EACCES probes. Unit/users/files cleanup passed before the final success
message. The first run had passed the probes but failed a redundant systemd cleanup
command; it was not recorded as acceptance. The corrected run verifies unit removal
and `LoadState=not-found` explicitly.
