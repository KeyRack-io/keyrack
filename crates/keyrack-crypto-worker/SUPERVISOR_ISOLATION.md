# Two-user supervisor acceptance fixture

This fixture implements the worker/coordinator credential-isolation acceptance
bar using **two real Linux OS users and systemd**, with actual coordinator reads
returning `EACCES` across worker restart and credential rotation. Containers are
used only by the pre-existing A2 Vault service fixture, not as the identity boundary.
A local macOS run cannot establish this acceptance result.

`prepare-worker-vault-fixture.py` invokes `worker-supervisor-isolation.py` after the
normal worker contribution succeeds on Linux. The existing A2 job already invokes
that contribution. Linux execution is mandatory: missing sudo, systemd, user tools,
identity evidence or permissions fails the lane. No new workflow, Vault service,
ignored live-test name or alternative maintained stack is added.

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
`ENOENT`, another error or inability to read the positive control fails.

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
bash scripts/test-vault-provider.sh -- bash scripts/test-worker-vault-contribution.sh --from-vault-provider-fixture
```

Before a deployment makes the same claim, preserve the demonstrated identity,
supervisor, credential-path and clean-environment controls in that deployment.
This fixture does not approve the production custody profile, pin a provider,
replace the external authority, or change required repository checks.
