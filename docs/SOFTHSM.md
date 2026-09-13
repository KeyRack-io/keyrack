# Persistent SoftHSM profile

The `keyrack-service-softhsm` image packages the service and SoftHSM2 for a
single writer with durable SQLite metadata and a file-backed token. The token
files and metadata must survive together: SQLite stores records and provider
handles, not a replacement for the provider's key material. SoftHSM provides
software token persistence; it does not establish a hardware custody boundary.

## Image and deployment

`docker/Dockerfile.softhsm` builds for `linux/amd64` and `linux/arm64`. The runtime
uses UID/GID `10001:10001` and `/usr/lib/softhsm/libsofthsm2.so` on both platforms.
It contains no initialized token or PINs. `deploy/softhsm` supplies a Kustomize
profile with one replica, `Recreate`, an RWO PVC, and a read-only root filesystem.
Metadata lives at `/var/lib/keyrack/metadata/keyrack.db`; tokens live at
`/var/lib/keyrack/tokens` on that same PVC.

The `SoftHSM persistent profile` workflow tests each native image before pushing
it on `main`, then composes the tested digests. Release promotion consumes that
exact commit's successful workflow artifact and manifest digest without a
rebuild. Select a published digest for **both** init and service containers;
`edge` in the example is a placeholder for that operator selection. A PR run
builds and tests images but does not publish them.

Provision a Kubernetes Secret named `keyrack-softhsm-secrets` with three keys:
`token-label`, `user-pin`, and `so-pin`. Use your secret provisioning system or
existing protected files, for example:

```sh
kubectl create secret generic keyrack-softhsm-secrets \
  --from-file=token-label=/secure/keyrack/token-label \
  --from-file=user-pin=/secure/keyrack/user-pin \
  --from-file=so-pin=/secure/keyrack/so-pin
```

The init container mounts all three files. The service mounts only the label
and user PIN. File references resolve under `KEYRACK_SECRET_ROOT` through the
existing `pin_ref` resolver; a single trailing newline is removed, and empty
files or paths escaping the root are rejected. No PIN is passed in an argument
or environment variable. The initializer uses these defaults:

| Input | Reference |
| --- | --- |
| Token label | `file:token-label` |
| User PIN | `file:user-pin` |
| SO PIN | `file:so-pin` |

The initializer verifies both supplied PINs on every retry. It creates a token
only in an empty dedicated store, resumes a token whose user PIN initialization
was interrupted, and refuses unrelated or duplicate initialized tokens. It does
not reset an existing token or change an initialized PIN. Labels must fit the
PKCS#11 32-byte field without truncation, edge whitespace, or control characters.

Configure authentication and policy in `deploy/softhsm/keyrack.yaml` before
serving API traffic: the example has `always_deny` policy and the default mTLS
identity mode. Set the storage class/size for your cluster and pin the image,
then render and apply your configured copy:

```sh
kubectl kustomize deploy/softhsm
kubectl apply -k deploy/softhsm
kubectl rollout status deployment/keyrack-softhsm
```

RWO permits multiple pods on the same node; it is not a mutex
([Kubernetes access-mode guidance](https://kubernetes.io/docs/tasks/administer-cluster/change-pv-access-mode-readwriteoncepod/)).
The image entrypoint therefore holds an exclusive, nonblocking `flock` on
`/var/lib/keyrack/.writer.lock` for the entire init, service, backup, or restore
process. A second cooperating process exits with code 75. Keep that entrypoint,
use a filesystem supporting advisory locks, and do not mount the token store in
other software that bypasses the lock. This profile does not implement HA.

## Startup and readiness

Startup rejects persistent SQLite/Postgres metadata with any effective
`software` or `in_memory` provider, including named nondefault providers. A
throwaway development environment can explicitly set
`dev_only_allow_ephemeral_provider_with_persistent_metadata: true`; startup then
warns that a restart loses keys and makes existing ciphertext undecryptable.
This acknowledgement does not make the provider durable. The packaged profile
uses PKCS#11 and requires no acknowledgement.

`/readyz` checks storage plus all registered providers. A configured PKCS#11
provider must open and authenticate a live token session. A persisted PKCS#11
connection that failed rehydration also makes readiness fail. Provider checks
have a two-second budget; timed-out native work retains its probe permit until
it exits, preventing repeated probes from accumulating for that provider.
This checks token access, not the continued existence of every key object or
a general health guarantee for other provider classes.

The deployment gives readiness five seconds and uses TCP liveness. A token
outage removes the pod from readiness without creating a liveness restart loop.
A provider that cannot initialize at startup prevents the service from starting.

## Quiesced backup and restore

Back up **both** directories in one quiesced snapshot. A metadata-only backup
cannot recover provider keys. SoftHSM describes backing up its token files in
its [upstream instructions](https://github.com/softhsm/SoftHSMv2/blob/main/README.md).
Retain the matching credential Secret separately through your protected backup
process. The archive contains sensitive token material and is not encrypted by
this helper; protect it as key-store data.

1. Stop traffic, scale the deployment to zero, and wait for its pod to terminate:
   `kubectl scale deployment/keyrack-softhsm --replicas=0`, then
   `kubectl wait --for=delete pod -l app=keyrack-softhsm --timeout=120s`.
2. Run a one-off pod using the **same pinned image**, UID/GID/fsGroup 10001,
   the existing data PVC mounted at `/var/lib/keyrack`, and a protected backup
   volume at `/backup`. Retain the image entrypoint and pass
   `args: [backup, /backup/snapshot.tar]`. No PIN Secret is needed for this
   stopped-file copy. Wait for exit zero before retaining the archive. The
   helper refuses live access and an existing output archive.
3. Remove the backup pod before scaling the deployment back to one. Do not
   copy a live SQLite database and token directory separately.
4. To restore, keep the deployment at zero and mount a fresh, empty destination
   PVC plus the trusted matching archive volume. Run the same image with
   `args: [restore, /backup/snapshot.tar]`. An existing destination is refused.
   Use archives produced by this helper, not untrusted third-party tar files.
5. Remove the restore pod, point the deployment at the restored PVC and matching
   Secret, and scale to one. The init container verifies the existing token.
   Require readiness and decrypt a retained pre-backup ciphertext before routing
   traffic. Preserve the old PVC until that check succeeds.

For a Docker-managed installation, the same entrypoint operations are:

```sh
# First stop the service container and wait for it to exit.
docker run --rm --read-only --cap-drop=ALL \
  -v keyrack-data:/var/lib/keyrack -v keyrack-backup:/backup \
  "$SOFTHSM_IMAGE" backup /backup/snapshot.tar
# Restore uses a new, empty volume; SOFTHSM_IMAGE is the pinned image reference.
docker run --rm --read-only --cap-drop=ALL \
  -v keyrack-restored:/var/lib/keyrack -v keyrack-backup:/backup \
  "$SOFTHSM_IMAGE" restore /backup/snapshot.tar
```

## Reproducible checks

The image proof uses disposable volumes and synthetic Secret files. It creates
and encrypts through the REST API, removes and restores token access to check
readiness, starts a fresh container against the same volume and decrypts the
original ciphertext, then restores a quiesced archive to another volume and
decrypts that same ciphertext again. It also rejects concurrent writers, live
backup, and restore over existing data.

```sh
docker build -f docker/Dockerfile.softhsm -t keyrack-softhsm-test:local .
python3 conformance/softhsm-profile/proof.py --image keyrack-softhsm-test:local
python3 conformance/softhsm-profile/mutations.py --image keyrack-softhsm-test:local
python3 conformance/softhsm-profile/deployment_mutations.py
python3 conformance/softhsm-profile/release_controls.py
# Native source controls require a local SoftHSM library and protoc.
export KEYRACK_SOFTHSM_TEST_LIB=/usr/lib/softhsm/libsofthsm2.so
python3 scripts/test-softhsm-deliverable-d-mutants.py
python3 scripts/test-softhsm-initializer-mutants.py
```

Mutation runners revert the relevant guard in isolated source copies, manifest
fixtures, or derived images, and require the named failure. An unrelated build
or setup failure does not count as evidence. The native image proof runs on both
architectures in CI; deployment constraints are checked statically, rather than
claiming a test on every Kubernetes storage driver.
