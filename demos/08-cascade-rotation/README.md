# Demo 08 — Depth-1 Cascade Rotation

Rotating a root key creates cooperative rotation jobs for its **two wrapped
children**. The demo verifies those jobs' targets and walks through
**acknowledge → complete** over gRPC.

## Release topology

This demo uses the 0.5.0 leaf-only hierarchy: one root and two sibling children,
at depth 1.

```
root (AES-256)
├── child (AES-256, wrapped under root)
└── child (AES-256, wrapped under root)
```

Each child is created with `parent_key_id` pointing to the root. A parent means
the child's material is wrapped under it, so the provider has to be activated
for wrapping — see the `wrapping:` block in `config/keyrack.yaml`. This demo
uses the software mechanism, where parent, envelope and unwrapped child all
live in one process's memory: the hierarchy here is shape, not custody.

The hierarchy is one level deep because a wrapped key cannot yet wrap a further
generation; the demo asserts that a grandchild is refused. Two siblings is still
depth 1. Multi-level hierarchies are a 0.6.0 capability.

## Cascade rotation

When the root is rotated using gRPC `RotateKey`:

1. KeyRack creates a new root key version.
2. Two `PENDING` rotation jobs target the two children's `dependent_key_id`.
3. An external consumer can poll `ListRotationJobs` and acknowledge each job.
   In an application, the consumer performs its data re-encryption work before
   reporting completion. This demo checks the API state transitions.
4. `CompleteRotationJob` moves each acknowledged job to `COMPLETED`.

REST and gRPC rotation use the same domain rotation implementation. The
cooperative job inspection and acknowledgement/completion APIs used here are
gRPC operations.

## Quick start

```bash
cd demos/08-cascade-rotation
docker compose up --build
# The demo container exits 0 when the protocol and independent graph checks pass.
docker compose down -v
```

The software provider stores key material in process memory. This disposable
demo explicitly acknowledges that SQLite metadata alone does not preserve keys
across a service restart.

## What the demo verifies

| Check | API |
|-------|-----|
| Root → two wrapped children | REST `POST /v1/keys` + `GET /describe` |
| A grandchild under a wrapped child is refused | REST `POST /v1/keys` |
| Root has 2 recursive dependents | gRPC `GetKeyDependents(recursive=true)` |
| Rotating root creates 2 pending jobs targeting the two distinct children (`dependent_key_id`) | gRPC `RotateKey` + gRPC `ListRotationJobs` |
| Each job transitions PENDING→ACKNOWLEDGED→COMPLETED | gRPC `AcknowledgeRotationJob` + `CompleteRotationJob` |
| Zero pending jobs remain after completion | gRPC `ListRotationJobs` |
| Independently computed parent graph has three keys, one root, two edges and maximum depth 1 | REST `GET /v1/keys` |

The final graph check reads actual stored key records. It does not derive its
expected topology from the demo's key-creation commands or job-count assertions.

## CI and reversion controls

The unconditional `Demo 08 depth-one contract` PR check builds and runs this
Compose fixture, then restores the former three-level script together with its
matching two-job assertions. That internally consistent fixture must fail the
independent graph check with `DEMO08_DEPTH_EXCEEDED`. Removing the graph check
from that same forbidden fixture demonstrates the control's specific failure.
These are isolated test fixtures; the shipped demo remains depth 1.

Run the same checks locally from the repository root:

```bash
python3 scripts/test-demo08-depth.py --output-dir target/proofs/demo08-depth
```

Each case uses a fresh, uniquely named Compose project. The harness retains
logs and a machine-readable receipt and removes only its own containers and
volumes.
