# Demo 08 — Depth-1 Cascade Rotation

Rotating a root key creates a cooperative rotation job for its **single leaf
child**. The demo verifies that job's target and walks through
**acknowledge → complete** over gRPC.

## Release topology

This demo uses the 0.5.0 leaf-only hierarchy: one root and one child, at depth 1.

```
root (AES-256)
└── leaf child (AES-256)
```

The child is created with `parent_key_id` pointing to the root. The checks here
cover the parent graph and cooperative job protocol. Provider wrapping is
qualified separately; acknowledging a job does not re-encrypt application data.

## Cascade rotation

When the root is rotated using gRPC `RotateKey`:

1. KeyRack creates a new root key version.
2. One `PENDING` rotation job targets the leaf child's `dependent_key_id`.
3. An external consumer can poll `ListRotationJobs` and acknowledge the job.
   In an application, the consumer performs its data re-encryption work before
   reporting completion. This demo checks the API state transitions.
4. `CompleteRotationJob` moves the acknowledged job to `COMPLETED`.

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
| Root → one leaf child | REST `POST /v1/keys` + `GET /describe` |
| Exactly one root dependent | gRPC `GetKeyDependents(recursive=true)` |
| Exactly one pending job targeting the child | gRPC `RotateKey` + `ListRotationJobs` |
| Job transitions PENDING → ACKNOWLEDGED → COMPLETED | gRPC `AcknowledgeRotationJob` + `CompleteRotationJob` |
| One completed job and zero pending jobs | gRPC `ListRotationJobs` |
| Independently computed parent graph has two keys, one root, one edge and maximum depth 1 | REST `GET /v1/keys` |

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
