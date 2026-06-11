# Demo 08 — Hierarchical Cascade Rotation

Shows that rotating a **root key** automatically creates cooperative rotation
jobs for every descendant in the key hierarchy (recursive BFS), and walks
through the **acknowledge → complete** protocol over gRPC.

## Key concepts

### Key hierarchy

```
root (AES-256)
└── child (AES-256)
    └── grandchild (AES-256)
```

Each key is created with `parent_key_id` pointing to its parent.

### Cascade rotation

When a root key is rotated (via gRPC `RotateKey`):

1. KeyRack generates a new key version for the root.
2. A **RotationJob** is created for every **direct and recursive descendant**
   (BFS order).  Each job is initially in `PENDING` state.
3. External orchestration code (a cron job, sidecar, or operator) polls
   `ListRotationJobs`, re-encrypts data under the new key material, then
   calls `AcknowledgeRotationJob` → `CompleteRotationJob`.
4. Rotation jobs that are neither acknowledged nor completed within their TTL
   transition to `EXPIRED`.

> **Note:** The REST `POST /v1/keys/:id/actions-rotate` endpoint also rotates
> a key's material but does **not** create descendant rotation jobs — it is
> intended for single-key rotations.  Use the gRPC `RotateKey` RPC when you
> need the cooperative cascade protocol.

### Cooperative protocol

The cooperative model lets external consumers control _when_ re-encryption
happens — critical for bulk datastores where re-encryption is expensive:

```
Orchestrator               KeyRack
     │  ListRotationJobs        │
     │─────────────────────────▶│  PENDING jobs
     │◀─────────────────────────│
     │                          │
     │  AcknowledgeRotationJob  │
     │─────────────────────────▶│  PENDING → ACKNOWLEDGED
     │◀─────────────────────────│
     │                          │
     │  (re-encrypt data ...)   │
     │                          │
     │  CompleteRotationJob     │
     │─────────────────────────▶│  ACKNOWLEDGED → COMPLETED
     │◀─────────────────────────│
```

## Quick start

```bash
cd demos/08-cascade-rotation
docker compose up --build
# The `demo` container exits 0 on success.
docker compose down -v
```

## What the demo verifies

| Check | API |
|-------|-----|
| Root → child → grandchild hierarchy | REST `POST /v1/keys` + `GET /describe` |
| Root has 2 recursive dependents | gRPC `GetKeyDependents(recursive=true)` |
| Rotating root creates 2 pending jobs targeting the distinct child + grandchild (`dependent_key_id`) | gRPC `RotateKey` + gRPC `ListRotationJobs` |
| Each job transitions PENDING→ACKNOWLEDGED→COMPLETED | gRPC `AcknowledgeRotationJob` + `CompleteRotationJob` |
| Zero pending jobs remain after completion | gRPC `ListRotationJobs` |

## Services

| Service | Role |
|---------|------|
| `keyrack` | KeyRack service (software provider, SQLite storage) |
| `demo` | Alpine + curl + jq + grpcurl; runs `scripts/run-demo.sh` |

## gRPC calls

The demo uses [grpcurl](https://github.com/fullstorydev/grpcurl) with the
repository's proto files mounted at `/proto`:

```bash
# List all rotation jobs
grpcurl -plaintext \
  -import-path /proto -proto keyrack/v1/key_service.proto \
  -d '{}' \
  localhost:50051 keyrack.v1.KeyService/ListRotationJobs

# Acknowledge a job
grpcurl -plaintext \
  -import-path /proto -proto keyrack/v1/key_service.proto \
  -d '{"jobId": "<JOB_ID>"}' \
  localhost:50051 keyrack.v1.KeyService/AcknowledgeRotationJob

# Complete a job
grpcurl -plaintext \
  -import-path /proto -proto keyrack/v1/key_service.proto \
  -d '{"jobId": "<JOB_ID>"}' \
  localhost:50051 keyrack.v1.KeyService/CompleteRotationJob
```
