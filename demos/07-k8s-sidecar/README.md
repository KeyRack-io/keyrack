# Demo 07 — Kubernetes Sidecar-in-a-Pod

Self-contained Kubernetes demo of the **sidecar pattern**: an application
container and a **KeyRack sidecar** share one Pod (and therefore one network
namespace), so the app reaches KeyRack over `localhost` — no service hop, no
network exposure of the key service beyond the pod.

```
            Pod: keyrack-sidecar-demo
   ┌───────────────────────────────────────────┐
   │  app container ──▶ http://localhost:8080 ──┼──▶  keyrack (native sidecar)
   │  (runs verify.sh)                          │        │        │
   └───────────────────────────────────────────┘        │        │
                                                   ┌──────▼──┐  ┌──▼────────┐
                                                   │ postgres │  │ cedar-pdp │
                                                   │ (Service)│  │ (Service) │
                                                   └──────────┘  └───────────┘
```

- **app** — main container; talks to the sidecar on `localhost:8080`, creates a
  key, encrypts, and decrypts, then exits.
- **keyrack** — runs as a **native sidecar** (an init container with
  `restartPolicy: Always`, GA since Kubernetes 1.29). It starts before the app
  and is auto-terminated once the app finishes.
- **postgres** / **cedar-pdp** — cluster Services the sidecar depends on
  (durable metadata + authorization). Postgres storage here is ephemeral; for
  restart survival see demo 04.

## Run

Requires `kind`, `kubectl`, and `docker`.

```bash
./run-demo.sh
```

It creates a kind cluster, builds and loads the `keyrack-service:demo` image,
applies the manifests, waits for the app Pod to complete, and asserts the
verification printed `ALL CHECKS PASSED`. Set `KEEP_UP=1` to keep the cluster
for inspection:

```bash
KEEP_UP=1 ./run-demo.sh
kubectl -n keyrack-demo get pods
kubectl -n keyrack-demo logs keyrack-sidecar-demo -c app
kind delete cluster --name keyrack-demo   # when done
```

## What it demonstrates

1. **Sidecar topology** — the app uses `localhost`, not a Service DNS name, to
   reach KeyRack. Key operations never leave the Pod's network namespace.
2. **Native sidecar lifecycle** — keyrack starts first (gated by a startup
   probe on `/healthz`) and is torn down automatically when the app exits.
3. **Real dependencies** — every op is authorized through the Cedar PDP and
   metadata is persisted to Postgres, exactly as in a non-k8s deployment.

## Files

| File | Role |
|------|------|
| `manifests/00-namespace.yaml` | `keyrack-demo` namespace |
| `manifests/10-config.yaml` | ConfigMaps: keyrack.yaml, Cedar policy, app verify script |
| `manifests/20-postgres.yaml` | Postgres Deployment + Service |
| `manifests/30-cedar-pdp.yaml` | Cedar PDP Deployment + Service |
| `manifests/40-app-pod.yaml` | The app + keyrack-sidecar Pod |
| `run-demo.sh` | kind up → build/load → apply → verify → teardown |

## Notes

- The Cedar policy here is permissive (`permit(principal, action, resource);`)
  for demo simplicity; the authorization path is still real. See demo 04 for
  tenant-isolation policies.
- This demo is **not** part of `scripts/run-demos-ci.sh` (that runner drives the
  docker-compose stacks); it needs a Kubernetes cluster.
