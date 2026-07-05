# Demo 06 — Provider Routing (multi-tenant HSM partitions)

Routes keys to **different HSM partitions** based on their identity tags — the
foundation for multi-tenant HYOK, where each tenant's keys live in their own
HSM token. A single KeyRack service drives **two SoftHSM2 tokens**
(`tenant-a`, `tenant-b`) through one PKCS#11 library.

| Aspect | This demo |
|--------|-----------|
| **Providers** | `hsm-tenant-a` + `hsm-tenant-b`, both PKCS#11 / SoftHSM2 |
| **Routing** | by `tenant` identity tag → tenant's HSM token |
| **Default** | untagged keys fall back to `default_provider` |
| **Guard** | optional fail-closed `keyrack.provider` assertion |

## Why this needs a shared PKCS#11 module

PKCS#11 allows `C_Initialize` only **once per library per process**. Two
providers backed by the same `libsofthsm2.so` therefore share one initialized
module (keyed by `lib_path` in `keyrack-pkcs11`) and select different tokens —
exactly how real multi-partition HSMs (e.g. Luna/nShield) are driven.

## Architecture

```
                         ┌──────────────────────────────┐
  create {tenant:a} ────▶│  KeyRack Service              │
  create {tenant:b} ────▶│  ProviderRouter (tag rules)   │
  create {} ────────────▶│  default_provider             │
                         └───────┬───────────────┬───────┘
                                 │ hsm-tenant-a   │ hsm-tenant-b
                         ┌───────▼──────┐  ┌──────▼───────┐
                         │ SoftHSM token│  │ SoftHSM token│
                         │   tenant-a   │  │   tenant-b   │
                         └──────────────┘  └──────────────┘
                          (one libsofthsm2.so, shared module)
```

## Quick start

```bash
docker compose up --build
# the `demo` container runs automatically and asserts each routing outcome
```

Or via the CI runner: `./scripts/run-demos-ci.sh 06-provider-routing`

## What it demonstrates

1. A `tenant=tenant-a` key is bound to `hsm-tenant-a`; round-trips encrypt/decrypt.
2. A `tenant=tenant-b` key is bound to `hsm-tenant-b` — a different token.
3. An untagged key falls back to `default_provider`.
4. Asserting `keyrack.provider=hsm-tenant-b` on a key that policy routes to
   `hsm-tenant-a` is rejected with **HTTP 409** (the assertion is fail-closed;
   it never overrides routing policy).
5. A matching assertion is accepted.

Each key's binding is visible in the REST response as `provider_ref`, and is
**permanent per version**: reads/decrypts always use the provider that minted
the version, so rules are never re-evaluated for existing keys.

## Configuration

See [`config/keyrack.yaml`](config/keyrack.yaml). The relevant block:

```yaml
providers:
  - { name: hsm-tenant-a, type: pkcs11, lib_path: ..., token_label: tenant-a, pin: "1234" }
  - { name: hsm-tenant-b, type: pkcs11, lib_path: ..., token_label: tenant-b, pin: "5678" }
default_provider: hsm-tenant-a
provider_routing:
  - { match: { tenant: tenant-a }, provider: hsm-tenant-a }
  - { match: { tenant: tenant-b }, provider: hsm-tenant-b }
```

Full reference: [`docs/OPERATOR.md` → Multiple providers and routing](../../docs/OPERATOR.md).
