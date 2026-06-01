# Demo 1 — KeyRack FOSS + HashiCorp Vault Transit

End-to-end demonstration of KeyRack using HashiCorp Vault's Transit secrets
engine as the crypto provider. Everything runs locally via Docker Compose.

## What this demo shows

1. **Key hierarchy** — creates a tenant root key (AES-256) and a child
   data-encryption key underneath it.
2. **Encrypt / Decrypt** — encrypts plaintext through the REST API and
   decrypts it back, verifying round-trip integrity.
3. **Zero-downtime key rotation** — rotates the key while a background loop
   continuously encrypts and decrypts, confirming no operations fail.
   Pre-rotation ciphertext is still decryptable after rotation.
4. **Key state transitions** — disables the key (encrypt is rejected),
   re-enables it (encrypt works again).

## Prerequisites

- Docker & Docker Compose v2+
- This demo lives inside the `keyrack-oss` repository; the KeyRack service
  image is built from source using the repository root (`../..`) as context.

## Running

```bash
docker compose up --build
```

The demo runner container will execute automatically once KeyRack is healthy.
Watch the output for a step-by-step walkthrough ending with a pass/fail
summary.

## Cleanup

```bash
docker compose down -v
```

## Architecture

```
┌──────────┐       ┌──────────┐       ┌───────────────┐
│  demo    │──────▶│ keyrack  │──────▶│  vault        │
│ (curl)   │ REST  │ :8080    │ HTTP  │  :8200        │
└──────────┘       │ :50051   │       │ Transit engine│
                   └──────────┘       └───────────────┘
```
