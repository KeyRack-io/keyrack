# Demo 2 — KeyRack FOSS + SoftHSM2 (PKCS#11)

This demo runs KeyRack with **hardware-security-module-backed cryptography** via the PKCS#11 interface, using [SoftHSM2](https://www.opendnssec.org/softhsm/) as the provider.

All key material lives inside the HSM — KeyRack never sees raw symmetric keys.

## What it demonstrates

| Step | Operation | Detail |
|------|-----------|--------|
| 1 | Create root key | AES-256 generated inside SoftHSM2 via PKCS#11 |
| 2 | Create child key | Hierarchical key, also HSM-backed |
| 3 | Encrypt | AES-256-GCM performed by the HSM |
| 4 | Decrypt | Round-trip verified |
| 5 | Rotate key | New version generated in HSM |
| 6 | Decrypt (old) | Old ciphertexts still work after rotation |
| 7 | Encrypt (new) | New data uses the latest key version |
| 8 | Describe key | Shows PKCS#11 provider class in metadata |

## Run

```bash
docker compose up --build
```

The demo container runs automatically once KeyRack is healthy and prints results to stdout.

## Architecture

```
┌────────────────────────────────────┐
│         KeyRack Service            │
│  (REST :8080 / gRPC :50051)       │
│                                    │
│  ┌──────────────────────────────┐  │
│  │   PKCS#11 CryptoProvider     │  │
│  │   (keyrack-pkcs11 crate)     │  │
│  └────────────┬─────────────────┘  │
│               │ PKCS#11 C_*() calls│
│  ┌────────────▼─────────────────┐  │
│  │   SoftHSM2                   │  │
│  │   /usr/lib/softhsm/          │  │
│  │   Token: keyrack-demo        │  │
│  └──────────────────────────────┘  │
└────────────────────────────────────┘
```

## Production note

SoftHSM2 is a **software emulation** of a PKCS#11 HSM, suitable for development and testing. In production, swap the `lib_path` in `config/keyrack.yaml` for a real HSM's PKCS#11 library (e.g., Thales Luna, Utimaco SecurityServer, YubiHSM2, or a cloud provider's PKCS#11 bridge).
