# C — Before and After

## Scenario

An IoT gateway device collects sensor readings from a factory floor
and encrypts them before transmission to the cloud. The device runs
Linux on ARM (Raspberry Pi or similar). Keys must be rotatable from
a central management plane without physical access to the device.

---

## Before: OpenSSL + hardcoded key

```c
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

/*
 * Key is baked into firmware or loaded from a file on the SD card.
 * Rotation means physical access to the device or an OTA update
 * that replaces the key file — neither is automated, neither is audited.
 */
static const unsigned char KEY[32] = { /* 256-bit key from somewhere */ };

int encrypt_reading(const unsigned char *plaintext, int pt_len,
                    unsigned char *ciphertext, int *ct_len,
                    unsigned char *iv, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    RAND_bytes(iv, 12);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, KEY, iv);
    EVP_EncryptUpdate(ctx, ciphertext, ct_len, plaintext, pt_len);

    int final_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + *ct_len, &final_len);
    *ct_len += final_len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return 0;

    /*
     * Problems:
     * - Key is static. No rotation without device access.
     * - No key hierarchy — one key for all sensors on this gateway.
     * - No audit trail.
     * - No encryption context — readings can be replayed or swapped.
     * - If the SD card is stolen, all historical data is compromised.
     * - Algorithm is hardcoded — no crypto agility path.
     */
}

int main(void) {
    unsigned char reading[] = "temperature=42.3,humidity=67.1,pressure=1013.2";
    unsigned char ciphertext[256], iv[12], tag[16];
    int ct_len;

    encrypt_reading(reading, strlen((char *)reading), ciphertext, &ct_len, iv, tag);
    /* transmit iv + ciphertext + tag to cloud */
    return 0;
}
```

---

## After: `libkeyrack` (C FFI from Rust)

```c
#include <keyrack.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    keyrack_error_t *err = NULL;

    /* Connect to KeyRack service running on the gateway.
     * KeyRack manages the key hierarchy:
     *   Fleet Root KEK (cloud-managed)
     *     → Gateway KEK (per-gateway, rotated from cloud)
     *       → Sensor DEK (per-sensor-type, auto-provisioned)
     */
    keyrack_client_t *kr = keyrack_connect("http://localhost:8080", &err);
    if (!kr) {
        fprintf(stderr, "keyrack connect: %s\n", keyrack_error_message(err));
        keyrack_error_free(err);
        return 1;
    }

    /* Create or resolve a sensor-specific DEK.
     * If it already exists, this is a no-op.
     * KeyRack tracks the key's parent (gateway KEK), version, and state. */
    keyrack_key_t *key = keyrack_create_key(kr, KEYRACK_AES_256,
        "temperature-sensor-dek",       /* description */
        "gateway-kek-gw-0042",          /* parent key */
        &err);
    if (!key) {
        fprintf(stderr, "create key: %s\n", keyrack_error_message(err));
        keyrack_error_free(err);
        keyrack_client_free(kr);
        return 1;
    }

    /* Encrypt with context binding.
     * The sensor ID and reading type are cryptographically bound.
     * Decrypt with wrong context fails — prevents replay/swap attacks. */
    const char *reading = "temperature=42.3,humidity=67.1,pressure=1013.2";

    keyrack_encryption_context_t *ctx = keyrack_context_new();
    keyrack_context_set(ctx, "gateway", "gw-0042");
    keyrack_context_set(ctx, "sensor", "temp-floor-3");
    keyrack_context_set(ctx, "type", "environmental");

    keyrack_ciphertext_t *ct = keyrack_encrypt(kr,
        keyrack_key_id(key),
        (const uint8_t *)reading, strlen(reading),
        ctx, &err);

    if (!ct) {
        fprintf(stderr, "encrypt: %s\n", keyrack_error_message(err));
        keyrack_error_free(err);
        /* ... cleanup ... */
        return 1;
    }

    /* Transmit keyrack_ciphertext_data(ct) to cloud.
     * The ciphertext includes a self-describing header with
     * key ID, version, algorithm, and context hash.
     * The cloud can decrypt by talking to KeyRack — it knows
     * which key and version to use from the header. */
    printf("encrypted %zu bytes → %zu bytes ciphertext\n",
           strlen(reading), keyrack_ciphertext_len(ct));

    /* When the cloud rotates the gateway KEK:
     *   POST /v1/keys/gateway-kek-gw-0042/actions-rotate
     *
     * KeyRack creates rotation jobs for all dependent DEKs.
     * The gateway's background agent polls for jobs and re-wraps.
     * No firmware update. No physical access. No downtime.
     * Full audit trail of what was rotated, when, by whom. */

    keyrack_ciphertext_free(ct);
    keyrack_context_free(ctx);
    keyrack_key_free(key);
    keyrack_client_free(kr);
    return 0;
}
```

### Compilation

```bash
# libkeyrack is built from Rust and installed as a system library
gcc -o gateway gateway.c $(pkg-config --cflags --libs keyrack)
```

### What changed

| Concern | Before | After |
|---------|--------|-------|
| Key storage | File on SD card | KeyRack service (encrypted, versioned) |
| Key rotation | Physical device access or OTA | Remote API call from cloud |
| Key hierarchy | None | Fleet root → gateway KEK → sensor DEK |
| Audit trail | None | Every encrypt/decrypt logged |
| Encryption context | None | Sensor ID + type bound via AAD |
| Crypto agility | Hardcoded AES-256-GCM | KeyRack provider abstraction |
| Blast radius | All data on gateway | Single sensor DEK |
| Memory management | Manual (EVP_CTX) | `keyrack_*_free()` matching pattern |

### Why C matters

No other KMS offers a native C library. PKCS#11 provides a C interface
to HSMs, but PKCS#11 is a crypto primitive API — it has no concept of
key hierarchy, rotation jobs, dependency tracking, or audit. KeyRack's
C FFI would sit one layer above PKCS#11, providing lifecycle management
to the millions of C/C++ programs that currently do key management
ad-hoc or not at all.

Target environments:
- IoT gateways (Raspberry Pi, industrial ARM boards)
- Embedded Linux appliances
- Legacy C services that can't be rewritten
- Database encryption plugins (PostgreSQL TDE, MySQL keyring)
- OpenSSL engine/provider plugins
- PAM authentication modules
