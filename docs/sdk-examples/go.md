# Go — Before and After

## Scenario

A Go microservice stores user payment tokens. Each token must be
encrypted at rest, rotatable per-tenant, and auditable.

---

## Before: ad-hoc key management

```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "database/sql"
    "encoding/hex"
    "fmt"
    "os"
)

// Key is loaded from an environment variable. Rotation means
// redeploying every service instance with a new key and re-encrypting
// all existing data in a maintenance window.
var encryptionKey = mustDecodeHex(os.Getenv("ENCRYPTION_KEY"))

func mustDecodeHex(s string) []byte {
    b, err := hex.DecodeString(s)
    if err != nil {
        panic("ENCRYPTION_KEY must be valid hex")
    }
    return b
}

func encryptToken(plaintext []byte) ([]byte, error) {
    block, _ := aes.NewCipher(encryptionKey)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptToken(ciphertext []byte) ([]byte, error) {
    block, _ := aes.NewCipher(encryptionKey)
    gcm, _ := cipher.NewGCM(block)
    nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ct, nil)
}

func storePaymentToken(db *sql.DB, userID string, token []byte) error {
    ct, err := encryptToken(token)
    if err != nil {
        return err
    }
    _, err = db.Exec("INSERT INTO payment_tokens (user_id, encrypted_token) VALUES ($1, $2)",
        userID, ct)
    return err
    // No audit trail. No key versioning. No rotation path.
    // If the key leaks, every token in the database is compromised
    // and you have no way to know which key version encrypted what.
}
```

### Problems

- Key lives in an env var — no rotation without redeploy
- No audit trail of encrypt/decrypt operations
- No key versioning — can't tell which key encrypted which row
- No per-tenant isolation — one key for all users
- Rotation means "re-encrypt everything in a maintenance window"
- If the key leaks, no way to identify the blast radius

---

## After: with KeyRack Go SDK

```go
package main

import (
    "context"
    "database/sql"
    "log"

    "go.keyrack.dev/keyrack"
)

var kr *keyrack.Client

func init() {
    var err error
    kr, err = keyrack.Connect("localhost:50051",
        keyrack.WithMTLS("certs/client.pem", "certs/client-key.pem", "certs/ca.pem"),
    )
    if err != nil {
        log.Fatal(err)
    }
}

func storePaymentToken(ctx context.Context, db *sql.DB, tenantID, userID string, token []byte) error {
    // KeyRack creates or resolves a per-tenant DEK.
    // The key hierarchy looks like:
    //   Root KEK (operator) → Tenant KEK (per-tenant) → Payment DEK (per-tenant)
    // All of this is managed by KeyRack's namespace rules.
    key, err := kr.CreateKey(ctx, keyrack.AES256,
        keyrack.WithParent("tenant-kek-"+tenantID),
        keyrack.WithDescription("payment-token-dek"),
        keyrack.WithTags(map[string]string{"tenant": tenantID}),
    )
    if err != nil {
        return err
    }

    // Encrypt with encryption context (AAD) binding.
    // The context is cryptographically bound — decrypt will fail
    // if context doesn't match, preventing cross-tenant data access.
    ct, err := kr.Encrypt(ctx, key.ID, token,
        keyrack.WithEncryptionContext(map[string]string{
            "tenant":  tenantID,
            "user":    userID,
            "purpose": "payment_token",
        }),
    )
    if err != nil {
        return err
    }

    // Store ciphertext. KeyRack's self-describing header embeds the
    // key ID and version, so decrypt knows which key to use even
    // after rotation.
    _, err = db.ExecContext(ctx,
        "INSERT INTO payment_tokens (user_id, encrypted_token) VALUES ($1, $2)",
        userID, ct)
    return err
}

func readPaymentToken(ctx context.Context, db *sql.DB, tenantID, userID string) ([]byte, error) {
    var ct []byte
    err := db.QueryRowContext(ctx,
        "SELECT encrypted_token FROM payment_tokens WHERE user_id = $1", userID,
    ).Scan(&ct)
    if err != nil {
        return nil, err
    }

    // KeyRack reads the key ID and version from the ciphertext header.
    // Works even after key rotation — old versions are retained for decrypt.
    pt, err := kr.Decrypt(ctx, ct,
        keyrack.WithEncryptionContext(map[string]string{
            "tenant":  tenantID,
            "user":    userID,
            "purpose": "payment_token",
        }),
    )
    return pt, err
}

// When it's time to rotate (compliance requirement, key age, incident):
//
//   kr.RotateKey(ctx, "tenant-kek-acme-corp")
//
// KeyRack creates rotation jobs for every dependent DEK.
// Your service polls for pending jobs and re-encrypts affected rows:
//
//   jobs, _ := kr.ListRotationJobs(ctx, keyrack.Pending)
//   for _, job := range jobs {
//       // re-encrypt affected rows with new key version
//       kr.AcknowledgeJob(ctx, job.ID)
//       // ... do the re-encryption ...
//       kr.CompleteJob(ctx, job.ID)
//   }
//
// No maintenance window. No downtime. Full audit trail.
```

### What changed

| Concern | Before | After |
|---------|--------|-------|
| Key storage | Env var | KeyRack manages keys in HSM or encrypted store |
| Key rotation | Redeploy + maintenance window | `RotateKey()` + re-encryption |
| Per-tenant isolation | None | Key hierarchy with tenant KEKs |
| Audit trail | None | Every operation logged with principal, action, result |
| Encryption context | None | AAD-bound, prevents cross-tenant misuse |
| Blast radius on leak | All data | Single tenant's DEK |
| Key versioning | None | Self-describing header, old versions retained |
