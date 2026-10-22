# Java — Before and After

## Scenario

A Spring Boot financial service encrypts transaction records. Compliance
requires annual key rotation with audit evidence. The team currently
uses AWS KMS but wants to avoid vendor lock-in.

---

## Before: AWS KMS via `aws-sdk-java`

```java
@Service
public class TransactionEncryptionService {

    private final KmsClient kms;
    // Hardcoded key ARN. Rotation is configured in AWS Console.
    // No hierarchy, no dependency tracking, no coordinated re-encryption.
    private static final String KEY_ARN =
        "arn:aws:kms:us-east-1:123456789:key/abc-def-123";

    public TransactionEncryptionService() {
        this.kms = KmsClient.builder()
            .region(Region.US_EAST_1)
            .build();
    }

    public byte[] encryptTransaction(String tenantId, byte[] record) {
        EncryptRequest req = EncryptRequest.builder()
            .keyId(KEY_ARN)
            .plaintext(SdkBytes.fromByteArray(record))
            .encryptionContext(Map.of("tenant", tenantId))
            .build();

        return kms.encrypt(req).ciphertextBlob().asByteArray();
        // Works, but:
        // - Locked to AWS. Can't run on-prem or multi-cloud.
        // - One key for all tenants (or manage N keys manually).
        // - Rotation creates a new key version in AWS but doesn't
        //   propagate to dependent systems.
        // - Audit is in CloudTrail — separate system, no correlation
        //   with application events.
        // - If you leave AWS, you re-encrypt everything.
    }

    public byte[] decryptTransaction(byte[] ciphertext) {
        DecryptRequest req = DecryptRequest.builder()
            .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
            .build();
        return kms.decrypt(req).plaintext().asByteArray();
    }
}
```

---

## After: use the native gRPC or REST API

Core 0.5.0 does not ship an AWS KMS compatibility shim. Changing an AWS SDK
endpoint to `keyrack-service` will not translate AWS operations into Core
operations. The in-tree `keyrack-aws-proxy` forwards requests to real AWS KMS;
it does not replace that backend with KeyRack providers.

There is also no packaged native Java SDK in this repository. Generate Java
gRPC bindings from [`key_service.proto`](../../proto/keyrack/v1/key_service.proto)
and its imports, or use an HTTP client against the REST API. The
[API surface inventory](../generated/api-surface-parity.md) lists available
operations and differences between the two transports.

For the transaction service above, a native integration needs to:

1. Configure a client connection and authentication for the deployed service.
2. Create a key through `CreateKey`, supplying attributes for namespace routing
   and optionally `parent_key_id` for logical ancestry. Store the returned key ID
   for subsequent use.
3. Call `Encrypt` with that key ID, the record bytes and encryption context.
4. Store the returned ciphertext blob intact, including its versioned header.
5. Supply the same encryption context to `Decrypt`.

These are integration steps, not calls to a supplied `KeyRackClient` Java
builder. Generated bindings expose `CreateKey.parent_key_id` for logical
ancestry; the illustrative `.parent(...)` builder is not a supplied Java API.
Creating cryptographically parent-wrapped children is not exposed through
the service API in 0.5.0.

### Rotation

`RotateKey` creates a new primary version and attempts to enqueue rotation jobs
for logical descendants. Existing versions remain available for decryption
subject to authorization, key state and backend availability. Applications
perform and verify data migration; completing a rotation job does not prove
all data has migrated or retire an old version. This is not automatic child-key
rewrapping.

### Migration choice

| Approach | What changes | Where cryptography runs |
|----------|--------------|-------------------------|
| Existing AWS SDK | Keep the AWS integration | AWS KMS |
| In-tree AWS pass-through proxy | Configure the proxy endpoint and credentials; validate supported calls | AWS KMS |
| Native Core API | Generate gRPC bindings or implement REST calls; adapt lifecycle and migration logic | The selected Core provider |

Use the native API when moving cryptographic operations to Core. Plan data
migration explicitly; an endpoint-only switch to Core is not supported by
this release.
