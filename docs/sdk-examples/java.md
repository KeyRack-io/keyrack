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

## After (zero code changes): AWS KMS shim

The fastest path for Java teams. No new SDK, no code changes. Just
change the endpoint:

```java
@Service
public class TransactionEncryptionService {

    private final KmsClient kms;
    private static final String KEY_ARN =
        "arn:aws:kms:us-east-1:123456789:key/abc-def-123";

    public TransactionEncryptionService() {
        this.kms = KmsClient.builder()
            .endpointOverride(URI.create("http://keyrack-aws-shim:8080"))
            .region(Region.US_EAST_1)
            .build();
        // That's it. Every existing encrypt/decrypt/sign/verify call
        // now goes through KeyRack. You get:
        // - On-prem or multi-cloud deployment
        // - KeyRack's audit trail (structured, queryable)
        // - Key hierarchy and rotation tracking
        // - PDP authorization on every operation
        // - Crypto agility (swap provider without changing app code)
    }

    // encrypt() and decrypt() methods are UNCHANGED.
}
```

---

## After (native SDK): idiomatic Java client

For greenfield Java projects or teams that want the full lifecycle API:

```java
@Service
public class TransactionEncryptionService {

    private final KeyRackClient kr;

    public TransactionEncryptionService(
            @Value("${keyrack.service-url}") String serviceUrl) {
        this.kr = KeyRackClient.builder()
            .serviceUrl(serviceUrl)
            .mtls("certs/client.pem", "certs/client-key.pem", "certs/ca.pem")
            .build();
    }

    public byte[] encryptTransaction(String tenantId, byte[] record) {
        // Per-tenant DEK, child of tenant KEK, child of root KEK
        Key key = kr.createKey(KeySpec.AES_256)
            .parent("tenant-kek-" + tenantId)
            .description("transaction-dek")
            .tags(Map.of("tenant", tenantId))
            .send();

        return kr.encrypt(key.getId(), record)
            .encryptionContext(Map.of(
                "tenant", tenantId,
                "purpose", "transaction_record"
            ))
            .send();
    }

    public byte[] decryptTransaction(String tenantId, byte[] ciphertext) {
        return kr.decrypt(ciphertext)
            .encryptionContext(Map.of(
                "tenant", tenantId,
                "purpose", "transaction_record"
            ))
            .send();
    }

    // Rotation with dependency tracking:
    //
    // @Scheduled(cron = "0 0 2 1 * *")  // monthly
    // public void rotateKeys() {
    //     kr.rotateKey("root-kek").send();
    //     // Cascade creates jobs for all tenant KEKs → all DEKs.
    //     // Each service polls its jobs and re-encrypts.
    // }
}
```

### What changed

| Concern | AWS KMS | KeyRack (shim) | KeyRack (native) |
|---------|---------|----------------|------------------|
| Code changes | — | 1 line (endpoint) | Full rewrite |
| Vendor lock-in | AWS only | Portable | Portable |
| Key hierarchy | Flat | Tracked (via metadata) | Native hierarchy |
| Cascade rotation | Manual | Tracked | Automated jobs |
| Audit | CloudTrail | KeyRack audit log | KeyRack audit log |
| On-prem | No | Yes | Yes |
| Effort | — | 5 minutes | 1-2 days |

### Recommendation for Java teams

Start with the AWS KMS shim (zero effort, immediate value). Evaluate
the native SDK path when you need key hierarchy, cascade rotation, or
are building greenfield.
