# Use Case: Go Backend Services

## Who

Go backend engineers who need key management for their services.

**Examples:** Kubernetes operators, microservices in Go, DevOps tooling,
infrastructure platforms built in Go (many cloud-native projects).

## The problem

Go is the most popular language for cloud infrastructure. These teams
typically:

- Use AWS KMS / GCP KMS / Azure Key Vault as their key management layer
- Suffer vendor lock-in (keys can't move between providers)
- Need crypto agility (algorithm migration path) but the cloud provider
  doesn't make this easy
- Want on-prem or hybrid deployment options

## How KeyRack serves Go today

KeyRack exposes gRPC and REST APIs. Go services can consume either:

### Option A: gRPC (recommended)

Generate a Go client from KeyRack's protobuf definitions:

```bash
protoc --go_out=. --go-grpc_out=. proto/keyrack/v1/key_service.proto
```

```go
conn, _ := grpc.Dial("localhost:50051", grpc.WithInsecure())
client := pb.NewKeyServiceClient(conn)

resp, _ := client.CreateKey(ctx, &pb.CreateKeyRequest{
    KeySpec: pb.KeySpec_AES_256,
})

encResp, _ := client.Encrypt(ctx, &pb.EncryptRequest{
    KeyId:     resp.Lid,
    Plaintext: []byte("hello keyrack"),
})
```

### Option B: REST

```go
resp, _ := http.Post("http://localhost:8080/v1/keys",
    "application/json",
    strings.NewReader(`{"key_spec": "AES_256"}`))
```

### Option C: AWS KMS shim (brownfield wedge)

If the Go service already uses the AWS SDK:

```go
cfg, _ := config.LoadDefaultConfig(ctx,
    config.WithEndpointResolverWithOptions(
        aws.EndpointResolverWithOptionsFunc(func(service, region string, opts ...interface{}) (aws.Endpoint, error) {
            return aws.Endpoint{URL: "http://keyrack-aws-shim:8080"}, nil
        }),
    ),
)
kmsClient := kms.NewFromConfig(cfg)

// Uses standard AWS SDK — no code changes needed
out, _ := kmsClient.Encrypt(ctx, &kms.EncryptInput{
    KeyId:     aws.String("alias/my-key"),
    Plaintext: []byte("hello keyrack"),
})
```

## Fit rating

**Good for greenfield, excellent with AWS shim for brownfield.**

Go has first-class gRPC tooling, so the native path is clean. For
existing services using AWS KMS, the shim provides a zero-code-change
migration path.

## What would improve the experience

| Item | Effort | Impact |
|---|---|---|
| Published Go client package (`go.keyrack.dev/client`) | 1-2 days | High — Go devs expect `go get` |
| Pre-generated Go stubs in a separate repo | 1 day | Medium — saves each user from running protoc |
| Go SDK wrapper (higher-level than raw gRPC) | 3-5 days | High — error handling, retry, connection pooling |
| Go example project | 1 day | Medium — demonstrates full lifecycle |
| AWS shim documentation for Go | 0.5 days | High — brownfield wedge enablement |

## Strategic note

Go is where the highest volume of potential users sits (Kubernetes
ecosystem, infrastructure tooling). The AWS KMS shim is the strongest
brownfield wedge here — a Go service using `aws-sdk-go-v2` can point
at KeyRack's shim and immediately get crypto agility, rotation tracking,
and audit without changing any application code. This should be a primary
marketing message.
