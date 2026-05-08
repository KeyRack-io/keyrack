# Use Case: Python Backend Services

## Who

Python backend engineers — Django, FastAPI, Flask developers who
handle sensitive data (PII, financial records, healthcare data).

**Examples:** SaaS platforms, data pipelines, ML training platforms
that handle sensitive training data, healthcare/fintech backends.

## The problem

Python services often:

- Use `cryptography` library directly, building ad-hoc key management
- Store encryption keys in environment variables or config files
- Have no key rotation, no audit trail, no hierarchy
- Use AWS KMS but want portability or on-prem options

## How KeyRack serves Python today

### Path 1: REST API (available now)

```python
import httpx

client = httpx.Client(base_url="http://localhost:8080")

# Create a key
key = client.post("/v1/keys", json={"key_spec": "AES_256"}).json()

# Encrypt
import base64
ct = client.post(
    f"/v1/keys/{key['lid']}/actions-encrypt",
    json={"plaintext": base64.b64encode(b"secret").decode()}
).json()

# Decrypt
pt = client.post(
    f"/v1/keys/{key['lid']}/actions-decrypt",
    json={"ciphertext_blob": ct["ciphertext_blob"]}
).json()
```

### Path 2: AWS KMS shim (brownfield wedge)

```python
import boto3

kms = boto3.client('kms', endpoint_url='http://keyrack-aws-shim:8080')

# Standard boto3 — no code changes
response = kms.encrypt(
    KeyId='alias/my-key',
    Plaintext=b'secret data'
)
```

### Path 3: gRPC

```python
import grpc
from keyrack.v1 import key_service_pb2_grpc, key_service_pb2

channel = grpc.insecure_channel('localhost:50051')
stub = key_service_pb2_grpc.KeyServiceStub(channel)

response = stub.CreateKey(key_service_pb2.CreateKeyRequest(
    key_spec=key_service_pb2.AES_256
))
```

## Fit rating

**Good via REST or AWS shim. No native Python SDK today.**

Python developers can use KeyRack today through REST or the AWS KMS
shim (if using boto3). The experience is usable but not idiomatic —
there's no `pip install keyrack` package.

## What would improve the experience

| Item | Effort | Impact |
|---|---|---|
| `keyrack` Python package (REST wrapper) | 2-3 days | High — Python devs expect pip install |
| Django integration (field-level encryption) | 3-5 days | Very high — massive Django install base |
| FastAPI middleware | 1-2 days | Medium |
| Pre-generated Python protobuf stubs | 0.5 days | Medium |
| Python example project | 1 day | Medium |
| AWS shim documentation for Python/boto3 | 0.5 days | High — brownfield wedge |

## Strategic note

Python has the largest web backend developer community. A Django
field-level encryption integration (`keyrack.fields.EncryptedTextField`)
would be extremely high value — it would make KeyRack the obvious choice
for any Django project that needs encryption at rest. The AWS shim is
again the strongest brownfield wedge — boto3 users can migrate with
zero code changes.
