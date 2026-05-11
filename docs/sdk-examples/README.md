# SDK Examples — Before and After

Each file in this directory shows a common key management task in a
specific language, comparing the typical approach today against the
same task with a KeyRack SDK.

The "after" examples assume an idealized native SDK exists for that
language. The actual implementation status is tracked in
[`LANGUAGE_SUPPORT.md`](../LANGUAGE_SUPPORT.md).

| Language | File | Scenario |
|----------|------|----------|
| Rust | [rust.md](rust.md) | Multi-tenant SaaS encrypting user data |
| Go | [go.md](go.md) | Microservice encrypting PII before storage |
| Python | [python.md](python.md) | Django app with encrypted model fields |
| TypeScript | [typescript.md](typescript.md) | Node.js API service + browser E2EE |
| Java | [java.md](java.md) | Spring Boot service with key rotation |
| C | [c.md](c.md) | IoT gateway encrypting sensor telemetry |
