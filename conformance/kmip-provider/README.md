# KMIP provider proof

Runs `keyrack-service` against a third-party KMIP server (PyKMIP) and exercises
the operations `docs/OPERATOR.md` documents for the `kmip` provider.

```bash
./run-proof.sh        # needs docker, openssl, python3 and a rust toolchain
```

The server is deliberately not `keyrack-kmip-server`. A client checked only
against our own server proves that the two agree, which is how a shared
misreading of the specification survives: four of this client's wire constants
named the wrong thing, each one a value the specification does define, and
every local test passed.

Pointing it at your own server is also the way to qualify that server:

```bash
KEYRACK_KMIP_PROOF_ENDPOINT="kmip://hsm.internal:5696" \
KEYRACK_KMIP_PROOF_CLIENT_CERT=... KEYRACK_KMIP_PROOF_CLIENT_KEY=... \
KEYRACK_KMIP_PROOF_CA_CERT=... \
  cargo test -p keyrack-kmip --test neutral_server -- --ignored
```

Those tests assert things only a live server can settle — most importantly that
it binds `AuthenticatedEncryptionAdditionalData` to the ciphertext rather than
accepting the field and ignoring it.

## Files

| File | Purpose |
| --- | --- |
| `run-proof.sh` | The whole proof: server, service, lifecycle, both config shapes |
| `check-constants.py` | Compares every wire constant against PyKMIP's tables |
| `proof.py` | Drives the documented operations over REST |
| `reference-probe.py` | Sanity-checks the server with its own client, so a failure can be attributed |
| `keyrack.yaml`, `keyrack-routing.yaml` | The two documented ways to configure a KMIP backend |
