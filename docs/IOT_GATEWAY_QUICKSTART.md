# KeyRack as an IoT Gateway KMS

## Overview

KeyRack runs natively on ARM64 Linux, making it a lightweight local Key Management
Service for IoT deployments. A Raspberry Pi on the edge network becomes the
cryptographic authority for all connected sensors and actuators.

**Architecture at a glance:**

```
┌──────────────┐        REST / gRPC        ┌────────────────┐
│  IoT Sensor  │ ──────────────────────────▶│                │
├──────────────┤                            │   KeyRack on   │
│  IoT Sensor  │ ──────────────────────────▶│  Raspberry Pi  │
├──────────────┤                            │                │
│  Actuator    │ ──────────────────────────▶│  (gateway)     │
└──────────────┘                            └───────┬────────┘
                                                    │ optional
                                                    ▼
                                            ┌────────────────┐
                                            │  Central KMS   │
                                            │  (cloud/HQ)    │
                                            └────────────────┘
```

- Sensors and devices call KeyRack's REST or gRPC API to encrypt/decrypt data.
- All cryptographic operations are audit-logged locally.
- Optional upstream sync to a central KMS for key hierarchy and disaster recovery.

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Hardware | Raspberry Pi 4 or 5 (ARM64) |
| OS | Raspberry Pi OS 64-bit, or Ubuntu Server 24.04+ |
| Runtime | Docker (recommended) **or** Rust 1.80+ toolchain |
| Network | IP connectivity between Pi and IoT devices |

Ensure the Pi is reachable from your sensor network (e.g. static IP or mDNS).

## Option A: Docker (recommended)

```bash
# Pull the multi-arch image (includes ARM64)
docker pull ghcr.io/keyrack-io/keyrack-service:latest

# Create directories
mkdir -p ~/keyrack/{config,data}

# Write configuration
cat > ~/keyrack/config/config.yaml << 'EOF'
grpc_addr: "0.0.0.0:50051"
rest_addr: "0.0.0.0:8080"
storage:
  type: sqlite
  path: /data/keyrack.db
provider:
  type: software
pdp:
  type: always_allow
audit:
  type: file
  path: /data/audit.log
authn:
  type: bootstrap_token
  max_age_secs: 3600
EOF

# Run KeyRack
docker run -d \
  --name keyrack \
  --restart unless-stopped \
  -p 50051:50051 \
  -p 8080:8080 \
  -v ~/keyrack/config:/etc/keyrack:ro \
  -v ~/keyrack/data:/data \
  -e KMS_BOOTSTRAP_TOKEN=my-secret-token \
  ghcr.io/keyrack-io/keyrack-service:latest
```

Verify it started:

```bash
docker logs keyrack --tail 5
```

## Option B: Native build

Building directly on the Pi avoids Docker overhead (~30 MB less RAM).

```bash
# Install Rust (if not already present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/KeyRack-io/keyrack.git
cd keyrack
cargo build --release -p keyrack-service

# Copy binary
sudo cp target/release/keyrack-service /usr/local/bin/

# Create config (same YAML as above)
sudo mkdir -p /etc/keyrack /var/lib/keyrack
sudo cp ~/keyrack/config/config.yaml /etc/keyrack/config.yaml
```

To run as a systemd service:

```ini
# /etc/systemd/system/keyrack.service
[Unit]
Description=KeyRack KMS
After=network.target

[Service]
Type=simple
Environment=KMS_BOOTSTRAP_TOKEN=my-secret-token
ExecStart=/usr/local/bin/keyrack-service --config /etc/keyrack/config.yaml
Restart=on-failure
User=keyrack

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin keyrack
sudo chown -R keyrack:keyrack /var/lib/keyrack
sudo systemctl daemon-reload
sudo systemctl enable --now keyrack
```

**Cross-compile from a faster machine** (optional):

```bash
# On your dev machine (x86_64 Linux or macOS with cross installed)
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu -p keyrack-service
scp target/aarch64-unknown-linux-gnu/release/keyrack-service pi@raspberrypi:/usr/local/bin/
```

## Quick test

```bash
# Health check
curl http://localhost:8080/healthz
# Expected: {"status":"ok"}

# Create a key for sensor data encryption
curl -X POST http://localhost:8080/v1/keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-token" \
  -d '{"key_spec": "AES_256", "description": "sensor-data-key"}'

# Encrypt a payload
curl -X POST http://localhost:8080/v1/keys/{KEY_ID}/encrypt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-token" \
  -d '{"plaintext": "dGVtcGVyYXR1cmU9MjIuNQ=="}'

# Decrypt it back
curl -X POST http://localhost:8080/v1/keys/{KEY_ID}/decrypt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-token" \
  -d '{"ciphertext": "<ciphertext-from-above>"}'
```

Replace `{KEY_ID}` with the ID returned by the create-key call.

## Python sensor example

A complete working example lives at [`examples/iot-sensor/sensor.py`](../examples/iot-sensor/sensor.py).

```bash
pip install requests
python examples/iot-sensor/sensor.py --keyrack-url http://raspberrypi:8080
```

The script simulates a temperature sensor that encrypts readings before storing
them locally, then decrypts on demand for display. See the file for full usage.

## Security considerations

| Area | Recommendation |
|------|----------------|
| Authentication | Use the bootstrap token for initial setup only. Move to mTLS for production deployments. |
| Storage | Mount the SQLite database on LUKS-encrypted storage or use dm-crypt. |
| Audit | Enable file-based audit logging; forward logs to a central SIEM via syslog or NATS. |
| Network | Segment the sensor VLAN from the KMS management interface. Only expose port 8080/50051 to the sensor subnet. |
| Key material | The `software` provider holds key bytes in process memory (not in the DB). For hardware-backed keys, use a PKCS#11 or KMIP provider, or Parsec with the Pi's TPM (when supported). |
| Updates | Pin the Docker image tag to a specific version; subscribe to KeyRack security advisories. |

## Next steps

- **Key rotation**: Configure automatic rotation policies so sensor keys are cycled
  periodically without downtime.
- **Audit streaming**: Point audit output at a NATS subject for real-time monitoring
  and alerting on anomalous access patterns.
- **Parsec / TPM integration**: Once available, back the root wrapping key with the
  Pi's hardware TPM via the Parsec provider for a stronger trust anchor.
- **Upstream sync**: Connect this gateway instance to a central KeyRack (or
  cloud KMS) to replicate the key hierarchy and enable centralized revocation.
- **Cedar policies**: Replace `always_allow` with fine-grained Cedar policies that
  restrict which device identities can access which keys.
