#!/usr/bin/env python3
"""
IoT Sensor Simulator — encrypts readings via KeyRack REST API.

Usage:
    python sensor.py --keyrack-url http://raspberrypi:8080 --token my-secret-token

This script:
  1. Creates (or reuses) an AES-256 encryption key on KeyRack.
  2. Simulates periodic temperature sensor readings.
  3. Encrypts each reading via the KeyRack /encrypt endpoint.
  4. Stores encrypted readings locally in a JSON file.
  5. Decrypts and displays readings on demand.
"""

import argparse
import base64
import json
import random
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

DEFAULT_URL = "http://localhost:8080"
STORAGE_FILE = Path("encrypted_readings.json")


def create_or_get_key(base_url: str, token: str, description: str) -> str:
    """Create a new AES-256 key and return its ID."""
    resp = requests.post(
        f"{base_url}/v1/keys",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        json={"key_spec": "AES_256", "description": description},
        timeout=5,
    )
    resp.raise_for_status()
    key_id = resp.json()["key_id"]
    print(f"[keyrack] Using key: {key_id}")
    return key_id


def encrypt(base_url: str, token: str, key_id: str, plaintext: bytes) -> str:
    """Encrypt plaintext bytes, return base64-encoded ciphertext."""
    resp = requests.post(
        f"{base_url}/v1/keys/{key_id}/encrypt",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        json={"plaintext": base64.b64encode(plaintext).decode()},
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()["ciphertext"]


def decrypt(base_url: str, token: str, key_id: str, ciphertext: str) -> bytes:
    """Decrypt ciphertext, return plaintext bytes."""
    resp = requests.post(
        f"{base_url}/v1/keys/{key_id}/decrypt",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        json={"ciphertext": ciphertext},
        timeout=5,
    )
    resp.raise_for_status()
    return base64.b64decode(resp.json()["plaintext"])


def simulate_reading() -> dict:
    """Generate a fake temperature/humidity reading."""
    return {
        "timestamp": time.time(),
        "temperature_c": round(20.0 + random.gauss(0, 2), 2),
        "humidity_pct": round(50.0 + random.gauss(0, 5), 1),
        "sensor_id": "sensor-001",
    }


def store_encrypted(ciphertext: str):
    """Append an encrypted reading to the local storage file."""
    readings = []
    if STORAGE_FILE.exists():
        readings = json.loads(STORAGE_FILE.read_text())
    readings.append({"ts": time.time(), "ciphertext": ciphertext})
    STORAGE_FILE.write_text(json.dumps(readings, indent=2))


def collect_loop(base_url: str, token: str, key_id: str, interval: float, count: int):
    """Collect sensor readings, encrypt, and store them."""
    print(f"[sensor] Collecting {count} readings (interval={interval}s)...")
    for i in range(count):
        reading = simulate_reading()
        plaintext = json.dumps(reading).encode()
        ciphertext = encrypt(base_url, token, key_id, plaintext)
        store_encrypted(ciphertext)
        print(f"  [{i+1}/{count}] temp={reading['temperature_c']}°C  (encrypted & stored)")
        if i < count - 1:
            time.sleep(interval)
    print(f"[sensor] Done. {count} encrypted readings saved to {STORAGE_FILE}")


def decrypt_all(base_url: str, token: str, key_id: str):
    """Decrypt and display all stored readings."""
    if not STORAGE_FILE.exists():
        print("[sensor] No stored readings found.")
        return
    readings = json.loads(STORAGE_FILE.read_text())
    print(f"[sensor] Decrypting {len(readings)} stored readings:\n")
    for entry in readings:
        plaintext = decrypt(base_url, token, key_id, entry["ciphertext"])
        data = json.loads(plaintext)
        print(f"  {data['sensor_id']}  temp={data['temperature_c']}°C  "
              f"humidity={data['humidity_pct']}%  ts={data['timestamp']:.0f}")


def main():
    parser = argparse.ArgumentParser(description="IoT sensor simulator with KeyRack encryption")
    parser.add_argument("--keyrack-url", default=DEFAULT_URL, help="KeyRack REST base URL")
    parser.add_argument("--token", default="my-secret-token", help="Bootstrap auth token")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between readings")
    parser.add_argument("--count", type=int, default=5, help="Number of readings to collect")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt and show stored readings")
    parser.add_argument("--key-description", default="iot-sensor-data-key",
                        help="Description for the encryption key")
    args = parser.parse_args()

    key_id = create_or_get_key(args.keyrack_url, args.token, args.key_description)

    if args.decrypt:
        decrypt_all(args.keyrack_url, args.token, key_id)
    else:
        collect_loop(args.keyrack_url, args.token, key_id, args.interval, args.count)


if __name__ == "__main__":
    main()
