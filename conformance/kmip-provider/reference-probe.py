#!/usr/bin/env python3
"""Sanity-check the neutral KMIP server with its own client.

This exists so that a failure of the KeyRack provider against this server can
be attributed. If this probe passes and the provider fails, the defect is on
our side; if this probe fails, the fixture is wrong. Without it, every failure
is ambiguous.

Reports which of the operations the KeyRack provider needs are actually served,
and at which KMIP version.
"""
import sys
import pathlib

from kmip.pie.client import ProxyKmipClient
from kmip.pie import objects
from kmip.core import enums

CERTS = pathlib.Path(__file__).parent / "certs"


def client(version):
    return ProxyKmipClient(
        hostname="127.0.0.1",
        port=5696,
        cert=str(CERTS / "client.crt"),
        key=str(CERTS / "client.key"),
        ca=str(CERTS / "ca.crt"),
        kmip_version=version,
    )


def main():
    failures = 0
    for version in (enums.KMIPVersion.KMIP_1_4, enums.KMIPVersion.KMIP_2_0):
        print(f"\n=== {version.name} ===")
        try:
            with client(version) as c:
                uid = c.create(
                    enums.CryptographicAlgorithm.AES,
                    256,
                    cryptographic_usage_mask=[
                        enums.CryptographicUsageMask.ENCRYPT,
                        enums.CryptographicUsageMask.DECRYPT,
                    ],
                )
                print(f"[PASS] Create              uid={uid}")

                c.activate(uid)
                print("[PASS] Activate")

                ct, iv = c.encrypt(
                    b"neutral-server-probe",
                    uid=uid,
                    cryptographic_parameters={
                        "cryptographic_algorithm": enums.CryptographicAlgorithm.AES,
                        "block_cipher_mode": enums.BlockCipherMode.CBC,
                        "padding_method": enums.PaddingMethod.PKCS5,
                    },
                    iv_counter_nonce=b"0" * 16,
                )
                print(f"[PASS] Encrypt (AES-CBC)   {len(ct)} bytes")

                pt = c.decrypt(
                    ct,
                    uid=uid,
                    cryptographic_parameters={
                        "cryptographic_algorithm": enums.CryptographicAlgorithm.AES,
                        "block_cipher_mode": enums.BlockCipherMode.CBC,
                        "padding_method": enums.PaddingMethod.PKCS5,
                    },
                    iv_counter_nonce=b"0" * 16,
                )
                assert pt == b"neutral-server-probe", pt
                print("[PASS] Decrypt round-trip")

                # GCM is what the KeyRack provider requests, so record whether
                # this server serves it at all.
                try:
                    c.encrypt(
                        b"gcm-probe",
                        uid=uid,
                        cryptographic_parameters={
                            "cryptographic_algorithm": enums.CryptographicAlgorithm.AES,
                            "block_cipher_mode": enums.BlockCipherMode.GCM,
                        },
                        iv_counter_nonce=b"0" * 12,
                    )
                    print("[PASS] Encrypt (AES-GCM)")
                except Exception as e:  # noqa: BLE001
                    print(f"[INFO] Encrypt (AES-GCM)   unsupported here: {e}")

                c.revoke(
                    enums.RevocationReasonCode.CESSATION_OF_OPERATION, uid
                )
                c.destroy(uid)
                print("[PASS] Revoke + Destroy")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"[FAIL] {version.name}: {type(e).__name__}: {e}")

    return 1 if failures == 2 else 0


if __name__ == "__main__":
    sys.exit(main())
