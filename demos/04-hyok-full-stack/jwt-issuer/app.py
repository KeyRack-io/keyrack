"""Minimal JWT issuer for KeyRack HYOK demo.

Generates an RSA-2048 key pair at startup and exposes:
  GET  /.well-known/jwks.json  — public key as JWKS
  POST /token                  — issue a signed JWT
"""

import json
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

app = Flask(__name__)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

KID = "demo-key-1"
ISSUER = "http://jwt-issuer:9000"


def _jwks():
    """Build a JWKS response from the RSA public key."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64

    pub_numbers = public_key.public_numbers()

    def _b64url(num, length):
        data = num.to_bytes(length, byteorder="big")
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    n_bytes = (pub_numbers.n.bit_length() + 7) // 8
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": _b64url(pub_numbers.n, n_bytes),
                "e": _b64url(pub_numbers.e, 3),
            }
        ]
    }


@app.route("/.well-known/jwks.json")
def jwks():
    return jsonify(_jwks())


@app.route("/token", methods=["POST"])
def issue_token():
    body = request.get_json(force=True, silent=True) or {}
    sub = body.get("sub", "anonymous")
    tenant_id = body.get("tenant_id", "unknown")
    ttl = int(body.get("ttl", 3600))

    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
        "keyrack:tenant_id": tenant_id,
    }

    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KID})
    return jsonify({"access_token": token, "token_type": "Bearer", "expires_in": ttl})


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
