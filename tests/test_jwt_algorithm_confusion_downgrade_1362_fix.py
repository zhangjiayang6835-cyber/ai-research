"""Tests for the Issue #1362 RS256 -> HS256 downgrade fix.

The key test reproduces the real attack: forge an HS256 token whose HMAC secret
is the *RSA public key* bytes, and assert the fixed verifier rejects it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

# The fix lives in the repo's FIXES/ directory. Import it robustly regardless of
# how the test runner has (or hasn't) put that directory on the path.
try:
    from fixes.fix_1362 import AlgorithmConfusionError, SecureRS256Verifier
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "FIXES"))
    from fix_1362 import AlgorithmConfusionError, SecureRS256Verifier


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_rs256(payload: dict, private_key, *, header: dict | None = None) -> str:
    header = header or {"alg": "RS256", "typ": "JWT"}
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
    signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


def _forge_hs256_with_public_key(payload: dict, public_pem: bytes) -> str:
    """The downgrade attack: sign HS256 using the public key bytes as secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
    signature = hmac.new(public_pem, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


class RS256DowngradeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.verifier = SecureRS256Verifier(self.public_pem)

    def test_valid_rs256_token_verifies(self) -> None:
        token = _sign_rs256({"sub": "user-1", "role": "user"}, self.private_key)
        claims = self.verifier.verify(token)
        self.assertEqual(claims["sub"], "user-1")

    def test_hs256_forged_with_public_key_is_rejected(self) -> None:
        # This is the core exploit for #1362.
        token = _forge_hs256_with_public_key({"sub": "attacker", "role": "admin"}, self.public_pem)
        with self.assertRaisesRegex(AlgorithmConfusionError, "downgrade|HMAC"):
            self.verifier.verify(token)

    def test_none_algorithm_is_rejected(self) -> None:
        header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = _b64url(json.dumps({"sub": "attacker", "role": "admin"}).encode())
        token = f"{header}.{payload}.anything"
        with self.assertRaisesRegex(AlgorithmConfusionError, "unsigned|none"):
            self.verifier.verify(token)

    def test_tampered_payload_fails_signature(self) -> None:
        token = _sign_rs256({"sub": "user-1", "role": "user"}, self.private_key)
        head, _payload, sig = token.split(".")
        tampered_payload = _b64url(json.dumps({"sub": "user-1", "role": "admin"}).encode())
        with self.assertRaisesRegex(AlgorithmConfusionError, "signature"):
            self.verifier.verify(f"{head}.{tampered_payload}.{sig}")

    def test_header_supplied_key_is_rejected(self) -> None:
        token = _sign_rs256(
            {"sub": "user-1"},
            self.private_key,
            header={"alg": "RS256", "typ": "JWT", "jwk": {"kty": "oct", "k": "attacker"}},
        )
        with self.assertRaisesRegex(AlgorithmConfusionError, "verification keys"):
            self.verifier.verify(token)

    def test_expired_token_is_rejected(self) -> None:
        verifier = SecureRS256Verifier(self.public_pem, now=lambda: 10_000)
        token = _sign_rs256({"sub": "user-1", "exp": 9_000}, self.private_key)
        with self.assertRaisesRegex(AlgorithmConfusionError, "expired"):
            verifier.verify(token)

    def test_issuer_and_audience_enforced(self) -> None:
        verifier = SecureRS256Verifier(self.public_pem, issuer="idp", audience="api")
        good = _sign_rs256({"sub": "u", "iss": "idp", "aud": "api"}, self.private_key)
        self.assertEqual(verifier.verify(good)["sub"], "u")
        bad_iss = _sign_rs256({"sub": "u", "iss": "evil", "aud": "api"}, self.private_key)
        with self.assertRaisesRegex(AlgorithmConfusionError, "issuer"):
            verifier.verify(bad_iss)

    def test_ec_public_key_is_refused_at_construction(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec

        ec_pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with self.assertRaisesRegex(ValueError, "RSA public key"):
            SecureRS256Verifier(ec_pem)


if __name__ == "__main__":
    unittest.main()
