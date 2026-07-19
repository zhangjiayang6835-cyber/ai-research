"""Tests for the Issue #1346 JWT kid-injection / path-traversal fix.

Key properties verified:
- traversal / absolute / newline / NUL kids are rejected
- the verifier performs NO filesystem access (open() is never called)
- unknown kids, header-embedded keys, and `none` are rejected
- valid registry tokens verify; tampered signatures fail
"""

from __future__ import annotations

import base64
import builtins
import json
import os
import sys
import unittest

try:
    from fixes.fix_1346 import (
        JWTKidValidationError,
        KeyRecord,
        SecureKidJWTVerifier,
        is_safe_kid,
        issue_token,
    )
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "FIXES"))
    from fix_1346 import (
        JWTKidValidationError,
        KeyRecord,
        SecureKidJWTVerifier,
        is_safe_kid,
        issue_token,
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class KidInjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = KeyRecord(kid="signing-key-1", algorithm="HS256", secret=b"server-secret")
        self.verifier = SecureKidJWTVerifier(
            {"signing-key-1": self.key}, issuer="idp", audience="api", now=lambda: 1000
        )

    def _claims(self) -> dict:
        return {"sub": "user-1", "iss": "idp", "aud": "api", "exp": 2000}

    def test_valid_registry_token_verifies(self) -> None:
        token = issue_token(self._claims(), self.key)
        self.assertEqual(self.verifier.verify(token)["sub"], "user-1")

    def test_path_traversal_kids_are_rejected(self) -> None:
        for kid in (
            "../../../../etc/passwd",
            "../../keys/public.pem",
            "/etc/shadow",
            "..\\..\\windows\\win.ini",
            "signing-key-1\n../evil",
            "signing-key-1\x00",
            "https://evil.example/jwks.json",
        ):
            token = issue_token(self._claims(), self.key, header_overrides={"kid": kid})
            with self.subTest(kid=kid):
                with self.assertRaisesRegex(JWTKidValidationError, "key id"):
                    self.verifier.verify(token)

    def test_verifier_never_touches_the_filesystem(self) -> None:
        # If any code path tried to open a file from the kid, this would fire.
        original_open = builtins.open

        def _guard(*args, **kwargs):
            raise AssertionError(f"verifier attempted filesystem access: open({args!r})")

        builtins.open = _guard
        try:
            token = issue_token(
                self._claims(), self.key, header_overrides={"kid": "../../../../etc/passwd"}
            )
            with self.assertRaises(JWTKidValidationError):
                self.verifier.verify(token)
        finally:
            builtins.open = original_open

    def test_unknown_kid_is_rejected(self) -> None:
        attacker = KeyRecord(kid="attacker-key", algorithm="HS256", secret=b"attacker-secret")
        token = issue_token(self._claims(), attacker)
        with self.assertRaisesRegex(JWTKidValidationError, "unknown key id"):
            self.verifier.verify(token)

    def test_none_algorithm_is_rejected(self) -> None:
        header = _b64url(json.dumps({"typ": "JWT", "alg": "none", "kid": "signing-key-1"}).encode())
        payload = _b64url(json.dumps(self._claims()).encode())
        token = f"{header}.{payload}.anything"
        with self.assertRaisesRegex(JWTKidValidationError, "algorithm"):
            self.verifier.verify(token)

    def test_header_supplied_key_is_rejected(self) -> None:
        token = issue_token(
            self._claims(), self.key, header_overrides={"jku": "https://evil.example/jwks.json"}
        )
        with self.assertRaisesRegex(JWTKidValidationError, "verification keys"):
            self.verifier.verify(token)

    def test_algorithm_must_match_pinned_key(self) -> None:
        confused = KeyRecord(kid="signing-key-1", algorithm="HS512", secret=b"server-secret")
        token = issue_token(self._claims(), confused)
        with self.assertRaisesRegex(JWTKidValidationError, "pinned key algorithm"):
            self.verifier.verify(token)

    def test_tampered_payload_fails_signature(self) -> None:
        token = issue_token(self._claims(), self.key)
        head, _payload, sig = token.split(".")
        tampered = _b64url(json.dumps({**self._claims(), "sub": "admin"}).encode())
        with self.assertRaisesRegex(JWTKidValidationError, "signature"):
            self.verifier.verify(f"{head}.{tampered}.{sig}")

    def test_is_safe_kid_helper(self) -> None:
        self.assertTrue(is_safe_kid("signing-key-1"))
        for bad in ("../x", "a/b", "a\\b", "", "a" * 65, "a b", 123):
            self.assertFalse(is_safe_kid(bad))


if __name__ == "__main__":
    unittest.main()
