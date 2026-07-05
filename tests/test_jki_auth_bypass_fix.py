from __future__ import annotations

import json
import unittest

from fixes.jki_auth_bypass_fix import (
    AuthBypassBlocked,
    AuthKey,
    SafeAuthTokenVerifier,
    _encode,
    issue_token,
)


class JKIAuthBypassTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = AuthKey("auth-main", "HS256", b"trusted-server-secret")
        self.verifier = SafeAuthTokenVerifier({"auth-main": self.key})

    def test_valid_registry_key_token_is_accepted(self) -> None:
        token = issue_token({"sub": "user-1", "role": "member"}, self.key)

        self.assertEqual(self.verifier.verify(token)["sub"], "user-1")

    def test_header_jki_or_jwk_key_injection_is_rejected(self) -> None:
        for header_name, value in (
            ("jki", "https://evil.example/jwks.json#attacker"),
            ("jwk", {"kty": "oct", "k": "attacker-secret"}),
            ("jku", "https://evil.example/jwks.json"),
            ("x5u", "file:///tmp/attacker.pem"),
            ("public_key", "-----BEGIN PUBLIC KEY----- attacker"),
        ):
            token = issue_token({"sub": "admin"}, self.key, extra_header={header_name: value})
            with self.subTest(header_name=header_name):
                with self.assertRaisesRegex(AuthBypassBlocked, "must not supply"):
                    self.verifier.verify(token)

    def test_path_url_and_query_like_kid_values_are_rejected(self) -> None:
        for kid in (
            "../keys/admin.pem",
            "https://evil.example/key",
            "auth-main\nX-Injected: yes",
            "auth-main;DROP TABLE keys",
            "",
        ):
            token = issue_token({"sub": "admin"}, self.key, extra_header={"kid": kid})
            with self.subTest(kid=kid):
                with self.assertRaisesRegex(AuthBypassBlocked, "kid"):
                    self.verifier.verify(token)

    def test_unknown_safe_kid_does_not_trigger_dynamic_lookup(self) -> None:
        attacker_key = AuthKey("attacker", "HS256", b"attacker-secret")
        token = issue_token({"sub": "admin", "role": "admin"}, attacker_key)

        with self.assertRaisesRegex(AuthBypassBlocked, "unknown"):
            self.verifier.verify(token)

    def test_algorithm_confusion_is_rejected_against_registry_key(self) -> None:
        confused_key = AuthKey("auth-main", "HS384", b"trusted-server-secret")
        token = issue_token({"sub": "admin"}, confused_key)

        with self.assertRaisesRegex(AuthBypassBlocked, "algorithm does not match"):
            self.verifier.verify(token)

    def test_alg_none_unsigned_token_is_rejected(self) -> None:
        header = _encode(json.dumps({"typ": "JWT", "alg": "none", "kid": "auth-main"}).encode())
        claims = _encode(json.dumps({"sub": "admin", "role": "admin"}).encode())
        token = f"{header}.{claims}.unsigned"

        with self.assertRaisesRegex(AuthBypassBlocked, "algorithm"):
            self.verifier.verify(token)

    def test_payload_tampering_breaks_signature(self) -> None:
        token = issue_token({"sub": "user-1", "role": "member"}, self.key)
        header, _claims, signature = token.split(".")
        admin_claims = _encode(json.dumps({"sub": "user-1", "role": "admin"}).encode())
        tampered = f"{header}.{admin_claims}.{signature}"

        with self.assertRaisesRegex(AuthBypassBlocked, "signature"):
            self.verifier.verify(tampered)


if __name__ == "__main__":
    unittest.main()
