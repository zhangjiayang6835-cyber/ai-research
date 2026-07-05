from __future__ import annotations

import json
import unittest

from fixes.jwt_none_algorithm_fix import (
    JWTSigningKey,
    JWTVerificationError,
    StrictJWTVerifier,
    _b64encode,
    issue_token,
    make_unsigned_token,
)


class JWTNoneAlgorithmFixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = JWTSigningKey("main", "HS256", b"trusted-secret")
        self.verifier = StrictJWTVerifier({"main": self.key})

    def test_signed_token_with_allowed_algorithm_is_accepted(self) -> None:
        token = issue_token({"sub": "user-1", "role": "member"}, self.key)

        self.assertEqual(self.verifier.verify(token)["sub"], "user-1")

    def test_unsigned_alg_none_token_is_rejected(self) -> None:
        token = make_unsigned_token({"sub": "attacker", "role": "admin"})

        with self.assertRaisesRegex(JWTVerificationError, "unsigned"):
            self.verifier.verify(token)

    def test_none_algorithm_with_fake_signature_is_rejected(self) -> None:
        header = _b64encode(json.dumps({"typ": "JWT", "alg": "none", "kid": "main"}).encode())
        claims = _b64encode(json.dumps({"sub": "attacker", "role": "admin"}).encode())
        token = f"{header}.{claims}.ZmFrZS1zaWduYXR1cmU"

        with self.assertRaisesRegex(JWTVerificationError, "unsigned"):
            self.verifier.verify(token)

    def test_header_algorithm_must_match_registered_key_policy(self) -> None:
        confused_key = JWTSigningKey("main", "HS384", b"trusted-secret")
        token = issue_token({"sub": "attacker"}, confused_key)

        with self.assertRaisesRegex(JWTVerificationError, "does not match"):
            self.verifier.verify(token)

    def test_unknown_algorithm_is_rejected_before_signature_trust(self) -> None:
        header = _b64encode(json.dumps({"typ": "JWT", "alg": "HS512", "kid": "main"}).encode())
        claims = _b64encode(json.dumps({"sub": "attacker"}).encode())
        token = f"{header}.{claims}.ZmFrZS1zaWduYXR1cmU"

        with self.assertRaisesRegex(JWTVerificationError, "algorithm"):
            self.verifier.verify(token)

    def test_unknown_or_unsafe_kid_is_rejected(self) -> None:
        for kid in ("unknown", "../main", "https://evil.example/key", "main\nkid:evil"):
            token = issue_token({"sub": "attacker"}, self.key, header_overrides={"kid": kid})
            with self.subTest(kid=kid):
                with self.assertRaises(JWTVerificationError):
                    self.verifier.verify(token)

    def test_payload_tampering_is_rejected(self) -> None:
        token = issue_token({"sub": "user-1", "role": "member"}, self.key)
        header, _claims, signature = token.split(".")
        admin_claims = _b64encode(json.dumps({"sub": "user-1", "role": "admin"}).encode())

        with self.assertRaisesRegex(JWTVerificationError, "signature"):
            self.verifier.verify(f"{header}.{admin_claims}.{signature}")

    def test_key_registry_rejects_none_algorithm_keys(self) -> None:
        with self.assertRaisesRegex(JWTVerificationError, "unsupported"):
            StrictJWTVerifier({"main": JWTSigningKey("main", "none", b"secret")})


if __name__ == "__main__":
    unittest.main()
