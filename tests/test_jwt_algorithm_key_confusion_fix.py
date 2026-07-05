from __future__ import annotations

import json
import unittest

from fixes.jwt_algorithm_key_confusion_fix import (
    JWTValidationError,
    KeyRecord,
    SecureJWTVerifier,
    issue_hmac_jwt,
)


class JWTAlgorithmKeyConfusionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = KeyRecord(kid="auth-2026", algorithm="HS256", secret=b"server-secret")
        self.verifier = SecureJWTVerifier(
            {"auth-2026": self.key},
            issuer="https://issuer.example",
            audience="api",
            now=lambda: 1000,
        )

    def test_valid_token_with_pinned_key_and_algorithm(self) -> None:
        token = issue_hmac_jwt(
            {"sub": "user-1", "iss": "https://issuer.example", "aud": "api", "exp": 1100},
            self.key,
        )

        claims = self.verifier.verify(token)

        self.assertEqual(claims["sub"], "user-1")

    def test_none_algorithm_is_rejected_before_signature_trust(self) -> None:
        from fixes.jwt_algorithm_key_confusion_fix import _b64url_encode

        header = _b64url_encode(json.dumps({"typ": "JWT", "alg": "none", "kid": "auth-2026"}).encode())
        payload = _b64url_encode(
            json.dumps(
                {"sub": "admin", "iss": "https://issuer.example", "aud": "api", "exp": 1100}
            ).encode()
        )
        token = f"{header}.{payload}.unsigned"

        with self.assertRaisesRegex(JWTValidationError, "algorithm"):
            self.verifier.verify(token)

    def test_algorithm_substitution_must_match_pinned_key_record(self) -> None:
        confused = KeyRecord(kid="auth-2026", algorithm="HS512", secret=b"server-secret")
        token = issue_hmac_jwt(
            {"sub": "admin", "iss": "https://issuer.example", "aud": "api", "exp": 1100},
            confused,
        )

        with self.assertRaisesRegex(JWTValidationError, "pinned key"):
            self.verifier.verify(token)

    def test_header_embedded_keys_are_rejected(self) -> None:
        token = issue_hmac_jwt(
            {"sub": "user-1", "iss": "https://issuer.example", "aud": "api", "exp": 1100},
            self.key,
            header_overrides={"jwk": {"kty": "oct", "k": "attacker-key"}},
        )

        with self.assertRaisesRegex(JWTValidationError, "must not supply"):
            self.verifier.verify(token)

    def test_kid_path_or_remote_lookup_injection_is_rejected(self) -> None:
        for kid in ("../../keys/private.pem", "https://evil.example/jwks.json", "auth-2026\nx"):
            token = issue_hmac_jwt(
                {"sub": "user-1", "iss": "https://issuer.example", "aud": "api", "exp": 1100},
                self.key,
                header_overrides={"kid": kid},
            )
            with self.subTest(kid=kid):
                with self.assertRaisesRegex(JWTValidationError, "key id"):
                    self.verifier.verify(token)

    def test_unknown_safe_kid_is_not_loaded_dynamically(self) -> None:
        attacker_key = KeyRecord(kid="attacker", algorithm="HS256", secret=b"attacker-secret")
        token = issue_hmac_jwt(
            {"sub": "admin", "iss": "https://issuer.example", "aud": "api", "exp": 1100},
            attacker_key,
        )

        with self.assertRaisesRegex(JWTValidationError, "unknown key"):
            self.verifier.verify(token)

    def test_payload_tampering_breaks_signature(self) -> None:
        token = issue_hmac_jwt(
            {"sub": "user-1", "iss": "https://issuer.example", "aud": "api", "exp": 1100},
            self.key,
        )
        header, _payload, signature = token.split(".")
        tampered_payload = json.dumps(
            {"sub": "admin", "iss": "https://issuer.example", "aud": "api", "exp": 1100},
            separators=(",", ":"),
        ).encode()
        from fixes.jwt_algorithm_key_confusion_fix import _b64url_encode

        tampered = f"{header}.{_b64url_encode(tampered_payload)}.{signature}"

        with self.assertRaisesRegex(JWTValidationError, "signature"):
            self.verifier.verify(tampered)

    def test_claim_checks_reject_expired_wrong_issuer_and_wrong_audience(self) -> None:
        cases = (
            ({"sub": "u", "iss": "https://issuer.example", "aud": "api", "exp": 999}, "expired"),
            ({"sub": "u", "iss": "https://evil.example", "aud": "api", "exp": 1100}, "issuer"),
            ({"sub": "u", "iss": "https://issuer.example", "aud": "other", "exp": 1100}, "audience"),
        )
        for payload, error in cases:
            token = issue_hmac_jwt(payload, self.key)
            with self.subTest(error=error):
                with self.assertRaisesRegex(JWTValidationError, error):
                    self.verifier.verify(token)


if __name__ == "__main__":
    unittest.main()
