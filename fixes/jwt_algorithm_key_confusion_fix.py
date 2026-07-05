"""JWT algorithm-confusion and key-injection guard for issue #154.

The vulnerable pattern is trusting attacker-controlled JWT headers to choose a
verification algorithm or load a key. A secure verifier pins each key id to a
server-side key record and its expected algorithm, rejects embedded or remote
header keys, and verifies signatures with constant-time comparison.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping


SUPPORTED_HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
SAFE_KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
FORBIDDEN_KEY_HEADERS = {"jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256", "key", "secret"}


class JWTValidationError(ValueError):
    """Raised when a token fails strict validation."""


@dataclass(frozen=True)
class KeyRecord:
    kid: str
    algorithm: str
    secret: bytes


class SecureJWTVerifier:
    """Verify JWTs without accepting attacker-selected algorithms or keys."""

    def __init__(
        self,
        keys: Mapping[str, KeyRecord],
        *,
        issuer: str | None = None,
        audience: str | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        self.keys = dict(keys)
        self.issuer = issuer
        self.audience = audience
        self._now = now or time.time
        for kid, record in self.keys.items():
            if kid != record.kid or not SAFE_KID_RE.fullmatch(kid):
                raise ValueError("key ids must be explicit safe registry keys")
            if record.algorithm not in SUPPORTED_HMAC_ALGORITHMS:
                raise ValueError("unsupported pinned algorithm")
            if not record.secret:
                raise ValueError("key secret must be non-empty")

    def verify(self, token: str) -> dict[str, Any]:
        header, payload, signing_input, signature = _decode_token(token)
        self._validate_header(header)

        kid = header["kid"]
        record = self.keys.get(kid)
        if record is None:
            raise JWTValidationError("unknown key id")
        if header["alg"] != record.algorithm:
            raise JWTValidationError("token algorithm does not match pinned key algorithm")

        expected = _sign(signing_input, record.secret, record.algorithm)
        if not hmac.compare_digest(signature, expected):
            raise JWTValidationError("invalid token signature")

        self._validate_claims(payload)
        return payload

    def _validate_header(self, header: Mapping[str, Any]) -> None:
        if not isinstance(header.get("alg"), str) or header["alg"] not in SUPPORTED_HMAC_ALGORITHMS:
            raise JWTValidationError("algorithm is not allowed")
        if not isinstance(header.get("kid"), str) or not SAFE_KID_RE.fullmatch(header["kid"]):
            raise JWTValidationError("key id is not a server registry key")
        if FORBIDDEN_KEY_HEADERS.intersection(header):
            raise JWTValidationError("token header must not supply verification keys")
        if header.get("typ") not in (None, "JWT"):
            raise JWTValidationError("unexpected token type")

    def _validate_claims(self, payload: Mapping[str, Any]) -> None:
        now = int(self._now())
        if "exp" in payload and int(payload["exp"]) <= now:
            raise JWTValidationError("token expired")
        if "nbf" in payload and int(payload["nbf"]) > now:
            raise JWTValidationError("token not yet valid")
        if self.issuer is not None and payload.get("iss") != self.issuer:
            raise JWTValidationError("issuer mismatch")
        if self.audience is not None:
            audience = payload.get("aud")
            if isinstance(audience, list):
                valid = self.audience in audience
            else:
                valid = audience == self.audience
            if not valid:
                raise JWTValidationError("audience mismatch")


def issue_hmac_jwt(
    payload: Mapping[str, Any],
    key: KeyRecord,
    *,
    header_overrides: Mapping[str, Any] | None = None,
) -> str:
    """Create a test token using a server-side key record."""

    header: dict[str, Any] = {"typ": "JWT", "alg": key.algorithm, "kid": key.kid}
    if header_overrides:
        header.update(header_overrides)
    signing_input = ".".join(
        (
            _b64url_encode_json(header),
            _b64url_encode_json(dict(payload)),
        )
    ).encode("ascii")
    signature = _sign(signing_input, key.secret, str(header["alg"]))
    return f"{signing_input.decode('ascii')}.{_b64url_encode(signature)}"


def _decode_token(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    if not isinstance(token, str):
        raise JWTValidationError("token must be text")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise JWTValidationError("malformed token")
    header = _b64url_decode_json(parts[0])
    payload = _b64url_decode_json(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JWTValidationError("header and payload must be JSON objects")
    return header, payload, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64url_decode(parts[2])


def _sign(signing_input: bytes, secret: bytes, algorithm: str) -> bytes:
    digest = SUPPORTED_HMAC_ALGORITHMS.get(algorithm)
    if digest is None:
        raise JWTValidationError("algorithm is not allowed")
    return hmac.new(secret, signing_input, digest).digest()


def _b64url_encode_json(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url_encode(encoded)


def _b64url_decode_json(value: str) -> Any:
    try:
        return json.loads(_b64url_decode(value))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JWTValidationError("invalid JSON segment") from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise JWTValidationError("invalid base64url segment") from exc


__all__ = [
    "KeyRecord",
    "JWTValidationError",
    "SecureJWTVerifier",
    "issue_hmac_jwt",
]
