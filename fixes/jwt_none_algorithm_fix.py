"""JWT ``alg=none`` rejection guard for issue #86.

The vulnerable pattern is trusting the token header to decide whether a JWT
needs signature verification. If ``alg`` is ``none`` and the verifier accepts
it, an attacker can forge admin claims without a key. This module uses a small
allowlist of signed HMAC algorithms and verifies the signature before returning
claims.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


SUPPORTED_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384}
SAFE_KID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class JWTVerificationError(ValueError):
    """Raised when a JWT fails verification policy."""


@dataclass(frozen=True)
class JWTSigningKey:
    kid: str
    algorithm: str
    secret: bytes


class StrictJWTVerifier:
    """Verify JWTs with explicit signed algorithms only."""

    def __init__(self, keys: Mapping[str, JWTSigningKey]) -> None:
        self._keys = dict(keys)
        for kid, key in self._keys.items():
            if kid != key.kid or not SAFE_KID_RE.fullmatch(kid):
                raise JWTVerificationError("key ids must be safe literals")
            if key.algorithm not in SUPPORTED_ALGORITHMS:
                raise JWTVerificationError("unsupported key algorithm")
            if not key.secret:
                raise JWTVerificationError("signing secret is required")

    def verify(self, token: str) -> dict[str, Any]:
        header, claims, signing_input, signature = _decode_jwt(token)
        key = self._resolve_key(header)
        expected = _sign(signing_input, key.secret, key.algorithm)
        if not hmac.compare_digest(signature, expected):
            raise JWTVerificationError("invalid signature")
        return claims

    def _resolve_key(self, header: Mapping[str, Any]) -> JWTSigningKey:
        algorithm = header.get("alg")
        if algorithm == "none":
            raise JWTVerificationError("unsigned JWTs are not accepted")
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise JWTVerificationError("algorithm is not allowed")
        kid = header.get("kid")
        if not isinstance(kid, str) or not SAFE_KID_RE.fullmatch(kid):
            raise JWTVerificationError("kid must be a safe registered key id")
        key = self._keys.get(kid)
        if key is None:
            raise JWTVerificationError("unknown signing key")
        if key.algorithm != algorithm:
            raise JWTVerificationError("token algorithm does not match key policy")
        return key


def issue_token(claims: Mapping[str, Any], key: JWTSigningKey, *, header_overrides: Mapping[str, Any] | None = None) -> str:
    header: dict[str, Any] = {"typ": "JWT", "alg": key.algorithm, "kid": key.kid}
    if header_overrides:
        header.update(header_overrides)
    signing_input = ".".join((_encode_json(header), _encode_json(dict(claims)))).encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64encode(_sign(signing_input, key.secret, str(header['alg'])))}"


def make_unsigned_token(claims: Mapping[str, Any], *, kid: str = "main") -> str:
    header = _encode_json({"typ": "JWT", "alg": "none", "kid": kid})
    body = _encode_json(dict(claims))
    return f"{header}.{body}."


def _decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    if not isinstance(token, str):
        raise JWTVerificationError("token must be text")
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTVerificationError("malformed JWT")
    header = _decode_json(parts[0])
    claims = _decode_json(parts[1])
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JWTVerificationError("JWT header and claims must be JSON objects")
    return header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64decode(parts[2])


def _sign(signing_input: bytes, secret: bytes, algorithm: str) -> bytes:
    digest = SUPPORTED_ALGORITHMS.get(algorithm)
    if digest is None:
        raise JWTVerificationError("algorithm is not allowed")
    return hmac.new(secret, signing_input, digest).digest()


def _encode_json(value: Mapping[str, Any]) -> str:
    return _b64encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _decode_json(value: str) -> Any:
    try:
        return json.loads(_b64decode(value))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JWTVerificationError("invalid JSON segment") from exc


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except (TypeError, ValueError) as exc:
        raise JWTVerificationError("invalid base64url segment") from exc


__all__ = ["JWTSigningKey", "JWTVerificationError", "StrictJWTVerifier", "issue_token", "make_unsigned_token"]
