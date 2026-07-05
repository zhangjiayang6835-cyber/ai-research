"""Authentication-bypass guard for issue #117.

The vulnerable pattern is treating a JWT header field such as ``jki``/``kid`` as
a dynamic key lookup expression. Attackers can point the verifier at their own
JWK, a remote JWKS URL, a filesystem path, or a database selector, then sign an
admin token with the attacker-controlled key. This module resolves key ids only
from a server-side registry and rejects every header-supplied key source.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


SAFE_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SUPPORTED_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384}
INJECTABLE_KEY_HEADERS = {"jki", "jwk", "jku", "x5u", "x5c", "key", "public_key", "cert"}


class AuthBypassBlocked(ValueError):
    """Raised when a token attempts key-resolution or signature bypass."""


@dataclass(frozen=True)
class AuthKey:
    key_id: str
    algorithm: str
    secret: bytes


class SafeAuthTokenVerifier:
    """Verify tokens without dynamic JKI/JWK key resolution."""

    def __init__(self, keys: Mapping[str, AuthKey]) -> None:
        self._keys = dict(keys)
        for key_id, key in self._keys.items():
            if key_id != key.key_id or not SAFE_KEY_ID_RE.fullmatch(key_id):
                raise ValueError("registry key ids must be safe literals")
            if key.algorithm not in SUPPORTED_ALGORITHMS:
                raise ValueError("unsupported key algorithm")
            if not key.secret:
                raise ValueError("registry keys must have non-empty secrets")

    def verify(self, token: str) -> dict[str, Any]:
        header, claims, signing_input, signature = _decode_token(token)
        key = self._resolve_registry_key(header)
        expected = _signature(signing_input, key.secret, key.algorithm)
        if not hmac.compare_digest(signature, expected):
            raise AuthBypassBlocked("invalid signature")
        return claims

    def _resolve_registry_key(self, header: Mapping[str, Any]) -> AuthKey:
        if INJECTABLE_KEY_HEADERS.intersection(header):
            raise AuthBypassBlocked("token header must not supply keys or key locators")
        if header.get("alg") not in SUPPORTED_ALGORITHMS:
            raise AuthBypassBlocked("algorithm is not allowed")
        key_id = header.get("kid")
        if not isinstance(key_id, str) or not SAFE_KEY_ID_RE.fullmatch(key_id):
            raise AuthBypassBlocked("kid must be a safe registry key id")
        key = self._keys.get(key_id)
        if key is None:
            raise AuthBypassBlocked("unknown registry key id")
        if header["alg"] != key.algorithm:
            raise AuthBypassBlocked("algorithm does not match registry key")
        return key


def issue_token(claims: Mapping[str, Any], key: AuthKey, *, extra_header: Mapping[str, Any] | None = None) -> str:
    header: dict[str, Any] = {"typ": "JWT", "alg": key.algorithm, "kid": key.key_id}
    if extra_header:
        header.update(extra_header)
    signing_input = ".".join((_encode_json(header), _encode_json(dict(claims)))).encode("ascii")
    return f"{signing_input.decode('ascii')}.{_encode(_signature(signing_input, key.secret, str(header['alg'])))}"


def _decode_token(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    if not isinstance(token, str):
        raise AuthBypassBlocked("token must be text")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise AuthBypassBlocked("malformed token")
    header = _decode_json(parts[0])
    claims = _decode_json(parts[1])
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise AuthBypassBlocked("token segments must be JSON objects")
    return header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), _decode(parts[2])


def _signature(signing_input: bytes, secret: bytes, algorithm: str) -> bytes:
    digest = SUPPORTED_ALGORITHMS.get(algorithm)
    if digest is None:
        raise AuthBypassBlocked("algorithm is not allowed")
    return hmac.new(secret, signing_input, digest).digest()


def _encode_json(value: Mapping[str, Any]) -> str:
    return _encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _decode_json(value: str) -> Any:
    try:
        return json.loads(_decode(value))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuthBypassBlocked("invalid JSON segment") from exc


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except (TypeError, ValueError) as exc:
        raise AuthBypassBlocked("invalid base64url segment") from exc


__all__ = ["AuthBypassBlocked", "AuthKey", "SafeAuthTokenVerifier", "issue_token"]
