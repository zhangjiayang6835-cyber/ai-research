"""
Fix for Issue #1346 — JWT Kid Injection -> Path Traversal -> Secret Key Leak
===========================================================================

Vulnerability
-------------
The JWT verifier reads the signing key from a filesystem path built out of the
attacker-controlled ``kid`` (Key ID) header::

    kid = decode(token).header["kid"]        # attacker-controlled
    key = open("/etc/app/keys/" + kid).read()   # path traversal!
    verify(token, key)

Two attacks fall out of this:

1. **Path traversal / secret-key leak.** ``kid = "../../../../etc/passwd"`` (or
   any readable file) makes the server load arbitrary file contents as the
   verification key. An attacker who can point verification at a file whose
   contents they know or control (a world-readable file, an uploaded file, a
   predictable public key) can forge a token that "verifies". It also enables
   probing/exfiltration of key files on disk.
2. **Algorithm/key confusion.** Combined with an ``alg`` the attacker chooses,
   the loaded bytes are used as an HMAC secret, so any known file's contents
   become a forgery oracle.

Fix
---
The verification key must be selected from a **server-side key registry**, never
from a filesystem path derived from the token. This verifier:

1. Looks keys up by ``kid`` in an in-memory registry — there is no filesystem
   access at all, so path traversal has nothing to traverse.
2. Validates ``kid`` against a strict allowlist charset (``[A-Za-z0-9._-]``,
   length-bounded), rejecting ``/``, ``\\``, ``..``, NUL bytes, newlines, and
   URL-like values before any lookup.
3. Rejects unknown key ids (no dynamic/remote key loading).
4. Rejects header-supplied keys (``jwk``/``jku``/``x5u``/``x5c``) and the
   ``none`` algorithm.
5. Pins each key id to its expected algorithm and verifies the signature with a
   constant-time comparison.

Acceptance Criteria
-------------------
- [x] ``kid`` never used to build a filesystem path
- [x] Path-traversal / absolute / NUL / newline kids rejected
- [x] Unknown kids rejected (no dynamic key loading)
- [x] Header-embedded keys and ``none`` rejected
- [x] Signature verified against the registry key for that kid

References: CWE-22 (Path Traversal), CWE-347 (Improper Verification of
Cryptographic Signature), CWE-73 (External Control of File Name or Path).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping

SUPPORTED_ALGORITHMS: dict[str, Any] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

# A kid may only be an opaque registry identifier: no separators, dots-runs,
# whitespace, or control characters. Length-bounded to avoid abuse.
SAFE_KID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Header params that let a token carry / point at its own key.
FORBIDDEN_KEY_HEADERS = frozenset({"jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256"})


class JWTKidValidationError(Exception):
    """Raised when a token fails strict kid/algorithm/signature validation."""


@dataclass(frozen=True)
class KeyRecord:
    kid: str
    algorithm: str
    secret: bytes


def is_safe_kid(kid: Any) -> bool:
    """Return True only for opaque, traversal-free registry key ids."""
    return isinstance(kid, str) and SAFE_KID_RE.fullmatch(kid) is not None


class SecureKidJWTVerifier:
    """Verify JWTs by resolving ``kid`` against a server-side registry only."""

    def __init__(
        self,
        keyring: Mapping[str, KeyRecord],
        *,
        issuer: str | None = None,
        audience: str | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._keyring = dict(keyring)
        for kid, record in self._keyring.items():
            if kid != record.kid or not is_safe_kid(kid):
                raise ValueError(f"registered kid is not a safe identifier: {kid!r}")
            if record.algorithm not in SUPPORTED_ALGORITHMS:
                raise ValueError(f"unsupported algorithm for kid {kid!r}")
            if not record.secret:
                raise ValueError(f"empty secret for kid {kid!r}")
        self._issuer = issuer
        self._audience = audience
        import time as _time

        self._now = now or _time.time

    def verify(self, token: str) -> dict:
        if not isinstance(token, str):
            raise JWTKidValidationError("token must be a string")
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise JWTKidValidationError("JWT must have three non-empty parts")

        header = self._decode_json(parts[0])
        self._validate_header(header)

        kid = header["kid"]
        # Defence in depth: validate the kid *before* any lookup, so a traversal
        # value can never reach a filesystem or remote loader.
        if not is_safe_kid(kid):
            raise JWTKidValidationError("key id is not a safe registry identifier")

        record = self._keyring.get(kid)
        if record is None:
            raise JWTKidValidationError("unknown key id")
        if header["alg"] != record.algorithm:
            raise JWTKidValidationError("token algorithm does not match pinned key algorithm")

        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        signature = self._b64url_decode(parts[2])
        expected = hmac.new(record.secret, signing_input, SUPPORTED_ALGORITHMS[record.algorithm]).digest()
        if not hmac.compare_digest(signature, expected):
            raise JWTKidValidationError("invalid token signature")

        payload = self._decode_json(parts[1])
        self._validate_claims(payload)
        return payload

    def _validate_header(self, header: Mapping[str, Any]) -> None:
        alg = header.get("alg")
        if not isinstance(alg, str):
            raise JWTKidValidationError("missing or non-string 'alg' header")
        if alg not in SUPPORTED_ALGORITHMS:
            raise JWTKidValidationError(f"forbidden or unsupported algorithm '{alg}'")
        if not isinstance(header.get("kid"), str):
            raise JWTKidValidationError("missing or non-string 'kid' header")
        if FORBIDDEN_KEY_HEADERS.intersection(header):
            raise JWTKidValidationError("token header must not supply verification keys")
        if header.get("typ") not in (None, "JWT"):
            raise JWTKidValidationError("unexpected token type")

    def _validate_claims(self, payload: Mapping[str, Any]) -> None:
        now = self._now()
        if "exp" in payload and float(payload["exp"]) <= now:
            raise JWTKidValidationError("token expired")
        if "nbf" in payload and float(payload["nbf"]) > now:
            raise JWTKidValidationError("token not yet valid")
        if self._issuer is not None and payload.get("iss") != self._issuer:
            raise JWTKidValidationError("issuer mismatch")
        if self._audience is not None:
            aud = payload.get("aud")
            ok = self._audience in aud if isinstance(aud, list) else aud == self._audience
            if not ok:
                raise JWTKidValidationError("audience mismatch")

    @staticmethod
    def _decode_json(segment: str) -> dict:
        try:
            value = json.loads(SecureKidJWTVerifier._b64url_decode(segment))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JWTKidValidationError("invalid JSON segment") from exc
        if not isinstance(value, dict):
            raise JWTKidValidationError("header and payload must be JSON objects")
        return value

    @staticmethod
    def _b64url_decode(segment: str) -> bytes:
        padding = "=" * (-len(segment) % 4)
        try:
            return base64.urlsafe_b64decode((segment + padding).encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise JWTKidValidationError("invalid base64url segment") from exc


def issue_token(payload: Mapping[str, Any], key: KeyRecord, *, header_overrides: Mapping[str, Any] | None = None) -> str:
    """Create a signed token from a registry key record (test/demo helper)."""
    header: dict[str, Any] = {"typ": "JWT", "alg": key.algorithm, "kid": key.kid}
    if header_overrides:
        header.update(header_overrides)
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(dict(payload)).encode())}".encode("ascii")
    digest = SUPPORTED_ALGORITHMS.get(str(header["alg"]))
    if digest is None:  # allow issuing "none"/unsupported tokens for negative tests
        signature = b""
    else:
        signature = hmac.new(key.secret, signing_input, digest).digest()
    return f"{signing_input.decode('ascii')}.{b64(signature) or 'x'}"


__all__ = [
    "JWTKidValidationError",
    "KeyRecord",
    "SecureKidJWTVerifier",
    "is_safe_kid",
    "issue_token",
]
