"""
Fix for Issue #1362 — JWT Algorithm Confusion (RS256 -> HS256 Downgrade)
========================================================================

Vulnerability
-------------
The service issues JWTs signed with **RS256** (asymmetric: the Identity
Provider signs with its RSA *private* key; verifiers check the signature with
the RSA *public* key, which is not a secret).

A naive verifier trusts the ``alg`` value inside the token header to decide how
to check the signature::

    header = decode(token)                      # attacker-controlled
    if header["alg"].startswith("HS"):
        verify_hmac(token, key)                 # key used as HMAC secret
    else:
        verify_rsa(token, key)                  # key used as RSA public key

Because the RSA *public* key is public, an attacker can:

1. Take the token, switch the header ``alg`` from ``RS256`` to ``HS256``.
2. Re-sign the token with **HMAC-SHA256 using the RSA public key bytes as the
   HMAC secret**.
3. Submit it. The verifier sees ``alg=HS256``, runs the HMAC branch with the
   very same public-key bytes, and the signature matches — the attacker has
   forged a fully valid token (typically escalating to ``admin``).

The ``none`` algorithm (no signature at all) is a related trivial forgery.

Fix
---
The choice of verification algorithm must be a **server-side policy**, never
derived from the untrusted token header. This verifier:

1. Pins the accepted algorithm(s) at construction time (default ``RS256``) and
   rejects any token whose ``alg`` is not in that allowlist — HS256/HS384/HS512
   and ``none`` are refused *before* any signature check runs.
2. Only ever performs **RSA** verification. There is no HMAC code path, so the
   public key can never be misused as an HMAC secret.
3. Rejects header-supplied key material (``jwk``/``jku``/``x5u``/``x5c`` ...),
   which is the sibling key-injection vector.
4. Verifies the signature with constant-time RSA PKCS#1 v1.5 and the hash that
   matches the pinned algorithm.
5. Validates standard claims (``exp``, ``nbf``, ``iss``, ``aud``) after the
   signature is trusted.

Acceptance criteria
-------------------
- [x] ``alg`` header validated against a server-side allowlist
- [x] HS256/HS384/HS512 rejected when RS256 is expected (downgrade blocked)
- [x] ``none`` algorithm rejected
- [x] Public key can never be used as an HMAC secret (no HMAC path)
- [x] Header-embedded / remote keys (jwk/jku/x5u/x5c) rejected
- [x] Tampered payloads fail signature verification

References: CWE-347 (Improper Verification of Cryptographic Signature),
CWE-757 (Selection of Less-Secure Algorithm During Negotiation / downgrade).
"""

from __future__ import annotations

import base64
import json
from typing import Any, Callable, FrozenSet, Mapping

# Algorithms this verifier is willing to accept. All asymmetric RSA-PKCS1v15.
RSA_ALGORITHMS: FrozenSet[str] = frozenset({"RS256", "RS384", "RS512"})

# Explicitly named so error messages make the downgrade attempt obvious.
FORBIDDEN_HMAC_ALGORITHMS: FrozenSet[str] = frozenset({"HS256", "HS384", "HS512"})
FORBIDDEN_NONE_ALGORITHMS: FrozenSet[str] = frozenset({"none", "None", "NONE", ""})

# Header parameters that let a token carry / point at its own verification key.
# Accepting any of these re-introduces algorithm/key confusion.
FORBIDDEN_KEY_HEADERS: FrozenSet[str] = frozenset(
    {"jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256"}
)


class AlgorithmConfusionError(Exception):
    """Raised when a token fails strict algorithm/signature validation."""


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment:
        raise AlgorithmConfusionError("empty JWT segment")
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise AlgorithmConfusionError(f"invalid base64url segment: {exc}") from exc


def _decode_json_object(segment: str) -> dict:
    try:
        value = json.loads(_b64url_decode(segment))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AlgorithmConfusionError(f"invalid JSON segment: {exc}") from exc
    if not isinstance(value, dict):
        raise AlgorithmConfusionError("header and payload must be JSON objects")
    return value


class SecureRS256Verifier:
    """Verify RS256 JWTs without trusting the token's own algorithm choice.

    The verification algorithm is fixed by server policy at construction time,
    so an attacker cannot downgrade RS256 to HS256 (or ``none``) by editing the
    token header. Only RSA verification is ever performed.
    """

    def __init__(
        self,
        public_key_pem: str | bytes,
        *,
        allowed_algorithms: FrozenSet[str] = RSA_ALGORITHMS,
        issuer: str | None = None,
        audience: str | None = None,
        leeway: int = 0,
        now: Callable[[], float] | None = None,
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        allowed = frozenset(allowed_algorithms)
        if not allowed or not allowed <= RSA_ALGORITHMS:
            raise ValueError("allowed_algorithms must be a non-empty subset of RSA_ALGORITHMS")
        self._allowed = allowed
        self._issuer = issuer
        self._audience = audience
        self._leeway = int(leeway)

        import time as _time

        self._now = now or _time.time

        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode("ascii")
        try:
            key = load_pem_public_key(public_key_pem)
        except Exception as exc:  # cryptography raises a variety of types
            raise ValueError(f"could not load RSA public key: {exc}") from exc
        # Guard against handing an EC/OKP/DSA key that would change the branch.
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("public key must be an RSA public key")
        self._public_key = key

    def verify(self, token: str) -> dict:
        """Return the token's claims, or raise ``AlgorithmConfusionError``."""
        if not isinstance(token, str):
            raise AlgorithmConfusionError("token must be a string")
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise AlgorithmConfusionError("JWT must have three non-empty parts")

        header = _decode_json_object(parts[0])
        alg = self._require_allowed_algorithm(header)

        if FORBIDDEN_KEY_HEADERS.intersection(header):
            raise AlgorithmConfusionError(
                "token header must not supply verification keys "
                f"({sorted(FORBIDDEN_KEY_HEADERS.intersection(header))})"
            )

        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        signature = _b64url_decode(parts[2])
        self._verify_rsa_signature(signing_input, signature, alg)

        payload = _decode_json_object(parts[1])
        self._validate_claims(payload)
        return payload

    def _require_allowed_algorithm(self, header: Mapping[str, Any]) -> str:
        alg = header.get("alg")
        if not isinstance(alg, str):
            raise AlgorithmConfusionError("missing or non-string 'alg' header")
        if alg in FORBIDDEN_NONE_ALGORITHMS:
            raise AlgorithmConfusionError(
                f"forbidden algorithm '{alg}': unsigned tokens are rejected"
            )
        if alg in FORBIDDEN_HMAC_ALGORITHMS:
            raise AlgorithmConfusionError(
                f"forbidden algorithm '{alg}': symmetric HMAC is not accepted when "
                "asymmetric RS256 is expected (algorithm-confusion downgrade blocked)"
            )
        if alg not in self._allowed:
            raise AlgorithmConfusionError(
                f"unsupported algorithm '{alg}'; allowed: {sorted(self._allowed)}"
            )
        return alg

    def _verify_rsa_signature(self, signing_input: bytes, signature: bytes, alg: str) -> None:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        hash_alg = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}[alg]()
        try:
            self._public_key.verify(signature, signing_input, padding.PKCS1v15(), hash_alg)
        except InvalidSignature as exc:
            raise AlgorithmConfusionError("invalid token signature") from exc

    def _validate_claims(self, payload: Mapping[str, Any]) -> None:
        now = self._now()
        if "exp" in payload:
            try:
                exp = float(payload["exp"])
            except (TypeError, ValueError) as exc:
                raise AlgorithmConfusionError("invalid 'exp' claim") from exc
            if exp + self._leeway <= now:
                raise AlgorithmConfusionError("token expired")
        if "nbf" in payload:
            try:
                nbf = float(payload["nbf"])
            except (TypeError, ValueError) as exc:
                raise AlgorithmConfusionError("invalid 'nbf' claim") from exc
            if nbf - self._leeway > now:
                raise AlgorithmConfusionError("token not yet valid")
        if self._issuer is not None and payload.get("iss") != self._issuer:
            raise AlgorithmConfusionError("issuer mismatch")
        if self._audience is not None:
            aud = payload.get("aud")
            ok = self._audience in aud if isinstance(aud, list) else aud == self._audience
            if not ok:
                raise AlgorithmConfusionError("audience mismatch")


__all__ = [
    "AlgorithmConfusionError",
    "SecureRS256Verifier",
    "RSA_ALGORITHMS",
]
