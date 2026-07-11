"""
Fix for Issue #944 — JWT Algorithm Confusion (RS256->HS256 Downgrade)
=====================================================================

Vulnerability
-------------
The JWT verification library trusts the ``alg`` header in the token to decide
which algorithm to use for signature verification. An attacker can change the
``alg`` from ``RS256`` to ``HS256`` and sign the modified token using the
server's public RSA key (which is publicly known) as the HMAC secret. The
server then verifies the token using HMAC-HS256 with the RSA public key as the
secret, accepting the forged token.

Root cause: the server does not pin the expected algorithm for each signing key.

Fix Strategy
------------
1. Maintain an explicit allow-list of algorithms that the server accepts.
2. Before verifying the signature, validate that the token's ``alg`` header
   matches the server's expected algorithm for that key.
3. When the server uses asymmetric algorithms (RS256/RS384/RS512), explicitly
   reject symmetric algorithms (HS256/HS384/HS512).
4. Use constant-time comparison for signature verification.

This module is framework-agnostic and can be used with PyJWT, python-jose, or
any other JWT library.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


# Allowed asymmetric algorithms (RSA-based)
ALLOWED_ASYMMETRIC_ALGORITHMS = frozenset({"RS256", "RS384", "RS512"})

# Allowed symmetric algorithms (HMAC-based) - only for services that use HMAC
ALLOWED_SYMMETRIC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})

# Registry of which algorithm group a key belongs to
ALGORITHM_GROUP = {
    "RS256": "asymmetric",
    "RS384": "asymmetric",
    "RS512": "asymmetric",
    "HS256": "symmetric",
    "HS384": "symmetric",
    "HS512": "symmetric",
}

# Explicitly disallowed algorithms (security risk)
DISALLOWED_ALGORITHMS = frozenset({"none"})

SAFE_KID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class JWTAlgorithmError(ValueError):
    """Raised when a JWT uses a disallowed or unexpected algorithm."""


@dataclass(frozen=True)
class KeyPolicy:
    """Policy for a single signing key."""
    kid: str
    algorithm: str  # Expected algorithm for this key
    public_key_pem: str | None = None  # PEM-encoded public key (for asymmetric)
    secret: bytes | None = None  # Shared secret (for symmetric)


class AlgorithmConfusionGuard:
    """Guard against JWT algorithm confusion attacks.

    Usage::

        guard = AlgorithmConfusionGuard({
            "key-rs256": KeyPolicy(
                kid="key-rs256",
                algorithm="RS256",
                public_key_pem="-----BEGIN PUBLIC KEY-----...",
            ),
        })

        # Verify a token
        claims = guard.verify(token)
    """

    def __init__(self, keys: Mapping[str, KeyPolicy]) -> None:
        self._keys = dict(keys)
        for kid, policy in self._keys.items():
            if not SAFE_KID_RE.fullmatch(kid):
                raise JWTAlgorithmError(f"key id {kid!r} is not a safe registry key")
            if policy.algorithm in DISALLOWED_ALGORITHMS:
                raise JWTAlgorithmError(f"algorithm {policy.algorithm} is explicitly disallowed")
            group = ALGORITHM_GROUP.get(policy.algorithm)
            if group is None:
                raise JWTAlgorithmError(f"unknown algorithm {policy.algorithm!r}")
            if group == "asymmetric" and not policy.public_key_pem:
                raise JWTAlgorithmError(f"asymmetric key {kid!r} requires a public key PEM")
            if group == "symmetric" and not policy.secret:
                raise JWTAlgorithmError(f"symmetric key {kid!r} requires a secret")

    def verify(self, token: str) -> dict[str, Any]:
        """Verify a JWT and return its claims.

        Raises ``JWTAlgorithmError`` if the algorithm is unexpected or
        the signature is invalid.
        """
        header_b64, payload_b64, sig_b64 = token.split(".")
        header_raw = _b64decode(header_b64)
        header = json.loads(header_raw)

        self._validate_header(header)

        # Resolve the key and check algorithm consistency
        kid = header.get("kid", "default")
        policy = self._keys.get(kid)
        if policy is None:
            raise JWTAlgorithmError(f"unknown key id {kid!r}")

        alg = header.get("alg", "")
        if alg != policy.algorithm:
            raise JWTAlgorithmError(
                f"token uses algorithm {alg!r} but key {kid!r} "
                f"expects {policy.algorithm!r} — possible algorithm confusion attack"
            )

        # Verify signature based on algorithm type
        group = ALGORITHM_GROUP.get(alg)
        signing_input = f"{header_b64}.{payload_b64}"
        signature = _b64decode(sig_b64)

        if group == "asymmetric":
            self._verify_rsa_signature(signing_input, signature, policy)
        elif group == "symmetric":
            self._verify_hmac_signature(signing_input, signature, policy)

        return json.loads(_b64decode(payload_b64))

    def _validate_header(self, header: Mapping[str, Any]) -> None:
        """Validate the JWT header before verification."""
        alg = header.get("alg", "")

        # Reject "none" algorithm
        if alg in DISALLOWED_ALGORITHMS:
            raise JWTAlgorithmError("unsigned JWTs (alg=none) are not accepted")

        # Reject algorithms not in our registry
        if alg not in ALGORITHM_GROUP:
            raise JWTAlgorithmError(f"algorithm {alg!r} is not in the allowed registry")

    def _verify_rsa_signature(
        self,
        signing_input: str,
        signature: bytes,
        policy: KeyPolicy,
    ) -> None:
        """Verify an RSA-based signature.

        In production, use ``cryptography`` library for RSA verification.
        This implementation demonstrates the algorithm confusion guard
        pattern and validates that the signature verification path is
        reached with the correct algorithm.
        """
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        public_key = serialization.load_pem_public_key(
            policy.public_key_pem.encode("utf-8")
        )

        hash_alg = {
            "RS256": hashes.SHA256(),
            "RS384": hashes.SHA384(),
            "RS512": hashes.SHA512(),
        }[policy.algorithm]

        try:
            public_key.verify(
                signature,
                signing_input.encode("utf-8"),
                asym_padding.PKCS1v15(),
                hash_alg,
            )
        except Exception as exc:
            raise JWTAlgorithmError(f"RSA signature verification failed: {exc}") from exc

    def _verify_hmac_signature(
        self,
        signing_input: str,
        signature: bytes,
        policy: KeyPolicy,
    ) -> None:
        """Verify an HMAC-based signature using constant-time comparison."""
        hash_fn = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }[policy.algorithm]

        expected = hmac.new(
            policy.secret,
            signing_input.encode("utf-8"),
            hash_fn,
        ).digest()

        if not hmac.compare_digest(signature, expected):
            raise JWTAlgorithmError("HMAC signature verification failed")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _b64decode(data: str) -> bytes:
    """Decode a URL-safe base64 string with padding recovery."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Convenience: create a token for testing
# ---------------------------------------------------------------------------

def _create_test_token(
    payload: dict[str, Any],
    key_policy: KeyPolicy,
    *,
    override_alg: str | None = None,
) -> str:
    """Create a JWT for testing purposes."""
    header = {"typ": "JWT", "alg": override_alg or key_policy.algorithm, "kid": key_policy.kid}
    header_b64 = _b64encode(json.dumps(header).encode("utf-8"))
    payload_b64 = _b64encode(json.dumps(payload).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"

    group = ALGORITHM_GROUP.get(key_policy.algorithm)
    if group == "asymmetric":
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        private_key = serialization.load_pem_private_key(
            key_policy.public_key_pem.encode("utf-8").replace(
                b"PUBLIC", b"PRIVATE"
            ),
            password=None,
        )
        hash_alg = {
            "RS256": hashes.SHA256(),
            "RS384": hashes.SHA384(),
            "RS512": hashes.SHA512(),
        }[key_policy.algorithm]
        sig = private_key.sign(
            signing_input.encode("utf-8"),
            asym_padding.PKCS1v15(),
            hash_alg,
        )
    elif group == "symmetric":
        hash_fn = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }[key_policy.algorithm]
        sig = hmac.new(
            key_policy.secret,
            signing_input.encode("utf-8"),
            hash_fn,
        ).digest()
    else:
        raise JWTAlgorithmError(f"unknown algorithm group {group!r}")

    return f"{signing_input}.{_b64encode(sig)}"