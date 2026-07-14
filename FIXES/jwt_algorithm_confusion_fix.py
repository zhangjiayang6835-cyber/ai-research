"""
Fix for Issue #735 — JWT Algorithm Confusion (RS256→HS256 Downgrade)

Vulnerability
-------------
The JWT library is configured to accept tokens signed with RS256 (asymmetric,
using a public/private key pair). However, the server does not validate the
`alg` header before verification. An attacker can change the algorithm from
RS256 to HS256 (symmetric HMAC) and sign the token using the RSA public key
(which is publicly known). The server's HS256 verification uses the same
public key as the HMAC secret, allowing the attacker to forge valid tokens.

Fix
---
1. Explicitly validate the JWT `alg` header against an allowlist
2. Reject HS256/HMAC algorithms when expecting RS256/ECDSA
3. Use key type validation to ensure asymmetric keys aren't used for HMAC
4. Implement a custom JWT decoder that enforces algorithm constraints

Acceptance Criteria
-------------------
- [x] Algorithm header validated against allowlist
- [x] HS256 rejected when RS256 is expected
- [x] Key type mismatch prevented
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Dict, FrozenSet, List, Optional, Tuple


# Allowed JWT algorithms for this application
ALLOWED_ALGORITHMS: FrozenSet[str] = frozenset({"RS256", "RS384", "RS512"})

# HMAC-based algorithms that must be rejected when asymmetric is expected
FORBIDDEN_HMAC_ALGORITHMS: FrozenSet[str] = frozenset({"HS256", "HS384", "HS512"})

# The "none" algorithm (no signature) is always forbidden
FORBIDDEN_NONE_ALGORITHMS: FrozenSet[str] = frozenset({"none", "None", "NONE"})


class JWTAlgorithmConfusionError(Exception):
    """Raised when JWT algorithm validation fails."""


def _base64url_decode(payload: str) -> bytes:
    """Decode a base64url-encoded string with padding."""
    remainder = len(payload) % 4
    if remainder:
        payload += "=" * (4 - remainder)
    return base64.urlsafe_b64decode(payload)


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt_parts(token: str) -> Tuple[dict, dict, bytes]:
    """
    Decode a JWT into its header, payload, and signature parts.

    Args:
        token: The JWT string.

    Returns:
        Tuple of (header_dict, payload_dict, signature_bytes).

    Raises:
        JWTAlgorithmConfusionError: If the token format is invalid.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTAlgorithmConfusionError("JWT must have 3 parts")

    try:
        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
        signature = _base64url_decode(parts[2])
    except (json.JSONDecodeError, ValueError, Exception) as e:
        raise JWTAlgorithmConfusionError(f"Invalid JWT encoding: {e}")

    return header, payload, signature


def validate_algorithm(header: dict) -> str:
    """
    Validate the JWT algorithm header against the allowlist.

    Rejects:
    - Missing algorithm
    - "none" algorithm (no signature → trivial forgery)
    - HMAC algorithms (HS256/HS384/HS512) when asymmetric is expected
    - Unknown or unsupported algorithms

    Args:
        header: The decoded JWT header dict.

    Returns:
        The validated algorithm string.

    Raises:
        JWTAlgorithmConfusionError: If the algorithm is not allowed.
    """
    alg = header.get("alg", "")

    if not alg:
        raise JWTAlgorithmConfusionError("Missing JWT algorithm")

    if alg in FORBIDDEN_NONE_ALGORITHMS:
        raise JWTAlgorithmConfusionError(
            f"Forbidden algorithm: '{alg}' — no-signature tokens are rejected"
        )

    if alg in FORBIDDEN_HMAC_ALGORITHMS:
        raise JWTAlgorithmConfusionError(
            f"Forbidden algorithm: '{alg}' — "
            f"HMAC symmetric algorithms are rejected when "
            f"asymmetric (RSA/ECDSA) is expected"
        )

    if alg not in ALLOWED_ALGORITHMS:
        raise JWTAlgorithmConfusionError(
            f"Unsupported algorithm: '{alg}'. "
            f"Allowed: {', '.join(sorted(ALLOWED_ALGORITHMS))}"
        )

    return alg


def verify_jwt(
    token: str,
    public_key_pem: str,
    allowed_algs: Optional[FrozenSet[str]] = None,
) -> dict:
    """
    Securely verify a JWT token with algorithm confusion protection.

    Args:
        token: The JWT string.
        public_key_pem: The RSA public key in PEM format.
        allowed_algs: Optional override for allowed algorithms.

    Returns:
        The decoded payload dict if verification succeeds.

    Raises:
        JWTAlgorithmConfusionError: If algorithm validation or signature
            verification fails.
    """
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.backends import default_backend

    algs = allowed_algs or ALLOWED_ALGORITHMS

    # Step 1: Decode and validate algorithm
    header, payload, signature = decode_jwt_parts(token)
    alg = validate_algorithm(header)

    # Step 2: Reconstruct the signing input
    parts = token.rsplit(".", 1)
    signing_input = parts[0].encode()

    # Step 3: Load the public key
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )
    except Exception as e:
        raise JWTAlgorithmConfusionError(f"Failed to load public key: {e}")

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise JWTAlgorithmConfusionError("Key must be an RSA public key")

    # Step 4: Verify the signature using the public key
    try:
        if alg == "RS256":
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        elif alg == "RS384":
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA384(),
            )
        elif alg == "RS512":
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA512(),
            )
        else:
            raise JWTAlgorithmConfusionError(f"Unsupported algorithm: {alg}")
    except Exception as e:
        raise JWTAlgorithmConfusionError(f"Signature verification failed: {e}")

    return payload