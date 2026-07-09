"""Secure SSO Federation module preventing cross-tenant account takeover.

This module implements federated single sign-on with strict tenant isolation:
  - Validates issuer (iss) to confirm token origin
  - Validates audience (aud) to confirm intended recipient
  - Validates tenant_id (tid) to prevent cross-tenant token reuse
  - Uses per-tenant public keys for signature verification
  - Prevents replay attacks via jti (JWT ID) tracking
  - Strictly validates all required claims before session creation
  - Enforces a hardcoded algorithm whitelist to prevent algorithm-confusion
    downgrade attacks (e.g., RS256 -> HS256)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TENANT_CONFIG: dict[str, dict[str, Any]] = {
    "tenant-alpha": {
        "issuer": "https://idp.example.com",
        "audience": "app.example.com",
        "public_key": "shared-idp-key",
    },
    "tenant-beta": {
        "issuer": "https://idp.example.com",
        "audience": "app.example.com",
        "public_key": "shared-idp-key",
    },
}

# For tenants with per-tenant audience isolation:
TENANT_AUDIENCE_ISOLATED_CONFIG: dict[str, dict[str, Any]] = {
    "tenant-alpha": {
        "issuer": "https://idp.example.com",
        "audience": "sp-alpha-app",
        "public_key": "shared-idp-key",
    },
    "tenant-beta": {
        "issuer": "https://idp.example.com",
        "audience": "sp-beta-app",
        "public_key": "shared-idp-key",
    },
}

TOKEN_MAX_AGE_SECONDS = 300  # 5 minutes
REQUIRED_CLAIMS = {"iss", "aud", "sub", "exp", "iat", "tid", "jti"}

# ---------------------------------------------------------------------------
# Algorithm whitelist — prevents JWT algorithm-confusion attacks.
#
# The server MUST hardcode exactly which algorithm(s) it accepts and MUST
# NEVER derive the verification algorithm from the (attacker-controlled)
# token header. Without this check, an attacker can take a token meant to
# be verified with an asymmetric algorithm (e.g. RS256, using a public key)
# and re-sign it with `alg: HS256`, using the known public key as the HMAC
# secret. A verifier that blindly trusts the header's `alg` would then
# "successfully" verify the forged token.
#
# This demo library only implements HMAC-SHA256 signing/verification, so
# EXPECTED_ALG pins the single algorithm this service accepts, and
# ALLOWED_ALGORITHMS is the explicit whitelist checked against the token
# header before any cryptographic verification is attempted.
# ---------------------------------------------------------------------------
EXPECTED_ALG = "HS256"
ALLOWED_ALGORITHMS = frozenset({"HS256"})

# In production, use Redis or a database for replay protection.
_used_jti: set[str] = set()
_session_store: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

@dataclass
class FederationConfig:
    issuer: str
    audience: str
    public_key: str


@dataclass
class SSOSession:
    user_id: str
    tenant_id: str
    email: str
    name: str
    jti: str
    issued_at: float
    expires_at: float


# ---------------------------------------------------------------------------
# Helper — simple HMAC-SHA256 JWT for demonstration
# In production, use a library like PyJWT or python-jose with RS256/ES256.
# ---------------------------------------------------------------------------

def _b64encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    padded = data + "=" * (4 - len(data) % 4)
    return urlsafe_b64decode(padded)


def _create_jwt(payload: dict, secret: str) -> str:
    header = _b64encode(json.dumps({"alg": EXPECTED_ALG, "typ": "JWT"}).encode())
    body = _b64encode(json.dumps(payload, sort_keys=True).encode())
    signature = hmac.new(
        secret.encode(), f"{header}.{body}".encode(), hashlib.sha256
    ).hexdigest()
    return f"{header}.{body}.{signature}"


def _verify_jwt(token: str, secret: str, expected_alg: str = EXPECTED_ALG) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, body_b64, sig = parts

    # --- Algorithm confusion defense ---------------------------------
    # Parse and validate the `alg` header BEFORE performing any signature
    # verification. The algorithm used for verification must never be
    # chosen based on attacker-controlled input.
    try:
        header = json.loads(_b64decode(header_b64))
    except (json.JSONDecodeError, Exception):
        return None

    if not isinstance(header, dict):
        return None

    alg = header.get("alg")

    # Reject anything outside the explicit server-side whitelist.
    if alg not in ALLOWED_ALGORITHMS:
        return None

    # Reject algorithm downgrade/confusion: the token's alg must match the
    # algorithm this verification call expects (e.g. reject a token signed
    # with HS256 when the caller expects RS256, and vice versa).
    if alg != expected_alg:
        return None
    # --------------------------------------------------------------------

    expected_sig = hmac.new(
        secret.encode(), f"{header_b64}.{body_b64}".encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        return json.loads(_b64decode(body_b64))
    except (json.JSONDecodeError, Exception):
        return None


# ---------------------------------------------------------------------------
# Tenant configuration lookup
# ---------------------------------------------------------------------------

def get_tenant_config(tenant_id: str) -> FederationConfig | None:
    cfg = TENANT_CONFIG.get(tenant_id)
    if cfg is None:
        return None
    return FederationConfig(
        issuer=cfg["issuer"],
        audience=cfg["audience"],
        public_key=cfg["public_key"],
    )


# ---------------------------------------------------------------------------
# Core validation — the fix for cross-tenant account takeover
# ---------------------------------------------------------------------------

def validate_sso_token(
    token: str,
    expected_tenant_id: str,
) -> SSOSession | dict:
    """Validate a federated SSO token with strict tenant-scoped checks.

    Returns an ``SSOSession`` on success or a ``dict`` error on failure.

    Security checks performed in order:
    0. Algorithm whitelist check (alg header) — prevents algorithm
       confusion / downgrade attacks (e.g. RS256 -> HS256)
    1. Token signature verification
    2. Required claims presence (iss, aud, sub, exp, iat, tid, jti)
    3. Token expiry (exp)
    4. Issuer match (iss)
    5. Audience match (aud)
    6. Tenant ID match (tid) — the cross-tenant check
    7. JTI replay prevention
    8. Token age (iat) freshness
    """
    # 1. Look up tenant configuration
    tenant_cfg = get_tenant_config(expected_tenant_id)
    if tenant_cfg is None:
        return {
            "success": False,
            "error": "unknown_tenant",
            "tenant_id": expected_tenant_id,
        }

    # 2. Verify token signature (alg header is checked against the
    #    hardcoded whitelist and expected algorithm inside _verify_jwt,
    #    BEFORE any cryptographic verification happens).
    payload = _verify_jwt(token, tenant_cfg.public_key, expected_alg=EXPECTED_ALG)
    if payload is None:
        return {"success": False, "error": "invalid_token_signature"}

    # 3. Check all required claims exist
    missing = REQUIRED_CLAIMS - set(payload.keys())
    if missing:
        return {
            "success": False,
            "error": "missing_required_claims",
            "missing_claims": sorted(missing),
        }

    now = time.time()

    # 4. Validate expiry
    exp = payload["exp"]
    if not isinstance(exp, (int, float)) or exp < now:
        return {"success": False, "error": "token_expired"}

    # 5. Validate issued-at freshness
    iat = payload["iat"]
    if not isinstance(iat, (int, float)):
        return {"success": False, "error": "invalid_iat"}
    if iat > now + 5:
        return {"success": False, "error": "token_from_future"}
    if now - iat > TOKEN_MAX_AGE_SECONDS:
        return {"success": False, "error": "token_too_old"}

    # 6. Validate issuer (must match the expected tenant's IdP)
    if payload["iss"] != tenant_cfg.issuer:
        return {
            "success": False,
            "error": "issuer_mismatch",
            "expected_issuer": tenant_cfg.issuer,
            "received_issuer": payload["iss"],
        }

    # 7. Validate audience (must match the expected tenant's SP)
    if payload["aud"] != tenant_cfg.audience:
        return {
            "success": False,
            "error": "audience_mismatch",
            "expected_audience": tenant_cfg.audience,
            "received_audience": payload["aud"],
        }

    # 8. CRITICAL: Validate tenant ID — this prevents cross-tenant token reuse
    token_tenant_id = payload["tid"]
    if token_tenant_id != expected_tenant_id:
        return {
            "success": False,
            "error": "tenant_mismatch",
            "message": (
                "The token was issued for a different tenant. "
                "Cross-tenant authentication is forbidden."
            ),
            "expected_tenant": expected_tenant_id,
            "token_tenant": token_tenant_id,
        }

    # 9. Replay protection: check jti uniqueness
    jti = payload["jti"]
    if not isinstance(jti, str) or len(jti) < 8:
        return {"success": False, "error": "invalid_jti"}
    if jti in _used_jti:
        return {
            "success": False,
            "error": "token_replayed",
            "detail": "This token has already been used (jti collision).",
        }
    _used_jti.add(jti)

    # 10. All checks passed — create a session
    session = SSOSession(
        user_id=payload["sub"],
        tenant_id=token_tenant_id,
        email=payload.get("email", ""),
        name=payload.get("name", ""),
        jti=jti,
        issued_at=iat,
        expires_at=exp,
    )

    # Store session for downstream use
    _session_store[session.jti] = {
        "user_id": session.user_id,
        "tenant_id": session.tenant_id,
        "email": session.email,
        "name": session.name,
    }

    return session


# ---------------------------------------------------------------------------
# IdP helper — for testing / demo only (not part of the fix)
# ---------------------------------------------------------------------------

def issue_sso_token(
    tenant_id: str,
    user_id: str,
    email: str = "",
    name: str = "",
    override_claims: dict[str, Any] | None = None,
) -> str:
    """Issue a signed SSO token for the given tenant.

    This simulates an Identity Provider. In production, this runs at the IdP,
    not in the service being protected.
    """
    cfg = get_tenant_config(tenant_id)
    if cfg is None:
        raise ValueError(f"Unknown tenant: {tenant_id}")

    now = int(time.time())
    jti = hashlib.sha256(f"{tenant_id}:{user_id}:{now}:{os.urandom(8).hex()}".encode()).hexdigest()[:24]

    payload = {
        "iss": cfg.issuer,
        "aud": cfg.audience,
        "sub": user_id,
        "tid": tenant_id,
        "email": email,
        "name": name,
        "iat": now,
        "exp": now + TOKEN_MAX_AGE_SECONDS,
        "jti": jti,
    }

    if override_claims:
        payload.update(override_claims)

    return _create_jwt(payload, cfg.public_key)


import os
