"""Tests for SSO Federation cross-tenant account takeover prevention."""

import hashlib
import hmac
import time
from base64 import urlsafe_b64encode
from json import dumps

from sso_federation import (
    SSOSession,
    issue_sso_token,
    validate_sso_token,
    _create_jwt,
    _used_jti,
    _session_store,
)


def setup_function():
    _used_jti.clear()
    _session_store.clear()


# ---------------------------------------------------------------------------
# JWT header hardening: none algorithm, weak secrets, and kid injection
# ---------------------------------------------------------------------------

def test_none_algorithm_token_rejected():
    payload = {
        "iss": "https://idp.example.com",
        "aud": "app.example.com",
        "sub": "admin",
        "tid": "tenant-alpha",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "jti": "none-alg-jti-0001",
    }
    header = urlsafe_b64encode(dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = urlsafe_b64encode(dumps(payload).encode()).decode().rstrip("=")
    token = f"{header}.{body}."

    result = validate_sso_token(token, "tenant-alpha")

    assert isinstance(result, dict)
    assert result.get("error") == "invalid_token_signature"


def test_weak_jwt_secret_refused():
    payload = {
        "iss": "https://idp.example.com",
        "aud": "app.example.com",
        "sub": "user-1",
        "tid": "tenant-alpha",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "jti": "weak-secret-jti-001",
    }

    try:
        _create_jwt(payload, "secret")
    except ValueError as exc:
        assert "at least 32 bytes" in str(exc)
    else:
        raise AssertionError("weak JWT secrets must be rejected")


def test_kid_path_traversal_token_rejected():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-1",
        override_claims={"jti": "kid-traversal-jti-001"},
    )
    header_b64, body_b64, _ = token.split(".")
    evil_header = urlsafe_b64encode(
        dumps({"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd"}).encode()
    ).decode().rstrip("=")
    signature = hmac.new(
        "shared-idp-demo-jwt-key-32-bytes-minimum".encode(),
        f"{evil_header}.{body_b64}".encode(),
        hashlib.sha256,
    ).hexdigest()
    evil_token = f"{evil_header}.{body_b64}.{signature}"

    result = validate_sso_token(evil_token, "tenant-alpha")

    assert isinstance(result, dict)
    assert result.get("error") == "invalid_token_signature"


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_valid_token_alpha_tenant():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-42",
        email="alice@alpha.example.com",
        name="Alice",
    )
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, SSOSession), f"Expected SSOSession, got {result}"
    assert result.tenant_id == "tenant-alpha"
    assert result.user_id == "user-42"
    assert result.email == "alice@alpha.example.com"
    assert result.name == "Alice"


def test_valid_token_beta_tenant():
    token = issue_sso_token(
        tenant_id="tenant-beta",
        user_id="user-99",
        email="bob@beta.example.com",
        name="Bob",
    )
    result = validate_sso_token(token, "tenant-beta")
    assert isinstance(result, SSOSession), f"Expected SSOSession, got {result}"
    assert result.tenant_id == "tenant-beta"
    assert result.user_id == "user-99"
    assert result.email == "bob@beta.example.com"


# ---------------------------------------------------------------------------
# Cross-tenant attack — the core vulnerability being fixed
# ---------------------------------------------------------------------------

def test_cross_tenant_token_rejected():
    """An attacker obtains a valid token for tenant-alpha and tries to
    use it against tenant-beta.  The fix MUST reject this."""
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="attacker",
        email="attacker@evil.com",
        name="Attacker",
    )
    result = validate_sso_token(token, "tenant-beta")
    assert isinstance(result, dict), "Expected error dict for cross-tenant attack"
    assert result.get("error") == "tenant_mismatch", f"Unexpected error: {result}"


def test_reverse_cross_tenant_rejected():
    """Same attack in the opposite direction."""
    token = issue_sso_token(
        tenant_id="tenant-beta",
        user_id="attacker",
        email="attacker@evil.com",
        name="Attacker",
    )
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "tenant_mismatch"


def test_spoofed_tid_in_token_rejected():
    """Attacker modifies tid in a tenant-alpha token, then uses tenant-alpha
    key to re-sign.  Since both tenants share the same IdP, signature passes,
    but the tid in the signed payload was set to tenant-alpha — the override
    is stripped because issue_sso_token signs after applying overrides.
    """
    # The attack: present a tenant-alpha token at tenant-beta
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="attacker",
        override_claims={"tid": "tenant-beta"},
    )
    # Even though tid override was passed, the token was signed with
    # tenant-alpha config and validates against tenant-alpha.
    # When validated against tenant-beta, audience/issuer match (shared IdP),
    # but the tid in the token is actually "tenant-beta" because we overrode it.
    # This demonstrates why the tid check is critical — in a shared-IdP setup,
    # the only thing preventing cross-tenant access is the tid claim.
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, dict)
    # The token's tid is "tenant-beta" (overridden), expected is "tenant-alpha"
    assert result.get("error") == "tenant_mismatch"


# ---------------------------------------------------------------------------
# Issuer validation
# ---------------------------------------------------------------------------

def test_wrong_issuer_rejected():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-1",
        override_claims={"iss": "https://evil-idp.example.com"},
    )
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "issuer_mismatch"


# ---------------------------------------------------------------------------
# Audience validation
# ---------------------------------------------------------------------------

def test_wrong_audience_rejected():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-1",
        override_claims={"aud": "some-other-app"},
    )
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "audience_mismatch"


# ---------------------------------------------------------------------------
# Token expiry
# ---------------------------------------------------------------------------

def test_expired_token_rejected():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-1",
        override_claims={"exp": int(time.time()) - 60},
    )
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "token_expired"


# ---------------------------------------------------------------------------
# Token freshness (iat)
# ---------------------------------------------------------------------------

def test_old_token_rejected():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-1",
        override_claims={"iat": int(time.time()) - 3600},
    )
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "token_too_old"


# ---------------------------------------------------------------------------
# Missing required claims
# ---------------------------------------------------------------------------

def test_missing_tid_rejected():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-1",
        override_claims={"tid": None},
    )
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, dict)
    # tid claim exists but is None -> will be caught by tenant_mismatch
    assert result.get("error") in ("missing_required_claims", "tenant_mismatch")


def test_tid_claim_removed_rejected():
    """Remove tid entirely from payload — must fail."""
    from sso_federation import _create_jwt
    import time
    payload = {
        "iss": "https://idp.example.com",
        "aud": "sp-alpha-app",
        "sub": "user-1",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "jti": "test-jti-removed-tid",
    }
    token = _create_jwt(payload, "shared-idp-demo-jwt-key-32-bytes-minimum", "shared-idp-v1")
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "missing_required_claims"


def test_missing_jti_rejected():
    payload = {
        "iss": "https://idp.example.com",
        "aud": "app.example.com",
        "sub": "user-1",
        "tid": "tenant-alpha",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
    }
    token = _create_jwt(payload, "shared-idp-demo-jwt-key-32-bytes-minimum", "shared-idp-v1")
    result = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "missing_required_claims"


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

def test_replay_attack_rejected():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-42",
        email="alice@alpha.example.com",
        name="Alice",
    )
    # First use — should succeed
    result1 = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result1, SSOSession)

    # Second use with same jti — must be rejected
    result2 = validate_sso_token(token, "tenant-alpha")
    assert isinstance(result2, dict)
    assert result2.get("error") == "token_replayed", f"Expected replayed, got {result2}"


# ---------------------------------------------------------------------------
# Token signature tampering
# ---------------------------------------------------------------------------

def test_tampered_token_rejected():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-1",
    )
    parts = token.split(".")
    tampered_body = urlsafe_b64encode(
        dumps(
            {
                "iss": "https://idp.alpha.example.com",
                "aud": "sp-alpha-app",
                "sub": "admin",
                "tid": "tenant-alpha",
                "exp": int(time.time()) + 300,
                "iat": int(time.time()),
                "jti": "evil-jti-000000",
            }
        ).encode()
    ).decode().rstrip("=")
    tampered = f"{parts[0]}.{tampered_body}.{parts[2]}"
    result = validate_sso_token(tampered, "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "invalid_token_signature"


# ---------------------------------------------------------------------------
# Unknown tenant
# ---------------------------------------------------------------------------

def test_unknown_tenant_rejected():
    token = issue_sso_token(
        tenant_id="tenant-alpha",
        user_id="user-1",
    )
    result = validate_sso_token(token, "nonexistent-tenant")
    assert isinstance(result, dict)
    assert result.get("error") == "unknown_tenant"


# ---------------------------------------------------------------------------
# Invalid token format
# ---------------------------------------------------------------------------

def test_malformed_token_rejected():
    result = validate_sso_token("not-a-jwt", "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "invalid_token_signature"


def test_empty_token_rejected():
    result = validate_sso_token("", "tenant-alpha")
    assert isinstance(result, dict)
    assert result.get("error") == "invalid_token_signature"
