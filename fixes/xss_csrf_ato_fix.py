"""
Fix: Full Chain — XSS → CSRF → Account Takeover
=================================================
Issue #343 — A chained attack where an attacker exploits Cross-Site
Scripting (XSS) to bypass CSRF protections, leading to full account
takeover. The attack chain:

1. XSS: Attacker injects malicious script into a page (stored or reflected)
2. CSRF bypass: The injected script makes authenticated requests on behalf
   of the victim, bypassing CSRF tokens by reading them from the DOM
3. Account Takeover: The script changes the victim's email/password

This fix provides defense-in-depth for each stage of the chain:
1. XSS prevention: Context-aware output encoding and CSP headers
2. CSRF hardening: Double-submit cookie pattern + SameSite=Strict
3. Account change protection: Re-authentication for sensitive operations
"""

from __future__ import annotations

import html
import hmac
import json
import os
import re
import secrets
import time
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

CSRF_SECRET = os.environ.get("CSRF_SECRET", secrets.token_hex(32))
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_TOKEN_EXPIRY = 3600  # 1 hour

# Sensitive actions that require re-authentication
SENSITIVE_ACTIONS = frozenset({
    "change_email",
    "change_password",
    "delete_account",
    "transfer_funds",
    "update_2fa",
    "export_data",
})


# ═══════════════════════════════════════════════════════════════════
# Custom Error
# ═══════════════════════════════════════════════════════════════════


class XSSProtectionError(ValueError):
    """Raised when XSS-related security check fails."""


class CSRFProtectionError(PermissionError):
    """Raised when CSRF validation fails."""


class AccountTakeoverProtectionError(PermissionError):
    """Raised when sensitive action re-authentication is required."""


# ═══════════════════════════════════════════════════════════════════
# PART 1: XSS PREVENTION
# ═══════════════════════════════════════════════════════════════════


# HTML context encoding
def encode_html(text: str) -> str:
    """Encode text for safe insertion into HTML body context.

    Args:
        text: Raw user input.

    Returns:
        HTML-encoded string safe for body context.
    """
    return html.escape(str(text), quote=True)


def encode_html_attribute(text: str) -> str:
    """Encode text for safe insertion into HTML attributes.

    Handles attribute-specific escaping beyond basic HTML encoding.

    Args:
        text: Raw user input for attribute value.

    Returns:
        Attribute-safe string.
    """
    # First do basic HTML escape
    escaped = html.escape(str(text), quote=True)
    # Additional attribute-specific escapes
    escaped = escaped.replace("`", "&#96;")
    return escaped


def encode_javascript(text: str) -> str:
    """Encode text for safe insertion into JavaScript string context.

    Args:
        text: Raw user input for JS string.

    Returns:
        JavaScript-safe string literal.
    """
    sanitized = json.dumps(str(text), ensure_ascii=False)
    # Remove the surrounding quotes that json.dumps adds
    return sanitized[1:-1]


def encode_url(text: str) -> str:
    """Encode text for safe insertion into URL parameter values.

    Args:
        text: Raw user input for URL parameter.

    Returns:
        URL-encoded string.
    """
    from urllib.parse import quote
    return quote(str(text), safe="")


# XSS Sanitization (for rich content / HTML)
def sanitize_html(html_content: str) -> str:
    """Remove dangerous HTML/XSS vectors from rich content.

    Strips script tags, event handlers, javascript: URLs,
    and other XSS vectors while preserving safe HTML.

    Args:
        html_content: Input HTML that may contain XSS.

    Returns:
        Sanitized HTML safe for rendering.
    """
    sanitized = str(html_content)

    # Remove script tags and their content
    sanitized = re.sub(
        r'<script[^>]*>.*?</script>',
        '',
        sanitized,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Remove event handlers (onclick, onload, onerror, etc.)
    sanitized = re.sub(
        r'\son\w+\s*=\s*["\']?[^"\'>\s]*["\']?',
        ' data-sanitized',
        sanitized,
        flags=re.IGNORECASE,
    )

    # Remove javascript: protocol in URLs
    sanitized = re.sub(
        r'javascript\s*:\s*',
        'javascript-removed:',
        sanitized,
        flags=re.IGNORECASE,
    )

    # Remove data: URLs in dangerous contexts
    sanitized = re.sub(
        r'data\s*:\s*text/html',
        'data-removed:text/html',
        sanitized,
        flags=re.IGNORECASE,
    )

    # Remove <object>, <embed>, <applet> tags
    for tag in ['object', 'embed', 'applet', 'iframe', 'frame']:
        sanitized = re.sub(
            rf'<{tag}[^>]*>.*?</{tag}>',
            '',
            sanitized,
            flags=re.IGNORECASE | re.DOTALL,
        )

    return sanitized


# CSP Header Builder
def build_csp_header(nonce: Optional[str] = None) -> str:
    """Build a Content-Security-Policy header string.

    Args:
        nonce: Optional CSP nonce for inline scripts.

    Returns:
        CSP policy string.
    """
    policies = [
        "default-src 'self'",
        "script-src 'self'" + (f" 'nonce-{nonce}'" if nonce else ""),
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
    ]
    return "; ".join(policies)


def generate_nonce() -> str:
    """Generate a CSP nonce for inline scripts."""
    return secrets.token_hex(16)


# ═══════════════════════════════════════════════════════════════════
# PART 2: CSRF PREVENTION (Double-Submit Cookie Pattern)
# ═══════════════════════════════════════════════════════════════════


def generate_csrf_token() -> tuple[str, str]:
    """Generate a CSRF token pair (cookie value, signed token).

    Uses HMAC-SHA256 for the signed version.

    Returns:
        (cookie_value, header_token) — cookie_value to set as cookie,
        header_token to include in forms/XHR headers.
    """
    cookie_value = secrets.token_hex(32)
    expiry = int(time.time()) + CSRF_TOKEN_EXPIRY
    message = f"{cookie_value}:{expiry}"
    signature = hmac.new(
        CSRF_SECRET.encode(),
        message.encode(),
        "sha256",
    ).hexdigest()
    header_token = f"{cookie_value}:{expiry}:{signature}"
    return cookie_value, header_token


def validate_csrf_token(
    cookie_value: str,
    header_token: str,
) -> bool:
    """Validate a CSRF token from double-submit cookie.

    Args:
        cookie_value: CSRF token from cookie.
        header_token: CSRF token from header/body.

    Returns:
        True if the token is valid.

    Raises:
        CSRFProtectionError: If validation fails.
    """
    if not cookie_value or not header_token:
        raise CSRFProtectionError("Missing CSRF token")

    parts = header_token.split(":")
    if len(parts) != 3:
        raise CSRFProtectionError("Invalid CSRF token format")

    token_value, expiry_str, signature = parts

    # Check token matches cookie
    if not hmac.compare_digest(token_value, cookie_value):
        raise CSRFProtectionError("CSRF token mismatch")

    # Check expiry
    try:
        expiry = int(expiry_str)
    except ValueError:
        raise CSRFProtectionError("Invalid CSRF token expiry")

    if time.time() > expiry:
        raise CSRFProtectionError("CSRF token expired")

    # Verify signature
    message = f"{cookie_value}:{expiry}"
    expected_sig = hmac.new(
        CSRF_SECRET.encode(),
        message.encode(),
        "sha256",
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        raise CSRFProtectionError("CSRF token signature invalid")

    return True


# ═══════════════════════════════════════════════════════════════════
# PART 3: ACCOUNT TAKEOVER PREVENTION
# ═══════════════════════════════════════════════════════════════════


def require_reauthentication(
    action: str,
    session_age: int,
    is_confirmed: bool = False,
) -> None:
    """Require re-authentication for sensitive account actions.

    Args:
        action: The sensitive action being performed.
        session_age: Seconds since last authentication.
        is_confirmed: Whether user has re-confirmed their password.

    Raises:
        AccountTakeoverProtectionError: If re-auth is required.
    """
    if action not in SENSITIVE_ACTIONS:
        return  # Non-sensitive actions don't need re-auth

    if not is_confirmed:
        raise AccountTakeoverProtectionError(
            f"Sensitive action '{action}' requires password confirmation. "
            f"Please re-enter your password."
        )

    # Require fresh authentication (within last 5 minutes)
    MAX_SESSION_AGE = 300  # 5 minutes
    if session_age > MAX_SESSION_AGE:
        raise AccountTakeoverProtectionError(
            f"Session too old for sensitive action '{action}'. "
            f"Please re-authenticate."
        )


def rate_limit_sensitive_actions(
    action: str,
    user_id: str,
    action_log: dict[str, list[float]],
    max_attempts: int = 3,
    window_seconds: int = 3600,
) -> None:
    """Rate-limit sensitive account actions to prevent automated takeover.

    Args:
        action: The action being attempted.
        user_id: User identifier.
        action_log: Dictionary tracking action timestamps per user.
        max_attempts: Max allowed actions per window.
        window_seconds: Time window in seconds.

    Raises:
        AccountTakeoverProtectionError: If rate limit exceeded.
    """
    if action not in SENSITIVE_ACTIONS:
        return

    now = time.time()
    key = f"{user_id}:{action}"

    if key not in action_log:
        action_log[key] = []

    # Filter out old entries
    action_log[key] = [
        t for t in action_log[key] if now - t < window_seconds
    ]

    if len(action_log[key]) >= max_attempts:
        retry_after = int(
            window_seconds - (now - action_log[key][0])
        )
        raise AccountTakeoverProtectionError(
            f"Rate limit exceeded for '{action}'. "
            f"Try again in {retry_after} seconds."
        )

    action_log[key].append(now)


# ═══════════════════════════════════════════════════════════════════
# Unified Security Middleware
# ═══════════════════════════════════════════════════════════════════


def validate_request(
    method: str,
    path: str,
    body: str,
    cookies: dict[str, str],
    headers: dict[str, str],
    session: dict[str, any],
) -> list[str]:
    """Validate a web request against XSS/CSRF/ATO protections.

    Args:
        method: HTTP method.
        path: Request path.
        body: Request body (for POST/PUT).
        cookies: Request cookies dict.
        headers: Request headers dict.
        session: Session data dict.

    Returns:
        List of validation warnings (empty = all checks passed).
    """
    warnings: list[str] = []

    # XSS: Check request body for XSS patterns
    if method in ("POST", "PUT", "PATCH") and body:
        if XSS_LOOKUP_PATTERN.search(body):
            warnings.append("XSS patterns detected in request body")

    # CSRF: Validate token for state-changing requests
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        cookie_token = cookies.get(CSRF_COOKIE_NAME, "")
        header_token = headers.get(CSRF_HEADER_NAME, "")
        try:
            validate_csrf_token(cookie_token, header_token)
        except CSRFProtectionError as exc:
            warnings.append(f"CSRF validation failed: {exc}")

    # Account Takeover: Check for sensitive actions
    for action in SENSITIVE_ACTIONS:
        if action in path or action in body:
            try:
                session_age = int(time.time()) - session.get(
                    "auth_time", 0
                )
                require_reauthentication(
                    action, session_age, session.get("confirmed", False)
                )
            except AccountTakeoverProtectionError as exc:
                warnings.append(f"ATO protection: {exc}")

    return warnings


# Pre-compiled XSS pattern
XSS_LOOKUP_PATTERN = re.compile(
    r"(<script[^>]*>|javascript\s*:|on\w+\s*=|"
    r"<embed[^>]*>|<object[^>]*>|<iframe[^>]*>|"
    r"expression\s*\(|url\s*\(|data\s*:\s*text/html)",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════
# Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable chain):
#
#   # 1. No XSS encoding → attacker injects <script>
#   # 2. No CSRF validation → script can make state-changing requests
#   # 3. No re-auth check → script changes email/password silently
#
#   @app.route("/profile")
#   def profile():
#       return f"Hello {request.args['name']}"  # ❌ XSS
#
#   @app.route("/change_email", methods=["POST"])
#   def change_email():
#       user.email = request.form["email"]  # ❌ No CSRF, no re-auth

# A F T E R  (fixed):
#
#   from fixes.xss_csrf_ato_fix import encode_html, validate_csrf_token
#   from fixes.xss_csrf_ato_fix import require_reauthentication
#
#   @app.route("/profile")
#   def profile():
#       return f"Hello {encode_html(request.args['name'])}"  # ✅
#
#   @app.route("/change_email", methods=["POST"])
#   def change_email():
#       validate_csrf_token(cookie_token, header_token)  # ✅
#       require_reauthentication("change_email", session_age, confirmed)  # ✅
#       user.email = request.form["email"]


# ═══════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════


def _test() -> None:
    # ── XSS: HTML encoding ──
    encoded = encode_html("<script>alert('xss')</script>")
    assert "<script>" not in encoded
    assert "&lt;script&gt;" in encoded
    print("  ✓ HTML context encoding")

    # ── XSS: Attribute encoding ──
    encoded = encode_html_attribute('" onclick="evil()')
    # The quotes are escaped to &quot; so the attribute boundary is safe
    # 'onclick' appears as text but cannot execute
    assert '&quot;' in encoded
    assert '" onclick="' not in encoded  # No raw attribute-breaking quote
    print("  ✓ HTML attribute encoding")

    # ── XSS: URL encoding ──
    encoded = encode_url("hello world?foo=bar")
    assert " " not in encoded
    print("  ✓ URL encoding")

    # ── XSS: sanitize_html ──
    sanitized = sanitize_html(
        "<p>Hello</p><script>alert(1)</script>"
    )
    assert "<script>" not in sanitized
    assert "<p>Hello</p>" in sanitized
    print("  ✓ HTML sanitization")

    # ── CSP header ──
    csp = build_csp_header(nonce="abc123")
    assert "default-src 'self'" in csp
    assert "'nonce-abc123'" in csp
    assert "frame-ancestors 'none'" in csp
    print("  ✓ CSP header generation")

    # ── CSRF: token generation and validation ──
    cookie_val, header_token = generate_csrf_token()
    assert validate_csrf_token(cookie_val, header_token)
    print("  ✓ CSRF token generation and validation")

    # ── CSRF: reject invalid token ──
    try:
        validate_csrf_token(cookie_val, "invalid:0:bad")
        assert False, "Invalid CSRF token was accepted!"
    except CSRFProtectionError:
        pass
    print("  ✓ CSRF invalid token rejected")

    # ── CSRF: reject expired token ──
    expired_parts = header_token.split(":")
    expired_token = f"{expired_parts[0]}:0:{expired_parts[2]}"
    try:
        validate_csrf_token(cookie_val, expired_token)
        assert False, "Expired CSRF token was accepted!"
    except CSRFProtectionError:
        pass
    print("  ✓ CSRF expired token rejected")

    # ── ATO: requires re-auth for sensitive actions ──
    try:
        require_reauthentication(
            "change_email", session_age=9999, is_confirmed=False
        )
        assert False, "Missing re-auth was accepted!"
    except AccountTakeoverProtectionError:
        pass
    print("  ✓ ATO: re-authentication required")

    # ── ATO: rate limiting ──
    action_log: dict = {}
    for i in range(3):
        rate_limit_sensitive_actions(
            "change_password", "user1", action_log, max_attempts=3
        )
    try:
        rate_limit_sensitive_actions(
            "change_password", "user1", action_log, max_attempts=3
        )
        assert False, "Rate limit was not enforced!"
    except AccountTakeoverProtectionError:
        pass
    print("  ✓ ATO: rate limiting")

    # ── Unified validation ──
    cookie_val, header_token = generate_csrf_token()
    warnings = validate_request(
        method="POST",
        path="/change_email",
        body="<script>alert(1)</script>",
        cookies={CSRF_COOKIE_NAME: cookie_val},
        headers={CSRF_HEADER_NAME: header_token},
        session={"auth_time": int(time.time()), "confirmed": True},
    )
    # Should have XSS warning (body has script tag)
    assert any("XSS" in w for w in warnings)
    print("  ✓ Unified validation")

    print("\n✅ XSS → CSRF → ATO fix: ALL TESTS PASSED")


if __name__ == "__main__":
    _test()
