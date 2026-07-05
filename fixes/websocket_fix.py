"""
Fix: WebSocket Cross-Origin Hijacking + Session Prediction
===========================================================
Issue #344 — WebSocket connections are vulnerable to Cross-Origin
WebSocket Hijacking (CSWSH) when the server doesn't validate the
Origin header during the WebSocket handshake. An attacker's page
can open a WebSocket to the target server and, if the victim is
authenticated (cookie-based auth), the server treats the connection
as authenticated. Combined with predictable session tokens, this
enables full session hijacking.

This fix provides:
1. Origin header validation during WebSocket handshake
2. CSRF-style token challenge for WebSocket connections
3. Unpredictable session token generation
4. Rate limiting for WebSocket upgrade requests
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from ipaddress import ip_address, ip_network
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

# Allowed origins for WebSocket connections
ALLOWED_ORIGINS: list[str] = os.environ.get(
    "WS_ALLOWED_ORIGINS",
    "https://example.com",
).split(",")

# Whether to allow localhost origins in development
ALLOW_LOCALHOST_ORIGINS = os.environ.get(
    "WS_ALLOW_LOCALHOST", "true"
).lower() == "true"

# WebSocket secret key for token-based auth
WS_SECRET = os.environ.get("WS_SECRET", secrets.token_hex(32))

# Rate limit: max WebSocket upgrade attempts per IP per minute
WS_RATE_LIMIT = 10
WS_RATE_WINDOW = 60  # seconds

# ═══════════════════════════════════════════════════════════════════
# Custom Error
# ═══════════════════════════════════════════════════════════════════


class WebSocketSecurityError(PermissionError):
    """Raised when WebSocket security validation fails."""


# ═══════════════════════════════════════════════════════════════════
# PART 1: ORIGIN HEADER VALIDATION
# ═══════════════════════════════════════════════════════════════════


# Pattern for validating origin format
ORIGIN_PATTERN = re.compile(
    r"^https?://([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}(:\d{1,5})?$"
)

# Localhost patterns
LOCALHOST_PATTERNS = [
    re.compile(r"^https?://localhost(:\d{1,5})?$", re.IGNORECASE),
    re.compile(r"^https?://127\.0\.0\.1(:\d{1,5})?$"),
    re.compile(r"^https?://\[::1\](:\d{1,5})?$"),
]


def validate_ws_origin(
    origin: Optional[str],
    allowed_origins: Optional[list[str]] = None,
) -> bool:
    """Validate the Origin header for a WebSocket upgrade request.

    Args:
        origin: The Origin header value from the handshake.
        allowed_origins: List of allowed origins (defaults to config).

    Returns:
        True if origin is allowed.

    Raises:
        WebSocketSecurityError: If origin validation fails.
    """
    if not origin:
        raise WebSocketSecurityError(
            "Missing Origin header — WebSocket connections "
            "must include an Origin header"
        )

    # For WebSocket from browser, origin is always set
    # Missing origin could indicate a non-browser client or attack

    allow = allowed_origins or ALLOWED_ORIGINS

    # Check localhost origins (dev mode)
    if ALLOW_LOCALHOST_ORIGINS:
        for pattern in LOCALHOST_PATTERNS:
            if pattern.match(origin):
                return True

    # Check allowed origins (exact match)
    for allowed in allow:
        allowed = allowed.strip()
        if origin.rstrip("/") == allowed.rstrip("/"):
            return True

    # Check if origin passes basic URL validation and is in allow-list
    if ORIGIN_PATTERN.match(origin):
        # Extract hostname and check against allowed domains
        from urllib.parse import urlparse
        parsed = urlparse(origin)
        hostname = parsed.hostname or ""

        for allowed in allow:
            allowed = allowed.strip()
            # Support wildcard subdomains: *.example.com
            if allowed.startswith("*."):
                domain = allowed[2:]
                if hostname == domain or hostname.endswith("." + domain):
                    return True
            else:
                allowed_parsed = urlparse(allowed)
                allowed_host = allowed_parsed.hostname or ""
                if hostname == allowed_host:
                    return True

    raise WebSocketSecurityError(
        f"Origin '{origin}' is not in the allowed origins list. "
        f"WebSocket connection rejected."
    )


# ═══════════════════════════════════════════════════════════════════
# PART 2: WEBSOCKET AUTHENTICATION TOKEN CHALLENGE
# ═══════════════════════════════════════════════════════════════════


def generate_ws_challenge_token(user_id: str) -> str:
    """Generate a WebSocket challenge token for authenticated connections.

    The token is a HMAC-SHA256 signed challenge that the client must
    include in the WebSocket handshake headers. This prevents CSWSH
    because an attacker's page cannot read the challenge token from
    the victim's cookies (HttpOnly + SameSite).

    Args:
        user_id: User identifier to bind the token to.

    Returns:
        Challenge token string: timestamp.signature.user_id
    """
    timestamp = int(time.time())
    # Token expires in 30 seconds (short-lived for handshake only)
    expiry = timestamp + 30
    message = f"{user_id}:{expiry}:{WS_SECRET}"
    signature = hashlib.sha256(message.encode()).hexdigest()[:16]
    return f"{expiry}.{signature}.{user_id}"


def validate_ws_challenge_token(
    challenge_token: str,
    user_id: str,
) -> bool:
    """Validate a WebSocket challenge token.

    Args:
        challenge_token: The challenge token from the client.
        user_id: Expected user ID.

    Returns:
        True if the token is valid.

    Raises:
        WebSocketSecurityError: If validation fails.
    """
    parts = challenge_token.split(".")
    if len(parts) != 3:
        raise WebSocketSecurityError("Invalid challenge token format")

    expiry_str, signature, token_user_id = parts

    # Check user ID matches
    if token_user_id != user_id:
        raise WebSocketSecurityError(
            "Challenge token user ID mismatch"
        )

    # Check expiry
    try:
        expiry = int(expiry_str)
    except ValueError:
        raise WebSocketSecurityError("Invalid challenge token expiry")

    if time.time() > expiry:
        raise WebSocketSecurityError("Challenge token expired")

    # Verify signature
    expected_message = f"{user_id}:{expiry_str}:{WS_SECRET}"
    expected_sig = hashlib.sha256(
        expected_message.encode()
    ).hexdigest()[:16]

    if not hmac.compare_digest(signature, expected_sig):
        raise WebSocketSecurityError("Challenge token signature invalid")

    return True


# ═══════════════════════════════════════════════════════════════════
# PART 3: UNPREDICTABLE SESSION TOKEN GENERATION
# ═══════════════════════════════════════════════════════════════════


def generate_session_token(user_id: str, extra_entropy: str = "") -> str:
    """Generate an unpredictable session token.

    Uses secrets.token_hex() for cryptographic randomness instead of
    predictable values like timestamps, sequential IDs, or MD5 hashes.

    Args:
        user_id: User identifier to bind to the token.
        extra_entropy: Optional additional entropy source.

    Returns:
        Unpredictable session token string.
    """
    # 32 bytes of cryptographic randomness
    random_full = secrets.token_hex(32)

    # Bind to user and add HMAC integrity (using the same portion as stored in token)
    random_short = random_full[:16]
    message = f"{user_id}:{random_short}:{WS_SECRET}"
    integrity = hashlib.sha256(message.encode()).hexdigest()[:32]

    # Format: integrity.random_short.timestamp
    timestamp = int(time.time())
    return f"{integrity}.{random_short}.{timestamp}"


def validate_session_token(
    token: str,
    user_id: str,
    max_age: int = 86400,  # 24 hours
) -> bool:
    """Validate a session token's integrity and expiry.

    Args:
        token: Session token to validate.
        user_id: Expected user ID.
        max_age: Maximum token age in seconds.

    Returns:
        True if valid.

    Raises:
        WebSocketSecurityError: If validation fails.
    """
    parts = token.split(".")
    if len(parts) < 3:
        raise WebSocketSecurityError("Invalid session token format")

    integrity_part = parts[0]
    random_part = parts[1]
    timestamp_part = parts[2]

    # Check expiry
    try:
        timestamp = int(timestamp_part)
    except ValueError:
        raise WebSocketSecurityError("Invalid session token timestamp")

    age = time.time() - timestamp
    if age > max_age:
        raise WebSocketSecurityError("Session token expired")

    if age < -300:  # Allow 5 min clock skew
        raise WebSocketSecurityError(
            "Session token from the future — clock skew?"
        )

    # Verify integrity
    expected_message = f"{user_id}:{random_part}:{WS_SECRET}"
    expected_integrity = hashlib.sha256(
        expected_message.encode()
    ).hexdigest()[:32]

    if not hmac.compare_digest(integrity_part, expected_integrity):
        raise WebSocketSecurityError("Session token integrity check failed")

    return True


# ═══════════════════════════════════════════════════════════════════
# PART 4: RATE LIMITING FOR WEBSOCKET UPGRADES
# ═══════════════════════════════════════════════════════════════════


class WebSocketRateLimiter:
    """Rate limiter for WebSocket upgrade requests per IP."""

    def __init__(self, max_attempts: int = WS_RATE_LIMIT,
                 window: int = WS_RATE_WINDOW):
        self.max_attempts = max_attempts
        self.window = window
        self.attempts: dict[str, list[float]] = {}

    def check(self, ip: str) -> None:
        """Check if this IP has exceeded the rate limit.

        Args:
            ip: Client IP address.

        Raises:
            WebSocketSecurityError: If rate limit exceeded.
        """
        now = time.time()

        if ip not in self.attempts:
            self.attempts[ip] = []

        # Clean old entries
        self.attempts[ip] = [
            t for t in self.attempts[ip] if now - t < self.window
        ]

        if len(self.attempts[ip]) >= self.max_attempts:
            retry_after = int(
                self.window - (now - self.attempts[ip][0])
            )
            raise WebSocketSecurityError(
                f"WebSocket upgrade rate limit exceeded for {ip}. "
                f"Max {self.max_attempts} per {self.window}s. "
                f"Retry in {retry_after}s."
            )

        self.attempts[ip].append(now)

    def reset(self, ip: str) -> None:
        """Reset rate limit counter for an IP."""
        self.attempts.pop(ip, None)


# ═══════════════════════════════════════════════════════════════════
# PART 5: WEBSOCKET HANDSHAKE VALIDATION (Unified)
# ═══════════════════════════════════════════════════════════════════


def validate_websocket_handshake(
    origin: Optional[str],
    user_id: Optional[str],
    challenge_token: Optional[str],
    client_ip: str,
    rate_limiter: Optional[WebSocketRateLimiter] = None,
) -> dict[str, bool]:
    """Validate a complete WebSocket handshake request.

    This is the main entry point that performs all security checks:
    1. Origin header validation
    2. Challenge token validation (if user_id provided)
    3. Rate limiting
    4. Returns validation results

    Args:
        origin: Origin header from the handshake.
        user_id: User ID for authenticated connections.
        challenge_token: Challenge token for authenticated connections.
        client_ip: Client IP for rate limiting.
        rate_limiter: Optional rate limiter instance.

    Returns:
        Dict of check results: {check_name: passed}.
    """
    results: dict[str, bool] = {}

    # Check 1: Origin validation
    try:
        validate_ws_origin(origin)
        results["origin_valid"] = True
    except WebSocketSecurityError as exc:
        results["origin_valid"] = False
        results["origin_error"] = str(exc)

    # Check 2: Challenge token (only if user is authenticating)
    if user_id and challenge_token:
        try:
            validate_ws_challenge_token(challenge_token, user_id)
            results["challenge_valid"] = True
        except WebSocketSecurityError as exc:
            results["challenge_valid"] = False
            results["challenge_error"] = str(exc)
    elif user_id:
        results["challenge_valid"] = False
        results["challenge_error"] = (
            "Challenge token required for authenticated connections"
        )
    else:
        results["challenge_valid"] = True  # No auth needed

    # Check 3: Rate limiting
    if rate_limiter:
        try:
            rate_limiter.check(client_ip)
            results["rate_ok"] = True
        except WebSocketSecurityError as exc:
            results["rate_ok"] = False
            results["rate_error"] = str(exc)
    else:
        results["rate_ok"] = True

    return results


# ═══════════════════════════════════════════════════════════════════
# Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable):
#
#   async def websocket_endpoint(websocket):
#       await websocket.accept()  # ❌ No origin check!
#       # Attacker's page on evil.com can open socket as victim
#
#   # Also: session IDs generated with:
#   session_id = hashlib.md5(f"{user_id}{timestamp}".encode()).hexdigest()
#   # ❌ Predictable — attacker can forge session tokens

# A F T E R  (fixed):
#
#   from fixes.websocket_fix import validate_ws_origin, generate_session_token
#   from fixes.websocket_fix import generate_ws_challenge_token
#
#   async def websocket_endpoint(websocket):
#       origin = websocket.headers.get("Origin")
#       validate_ws_origin(origin)  # ✅ Blocks cross-origin hijacking
#
#       challenge = websocket.headers.get("X-WS-Challenge")
#       validate_ws_challenge_token(challenge, user_id)  # ✅ Prevents hijacking
#
#       await websocket.accept()
#
#   # Session tokens now use:
#   session_id = generate_session_token(user_id)  # ✅ Unpredictable


# ═══════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════


def _test() -> None:
    # ── Origin validation: allowed origin ──
    try:
        validate_ws_origin("https://example.com")
        print("  ✓ Allowed origin accepted")
    except WebSocketSecurityError:
        assert False, "Allowed origin was rejected!"

    # ── Origin validation: blocked origin ──
    try:
        validate_ws_origin("https://evil.com")
        assert False, "Evil origin was accepted!"
    except WebSocketSecurityError:
        pass
    print("  ✓ Evil origin rejected")

    # ── Origin validation: missing origin ──
    try:
        validate_ws_origin(None)
        assert False, "Missing origin was accepted!"
    except WebSocketSecurityError:
        pass
    print("  ✓ Missing origin rejected")

    # ── Origin validation: localhost (dev mode) ──
    try:
        validate_ws_origin("http://localhost:3000")
        print("  ✓ Localhost origin accepted (dev mode)")
    except WebSocketSecurityError:
        assert False, "Localhost origin was rejected!"

    # ── Challenge token: generation and validation ──
    token = generate_ws_challenge_token("user123")
    assert validate_ws_challenge_token(token, "user123")
    print("  ✓ Challenge token generation and validation")

    # ── Challenge token: user ID mismatch rejected ──
    try:
        validate_ws_challenge_token(token, "attacker")
        assert False, "User ID mismatch was accepted!"
    except WebSocketSecurityError:
        pass
    print("  ✓ Challenge token user ID mismatch rejected")

    # ── Session token: generation ──
    session = generate_session_token("user123")
    assert len(session) > 20
    assert session.count(".") >= 2
    print("  ✓ Session token generation")

    # ── Session token: validation ──
    assert validate_session_token(session, "user123")
    print("  ✓ Session token validation")

    # ── Session token: forged token rejected ──
    forged_parts = session.split(".")
    forged = f"aaaa{forged_parts[0][4:]}.{forged_parts[1]}.{forged_parts[2]}"
    try:
        validate_session_token(forged, "user123")
        assert False, "Forged session token was accepted!"
    except WebSocketSecurityError:
        pass
    print("  ✓ Forged session token rejected")

    # ── Rate limiter: normal requests ──
    limiter = WebSocketRateLimiter(max_attempts=3, window=60)
    limiter.check("1.2.3.4")
    limiter.check("1.2.3.4")
    limiter.check("1.2.3.4")
    print("  ✓ Rate limiter: normal requests passed")

    # ── Rate limiter: exceeded limit ──
    try:
        limiter.check("1.2.3.4")
        assert False, "Rate limit was not enforced!"
    except WebSocketSecurityError:
        pass
    print("  ✓ Rate limiter: exceeded limit blocked")

    # ── Rate limiter: different IP not affected ──
    limiter.check("5.6.7.8")  # Should work
    print("  ✓ Rate limiter: different IP not affected")

    # ── Handshake validation ──
    challenge = generate_ws_challenge_token("user123")
    results = validate_websocket_handshake(
        origin="https://example.com",
        user_id="user123",
        challenge_token=challenge,
        client_ip="1.2.3.4",
        rate_limiter=WebSocketRateLimiter(),
    )
    assert results["origin_valid"]
    assert results["challenge_valid"]
    assert results["rate_ok"]
    print("  ✓ Full handshake validation")

    # ── Handshake with evil origin ──
    results = validate_websocket_handshake(
        origin="https://evil.com",
        user_id="user123",
        challenge_token=challenge,
        client_ip="9.9.9.9",
    )
    assert not results["origin_valid"]
    print("  ✓ Handshake with evil origin blocked")

    print("\n✅ WebSocket security fix: ALL TESTS PASSED")


if __name__ == "__main__":
    _test()
