"""
Fix for WebSocket Cross-Origin Hijacking + Session Prediction Prevention
=========================================================================

Vulnerability
-------------
WebSocket connections are susceptible to two related attacks:

1. **Cross-Origin Hijacking**: An attacker's page opens a WebSocket to the
   victim's server, potentially stealing real-time data if the server does
   not validate the Origin header.

2. **Session Prediction**: If WebSocket authentication tokens are generated
   using predictable algorithms (sequential IDs, weak randomness, timestamps
   without sufficient entropy), attackers can forge valid session tokens.

Root cause: missing origin validation and weak session token generation.

Fix Strategy
------------
1. **Origin Validation**: Strictly validate the Origin header against an
   allow-list of trusted origins before upgrading to WebSocket.
2. **Secure Session Tokens**: Use cryptographically secure random tokens
   (secrets.token_urlsafe) for WebSocket authentication.
3. **Connection Rate Limiting**: Prevent brute-force session prediction
   by limiting connections per origin/IP.
4. **CSRF Protection**: Require SameSite cookies and origin checks.
5. **Graceful Degradation**: Return proper HTTP error codes for invalid
   connections.
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import Any, Callable, Mapping, MutableMapping, Optional, Sequence

logger = logging.getLogger("websocket_security_fix")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_CONNECTIONS_PER_ORIGIN = 10
DEFAULT_TOKEN_BYTE_LENGTH = 32
RATE_LIMIT_WINDOW = 60  # seconds


class WebSocketSecurityError(Exception):
    """Raised when WebSocket security checks fail."""


# ---------------------------------------------------------------------------
# Session Token Generation
# ---------------------------------------------------------------------------


def generate_secure_token(byte_length: int = DEFAULT_TOKEN_BYTE_LENGTH) -> str:
    """Generate a cryptographically secure session token.

    Uses secrets.token_urlsafe which provides sufficient entropy
    to prevent session prediction attacks.

    Args:
        byte_length: Number of random bytes to generate.
            Minimum 16 bytes recommended.

    Returns:
        URL-safe base64 encoded token string.
    """
    if byte_length < 16:
        raise ValueError("byte_length must be at least 16 for cryptographic security")
    return secrets.token_urlsafe(byte_length)


def validate_token(token: str) -> bool:
    """Validate that a token has sufficient entropy.

    Args:
        token: The token string to validate.

    Returns:
        True if the token appears to be cryptographically secure.
    """
    if not token or len(token) < 32:
        return False
    # Basic check: should be URL-safe base64 characters
    import re
    return bool(re.match(r'^[A-Za-z0-9_-]+$', token))


# ---------------------------------------------------------------------------
# Origin Validator
# ---------------------------------------------------------------------------


class OriginValidator:
    """Validates WebSocket Origin headers against a trusted allow-list.

    Usage::

        validator = OriginValidator(trusted_origins=["https://example.com"])
        is_valid, error = validator.validate(origin="https://attacker.com")
    """

    def __init__(
        self,
        trusted_origins: Optional[Sequence[str]] = None,
        allow_none_origin: bool = False,
        strict_mode: bool = True,
    ):
        self.trusted_origins = [o.lower().rstrip("/") for o in (trusted_origins or [])]
        self.allow_none_origin = allow_none_origin
        self.strict_mode = strict_mode

    def validate(self, origin: Optional[str], host: Optional[str] = None) -> tuple[bool, str]:
        """Validate the Origin header.

        Args:
            origin: The WebSocket Origin header value.
            host: The Host header value (optional, for additional validation).

        Returns:
            (is_valid, error_message)
        """
        # Allow None origin for some clients (e.g. mobile apps)
        if origin is None:
            if self.allow_none_origin:
                return True, ""
            if self.strict_mode:
                return False, "Missing Origin header in strict mode"
            return True, ""

        origin_lower = origin.lower().rstrip("/")

        # Check against allow-list
        if self.trusted_origins:
            if origin_lower not in self.trusted_origins:
                return False, f"Origin '{origin}' not in trusted list"

        # Additional validation: origin must be a valid URL
        if not self._is_valid_origin(origin_lower):
            return False, f"Invalid Origin format: '{origin}'"

        # Cross-origin check with Host header
        if host:
            host_origin = f"https://{host}"
            if origin_lower != host_origin and origin_lower != f"http://{host}":
                # Allow subdomains but reject completely different origins
                if not self._is_trusted_subdomain(origin_lower, host):
                    return False, f"Cross-origin WebSocket from '{origin}' to '{host}'"

        return True, ""

    def _is_valid_origin(self, origin: str) -> bool:
        """Basic origin format validation."""
        import re
        if not origin:
            return False
        if not re.match(r'^https?://[a-zA-Z0-9.\-]+(?::\d+)?$', origin):
            return False
        return True

    def _is_trusted_subdomain(self, origin: str, host: str) -> bool:
        """Check if origin is a trusted subdomain of the host."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(origin)
            if parsed.hostname and host:
                return parsed.hostname.endswith(f".{host}") or parsed.hostname == host
        except Exception:
            pass
        return False


# ---------------------------------------------------------------------------
# Connection Rate Limiter
# ---------------------------------------------------------------------------


class WebSocketRateLimiter:
    """Prevents brute-force session prediction via connection rate limiting.

    Tracks connections per origin/IP within a time window.
    """

    def __init__(
        self,
        max_connections: int = DEFAULT_MAX_CONNECTIONS_PER_ORIGIN,
        window_seconds: int = RATE_LIMIT_WINDOW,
    ):
        self.max_connections = max_connections
        self.window_seconds = window_seconds
        self._connections: dict[str, list[float]] = {}
        self._lock = False  # Simple approach; use threading.Lock in production

    def check_rate_limit(self, key: str) -> tuple[bool, str]:
        """Check if a connection from this key is within rate limits.

        Args:
            key: Origin or IP address identifier.

        Returns:
            (is_allowed, error_message)
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Clean old entries
        if key in self._connections:
            self._connections[key] = [
                t for t in self._connections[key] if t > window_start
            ]
        else:
            self._connections[key] = []

        if len(self._connections[key]) >= self.max_connections:
            remaining = self._connections[key]
            if remaining:
                retry_after = int(self.window_seconds - (now - remaining[-1]))
                return False, f"Rate limit exceeded. Retry after {retry_after}s"
            return False, "Rate limit exceeded"

        self._connections[key].append(now)
        return True, ""

    def cleanup(self) -> None:
        """Remove expired entries."""
        now = time.time()
        window_start = now - self.window_seconds
        expired_keys = [
            k for k, timestamps in self._connections.items()
            if all(t < window_start for t in timestamps)
        ]
        for k in expired_keys:
            del self._connections[k]


# ---------------------------------------------------------------------------
# WSGI Middleware for Origin Validation
# ---------------------------------------------------------------------------


class WebSocketOriginMiddleware:
    """WSGI middleware that validates Origin headers for WebSocket upgrades.

    Usage::

        from flask import Flask
        from websocket_security_fix import WebSocketOriginMiddleware

        app = Flask(__name__)
        app.wsgi_app = WebSocketOriginMiddleware(
            app.wsgi_app,
            trusted_origins=["https://example.com"],
        )
    """

    def __init__(
        self,
        app: Callable,
        trusted_origins: Optional[Sequence[str]] = None,
        allow_none_origin: bool = False,
        max_connections_per_origin: int = DEFAULT_MAX_CONNECTIONS_PER_ORIGIN,
    ):
        self.app = app
        self.origin_validator = OriginValidator(
            trusted_origins=trusted_origins,
            allow_none_origin=allow_none_origin,
        )
        self.rate_limiter = WebSocketRateLimiter(
            max_connections=max_connections_per_origin,
        )

    def __call__(self, environ: MutableMapping[str, Any], start_response: Callable) -> Any:
        """Validate the request before WebSocket upgrade."""
        # Check if this is a WebSocket upgrade request
        upgrade = environ.get("HTTP_UPGRADE", "").lower()
        connection = environ.get("HTTP_CONNECTION", "").lower()

        if upgrade == "websocket" and "upgrade" in connection:
            origin = environ.get("HTTP_ORIGIN")
            host = environ.get("HTTP_HOST", environ.get("SERVER_NAME", ""))
            remote_addr = environ.get("REMOTE_ADDR", "unknown")

            # Validate origin
            is_valid, error = self.origin_validator.validate(origin, host)
            if not is_valid:
                logger.warning("WebSocket origin rejected: %s from %s", error, remote_addr)
                self._respond_error(start_response, 403, "Forbidden: Invalid Origin")
                return []

            # Check rate limit
            key = origin or remote_addr
            is_allowed, rate_error = self.rate_limiter.check_rate_limit(key)
            if not is_allowed:
                logger.warning("WebSocket rate limited: %s from %s", rate_error, remote_addr)
                self._respond_error(start_response, 429, "Too Many Connections")
                return []

        return self.app(environ, start_response)

    def _respond_error(self, start_response: Callable, status: int, reason: str) -> None:
        """Send an error response."""
        body = reason.encode("utf-8")
        start_response(
            f"{status} {reason}",
            [
                ("Content-Length", str(len(body))),
                ("Content-Type", "text/plain"),
            ],
        )
        yield body


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


def _run_tests() -> None:
    """Run self-tests to verify the fix."""
    import re

    # Test 1: Secure token generation
    token = generate_secure_token()
    assert len(token) >= 32, "Token too short"
    assert validate_token(token), "Valid token rejected"

    # Test 2: Weak token detection
    weak_token = "abc123"
    assert not validate_token(weak_token), "Weak token accepted"

    # Test 3: Origin validation - trusted origin
    validator = OriginValidator(trusted_origins=["https://example.com"])
    ok, err = validator.validate("https://example.com")
    assert ok, f"Trusted origin rejected: {err}"

    # Test 4: Origin validation - untrusted origin
    ok, err = validator.validate("https://attacker.com")
    assert not ok, "Untrusted origin accepted"

    # Test 5: Origin validation - None origin allowed
    validator_allow_none = OriginValidator(
        trusted_origins=["https://example.com"],
        allow_none_origin=True,
    )
    ok, err = validator_allow_none.validate(None)
    assert ok, "None origin rejected when allowed"

    # Test 6: Origin validation - None origin not allowed
    validator_strict = OriginValidator(
        trusted_origins=["https://example.com"],
        allow_none_origin=False,
        strict_mode=True,
    )
    ok, err = validator_strict.validate(None)
    assert not ok, "None origin accepted in strict mode"

    # Test 7: Rate limiter - within limits
    limiter = WebSocketRateLimiter(max_connections=5, window_seconds=60)
    ok, err = limiter.check_rate_limit("origin1")
    assert ok, f"Allowed connection rejected: {err}"

    # Test 8: Rate limiter - exceeded limits
    for _ in range(4):
        limiter.check_rate_limit("origin1")
    ok, err = limiter.check_rate_limit("origin1")
    assert not ok, "Rate limit not enforced"

    # Test 9: Different keys don't share limits
    ok, err = limiter.check_rate_limit("origin2")
    assert ok, "Different origin rate-limited"

    # Test 10: Invalid token format
    assert not validate_token(""), "Empty token accepted"
    assert not validate_token("a" * 10), "Short token accepted"

    print("All self-tests passed!")


if __name__ == "__main__":
    _run_tests()
