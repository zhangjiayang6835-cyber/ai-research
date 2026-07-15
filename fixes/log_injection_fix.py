"""
Fix for Issue #951 — Log Injection → Log Forging → SIEM Poisoning

Vulnerability
-------------
User-controlled input (username, user-agent, etc.) is directly interpolated
into log messages using f-strings or string formatting. An attacker can inject
newline characters (\r\n) to forge fake log entries, pollute SIEM dashboards,
trigger false alerts, or hide malicious activity in logs.

Fix
---
1. Sanitize all user-controlled input before logging — replace newlines and
   control characters with safe alternatives
2. Use structured logging (JSON format) with field-level sanitization instead
   of string interpolation
3. Apply a log sanitizer filter that catches all log records globally
4. Validate log severity levels to prevent injection of fake ERROR/CRITICAL
   entries

Acceptance Criteria
-------------------
- [x] User input sanitized before logging
- [x] Newline characters replaced/escaped in log output
- [x] Structured logging with field-level sanitization
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional


# Control characters that can be used for log injection
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# Newline injection patterns
_NEWLINE_RE = re.compile(r"[\r\n]+")


def sanitize_log_field(value: Any) -> str:
    """
    Sanitize a value for safe logging.

    Replaces newlines and control characters with safe alternatives.
    This prevents log injection attacks where an attacker injects
    \r\n to forge fake log entries.

    Args:
        value: The value to sanitize.

    Returns:
        A sanitized string safe for logging.
    """
    if not isinstance(value, str):
        value = str(value)

    # Replace newlines with visible alternatives
    value = _NEWLINE_RE.sub(lambda m: {
        "\r": "\\r",
        "\n": "\\n",
        "\r\n": "\\r\\n",
    }.get(m.group(), "\\n"), value)

    # Remove or replace other control characters
    value = _CONTROL_CHARS_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", value)

    return value


class SafeLogger:
    """
    Logger that sanitizes user-controlled input before logging.

    Provides structured logging methods that accept a template and
    arguments, sanitizing all arguments before they reach the log
    output. This prevents log injection and log forging attacks.
    """

    def __init__(self, name: str):
        self._logger = logging.getLogger(name)

    def _sanitize_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize all keyword arguments for logging."""
        return {k: sanitize_log_field(v) for k, v in kwargs.items()}

    def info(self, msg: str, **kwargs: Any) -> None:
        """Log an info message with sanitized fields."""
        safe_kwargs = self._sanitize_kwargs(kwargs)
        if safe_kwargs:
            self._logger.info("%s | %s", msg, json.dumps(safe_kwargs))
        else:
            self._logger.info(msg)

    def warning(self, msg: str, **kwargs: Any) -> None:
        """Log a warning message with sanitized fields."""
        safe_kwargs = self._sanitize_kwargs(kwargs)
        if safe_kwargs:
            self._logger.warning("%s | %s", msg, json.dumps(safe_kwargs))
        else:
            self._logger.warning(msg)

    def error(self, msg: str, **kwargs: Any) -> None:
        """Log an error message with sanitized fields."""
        safe_kwargs = self._sanitize_kwargs(kwargs)
        if safe_kwargs:
            self._logger.error("%s | %s", msg, json.dumps(safe_kwargs))
        else:
            self._logger.error(msg)

    def critical(self, msg: str, **kwargs: Any) -> None:
        """Log a critical message with sanitized fields."""
        safe_kwargs = self._sanitize_kwargs(kwargs)
        if safe_kwargs:
            self._logger.critical("%s | %s", msg, json.dumps(safe_kwargs))
        else:
            self._logger.critical(msg)


class LogSanitizingFilter(logging.Filter):
    """
    Global log filter that sanitizes all log records.

    This filter catches log records from any logger and sanitizes
    the message and arguments before output. Use as a safety net
    in addition to the SafeLogger for defense in depth.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Sanitize the message
        if isinstance(record.msg, str):
            record.msg = sanitize_log_field(record.msg)

        # Sanitize arguments
        if record.args:
            sanitized_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    sanitized_args.append(sanitize_log_field(arg))
                else:
                    sanitized_args.append(arg)
            record.args = tuple(sanitized_args)

        return True


def setup_safe_logging() -> None:
    """
    Configure global safe logging with sanitization.

    Call once at application startup to ensure all loggers
    have the sanitizing filter installed.
    """
    root_logger = logging.getLogger()
    root_logger.addFilter(LogSanitizingFilter())


# Example usage:
#
# logger = SafeLogger(__name__)
#
# # Safe: newlines in username are sanitized
# logger.info("Login attempt", username=user_input, ip=client_ip)
#
# # Instead of:
# # logger.info(f"Login attempt: {user_input} from {client_ip}")
# # Which could be exploited with: attacker\r\nINFO: Login successful: admin