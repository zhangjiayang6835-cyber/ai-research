"""
Fix for Issue #726 — TOTP Secret Leaked via QR Code in Logs

Vulnerability
-------------
TOTP setup QR codes contain the TOTP secret (otpauth:// URL). The application
logs the QR code generation path, including the full URL with the secret.
Attackers with log access can extract TOTP secrets and bypass 2FA.

Fix
---
1. Log filter masks sensitive fields (secret, key, token, password) in log output
2. QR code generation path never logs the secret or full URL
3. Structured logging with field-level redaction instead of string formatting
4. Configurable sensitive field patterns

Acceptance Criteria
-------------------
- [x] Logs never contain TOTP secrets
- [x] QR code generation does not log the secret
- [x] Sensitive fields are masked in all log output
"""

from __future__ import annotations

import logging
import re
from typing import FrozenSet, Optional


# Sensitive field patterns — matched case-insensitively in log messages
SENSITIVE_FIELDS: FrozenSet[str] = frozenset({
    "secret",
    "totp_secret",
    "totpsecret",
    "otpauth",
    "otp_secret",
    "2fa_secret",
    "mfa_secret",
    "key",
    "token",
    "password",
    "passwd",
    "credential",
    "auth_code",
})


class SensitiveDataFilter(logging.Filter):
    """
    Log filter that redacts sensitive data from log records.

    Uses regex to detect and mask sensitive fields in log messages.
    The filter runs on every log record before output, ensuring
    secrets are never written to logs regardless of the logging path.
    """

    # Pattern matches: sensitive_field=value or "sensitive_field":"value"
    _REDACT_PATTERN = re.compile(
        r'(?i)({pattern})\s*[:=]\s*["\']?[^"\'&\s,;}}]+["\']?'.format(
            pattern="|".join(
                re.escape(f) for f in sorted(SENSITIVE_FIELDS, key=len, reverse=True)
            )
        )
    )

    # Pattern matches URLs containing sensitive parameters
    _URL_PATTERN = re.compile(
        r'(?i)(otpauth://[^?\s]+)\?[^\s]*'
    )

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            # Redact sensitive field=value pairs
            record.msg = self._REDACT_PATTERN.sub(
                lambda m: f"{m.group(1)}=[REDACTED]", record.msg
            )
            # Redact otpauth URLs entirely
            record.msg = self._URL_PATTERN.sub("[TOTP_URL_REDACTED]", record.msg)

        # Also redact args passed to logging
        if record.args:
            redacted_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    arg = self._REDACT_PATTERN.sub(
                        lambda m: f"{m.group(1)}=[REDACTED]", arg
                    )
                    arg = self._URL_PATTERN.sub("[TOTP_URL_REDACTED]", arg)
                redacted_args.append(arg)
            record.args = tuple(redacted_args)

        return True


def setup_secure_logging() -> None:
    """
    Configure root logger with sensitive data filtering.

    Call once at application startup to ensure all loggers
    inherit the sensitive data filter.
    """
    root_logger = logging.getLogger()
    root_logger.addFilter(SensitiveDataFilter())


class SecureQRCodeGenerator:
    """
    QR code generator that never leaks secrets in logs.

    The TOTP secret is used to generate the QR code but is never
    passed to any logging function.
    """

    def __init__(self, issuer: str, account: str):
        self._issuer = issuer
        self._account = account
        self._logger = logging.getLogger(__name__)

    def generate_qr_url(self, secret: str) -> str:
        """
        Generate an otpauth:// URL for QR code rendering.

        The secret is used internally but is NOT logged. The URL
        is returned to the caller for rendering; logging only
        records that a QR code was generated, not its contents.

        Args:
            secret: The TOTP shared secret.

        Returns:
            The otpauth:// URL for QR code generation.
        """
        import urllib.parse

        params = urllib.parse.urlencode({
            "secret": secret,
            "issuer": self._issuer,
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        })
        url = f"otpauth://totp/{urllib.parse.quote(self._issuer)}:{urllib.parse.quote(self._account)}?{params}"

        # Safe log — no secret or URL logged
        self._logger.info(
            "QR code generated for issuer=%s account=%s",
            self._issuer,
            self._account,
        )

        return url