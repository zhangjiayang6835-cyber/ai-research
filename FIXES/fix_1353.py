"""
Fix for Issue #1353 — TOTP Secret Leaked via QR Code in Logs
============================================================

Vulnerability
-------------
During 2FA (TOTP) setup the server builds an ``otpauth://`` provisioning URI
and renders it as a QR code for the user to scan. That URI embeds the raw
base32 TOTP shared secret::

    otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

The application logs the QR-code generation step (request tracing, debug logs,
access logs, exception dumps ...). Because the full URI — including
``secret=...`` — ends up in those logs, anyone with log access (SIEM, log
aggregator, on-call engineer, leaked backup) can read the secret and generate
valid TOTP codes forever, fully bypassing 2FA.

Fix
---
Two layers of defense:

1. ``SensitiveDataRedactor`` — a ``logging.Filter`` that scrubs ``otpauth://``
   URIs and ``secret=``/other sensitive ``key=value`` pairs from *every* log
   record (message and ``%`` args) before it is emitted. This is the safety net:
   even code that accidentally logs the URI cannot leak the secret. The secret
   is replaced *entirely* — no prefix characters are left behind.
2. ``SecureTOTPProvisioner`` — builds the provisioning URI for QR rendering but
   only ever logs non-sensitive metadata (issuer + account). The secret and the
   URI are returned to the caller for rendering and are never passed to a
   logging call.

Use ``redact()`` directly to sanitise any string (e.g. before writing to an
audit trail) without touching the logging framework.

Acceptance Criteria
-------------------
- [x] TOTP secret never appears in emitted log output
- [x] Full ``otpauth://`` URI is redacted from logs (message and args)
- [x] Secret is fully removed, not partially masked
- [x] QR/provisioning path logs only issuer + account, never the secret
"""

from __future__ import annotations

import logging
import re
from typing import Any, FrozenSet
from urllib.parse import quote

# Sensitive key=value / "key":"value" field names, matched case-insensitively.
SENSITIVE_FIELDS: FrozenSet[str] = frozenset(
    {
        "secret",
        "totp_secret",
        "otp_secret",
        "mfa_secret",
        "2fa_secret",
        "seed",
        "key",
        "token",
        "password",
        "passwd",
        "credential",
    }
)

_URI_REDACTED = "[OTPAUTH_URI_REDACTED]"
_VALUE_REDACTED = "[REDACTED]"

# A whole otpauth:// URI (path + query), stopping at whitespace/quotes/commas.
_OTPAUTH_URI_RE = re.compile(r"otpauth://[^\s\"'<>,;]+", re.IGNORECASE)

# key=value or key: value or "key":"value" — value stops at the usual delimiters.
_FIELD_RE = re.compile(
    r"(?i)(?P<key>{fields})(?P<sep>\s*[:=]\s*)(?P<q>[\"']?)[^\"'&\s,;}}]+(?P=q)".format(
        fields="|".join(re.escape(f) for f in sorted(SENSITIVE_FIELDS, key=len, reverse=True))
    )
)


def redact(text: str) -> str:
    """Return ``text`` with otpauth URIs and sensitive values fully removed."""
    if not isinstance(text, str):
        return text
    text = _OTPAUTH_URI_RE.sub(_URI_REDACTED, text)
    text = _FIELD_RE.sub(lambda m: f"{m.group('key')}{m.group('sep')}{_VALUE_REDACTED}", text)
    return text


class SensitiveDataRedactor(logging.Filter):
    """Logging filter that scrubs TOTP secrets from every log record.

    Attach to a handler or logger so redaction runs regardless of which code
    path produced the record::

        handler.addFilter(SensitiveDataRedactor())
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._scrub_field(k, v) for k, v in record.args.items()}
            else:
                record.args = tuple(self._scrub(a) for a in record.args)
        return True

    @staticmethod
    def _scrub_field(key: Any, value: Any) -> Any:
        # For keyed (dict) args we can redact by field name, catching even a
        # bare secret value that carries no ``otpauth://`` or ``secret=`` context.
        if isinstance(key, str) and key.lower() in SENSITIVE_FIELDS:
            return _VALUE_REDACTED
        return SensitiveDataRedactor._scrub(value)

    @staticmethod
    def _scrub(value: Any) -> Any:
        return redact(value) if isinstance(value, str) else value


def install_redaction(logger: logging.Logger | None = None) -> SensitiveDataRedactor:
    """Install the redactor on ``logger`` (root by default) and return it.

    Adding the filter to the logger itself only scrubs records created by that
    logger, so we also add it to each of its handlers to cover propagation.
    """
    logger = logger or logging.getLogger()
    redactor = SensitiveDataRedactor()
    logger.addFilter(redactor)
    for handler in logger.handlers:
        handler.addFilter(redactor)
    return redactor


class SecureTOTPProvisioner:
    """Build TOTP provisioning URIs without ever logging the secret."""

    def __init__(self, issuer: str, account: str) -> None:
        self._issuer = issuer
        self._account = account
        self._log = logging.getLogger(__name__)

    def provisioning_uri(
        self,
        secret: str,
        *,
        algorithm: str = "SHA1",
        digits: int = 6,
        period: int = 30,
    ) -> str:
        """Return an ``otpauth://`` URI for QR rendering.

        The secret is embedded in the returned URI (the client needs it to seed
        the authenticator) but is never passed to a logging call. Only
        non-sensitive provisioning metadata is logged.
        """
        label = f"{quote(self._issuer)}:{quote(self._account)}"
        query = (
            f"secret={quote(secret)}"
            f"&issuer={quote(self._issuer)}"
            f"&algorithm={quote(algorithm)}"
            f"&digits={int(digits)}"
            f"&period={int(period)}"
        )
        uri = f"otpauth://totp/{label}?{query}"

        # Safe: issuer/account are not secrets; the URI and secret are omitted.
        self._log.info(
            "Generated TOTP provisioning QR for issuer=%s account=%s",
            self._issuer,
            self._account,
        )
        return uri


__all__ = [
    "redact",
    "SensitiveDataRedactor",
    "install_redaction",
    "SecureTOTPProvisioner",
    "SENSITIVE_FIELDS",
]
