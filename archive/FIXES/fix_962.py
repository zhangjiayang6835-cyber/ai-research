"""
Fix for Issue #962 — Blind Command Injection via Email Header
===============================================================

Vulnerability
-------------
Email sending function passes user-supplied Subject directly to sendmail:
sendmail -s "{subject}" {email}. Attackers inject ;id > /tmp/out in the
Subject to execute arbitrary commands.

Fix Strategy
------------
1. Use email library (smtplib/email) API instead of shell commands.
2. Sanitize all email header inputs.
3. Escape shell special characters as defense-in-depth.
"""

from __future__ import annotations

import re
import shlex
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr
from typing import Final

# Shell special characters that should be escaped
SHELL_SPECIAL_CHARS: Final[re.Pattern] = re.compile(r'[;&|`$(){}[\]<>!#~*?\\\n\r]')

# Dangerous command injection patterns
INJECTION_PATTERNS: Final[list[re.Pattern]] = [
    re.compile(r"[;&|]\s*(id|whoami|cat|curl|wget|nc|bash|sh|python|perl|ruby)", re.IGNORECASE),
    re.compile(r"`[^`]+`"),
    re.compile(r"\$\([^)]+\)"),
    re.compile(r"\|[^\s]"),
    re.compile(r">\s*/"),
]


def sanitize_email_header(value: str) -> str:
    """Sanitize an email header value, removing shell injection characters."""
    # Remove shell special characters
    sanitized = SHELL_SPECIAL_CHARS.sub("", value)
    # Remove newlines (header injection)
    sanitized = sanitized.replace("\n", "").replace("\r", "")
    # Strip whitespace
    sanitized = sanitized.strip()
    return sanitized


def has_command_injection(value: str) -> bool:
    """Check if a value contains command injection patterns."""
    for pattern in INJECTION_PATTERNS:
        if pattern.search(value):
            return True
    return False


def send_email_safe(
    to_email: str,
    subject: str,
    body: str,
    from_email: str = "noreply@example.com",
    smtp_host: str = "localhost",
    smtp_port: int = 25,
) -> bool:
    """
    Send an email using the email library API (no shell commands).

    This is the safe alternative to shell-based sendmail.
    """
    import smtplib

    # Sanitize inputs
    safe_subject = sanitize_email_header(subject)
    safe_to = sanitize_email_header(to_email)

    if has_command_injection(subject):
        raise ValueError("Subject contains command injection patterns")

    # Create email using MIMEText (safe API)
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(safe_subject, "utf-8")
    msg["From"] = formataddr(("", from_email))
    msg["To"] = formataddr(("", safe_to))

    # Send via SMTP library (no shell)
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.sendmail(from_email, [safe_to], msg.as_string())
        return True
    except Exception:
        return False


# Alternative: shell-based sendmail with escaping (if library is unavailable)
def send_email_shell_safe(
    to_email: str,
    subject: str,
    body: str,
) -> bool:
    """Send email via sendmail with proper shell escaping (fallback)."""
    import subprocess

    safe_subject = sanitize_email_header(subject)
    safe_to = sanitize_email_header(to_email)

    if has_command_injection(subject):
        raise ValueError("Subject contains command injection patterns")

    # Use shlex.quote() for proper shell escaping
    # Pass body via stdin, not as argument
    try:
        proc = subprocess.run(
            ["sendmail", "-t"],
            input=f"To: {safe_to}\nSubject: {safe_subject}\n\n{body}\n",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False
