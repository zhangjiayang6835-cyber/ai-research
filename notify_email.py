"""
Email notification module for AI Research Platform.

Vulnerability fix: Blind Command Injection via Email Header.
- Use email library API instead of shell commands
- Sanitize all email header inputs
- Escape shell special characters as defense-in-depth
"""

import os
import re
import smtplib
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr

SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.example.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER', 'noreply@example.com')
SMTP_PASS = os.getenv('SMTP_PASS', '')

SHELL_SPECIAL_CHARS = re.compile(r'[;&|`$(){}[\]<>!#~*?\\\n\r]')
INJECTION_PATTERNS = [
    re.compile(r"[;&|]\s*(id|whoami|cat|curl|wget|nc|bash|sh|python|perl|ruby)", re.IGNORECASE),
    re.compile(r"`[^`]+`"),
    re.compile(r"\$\([^)]+\)"),
    re.compile(r">\s*/"),
]


def sanitize_email_header(value: str) -> str:
    sanitized = SHELL_SPECIAL_CHARS.sub("", value)
    sanitized = sanitized.replace("\n", "").replace("\r", "")
    return sanitized.strip()


def has_command_injection(value: str) -> bool:
    for pattern in INJECTION_PATTERNS:
        if pattern.search(value):
            return True
    return False


def send_notification(to_email: str, subject: str, body: str) -> bool:
    if not to_email or '@' not in to_email:
        raise ValueError("Invalid recipient email address")

    safe_subject = sanitize_email_header(subject)
    safe_to = sanitize_email_header(to_email)

    if has_command_injection(subject):
        raise ValueError("Subject contains command injection patterns")

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(safe_subject, "utf-8")
    msg["From"] = formataddr(("", SMTP_USER))
    msg["To"] = formataddr(("", safe_to))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_PASS:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [safe_to], msg.as_string())
        return True
    except smtplib.SMTPException:
        raise RuntimeError("Failed to send email")
