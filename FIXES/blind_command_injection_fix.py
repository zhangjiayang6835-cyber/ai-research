"""
Blind Command Injection via Email Header Fix
Bounty #783 ($150)
=========================================
Vulnerability: sendmail -s "{subject}" {email} — user Subject injected
into shell command. Attacker inputs ;id > /tmp/out to execute commands.

Fix: Use SMTP library API instead of shell commands.
"""

import os
import re
import shlex
import subprocess
from typing import List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib


class SecureMailSender:
    """
    Email sender that prevents command injection.
    Uses SMTP library API instead of shell commands.
    """

    def __init__(self, smtp_host: str = "localhost",
                 smtp_port: int = 25,
                 use_tls: bool = False):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.use_tls = use_tls

    def send_email(self, to_email: str, subject: str,
                   body: str, from_email: Optional[str] = None) -> bool:
        """
        Send email using SMTP library API.
        Subject is set via library API, not shell interpolation.
        """
        if not from_email:
            from_email = "noreply@example.com"

        # Create message using email library (safe API)
        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject  # ← Set via library API, not shell!

        # Attach body
        msg.attach(MIMEText(body, "plain"))

        # Send via SMTP (no shell involved)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False

    def send_email_bulk(self, to_emails: List[str], subject: str,
                        body: str, from_email: Optional[str] = None) -> int:
        """
        Send email to multiple recipients.
        """
        sent_count = 0
        for email in to_emails:
            if self.send_email(email, subject, body, from_email):
                sent_count += 1
        return sent_count


# ========== Alternative: Shell-based with proper escaping ==========

class ShellMailSender:
    """
    Shell-based email sender with proper escaping.
    Only use this as fallback when SMTP library is unavailable.
    """

    # Characters that must be escaped in shell context
    SHELL_SPECIAL_CHARS = re.compile(r'[;&|`$(){}[\]!#~<>\\\n\r]')

    @classmethod
    def escape_shell_arg(cls, arg: str) -> str:
        """
        Escape argument for shell use.
        Uses shlex.quote() for POSIX shell escaping.
        """
        return shlex.quote(arg)

    @classmethod
    def send_email_safe(cls, to_email: str, subject: str,
                        body: str, sendmail_path: str = "/usr/sbin/sendmail") -> bool:
        """
        Send email via sendmail with proper shell escaping.
        """
        # Escape all user-controlled inputs
        safe_subject = cls.escape_shell_arg(subject)
        safe_email = cls.escape_shell_arg(to_email)

        # Build command using list (not shell string)
        cmd = [
            sendmail_path,
            "-s", subject,  # sendmail -s flag
            to_email,
        ]

        try:
            result = subprocess.run(
                cmd,
                input=body.encode("utf-8"),
                capture_output=True,
                timeout=30,
                # NO shell=True — this is critical!
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print("Email sending timed out")
            return False
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False

    @staticmethod
    def validate_email(email: str) -> bool:
        """Basic email validation."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Blind Command Injection Prevention ===")
    print()

    # Attack scenario:
    # Subject: "Hello ;id > /tmp/out"
    # Vulnerable: sendmail -s "Hello ;id > /tmp/out" user@example.com
    # → Executes: id > /tmp/out

    malicious_subject = 'Hello ;id > /tmp/out'
    print(f"Malicious subject: {malicious_subject}")
    print()

    # Before (vulnerable):
    vulnerable_cmd = f'sendmail -s "{malicious_subject}" user@example.com'
    print(f"Vulnerable command:")
    print(f"  {vulnerable_cmd}")
    print(f"  → Executes: id > /tmp/out (blind command injection!)")
    print()

    # After (fixed - SMTP library):
    print("Fixed approach 1 (SMTP library):")
    print("  msg['Subject'] = subject  # Set via library API")
    print("  smtp.send_message(msg)     # No shell involved")
    print("  → Command injection impossible!")
    print()

    # After (fixed - shell with escaping):
    escaped = shlex.quote(malicious_subject)
    print(f"Fixed approach 2 (shell with escaping):")
    print(f"  Escaped subject: {escaped}")
    print(f"  → Shell special characters are quoted, injection prevented!")
    print()

    print("=== Recommendations ===")
    print("✓ PREFERRED: Use SMTP library (smtplib) — no shell at all")
    print("✓ FALLBACK: Use subprocess with list (no shell=True)")
    print("✓ ALWAYS: Escape user input with shlex.quote()")
    print("✗ NEVER: Use os.system() or subprocess with shell=True")
