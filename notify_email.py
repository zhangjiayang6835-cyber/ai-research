import smtplib
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def sanitize_subject(subject):
    """
    Sanitize the subject line to prevent command injection.
    Removes or escapes shell special characters.
    """
    # Remove shell metacharacters that could be used for command injection
    dangerous_chars = r'[;&|`$(){}[\]!<>#\\\'\"\n\r\t]'
    sanitized = re.sub(dangerous_chars, '', subject)
    # Also strip any null bytes
    sanitized = sanitized.replace('\x00', '')
    return sanitized.strip()

def send_email(subject, email):
    """
    Send email using SMTP library API instead of shell command.
    This prevents command injection vulnerabilities.
    """
    # Sanitize the subject to remove any shell special characters
    safe_subject = sanitize_subject(subject)
    
    # Get SMTP configuration from environment variables
    smtp_host = os.environ.get('SMTP_HOST', 'localhost')
    smtp_port = int(os.environ.get('SMTP_PORT', 25))
    smtp_user = os.environ.get('SMTP_USER', None)
    smtp_pass = os.environ.get('SMTP_PASS', None)
    from_addr = os.environ.get('FROM_EMAIL', 'noreply@example.com')
    
    # Build email using MIME API
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = email
    msg['Subject'] = safe_subject  # Using setSubject() equivalent via MIME headers
    msg.attach(MIMEText('', 'plain'))
    
    # Send via SMTP library (no shell involved)
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.send_message(msg)

if __name__ == '__main__':
    import sys
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.example.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER', 'noreply@example.com')
SMTP_DOMAIN = SMTP_USER.split('@')[-1] if '@' in SMTP_USER else 'example.com'
DKIM_SELECTOR = os.getenv('DKIM_SELECTOR', 'default')
SMTP_PASS = os.getenv('SMTP_PASS', '')
FROM_NAME = os.getenv('FROM_NAME', 'AI Research Platform')

<p><b>Time:</b> {ts}</p>
    'use_tls': True,
}

DKIM_PRIVATE_KEY = os.getenv('DKIM_PRIVATE_KEY', '')


def verify_spf(sender_domain):
    """
    Verify that the sender domain has a valid SPF record.
    Returns True if SPF record exists, False otherwise.
    """
    try:
        answers = dns.resolver.resolve(sender_domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if b'v=spf1' in txt_string:
                    return True
        return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return False


def verify_dkim(sender_domain, selector='default'):
    """
    Verify that the sender domain has a valid DKIM record.
    Returns True if DKIM record exists, False otherwise.
    """
    try:
        dk = dkim.DKIM()
        # Check if selector record exists
        dkim_domain = f"{selector}._domainkey.{sender_domain}'
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            return True
        return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return False


def sign_email_with_dkim(msg_bytes, selector, domain, private_key):
    """Sign email with DKIM signature."""
    try:
        signature = dkim.sign(
            msg_bytes,
            selector.encode(),
            domain.encode(),
            private_key.encode() if isinstance(private_key, str) else private_key
        )
        return signature
    except Exception:
        return None


def send_notification(to_email, subject, body, html_body=None):
    """
        body = f"""
<h2>Task Completed!</h2>
<p><b>User:</b> {username}</p>
    if not to_email or '@' not in to_email:
        raise ValueError("Invalid recipient email address")
    
    # Security: Verify SPF record for sender domain
    if not verify_spf(SMTP_DOMAIN):
        raise SecurityError(
            f"Email spoofing prevention: Missing or invalid SPF record for domain {SMTP_DOMAIN}"
        )
    
    # Security: Verify DKIM record for sender domain
    if not verify_dkim(SMTP_DOMAIN, DKIM_SELECTOR):
        raise SecurityError(
            f"Email spoofing prevention: Missing or invalid DKIM record for domain {SMTP_DOMAIN}"
        )
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f"{FROM_NAME} <{SMTP_USER}>"
        return
    
    html = f"""<html><body style="font-family:Arial,sans-serif;">{body}
<hr>
<p style="color:#888;font-size:12px;">AI Research Monitor | {ts}</p>
</body></html>"""
    
    msg = MIMEText(html, "html", "utf-8")
        msg.attach(part2)
    
    msg_bytes = msg.as_bytes()
    
    # Sign email with DKIM if private key is available
    if DKIM_PRIVATE_KEY:
        dkim_signature = sign_email_with_dkim(
            msg_bytes, 
            DKIM_SELECTOR, 
            SMTP_DOMAIN, 
            DKIM_PRIVATE_KEY
        )
        if dkim_signature:
            # Reconstruct message with DKIM signature
            msg['DKIM-Signature'] = dkim_signature.decode('utf-8', errors='replace').split(':', 1)[1].strip()
            msg_bytes = msg.as_bytes()
    
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_CONFIG['use_tls']:
        s.login("2593697591@QQ.com", "hwazivgrdiofebaj")
        s.sendmail("2593697591@QQ.com", "2593697591@QQ.com", msg.as_string())
    print(f"[EMAIL] {subject}")

if __name__ == "__main__":
        return True
    except smtplib.SMTPException as e:
        raise RuntimeError(f"Failed to send email: {e}")
    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(f"Unexpected error sending email: {e}")


def send_task_notification(to_email, task_title, task_url):
        f"Details: {details}\n\n"
    )
    return send_notification(to_email, subject, body)


class SecurityError(Exception):
    """Raised when a security check fails."""
