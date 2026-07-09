import smtplib
import re
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.header import Header
import logging

logger = logging.getLogger(__name__)

# SMTP Configuration - should be moved to environment variables in production
SMTP_HOST = "localhost"
SMTP_PORT = 25
SMTP_USERNAME = None
SMTP_PASSWORD = None


def sanitize_subject(subject: str) -> str:
    """
    Sanitize subject line to prevent command injection and header injection.
    Removes shell special characters and newlines that could be used for SMTP header injection.
    """
    # Remove newlines and carriage returns to prevent SMTP header injection
    sanitized = subject.replace('\n', '').replace('\r', '')
    
    # Remove shell special characters that could be used in command injection
    # Even though we're not using shell, defense in depth
    shell_chars_pattern = r'[;&|`$(){}[\]!<>#\\\'"*?~]'
    sanitized = re.sub(shell_chars_pattern, '', sanitized)
    
    # Trim whitespace
    sanitized = sanitized.strip()
    
    # If subject is empty after sanitization, provide a default
    if not sanitized:
        sanitized = "(No Subject)"
    
    return sanitized


def send_email(subject: str, recipient: str, body: str = "") -> bool:
    """
    Send email using SMTP library with proper API calls.
    Uses EmailMessage.setSubject() for safe subject handling.
    """
    try:
        # Sanitize subject to prevent injection attacks
        safe_subject = sanitize_subject(subject)
        
        # Create email message using EmailMessage API
        msg = EmailMessage()
        msg.set_content(body if body else "")
        msg['Subject'] = safe_subject
        msg['From'] = "noreply@ai-research.local"
        msg['To'] = recipient
        
        # Connect to SMTP server and send
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            # Use STARTTLS if available for security
            if server.has_extn('STARTTLS'):
                server.starttls()
            
            # Authenticate if credentials are configured
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            
            # Send the email using the library's send_message API
            server.send_message(msg)
        
        logger.info(f"Email sent successfully to {recipient} with subject: {safe_subject}")
        return True
        
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending email to {recipient}: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to send email to {recipient}: {e}")
        return False
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
