--- notify_email.py ---
import smtplib
import dkim
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import re

ts = __import__("time").strftime("%Y-%m-%d %H:%M:%S")

SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.example.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER', 'noreply@example.com')
SMTP_DOMAIN = SMTP_USER.split('@')[-1] if '@' in SMTP_USER else 'example.com'
DKIM_SELECTOR = os.getenv('DKIM_SELECTOR', 'default')
SMTP_PASS = os.getenv('SMTP_PASS', '')
FROM_NAME = os.getenv('FROM_NAME', 'AI Research Platform')

def filter_secret(text):
    return re.sub(r'secret=[^&]+', 'secret=***', text)

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
        dkim_domain = f"{selector}._domainkey.{sender_domain}"
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
        # Sign the message
        pass