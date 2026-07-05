import ipaddress
import re
import socket
import urllib.parse
from typing import Optional

def is_safe_url(url: str) -> bool:
    """
    Validates that the URL does not point to internal/private networks to prevent SSRF.
    Returns True if safe, False otherwise.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        # Only allow http and https
        if parsed.scheme not in ('http', 'https'):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Block hostnames that are IP addresses in private ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            # Not an IP, likely a domain - resolve and check
            pass

        # Resolve domain and check all resolved IPs
        try:
            ips = socket.getaddrinfo(hostname, None)
            for addr in ips:
                ip_str = addr[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        return False
                except ValueError:
                    continue
        except socket.gaierror:
            # Cannot resolve - block to be safe
            return False

        # Additional check: block hostnames that look like internal names
        internal_patterns = [
            r'^localhost$',
            r'^127\.',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^169\.254\.',
            r'^0\.',
            r'^::1$',
            r'^fe80:'
        ]
        for pattern in internal_patterns:
            if re.match(pattern, hostname, re.IGNORECASE):
                return False

        return True
    except Exception:
        return False


def generate_pdf_safe(url: str, output_path: str) -> Optional[str]:
    """
    Generate a PDF from a URL, with SSRF protection.
    Uses pdfkit (wkhtmltopdf) under the hood.
    """
    if not is_safe_url(url):
        raise ValueError("Unsafe URL blocked: potential SSRF risk")

    import pdfkit  # type: ignore
    pdfkit.from_url(url, output_path)
    return output_path
