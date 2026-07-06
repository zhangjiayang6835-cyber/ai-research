import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_IP_RANGES = [
    "127.0.0.0/8",      # loopback
    "10.0.0.0/8",       # private
    "172.16.0.0/12",    # private
    "192.168.0.0/16",   # private
    "169.254.0.0/16",   # link-local
    "0.0.0.0/8",        # current network
    "::1/128",          # loopback IPv6
    "fc00::/7",         # private IPv6
    "fe80::/10",        # link-local IPv6
]

def is_safe_url(url: str) -> bool:
    """Check if URL is safe from SSRF."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        # Resolve hostname to IP
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        for block in BLOCKED_IP_RANGES:
            if ip_obj in ipaddress.ip_network(block, strict=False):
                return False
        return True
    except Exception:
        return False


def safe_fetch_url(url: str) -> bytes:
    """Fetch URL content if safe, otherwise raise exception."""
    if not is_safe_url(url):
        raise ValueError(f"URL is not allowed: {url}")
    import requests
    resp = requests.get(url, timeout=10, allow_redirects=True)
    resp.raise_for_status()
    return resp.content


# Example usage inside PDF generator:
# content = safe_fetch_url(user_input_url)
# Then pass content to PDF library (e.g., reportlab, weasyprint).
