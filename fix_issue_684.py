"""Fix for Issue #684: SSRF via Gopher Protocol → Redis RCE"""
import re
import json
import ipaddress
from urllib.parse import urlparse

SECURITY_FIX = True

ALLOWED_PROTOCOLS = frozenset({"http", "https"})
FORBIDDEN_PROTOCOLS = frozenset({"gopher", "dict", "file", "ftp", "tftp", "ldap", "redis"})
PRIVATE_IP_RANGES = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
    "::1/128", "fc00::/7", "fe80::/10"
]

def validate_url(url):
    """Validate URL against SSRF attacks."""
    if not url or not isinstance(url, str):
        return False, "Invalid URL"
    
    parsed = urlparse(url)
    scheme = parsed.scheme.lower() if parsed.scheme else ""
    
    if scheme in FORBIDDEN_PROTOCOLS:
        return False, f"Forbidden protocol: {scheme}"
    
    if scheme not in ALLOWED_PROTOCOLS:
        return False, f"Unsupported protocol: {scheme}"
    
    # Check hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "Missing hostname"
    
    # Check for private IP
    try:
        ip = ipaddress.ip_address(hostname)
        for cidr in PRIVATE_IP_RANGES:
            if ip in ipaddress.ip_network(cidr):
                return False, f"Private IP blocked: {hostname}"
    except ValueError:
        pass  # Not an IP, might be a domain name
    
    return True, "URL is safe"

def apply_security_patch(input_data):
    """Apply security fix: URL validation + protocol allowlist + IP blacklist."""
    if isinstance(input_data, str):
        url = input_data
    elif isinstance(input_data, dict):
        url = input_data.get("url", "")
    else:
        return {"status": "error", "data": "Invalid input"}
    
    is_valid, message = validate_url(url)
    if not is_valid:
        return {"status": "rejected", "data": message}
    
    return {"status": "patched", "data": f"URL '{url[:50]}...' validated and safe"}

if __name__ == "__main__":
    # Test 1: Gopher protocol blocked
    result = apply_security_patch("gopher://redis:6379/_*CONFIG%20SET%20dir%20/tmp")
    assert result["status"] == "rejected", "Gopher protocol not blocked"
    print("✓ Gopher protocol blocked")
    
    # Test 2: HTTP allowed
    result = apply_security_patch("https://api.example.com/data")
    assert result["status"] == "patched", "Valid HTTP rejected"
    print("✓ HTTP/HTTPS allowed")
    
    # Test 3: Private IP blocked
    result = apply_security_patch("http://169.254.169.254/latest/meta-data/")
    assert result["status"] == "rejected", "Private IP not blocked"
    print("✓ Private IP blocked")
    
    # Test 4: Dict protocol blocked
    result = apply_security_patch("dict://redis:6379/info")
    assert result["status"] == "rejected", "Dict protocol not blocked"
    print("✓ Dict protocol blocked")
    
    # Test 5: Localhost blocked
    result = apply_security_patch("http://127.0.0.1:6379/")
    assert result["status"] == "rejected", "Localhost not blocked"
    print("✓ Localhost blocked")
    
    # Test 6: File protocol blocked
    result = apply_security_patch("file:///etc/passwd")
    assert result["status"] == "rejected", "File protocol not blocked"
    print("✓ File protocol blocked")
    
    # Test 7: Empty URL rejected
    result = apply_security_patch("")
    assert result["status"] == "rejected", "Empty URL not rejected"
    print("✓ Empty URL rejected")
    
    print("\n✅ All tests passed for #684: SSRF Gopher Redis Fix")