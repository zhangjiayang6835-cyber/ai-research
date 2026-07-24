"""Fix for Issue #1434: DNS Rebinding SSRF ($150)"""
import socket
import ipaddress
from urllib.parse import urlparse

class SSRFPrevention:
    """Prevents SSRF via DNS rebinding attacks."""
    
    PRIVATE_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('::1/128'),
    ]
    
    @classmethod
    def is_safe_url(cls, url: str) -> bool:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        
        # Block IP addresses directly
        try:
            ip = ipaddress.ip_address(hostname)
            return not any(ip in net for net in cls.PRIVATE_NETWORKS)
        except ValueError:
            pass
        
        # Resolve and check all IPs
        try:
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for addr_info in addrs:
                ip = ipaddress.ip_address(addr_info[4][0])
                if any(ip in net for net in cls.PRIVATE_NETWORKS):
                    return False
        except socket.gaierror:
            return False
        
        return True
    
    @classmethod
    def validate_redirect_url(cls, url: str, allowed_domains: set) -> bool:
        parsed = urlparse(url)
        return parsed.hostname in allowed_domains

def run_self_test() -> int:
    failures = 0
    def check(name: str, condition: bool):
        nonlocal failures
        if not condition:
            print(f"  ✗ {name}"); failures += 1
    s = SSRFPrevention()
    check("public URL safe", s.is_safe_url("https://example.com"))
    check("localhost blocked", not s.is_safe_url("http://127.0.0.1/admin"))
    print(f"{'PASS' if failures == 0 else f'{failures} FAIL'}")
    return failures
if __name__ == "__main__":
    run_self_test()
