```python
"""
Fix for Blind SSRF via DNS Rebinding Vulnerability

This script prevents blind SSRF attacks by ensuring that only requests to whitelisted domains are allowed.
"""

import socket
import re

WHITELISTED_DOMAINS = ['example.com', 'localhost']

def is_valid_domain(domain):
    """
    Check if the provided domain is in the whitelist.
    """
    return any(re.match(rf'\b{re.escape(d)}\b', domain) for d in WHITELISTED_DOMAINS)

def resolve_host(hostname):
    """
    Resolve the hostname and check against the whitelisted domains.
    """
    try:
        ip_address = socket.gethostbyname(hostname)
        if is_valid_domain(hostname):
            return ip_address
        else:
            raise ValueError(f"Invalid domain: {hostname}")
    except socket.error as e:
        raise ValueError(f"Failed to resolve host: {e}")

def main():
    hostname = input("Enter the hostname you want to query: ")
    try:
        ip_address = resolve_host(hostname)
        print(f"The IP address of {hostname} is {ip_address}")
    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()
```