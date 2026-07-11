```python
import requests
from urllib.parse import urlparse
import socket
import time

def is_private_ip(ip):
    private_networks = [
        "10.",
        "172.(1[6-9]|2[0-9]|3[0-1)",
        "192.168."
    ]
    for network in private_networks:
        if ip.startswith(network):
            return True
    return False

def validate_dns_rebinding(ip, domain):
    try:
        # Get the current IP address from DNS query
        current_ip = socket.gethostbyname(domain)
        if current_ip != ip:
            raise Exception("DNS rebind detected")
    except Exception as e:
        print(f"DNS rebind attempt detected: {e}")
        return False
    return True

def limit_redirects(response):
    if response.history and len(response.history) > 2:
        raise Exception("Too many redirects")

def main():
    url = "http://example.com"  # Replace with the actual URL to be checked

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        ip_address = socket.gethostbyname(domain)

        if not validate_dns_rebinding(ip_address, domain):
            raise Exception("Request blocked due to DNS rebind")

        session = requests.Session()
        session.max_redirects = 2  # Limit redirects

        response = session.get(url, allow_redirects=False)
        limit_redirects(response)

        content = response.content.decode('utf-8', errors='ignore')

        if is_private_ip(ip_address):
            raise Exception("Response contains private IP address")

        print(f"Request successful: {response.status_code}")
        print(content)
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    main()
```