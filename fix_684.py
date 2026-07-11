```python
import urllib.parse
import ipaddress

class URLValidator:
    def __init__(self):
        self.allowed_protocols = {'http', 'https'}
        self.forbidden_protocols = {'gopher', 'dict', 'file'}
        self.internal_ip_blacklist = {'127.0.0.1', '::1'}

    def is_valid_protocol(self, url):
        parsed_url = urllib.parse.urlparse(url)
        return parsed_url.scheme in self.allowed_protocols and parsed_url.scheme not in self.forbidden_protocols

    def is_internal_ip(self, ip_address):
        try:
            ip = ipaddress.ip_address(ip_address)
            if ip.is_loopback or ip.is_private:
                return True
        except ValueError:
            pass
        return False

    def validate_url(self, url):
        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.netloc.split(':')[0]  # Extract the hostname without port

        if not self.is_valid_protocol(url):
            raise ValueError("Invalid protocol")

        if self.is_internal_ip(host):
            raise ValueError("Internal IP address detected")

def main():
    validator = URLValidator()

    try:
        url = "gopher://127.0.0.1/_*CONFIG SET dir /tmp"
        validator.validate_url(url)
        print(f"URL '{url}' is valid.")
    except ValueError as e:
        print(e)

    # Valid URL
    try:
        url = "http://example.com/_*CONFIG SET dir /tmp"
        validator.validate_url(url)
        print(f"URL '{url}' is valid.")
    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()
```