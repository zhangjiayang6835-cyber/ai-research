import dns.resolver
import requests

# Suspicious CNAME targets that are known for takeover
UNMANAGED_TARGETS = [
    'github.io',
    's3.amazonaws.com',
    'cloudfront.net',
    'azureedge.net',
    'herokuapp.com',
]

def check_dangling(domain):
    """Check if a domain has a dangling DNS record."""
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            target = str(rdata.target).rstrip('.')
            for t in UNMANAGED_TARGETS:
                if target.endswith(t):
                    # Check if the target is still live
                    try:
                        resp = requests.get(f'http://{target}', timeout=10)
                        if resp.status_code >= 400:
                            print(f'Dangling record detected: {domain} -> {target} (HTTP {resp.status_code})')
                    except requests.ConnectionError:
                        print(f'Dangling record detected: {domain} -> {target} (unreachable)')
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass

def remove_dangling(domain):
    """Placeholder for DNS record removal. In production, integrate with DNS provider API."""
    print(f'To fix, remove the CNAME record for {domain} or ensure the target service is active.')

if __name__ == '__main__':
    domains = ['example.com', 'sub.example.com']  # Replace with actual domains
    for d in domains:
        check_dangling(d)
