import hashlib
from urllib.parse import urlparse, parse_qs

def generate_cache_key(request, safe_headers=None):
    """
    Generate a secure cache key that avoids cache poisoning via unkeyed headers.
    Only whitelisted components are used: scheme, host, path, query (sorted), and a limited set of headers.
    """
    if safe_headers is None:
        safe_headers = {'accept', 'accept-encoding', 'accept-language'}
    
    parsed = urlparse(request.url)
    key_parts = [
        parsed.scheme,
        parsed.hostname,
        parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80),
        parsed.path,
        tuple(sorted(parse_qs(parsed.query).items())),  # sorted query params
    ]
    
    # Only include whitelisted headers, in a consistent order
    header_items = []
    for header in safe_headers:
        value = request.headers.get(header)
        if value:
            header_items.append((header, value))
    header_items.sort()
    key_parts.append(tuple(header_items))
    
    raw_key = str(key_parts)
    cache_key = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
    return cache_key