import re
from urllib.parse import urlparse

def validate_redirect_uri(redirect_uri, allowed_uris, allow_subdomains=False):
    """
    Validate redirect_uri against a list of allowed URIs to prevent open redirect.
    
    :param redirect_uri: The redirect_uri from the OAuth request.
    :param allowed_uris: List of allowed redirect URIs (strings).
    :param allow_subdomains: If True, allow subdomains of allowed origins.
    :return: True if valid, False otherwise.
    """
    if not redirect_uri:
        return False
    
    parsed = urlparse(redirect_uri)
    # Reject if no scheme or netloc
    if not parsed.scheme or not parsed.netloc:
        return False
    
    # Build allowed origins (scheme + netloc) from allowed URIs
    allowed_origins = set()
    for uri in allowed_uris:
        allowed_parsed = urlparse(uri)
        if allowed_parsed.scheme and allowed_parsed.netloc:
            allowed_origins.add((allowed_parsed.scheme, allowed_parsed.netloc))
    
    # Check exact match first (including path)
    if redirect_uri in allowed_uris:
        return True
    
    # Otherwise check origin + optional subdomain
    for scheme, netloc in allowed_origins:
        if parsed.scheme != scheme:
            continue
        if allow_subdomains:
            # Check if netloc matches or is a subdomain
            if parsed.netloc == netloc or parsed.netloc.endswith('.' + netloc):
                return True
        else:
            if parsed.netloc == netloc:
                return True
    
    return False

# Example usage:
if __name__ == '__main__':
    # Replace with actual configuration
    ALLOWED_REDIRECT_URIS = [
        'https://example.com/callback',
        'https://app.example.com/callback'
    ]
    test_uri = 'https://evil.com/callback'
    print(validate_redirect_uri(test_uri, ALLOWED_REDIRECT_URIS))  # False