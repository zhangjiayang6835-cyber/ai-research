# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

import re
from urllib.parse import urlparse

def sanitize_header_value(value):
    """
    Sanitize a header value to prevent CRLF injection.
    Removes carriage returns, line feeds, and null bytes.
    """
    if value is None:
        return ""
    # Remove CR, LF, and null bytes
    sanitized = value.replace('\r', '').replace('\n', '').replace('\x00', '')
    return sanitized


def sanitize_url_for_redirect(url):
    """
    Sanitize a URL to prevent open redirect and header injection.
    Only allows http:// and https:// schemes.
    """
    if not url:
        return "/"
    
    # Parse the URL
    parsed = urlparse(url)
    
    # Only allow http and https schemes
    if parsed.scheme not in ('http', 'https'):
        return "/"
    
    # Rebuild safe URL
    safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        safe_url += f"?{parsed.query}"
    
    return safe_url


def set_safe_header(headers, name, value):
    """
    Safely set an HTTP header, preventing CRLF injection.
    """
    if headers is None:
        headers = {}
    
    sanitized_value = sanitize_header_value(value)
    headers[name] = sanitized_value
    return headers


def create_redirect_response(location, status=302):
    """
    Create a safe redirect response with sanitized Location header.
    """
    safe_location = sanitize_url_for_redirect(location)
    return {
       "status": status,
        "headers": {
            "Location": safe_location
        }
    }


def validate_cache_key(key):
    """
    Validate and sanitize a cache key to prevent cache poisoning.
    """
    if not key or not isinstance(key, str):
        return "default"
    
    # Remove dangerous characters
    sanitized = re.sub(r'[\r\n\x00]', '', key)
    
    # Limit length
    max_length = 250
    sanitized = sanitized[:max_length]
    
    return sanitized


def set_cache_headers(headers, max_age=3600, no_store=False):
    """
    Safely set cache headers with proper values to prevent cache poisoning.
    """
    if headers is None:
        headers = {}
    
    if no_store:
        headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        headers['Pragma'] = 'no-cache'
        if 'Expires' in headers:
            del headers['Expires']
    else:
        # Sanitize max_age
        try:
            max_age = int(max_age)
            if max_age < 0:
                max_age = 0
            if max_age > 31536000:  # Max 1 year
                max_age = 31536000
        except (ValueError, TypeError):
            max_age = 3600
        
        headers['Cache-Control'] = f'public, max-age={max_age}'
    
    return headers


def build_http_response(status_code, headers, body):
    """
    Build an HTTP response with sanitized headers to prevent CRLF injection.
    """
    safe_headers = {}
    for name, value in (headers or {}).items():
        # Sanitize header names (prevent header injection)
        safe_name = re.sub(r'[\r\n\x00:]', '', str(name))
        # Sanitize header values
        safe_value = sanitize_header_value(str(value))
        safe_headers[safe_name] = safe_value
    
    return {
        "status_code": int(status_code),
        "headers": safe_headers,
        "body": body
    }


# Example vulnerable code that would be fixed:
"""
# VULNERABLE - DO NOT USE:
# location = request.args.get('redirect')
# response.headers['Location'] = location  # CRLF injection!

# FIXED:
# location = request.args.get('redirect')
# safe_location = sanitize_url_for_redirect(location)
# response.headers['Location'] = safe_location
"""
print("fix #194")
