# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

#!/usr/bin/env python3
"""
CRLF Injection to HTTP Response Splitting + Cache Poisoning Fix

This module provides a secure HTTP response header builder that sanitizes
user-controlled input to prevent CRLF injection attacks.
"""

import re


def sanitize_header_value(value: str) -> str:
    """
    Remove CRLF characters from header values to prevent HTTP response splitting.
    
    Args:
        value: The raw header value that may contain malicious input.
        
    Returns:
        A sanitized header value with CRLF sequences removed.
    """
    if not isinstance(value, str):
        value = str(value)
    # Remove carriage return and line feed characters
    sanitized = value.replace('\r', '').replace('\n', '')
    return sanitized


def build_safe_header(header_name: str, header_value: str) -> tuple:
    """
    Build a safe HTTP header tuple with sanitized values.
    
    Args:
        header_name: The HTTP header name.
        header_value: The HTTP header value (user-controlled input).
        
    Returns:
        A tuple of (header_name, sanitized_header_value).
    """
    # Also sanitize header name to prevent header injection
    safe_name = sanitize_header_value(header_name).strip()
    safe_value = sanitize_header_value(header_value)
    return (safe_name, safe_value)


def set_cache_control_headers(response_headers: dict, max_age: int = 3600) -> dict:
    """
    Set safe cache control headers to prevent cache poisoning.
    
    Args:
        response_headers: Existing response headers dictionary.
        max_age: Maximum age for cache in seconds.
        
    Returns:
        Updated headers with secure cache control.
    """
    if response_headers is None:
        response_headers = {}
    
    # Prevent cache poisoning by setting strict cache controls
    response_headers['Cache-Control'] = f'private, no-store, max-age={max_age}'
    response_headers['Pragma'] = 'no-cache'
    response_headers['Expires'] = '0'
    
    return response_headers


def create_safe_redirect(location: str, base_url: str = '') -> str:
    """
    Create a safe redirect URL preventing CRLF injection in Location header.
    
    Args:
        location: The user-provided redirect location.
        base_url: The base URL to validate against.
        
    Returns:
        A sanitized redirect URL.
    """
    sanitized = sanitize_header_value(location)
    
    # Prevent open redirects by validating against base_url if provided
    if base_url and not sanitized.startswith(base_url):
        # If location doesn't start with base_url, use base_url as fallback
        if sanitized.startswith('http://') or sanitized.startswith('https://'):
            # External URL detected, redirect to base_url instead
            return base_url
    
    return sanitized


def validate_header_injection(response: str) -> bool:
    """
    Check if a response contains potential header injection patterns.
    
    Args:
        response: The HTTP response string to validate.
        
    Returns:
        True if the response is safe, False if injection detected.
    """
    if not isinstance(response, str):
        return True
    
    # Check for CRLF patterns that could indicate injection
    if '\r\n' in response or '\n' in response or '\r' in response:
        # Additional check: look for common header injection patterns
        header_patterns = [
            r'[\r\n][ \t]*[A-Za-z0-9-]+[ \t]*:',
            r'[\r\n][ \t]*[A-Za-z0-9-]+[ \t]*=',
        ]
        for pattern in header_patterns:
            if re.search(pattern, response):
                return False
    
    return True


class SecureHTTPResponse:
    """
    A secure HTTP response builder that prevents CRLF injection and cache poisoning.
    """
    
    def __init__(self):
        self.headers = {}
        self.body = ''
        self.status_code = 200
    
    def add_header(self, name: str, value: str) -> 'SecureHTTPResponse':
        """
        Add a header with automatic CRLF sanitization.
        """
        safe_name, safe_value = build_safe_header(name, value)
        self.headers[safe_name] = safe_value
        return self
    
    def set_body(self, body: str) -> 'SecureHTTPResponse':
        """
        Set the response body.
        """
        self.body = body
        return self
    
    def set_status(self, code: int) -> 'SecureHTTPResponse':
        """
        Set the HTTP status code.
        """
        self.status_code = code
        return self
    
    def build(self) -> dict:
        """
        Build the secure response with cache poisoning protection.
        """
        # Apply cache control to prevent cache poisoning
        self.headers = set_cache_control_headers(self.headers)
        
        return {
            'status_code': self.status_code,
            'headers': self.headers,
            'body': self.body
        }


# Example usage and backward compatibility
if __name__ == '__main__':
    # Demonstrate the fix
    malicious_input = "evil\r\nSet-Cookie: hacked=true\r\n\r\n<script>alert('xss')</script>"
    
    # Build secure response
    response = SecureHTTPResponse()
    response.set_status(302)
    response.add_header('Location', malicious_input)
    result = response.build()
    
    print("Secure Response:", result)
    print("Location header sanitized:", result['headers'].get('Location'))
    
    # Verify no CRLF injection
    assert '\r' not in result['headers'].get('Location', '')
    assert '\n' not in result['headers'].get('Location', '')
    print("CRLF Injection prevented successfully!")
print("fix #194")
