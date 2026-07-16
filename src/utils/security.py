import re
from typing import Optional

def sanitize_log_input(value: Optional[str]) -> str:
    """
    Sanitize input for logging to prevent CRLF injection attacks.
    
    This function removes or escapes characters that could be used for
    HTTP response splitting or log injection attacks.
    
    Args:
        value: The string to sanitize (e.g., User-Agent header)
        
    Returns:
        Sanitized string safe for logging
    """
    if not value:
        return ""
    
    # Remove CR (\r) and LF (\n) characters to prevent CRLF injection
    sanitized = value.replace('\r', '').replace('\n', '')
    
    # Also remove null bytes which can cause issues
    sanitized = sanitized.replace('\x00', '')
    
    # Optionally truncate very long strings to prevent log flooding
    max_length = 1000
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "...[truncated]"
    
    return sanitized


def sanitize_for_response_header(value: Optional[str]) -> str:
    """
    Sanitize input before including in HTTP response headers.
    
    This is a stricter sanitization for when user input must be
    reflected in HTTP response headers.
    
    Args:
        value: The string to sanitize
        
    Returns:
        Sanitized string safe for HTTP headers
    """
    if not value:
        return ""
    
    # Remove any characters that could break HTTP headers
    # Only allow printable ASCII characters except control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\xff]', '', value)
    
    # Remove CR and LF explicitly
    sanitized = sanitized.replace('\r', '').replace('\n', '')
    
    # Truncate to reasonable length
    max_length = 500
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized


# Example usage in logging middleware
def log_access(request, response, user_agent: Optional[str] = None):
    """
    Log HTTP access with sanitized user input.
    
    Args:
        request: HTTP request object
        response: HTTP response object
        user_agent: User-Agent header value
    """
    # Sanitize the User-Agent before logging
    safe_user_agent = sanitize_log_input(user_agent or request.headers.get('User-Agent', ''))
    
    # Log safely
    log_entry = f"{request.method} {request.path} - UA: {safe_user_agent} - Status: {response.status_code}"
    # Your logging implementation here
    print(log_entry)
    
    # If User-Agent needs to be in response headers (NOT RECOMMENDED)
    # Use the stricter sanitization
    if 'X-User-Agent' in response.headers:
        response.headers['X-User-Agent'] = sanitize_for_response_header(user_agent)
    
    return response