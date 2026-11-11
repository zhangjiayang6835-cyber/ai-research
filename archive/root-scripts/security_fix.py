#!/usr/bin/env python3
"""Security fix: input validation and sanitization"""
import re

def sanitize_input(data):
    """Sanitize user input to prevent injection attacks"""
    if isinstance(data, str):
        # Remove dangerous characters
        data = re.sub(r'[<>&"'\\]', '', data)
    return data

def validate_request(headers, body):
    """Validate incoming request"""
    if not headers or not body:
        return False
    return True

if __name__ == "__main__":
    test = "<script>alert('xss')</script>"
    result = sanitize_input(test)
    print(f"Sanitized: {result}")
    assert '<' not in result
    print("All tests passed!")
