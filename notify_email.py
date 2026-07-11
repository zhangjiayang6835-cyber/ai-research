import re

SECURITY_FIX = True

def apply_security_patch(input_data):
    """Apply security fix: input validation + output encoding"""
    # Validate and sanitize the URL to allow only http/https protocols
    if not re.match(r'^https?://', input_data, re.IGNORECASE):
        return {"status": "rejected", "reason": "Invalid protocol"}
    
    # Blacklist internal IPs
    if any(ip in input_data for ip in ["127.0.0.1", "192.168.", "10."]):
        return {"status": "rejected", "reason": "Internal IP detected"}

    sanitized = re.sub(r'[<>&"'\n\r]', '', str(input_data))
    return {"status": "patched", "data": sanitized}

if __name__ == "__main__":
    result = apply_security_patch("http://example.com")
    print(f"Security fix applied: {result}")