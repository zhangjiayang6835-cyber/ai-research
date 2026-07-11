"""Fix for Issue #721: HTTP/2 Downgrade → Request Smuggling"""
import re
import json

SECURITY_FIX = True

class HTTP2DowngradeProtector:
    """Protects against HTTP/2 to HTTP/1.1 downgrade request smuggling."""
    
    def __init__(self):
        self.enforce_end_to_end_h2 = True
        self.pseudo_header_pattern = re.compile(r"^:")
        self.forbidden_pseudo_headers_in_h1 = frozenset({
            ":authority", ":path", ":method", ":scheme", ":status"
        })
    
    def validate_request(self, headers, protocol="HTTP/2"):
        """Validate request for smuggling indicators during protocol downgrade."""
        issues = []
        
        if protocol == "HTTP/2" and not self.enforce_end_to_end_h2:
            issues.append("HTTP/2 downgrade allowed - potential smuggling vector")
        
        # Check for pseudo-headers in HTTP/1.1
        if protocol == "HTTP/1.1":
            for key in headers:
                if key.startswith(":") and key in self.forbidden_pseudo_headers_in_h1:
                    issues.append(f"Pseudo-header '{key}' found in HTTP/1.1 request")
        
        # Check Content-Length consistency
        if "content-length" in headers and "transfer-encoding" in headers:
            issues.append("CL/TE conflict - potential request smuggling")
        
        # Check for duplicate headers
        seen = {}
        for key in headers:
            lower_key = key.lower()
            if lower_key in seen:
                issues.append(f"Duplicate header: {key}")
            seen[lower_key] = True
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "recommendation": "Enforce end-to-end HTTP/2 without downgrade" if issues else "Request is valid"
        }

def apply_security_patch(input_data):
    """Apply security fix: HTTP/2 downgrade protection + request validation."""
    if not isinstance(input_data, dict):
        return {"status": "error", "data": "Invalid input"}
    
    headers = input_data.get("headers", {})
    protocol = input_data.get("protocol", "HTTP/2")
    
    protector = HTTP2DowngradeProtector()
    result = protector.validate_request(headers, protocol)
    
    if not result["valid"]:
        return {
            "status": "rejected",
            "data": {
                "issues": result["issues"],
                "recommendation": result["recommendation"]
            }
        }
    
    return {"status": "patched", "data": "Request validated - no smuggling detected"}

if __name__ == "__main__":
    # Test 1: Clean HTTP/2 request passes
    result = apply_security_patch({
        "headers": {"host": "example.com", "content-type": "application/json"},
        "protocol": "HTTP/2"
    })
    assert result["status"] == "patched", f"Clean H2 rejected: {result}"
    print("✓ Clean HTTP/2 request passes")
    
    # Test 2: Pseudo-headers in HTTP/1.1 flagged
    result = apply_security_patch({
        "headers": {":authority": "evil.com", "host": "example.com"},
        "protocol": "HTTP/1.1"
    })
    assert result["status"] == "rejected", f"Pseudo-header not flagged: {result}"
    print("✓ Pseudo-headers in HTTP/1.1 flagged")
    
    # Test 3: CL/TE conflict detected
    result = apply_security_patch({
        "headers": {"content-length": "42", "transfer-encoding": "chunked"},
        "protocol": "HTTP/1.1"
    })
    assert result["status"] == "rejected", f"CL/TE not detected: {result}"
    print("✓ CL/TE conflict detected")
    
    # Test 4: Duplicate headers detected
    result = apply_security_patch({
        "headers": {"content-length": "42", "Content-Length": "0"},
        "protocol": "HTTP/1.1"
    })
    assert result["status"] == "rejected", f"Duplicate headers not detected: {result}"
    print("✓ Duplicate headers detected")
    
    # Test 5: Invalid input rejected
    result = apply_security_patch("invalid")
    assert result["status"] == "error", f"Invalid input not rejected: {result}"
    print("✓ Invalid input rejected")
    
    print("\n✅ All tests passed for #721: HTTP/2 Downgrade Fix")