"""Fix for Issue #677: JWT Kid Injection → Path Traversal → Secret Key Leak"""
import re
import json
import hmac
import hashlib
import base64

SECURITY_FIX = True

KID_ALLOWED_CHARS = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
FORBIDDEN_KID_PATTERNS = re.compile(r"(\.\.|/|\\\\|~|\\x00)")

def validate_kid(kid):
    """Validate kid header against path traversal attacks."""
    if not kid or not isinstance(kid, str):
        return False
    if len(kid) > 64:
        return False
    if FORBIDDEN_KID_PATTERNS.search(kid):
        return False
    if not KID_ALLOWED_CHARS.match(kid):
        return False
    return True

def apply_security_patch(input_data):
    """Apply security fix: JWT kid validation + allowlist check."""
    if not isinstance(input_data, dict):
        return {"status": "error", "data": "Invalid input format"}
    kid = input_data.get("kid", "")
    allowed_kids = input_data.get("allowed_kids", None)
    if not validate_kid(kid):
        return {"status": "rejected", "data": "Invalid kid header - path traversal blocked"}
    if allowed_kids and kid not in allowed_kids:
        return {"status": "rejected", "data": "Kid not in allowlist"}
    return {"status": "patched", "data": f"Kid '{kid}' validated successfully"}

if __name__ == "__main__":
    assert apply_security_patch({"kid": "my-key-2024"})["status"] == "patched"
    assert apply_security_patch({"kid": "../../etc/passwd"})["status"] == "rejected"
    assert apply_security_patch({"kid": "/etc/keys/secret.pem"})["status"] == "rejected"
    assert apply_security_patch({"kid": "unknown", "allowed_kids": {"key-1"}})["status"] == "rejected"
    assert apply_security_patch({"kid": ""})["status"] == "rejected"
    assert apply_security_patch({"kid": 12345})["status"] == "rejected"
    print("All tests passed for #677")