"""Fix for JWT Kid Injection -> Path Traversal -> Secret Key Leak"""
import re
import os

def sanitize(data):
    """Sanitize user input to prevent path traversal and injection via kid"""
    if isinstance(data, str):
        # Remove dangerous path traversal sequences and special characters
        data = data.replace('..', '').replace('/', '').replace('\\', '')
        return re.sub(r'[<>&"\'\0]', '', data)
    return data

def validate(data):
    """Validate input (e.g., kid parameter) against path traversal and allowlisting"""
    if not data or not isinstance(data, str):
        return False
    # Ensure kid does not contain path traversal attempts
    if '..' in data or '/' in data or '\\' in data:
        return False
    return True

if __name__ == "__main__":
    assert sanitize("../secret") == "secret"
    assert sanitize("<script>") == "script"
    assert validate("test") == True
    assert validate("../test") == False
    assert validate("etc/passwd") == False
    print("All tests passed!")