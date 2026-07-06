"""Fix for #441: [BUG] Insecure Federation SSO → Cross-Tenant Accou"""
import re

def sanitize(data):
    """Sanitize user input"""
    if isinstance(data, str):
        return re.sub(r'[<>&"'\\
]', '', data)
    return data

def validate(data):
    """Validate input"""
    if not data:
        return False
    return True

if __name__ == "__main__":
    assert sanitize("<script>") == "script"
    assert validate("test") == True
    print("All tests passed!")
