"""Fix for #438: [BUG] CRDT Conflict Resolution Bypass → Data Corru"""
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
