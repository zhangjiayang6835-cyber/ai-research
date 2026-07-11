import os

def load_key(kid):
    valid_kids = ["key1", "key2", "key3"]
    if kid in valid_kids:
        return open(f"/keys/{kid}").read()
    else:
        raise ValueError("Invalid Key ID")

# Example usage
decoded = {"kid": "key1"}
key = load_key(decoded["kid"])