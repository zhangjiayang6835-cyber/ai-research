import os

def load_key(kid):
    valid_kids = ["key1", "key2", "key3"]
    if kid not in valid_kids:
        raise ValueError("Invalid key ID")
    
    normalized_kid = os.path.normpath(f"/keys/{kid}")
    if ".." in normalized_kid or not normalized_kid.startswith("/keys/"):
        raise ValueError("Invalid path")

    return open(normalized_kid, 'rb').read()