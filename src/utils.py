import hashlib
import hmac


def generate_signature(data, key):
    Generate a signature for data using a key.
    Vulnerable to length extension if using raw hash.
    """
    # FIXED: Using HMAC-SHA256 instead of raw SHA256
    return hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest()


def verify_signature(data, signature, key):
    Verify a signature for data using a key.
    """
    expected = generate_signature(data, key)
    return hmac.compare_digest(signature.encode('utf-8'), expected.encode('utf-8'))