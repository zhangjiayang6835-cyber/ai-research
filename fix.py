import hashlib
import hmac


def verify_jwt(token, secret):
    """
    Verify JWT token using HMAC-SHA256.
    Protected against hash length extension attacks.
    """
    parts = token.split('.')
    message = f"{parts[0]}.{parts[1]}"
    expected = hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(parts[2].encode('utf-8'), expected.encode('utf-8'))
