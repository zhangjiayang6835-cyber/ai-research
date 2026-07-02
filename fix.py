import hmac
import hashlib
import secrets


def verify_jwt(token, secret):
    expected_sig = hmac.new(
        secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).hexdigest()
    
    # Use constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(
        sig.encode('utf-8'), expected_sig.encode('utf-8')
    ):
        raise ValueError("Invalid signature")
    
    return payload
def create_jwt(payload, secret):
    import base64, json
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
