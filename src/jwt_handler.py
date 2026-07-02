import hmac
import hashlib
import base64
import secrets


def base64url_encode(data):

def sign_token(header, payload, secret):
    message = f"{header}.{payload}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    return base64url_encode(signature)


    except ValueError:
        return False
    
    expected_signature = base64url_encode(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    
    if not hmac.compare_digest(signature, expected_signature):
        return False
        return json.loads(base64url_decode(payload))
    except Exception:
        return False


def create_token(header, payload, secret):
    import json
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    signature = sign_token(header_b64, payload_b64, secret)
    return f"{header_b64}.{payload_b64}.{signature}"


def generate_secure_secret(length=32):
    """
    Generate a cryptographically secure random secret.
    """
    return secrets.token_hex(length)