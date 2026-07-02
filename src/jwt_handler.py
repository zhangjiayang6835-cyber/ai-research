import hmac
import hashlib
import base64
import json


def base64url_encode(data):

def sign_token(header, payload, secret):
    """Sign a JWT token using HMAC-SHA256."""
    message = f"{header}.{payload}".encode('utf-8')
    signature = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).digest()
    return base64url_encode(signature)

        return False
    
    expected_signature = sign_token(parts[0], parts[1], secret)
    return hmac.compare_digest(parts[2].encode('utf-8'), expected_signature)


def create_token(payload_data, secret):
    payload_json = json.dumps(payload_data, separators=(',', ':'))
    payload = base64url_encode(payload_json.encode('utf-8'))
    
    signature = sign_token(header.decode('utf-8'), payload.decode('utf-8'), secret)
    
    return f"{header}.{payload}.{signature}"

    if not verify_token(token, secret):
        raise ValueError("Invalid token signature")
    
    payload_json = base64url_decode(parts[1].encode('utf-8'))
    return json.loads(payload_json.decode('utf-8'))


    """Unsafe token creation vulnerable to hash length extension."""
    header = base64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = base64url_encode(json.dumps(payload_data, separators=(',', ':')).encode('utf-8'))
    message = header.decode('utf-8') + "." + payload.decode('utf-8')
    signature = hashlib.sha256(secret.encode('utf-8') + message.encode('utf-8')).hexdigest()
    return f"{header}.{payload}.{signature}"

    """Unsafe token verification vulnerable to hash length extension."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    message = parts[0].encode('utf-8') + b"." + parts[1].encode('utf-8')
    expected = hashlib.sha256(secret.encode('utf-8') + message.encode('utf-8')).hexdigest()
    return parts[2] == expected