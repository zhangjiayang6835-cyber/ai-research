#!/usr/bin/env python3
"""
Fix for Issue #1489: JWT Kid Injection → Path Traversal → Secret Key Leak

Vulnerability: JWT verification uses the 'kid' (Key ID) header to look up keys
by file path. Attacker injects path traversal in 'kid' to read arbitrary files.

Fix: Whitelist-based key ID lookup. Never trust user-supplied 'kid' as filesystem path.
"""

import hmac, hashlib, json, base64, secrets, time
from typing import Dict, Optional

KEY_STORE: Dict[str, bytes] = {}

def init_keys():
    KEY_STORE.update({
        'key-001': secrets.token_bytes(32),
        'key-002': secrets.token_bytes(32),
        'default': secrets.token_bytes(32),
    })

def b64url_decode(data: str) -> bytes:
    p = 4 - len(data) % 4
    if p != 4: data += '=' * p
    return base64.urlsafe_b64decode(data)

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def verify_jwt_secure(token: str) -> Optional[dict]:
    """Securely verify JWT: whitelist kid, pin algorithm, constant-time HMAC."""
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        hb, pb, sb = parts
        header = json.loads(b64url_decode(hb))
        payload = json.loads(b64url_decode(pb))
        signature = b64url_decode(sb)

        kid = header.get('kid', 'default')
        if '/' in kid or '\\' in kid or '..' in kid:
            print(f"[SEC] Rejected malicious kid: {kid}"); return None
        secret = KEY_STORE.get(kid)
        if not secret: print(f"[SEC] Unknown kid: {kid}"); return None

        alg = header.get('alg', 'HS256')
        if alg != 'HS256': print(f"[SEC] Rejected alg: {alg}"); return None

        sig_input = f"{hb}.{pb}".encode()
        expected = hmac.new(secret, sig_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            print("[SEC] Invalid signature"); return None

        if payload.get('exp', 0) and time.time() > payload['exp']:
            print("[SEC] Token expired"); return None
        return payload
    except Exception as e:
        print(f"[SEC] Malformed: {e}"); return None

def sign_jwt_secure(payload: dict, kid='key-001') -> str:
    secret = KEY_STORE.get(kid)
    if not secret: raise ValueError(f"Unknown kid: {kid}")
    hb = b64url_encode(json.dumps({"alg":"HS256","typ":"JWT","kid":kid}, separators=(',',':')).encode())
    pb = b64url_encode(json.dumps(payload, separators=(',',':')).encode())
    sig = b64url_encode(hmac.new(secret, f"{hb}.{pb}".encode(), hashlib.sha256).digest())
    return f"{hb}.{pb}.{sig}"

if __name__ == '__main__':
    init_keys()
    t = sign_jwt_secure({"sub":"u1","role":"admin","exp":9999999999})
    assert verify_jwt_secure(t), "Valid token failed"
    # Path traversal blocked
    mh = b64url_encode(json.dumps({"alg":"HS256","kid":"../../../etc/passwd"}).encode())
    assert verify_jwt_secure(f"{mh}.eyJzdWIiOiJhIn0.bad") is None, "Path traversal not blocked"
    # Unknown kid blocked
    uh = b64url_encode(json.dumps({"alg":"HS256","kid":"stolen-999"}).encode())
    assert verify_jwt_secure(f"{uh}.eyJzdWIiOiJhIn0.bad") is None, "Unknown kid not blocked"
    # None alg blocked
    nh = b64url_encode(json.dumps({"alg":"none","kid":"key-001"}).encode())
    assert verify_jwt_secure(f"{nh}.eyJzdWIiOiJhIn0.") is None, "None alg not blocked"
    print("All tests passed - Issue #1489 FIXED")
