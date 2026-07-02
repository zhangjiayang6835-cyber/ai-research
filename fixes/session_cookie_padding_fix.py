#!/usr/bin/env python3
"""Fix #268: Padding Oracle Attack on Encrypted Session Cookies.

Root cause: Session cookies encrypted with unauthenticated AES-CBC allow
a padding oracle attack (Vaudenay 2002). An attacker recovers plaintext
by observing server error responses.

Defense: AES-256-GCM authenticated encryption with HKDF key derivation,
AAD binding, constant-time comparison, single error for all failure modes.
"""

from __future__ import annotations
import base64, hmac, os, secrets, struct, time
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_MAGIC = b'SC1'; _HDR_STRUCT = '>3sBBQ'
_HDR_LEN = struct.calcsize(_HDR_STRUCT)
_NONCE_LEN = 12; _TAG_LEN = 16

class InvalidSession(Exception): pass

@dataclass
class SecureCookie:
    value: bytes; issued_at: int; key_id: int

class SessionCookieCodec:
    def __init__(self, master_key=None):
        self._master_key = master_key or secrets.token_bytes(32)
        self._keys = {0: self._master_key}
        self._current_kid = 0

    def _derive_key(self, kid, purpose):
        info = f'session-cookie-v1|kid={kid}|purpose={purpose}'.encode()
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(self._keys[kid])

    def encrypt(self, value, cookie_name='session', ttl=3600):
        enc_key = self._derive_key(self._current_kid, 'encrypt')
        iv = secrets.token_bytes(_NONCE_LEN)
        now = int(time.time())
        header = struct.pack(_HDR_STRUCT, _MAGIC, 1, self._current_kid, now)
        aesgcm = AESGCM(enc_key)
        ciphertext = aesgcm.encrypt(iv, value, cookie_name.encode())
        payload = header + iv + ciphertext
        return base64.urlsafe_b64encode(payload).rstrip(b'=').decode()

    def decrypt(self, token, cookie_name='session', max_age=86400):
        try:
            raw = base64.urlsafe_b64decode(token + '=' * (4 - len(token) % 4))
        except Exception:
            raise InvalidSession('invalid session')
        if len(raw) < _HDR_LEN + _NONCE_LEN + _TAG_LEN:
            raise InvalidSession('invalid session')
        header = raw[:_HDR_LEN]
        magic, version, kid, issued_at = struct.unpack(_HDR_STRUCT, header)
        if magic != _MAGIC or version != 1:
            raise InvalidSession('invalid session')
        key = self._keys.get(kid)
        if key is None:
            raise InvalidSession('invalid session')
        enc_key = self._derive_key(kid, 'encrypt')
        iv = raw[_HDR_LEN:_HDR_LEN + _NONCE_LEN]
        ciphertext = raw[_HDR_LEN + _NONCE_LEN:]
        aesgcm = AESGCM(enc_key)
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, cookie_name.encode())
        except Exception:
            raise InvalidSession('invalid session')
        if max_age > 0 and int(time.time()) - issued_at > max_age:
            raise InvalidSession('invalid session')
        return SecureCookie(value=plaintext, issued_at=issued_at, key_id=kid)

if __name__ == '__main__':
    codec = SessionCookieCodec()
    token = codec.encrypt(b'user_id=42', 'session', ttl=3600)
    s = codec.decrypt(token, 'session')
    assert s.value == b'user_id=42', 'roundtrip failed'
    try:
        codec.decrypt(token + 'x', 'session')
        assert False, 'tampered should fail'
    except InvalidSession: pass
    print('OK: all checks pass')
