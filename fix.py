import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def vulnerable_decrypt(ciphertext, key):
    """Vulnerable: CBC mode without MAC, vulnerable to padding oracle"""
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

def fixed_encrypt(plaintext, key):
    """Fixed: Use AES-GCM which provides authentication"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def fixed_decrypt(ciphertext, key):
    """Fixed: Use AES-GCM which verifies authenticity"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext
