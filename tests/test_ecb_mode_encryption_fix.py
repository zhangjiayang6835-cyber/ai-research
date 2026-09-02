import inspect

import pytest

import fixes.ecb_mode_encryption_fix as ecb_fix
from fixes.ecb_mode_encryption_fix import EncryptionError, UserDataEncryptor


def test_round_trip_admin_and_user_roles():
    enc = UserDataEncryptor()
    for role in ("admin", "user", "admin_role_user", "user_role_admin"):
        payload = enc.encrypt(role)
        assert enc.decrypt(payload) == role


def test_same_plaintext_yields_distinct_ciphertext():
    enc = UserDataEncryptor()
    first = enc.encrypt("admin")
    second = enc.encrypt("admin")
    assert first.blob != second.blob


def test_nonce_is_random_per_encryption():
    enc = UserDataEncryptor()
    nonces = {enc.encrypt("admin").nonce for _ in range(32)}
    assert len(nonces) == 32


def test_tampered_ciphertext_is_rejected():
    enc = UserDataEncryptor()
    payload = enc.encrypt("admin")
    tampered = bytearray(payload.blob)
    tampered[-1] ^= 0x01
    with pytest.raises(EncryptionError, match="authentication failed"):
        enc.decrypt(type(payload)(bytes(tampered)))


def test_wrong_context_is_rejected():
    enc = UserDataEncryptor()
    payload = enc.encrypt("admin", context=b"user-data-v1")
    with pytest.raises(EncryptionError):
        enc.decrypt(payload, context=b"other-context")


def test_implementation_does_not_use_ecb():
    module_source = inspect.getsource(ecb_fix)
    assert "modes.ECB" not in module_source
    assert "AESGCM" in module_source


def test_invalid_key_length_rejected():
    with pytest.raises(ValueError, match="32-byte"):
        UserDataEncryptor(key=b"too-short")
