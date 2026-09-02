"""Submission entrypoint for issue #1475: ECB Mode Encryption → Data Leak."""

from fixes.ecb_mode_encryption_fix import EncryptedUserData, UserDataEncryptor


__all__ = ["EncryptedUserData", "UserDataEncryptor"]


if __name__ == "__main__":
    enc = UserDataEncryptor()
    admin = enc.encrypt("admin")
    again = enc.encrypt("admin")
    assert admin.blob != again.blob
    assert enc.decrypt(admin) == "admin"
    print("fix #1475: user data encrypted with AES-256-GCM (random nonce, AEAD)")
