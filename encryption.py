from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import os

# Function to generate a random initialization vector (IV)
def generate_iv():
    return os.urandom(12)  # GCM mode requires a 96-bit IV (12 bytes)

# Function to derive a key from a password
def derive_key(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password.encode())

# Function to encrypt data using AES-GCM
def encrypt_data(data, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = generate_iv()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    tag = encryptor.tag

    return (salt, iv, ciphertext, tag)

# Function to decrypt data using AES-GCM
def decrypt_data(salt, iv, ciphertext, tag, password):
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# Example usage
if __name__ == "__main__":
    password = "supersecretpassword"
    data = "This is a secret message"

    # Encrypt the data
    salt, iv, ciphertext, tag = encrypt_data(data, password)
    print(f"Encrypted: {ciphertext}")

    # Decrypt the data
    decrypted_data = decrypt_data(salt, iv, ciphertext, tag, password)
    print(f"Decrypted: {decrypted_data}")