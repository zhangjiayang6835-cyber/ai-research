import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Function to perform constant-time comparison
def constant_time_compare(a, b):
    if len(a)!= len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

# Function to generate a random key
def generate_random_key(key_size):
    return os.urandom(key_size)

# RSA-OAEP decryption function with constant-time error handling
def rsa_oaep_decrypt(private_key, ciphertext, label=b''):
    try:
        # Perform RSA-OAEP decryption
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label
            )
        )
        
        # Simulate MAC verification (for demonstration purposes)
        expected_mac = generate_random_key(16)
        actual_mac = generate_random_key(16)
        
        # Constant-time MAC comparison
        if not constant_time_compare(expected_mac, actual_mac):
            raise ValueError("MAC verification failed")
        
        return plaintext
    
    except Exception as e:
        # Return a uniform error message for all decryption failures
        return "Decryption failed"

# Example usage
if __name__ == "__main__":
    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Encrypt some data
    message = b"Hello, RSA-OAEP!"
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the ciphertext
    decrypted_message = rsa_oaep_decrypt(private_key, ciphertext)
    print(decrypted_message)

    # Test with Bleichenbacher test vectors
    # (This part is for demonstration; actual test vectors should be used)
    bleichenbacher_test_vectors = [
        b"Test vector 1",
        b"Test vector 2",
        b"Test vector 3"
    ]
    for test_vector in bleichenbacher_test_vectors:
        encrypted_test_vector = public_key.encrypt(
            test_vector,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_test_vector = rsa_oaep_decrypt(private_key, encrypted_test_vector)
        print(f"Test vector: {test_vector} -> Decrypted: {decrypted_test_vector}")