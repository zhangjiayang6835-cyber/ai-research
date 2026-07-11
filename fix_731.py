```python
import struct

def constant_time_compare(val1, val2):
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0

class RSAOAEP:
    def __init__(self, key):
        self.key = key
    
    def decrypt(self, ciphertext):
        # Simulate decryption with potential padding oracle
        if len(ciphertext) < 48:  # Example threshold for OAEP padding length
            return b"Invalid Ciphertext"
        
        # Perform RSA decryption (simplified)
        decrypted = b"DECRYPTED_MESSAGE"  # Placeholder for actual decryption logic
        
        # Simulate padding check with constant-time comparison
        if not constant_time_compare(decrypted, b"VALID_PADDING"):
            return b"Decryption Failed: Invalid Padding"
        
        # Simulate MAC check (simplified)
        mac = b"MAC"  # Placeholder for actual MAC verification logic
        if not constant_time_compare(mac, decrypted[-32:]):
            return b"Decryption Failed: MAC Mismatch"
        
        return b"Decrypted Successfully"

def main():
    key = "RSA_KEY"  # Replace with actual RSA key
    rsa_oaep = RSAOAEP(key)
    
    # Test vectors (example)
    test_ciphertext1 = b"CIPHERTEXT1"  # Valid ciphertext
    test_ciphertext2 = b"CIPHERTEXT2"  # Invalid padding
    
    print("Decrypting valid ciphertext:", rsa_oaepp.decrypt(test_ciphertext1))
    print("Decrypting invalid ciphertext:", rsa_oaep.decrypt(test_ciphertext2))

if __name__ == "__main__":
    main()
```

Note: The actual RSA decryption and MAC verification logic should be implemented based on your specific requirements. This example uses placeholders to demonstrate the constant-time comparison fix for padding oracle vulnerability.