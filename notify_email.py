def decrypt_rsa_oaep(ciphertext):
    try:
        # Assume this is the decryption logic that might fail
        plaintext = decrypt_logic(ciphertext)
    except PaddingError:
        return "Decryption failed due to padding error"
    except MacMismatchError:
        return "Decryption failed due to MAC mismatch"

    # Constant-time comparison or further processing
    if constant_time_compare(plaintext, expected_value):
        return plaintext
    else:
        return "Decryption failed for unknown reason"
```
```python
def constant_time_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0