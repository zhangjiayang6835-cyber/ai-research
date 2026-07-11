```python
import pickle
import json
from hashlib import sha256
from hmac import new as hmac_new

# Function to sign data using HMAC
def sign_data(data, secret_key):
    return hmac_new(secret_key.encode(), data).hexdigest()

# Function to safely deserialize data
def safe_deserialize(serialized_data, secret_key):
    expected_signature = serialized_data.pop('signature')
    actual_signature = sign_data(json.dumps(serialized_data), secret_key)
    
    if expected_signature != actual_signature:
        raise ValueError("Signature mismatch")
    
    return json.loads(json.dumps(serialized_data))

# Example usage
def main():
    # Simulated cache with signed and deserialized data
    cache = {
        "user_session": {"id": 123, "username": "admin"},
        "signature": sign_data(json.dumps({"id": 123, "username": "admin"}), "secret_key")
    }
    
    try:
        # Safe deserialize using HMAC verification
        deserialized_data = safe_deserialize(cache["user_session"], "secret_key")
        print("Deserialization successful:", deserialized_data)
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```
```python
import pickle
import json
from hashlib import sha256
from hmac import new as hmac_new

# Function to sign data using HMAC
def sign_data(data, secret_key):
    return hmac_new(secret_key.encode(), data).hexdigest()

# Function to safely deserialize data
def safe_deserialize(serialized_data, secret_key):
    expected_signature = serialized_data.pop('signature')
    actual_signature = sign_data(json.dumps(serialized_data), secret_key)
    
    if expected_signature != actual_signature:
        raise ValueError("Signature mismatch")
    
    return json.loads(json.dumps(serialized_data))

# Example usage
def main():
    # Simulated cache with signed and deserialized data
    cache = {
        "user_session": {"id": 123, "username": "admin"},
        "signature": sign_data(json.dumps({"id": 123, "username": "admin"}), "secret_key")
    }
    
    try:
        # Safe deserialize using HMAC verification
        deserialized_data = safe_deserialize(cache["user_session"], "secret_key")
        print("Deserialization successful:", deserialized_data)
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```