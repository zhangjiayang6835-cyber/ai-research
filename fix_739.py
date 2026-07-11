```python
import json
from hmac import new as hmac_new
import hashlib
import base64

def secure_cache(data, secret_key):
    """
    Securely cache data by signing it with HMAC and then serializing it to JSON.
    
    :param data: The data to be cached (must be JSON-serializable).
    :param secret_key: A secret key used for HMAC signing.
    :return: A dictionary containing the signed, JSON-serialized data.
    """
    json_data = json.dumps(data)
    signature = hmac_new(secret_key.encode(), json_data.encode(), hashlib.sha256).hexdigest()
    return {
        'data': json_data,
        'signature': signature
    }

def verify_cache(cache_item, secret_key):
    """
    Verify the cache item's signature and deserialize its data.
    
    :param cache_item: A dictionary containing cached data and its signature.
    :param secret_key: The secret key used for HMAC signing.
    :return: The deserialized JSON data if verification is successful; otherwise, raise an error.
    """
    expected_signature = hmac_new(secret_key.encode(), cache_item['data'].encode(), hashlib.sha256).hexdigest()
    if expected_signature != cache_item['signature']:
        raise ValueError("Cache item signature does not match!")
    
    return json.loads(cache_item['data'])

def main():
    # Example data to be cached
    example_data = {'key': 'value'}
    secret_key = 'my_secret_key'

    # Cache the secure data
    cache_item = secure_cache(example_data, secret_key)
    print("Cached item:", cache_item)

    # Verify and deserialize the cached data
    try:
        deserialized_data = verify_cache(cache_item, secret_key)
        print("Deserialized data:", deserialized_data)
    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()
```