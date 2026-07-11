```python
import json
from collections import UserDict

class SafeUserInput(UserDict):
    def __setitem__(self, key, value):
        if key in ["__proto__", "constructor.prototype"]:
            raise ValueError("Invalid key")
        super().__setitem__(key, value)

def safe_merge(dict1, dict2):
    safe_dict2 = SafeUserInput(dict2)
    return {**dict1, **safe_dict2}

def main():
    user_input = '{"name": "Alice", "__proto__": {" polluted": true}}'
    try:
        safe_data = json.loads(user_input, object_hook=safe_merge({}, lambda d: {}))
        print("Safe Data:", safe_data)
    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()
```
```python
import json

def sanitize_input(data):
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items() if k not in ["__proto__", "constructor.prototype"]}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    else:
        return data

def safe_merge(dict1, dict2):
    sanitized_dict2 = sanitize_input(dict2)
    merged_data = {**dict1, **sanitized_dict2}
    return merged_data

def main():
    user_input = '{"name": "Alice", "__proto__": {" polluted": true}}'
    try:
        safe_data = json.loads(user_input)
        merged_data = safe_merge({}, safe_data)
        print("Safe Merged Data:", merged_data)
    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()
```