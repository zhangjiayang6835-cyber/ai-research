```python
import json
from collections import UserDict


class SafeObject(UserDict):
    def __init__(self, data=None):
        super().__init__()
        if data:
            self.update(data)

    @staticmethod
    def safe_parse(json_str):
        obj = json.loads(json_str)
        return SafeObject(obj)

    def update(self, other):
        for key in other.keys():
            if not (key.startswith('__') and key.endswith '__'):
                super().update({key: other[key]})


def main():
    # Demonstrate the fix
    unsafe_input = '{"__proto__": {"pollute": "test"}, "data": "original data"}'
    safe_obj = SafeObject.safe_parse(unsafe_input)
    print(safe_obj)  # Should not include the __proto__ key


if __name__ == "__main__":
    main()
```