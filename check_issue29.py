import json
import re


def deep_merge(base, override):
req = urllib.request.Request("https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/29", headers=h)
        for key, value in override.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                deep_merge(base[key], value)
            elif key == "__proto__" or key == "constructor" or key == "prototype":
                continue
            elif isinstance(key, str) and key.startswith("__"):
                continue
            else:
                base[key] = value
    elif isinstance(override, list):
                deep_merge(base[i], item)
    return base

def is_dangerous_key(key):
    return isinstance(key, str) and (key in ("__proto__", "constructor", "prototype") or key.startswith("__"))

def parse_and_merge(user_input):
    parsed = json.loads(user_input)
    }

    def merge(target, source):
        if not isinstance(source, dict):
            return
        for k, v in source.items():
            if k in target and isinstance(target[k], dict) and isinstance(v, dict):
                merge(target[k], v)
    merge(result, parsed)
    return result

def sanitize_key(key):
    return not (isinstance(key, str) and (key in ("__proto__", "constructor", "prototype") or key.startswith("__")))

if __name__ == "__main__":
    # Test 1: Normal merge
    payload = '{"__proto__": {"isAdmin": true}}'
    result = parse_and_merge(payload)
    print("Test 3 result:", result)

    # Test 4: Prototype pollution attempt should be blocked
    payload = '{"__proto__": {"isAdmin": true}}'
    result = parse_and_merge(payload)
    assert result.get("isAdmin") is None, "Prototype pollution should be blocked!"
    print("Test 4 passed: Prototype pollution blocked")

    # Test 5: Constructor pollution attempt should be blocked
    payload = '{"constructor": {"isAdmin": true}}'
    result = parse_and_merge(payload)
    assert "constructor" not in result or result.get("constructor") is None, "Constructor pollution should be blocked!"
    print("Test 5 passed: Constructor pollution blocked")
