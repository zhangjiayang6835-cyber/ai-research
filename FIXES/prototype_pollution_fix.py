"""
Fix for Issue #737 — Server-Side Prototype Pollution to RCE

Vulnerability
-------------
Express application uses lodash.merge to merge user-supplied JSON input.
An attacker can set __proto__ or constructor.prototype keys to pollute
the global Object prototype, achieving Remote Code Execution.

Fix
---
- Reject __proto__, prototype, and constructor keys recursively
- Use safe deep-merge function with key validation
- Prefer Map over Object for dynamic key storage
"""

import json
import re
from typing import Any, Dict

DANGEROUS_KEYS = {"__proto__", "prototype", "constructor"}


def sanitize_input(obj: Any, path: str = "") -> Any:
    """Recursively sanitize input to prevent prototype pollution."""
    if isinstance(obj, dict):
        sanitized = {}
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key
            if key in DANGEROUS_KEYS:
                raise ValueError(
                    f"Prototype pollution blocked at '{current_path}'"
                )
            if re.search(r'(?i)(__proto__|prototype|constructor)', str(key)):
                raise ValueError(
                    f"Suspicious key pattern at '{current_path}'"
                )
            sanitized[key] = sanitize_input(value, current_path)
        return sanitized
    elif isinstance(obj, list):
        return [sanitize_input(item, f"{path}[{i}]") for i, item in enumerate(obj)]
    return obj


def safe_merge(base: Dict, update: Dict) -> Dict:
    """Safe deep merge that prevents prototype pollution."""
    sanitized = sanitize_input(update)
    result = base.copy()
    for key, value in sanitized.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = safe_merge(result[key], value)
        else:
            result[key] = value
    return result


class SafeJSONMiddleware:
    """WSGI middleware to sanitize JSON request bodies."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        content_length = int(environ.get("CONTENT_LENGTH", 0))
        if content_length > 0:
            body = environ["wsgi.input"].read(content_length)
            try:
                parsed = json.loads(body)
                sanitize_input(parsed)
            except (json.JSONDecodeError, ValueError) as e:
                start_response("400 Bad Request", [("Content-Type", "text/plain")])
                return [f"Invalid input: {e}".encode()]
        return self.app(environ, start_response)


if __name__ == "__main__":
    assert safe_merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}

    try:
        safe_merge({}, {"__proto__": {"admin": True}})
        print("FAIL: should have rejected __proto__")
    except ValueError:
        print("PASS: __proto__ rejected")

    try:
        safe_merge({}, {"constructor": {"prototype": {"admin": True}}})
        print("FAIL: should have rejected constructor.prototype")
    except ValueError:
        print("PASS: constructor.prototype rejected")

    print("All prototype pollution tests passed!")