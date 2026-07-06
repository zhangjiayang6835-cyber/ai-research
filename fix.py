"""
Server-Side Prototype Pollution to RCE Chain - Security Fix

This module provides protection against prototype pollution attacks
that can lead to Remote Code Execution (RCE) in server-side JavaScript
and Python environments.
"""

import json
import re
from typing import Any, Dict, Optional


class PrototypePollutionGuard:
    """Guard against prototype pollution attacks in object merging operations."""

    # Dangerous keys that could lead to prototype pollution
    DANGEROUS_KEYS = {
        '__proto__',
        'constructor',
        'prototype',
        '__defineGetter__',
        '__defineSetter__',
        '__lookupGetter__',
        '__lookupSetter__',
    }

    # Dangerous key patterns (for nested access)
    DANGEROUS_PATTERNS = [
        re.compile(r'__proto__', re.IGNORECASE),
        re.compile(r'\.constructor\b'),
        re.compile(r'\.prototype\b'),
    ]

    @classmethod
    def sanitize_key(cls, key: str) -> str:
        """Sanitize a single key to prevent prototype pollution."""
        if key in cls.DANGEROUS_KEYS:
            raise ValueError(f"Dangerous key detected: {key}")
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(key):
                raise ValueError(f"Dangerous key pattern detected: {key}")
        return key

    @classmethod
    def safe_merge(cls, target: Dict[str, Any], source: Dict[str, Any],
                   max_depth: int = 20) -> Dict[str, Any]:
        """Safely merge two dictionaries, blocking prototype pollution vectors."""
        return cls._safe_merge_recursive(target, source, max_depth, depth=0)

    @classmethod
    def _safe_merge_recursive(cls, target: Dict[str, Any], source: Dict[str, Any],
                              max_depth: int, depth: int) -> Dict[str, Any]:
        """Recursive safe merge with depth limit and key sanitization."""
        if depth > max_depth:
            raise ValueError(f"Maximum merge depth exceeded: {max_depth}")

        for key, value in source.items():
            safe_key = cls.sanitize_key(str(key))

            if (safe_key in target and isinstance(target[safe_key], dict)
                    and isinstance(value, dict)):
                target[safe_key] = cls._safe_merge_recursive(
                    target[safe_key], value, max_depth, depth + 1
                )
            else:
                target[safe_key] = value

        return target

    @classmethod
    def safe_json_parse(cls, json_string: str,
                        object_hook: Optional[callable] = None) -> Any:
        """Parse JSON safely, preventing prototype pollution via object_hook."""
        def safe_object_hook(pairs):
            result = {}
            for key, value in pairs:
                safe_key = cls.sanitize_key(str(key))
                result[safe_key] = value
            if object_hook:
                return object_hook(result)
            return result

        return json.loads(json_string, object_pairs_hook=safe_object_hook)


# Convenience function for quick usage
safe_merge = PrototypePollutionGuard.safe_merge
safe_json_parse = PrototypePollutionGuard.safe_json_parse
# 1782921258

print("fix #194")
