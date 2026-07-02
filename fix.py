# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

#!/usr/bin/env python3
"""
Server-Side Prototype Pollution Fix

This module provides safe alternatives to vulnerable recursive merge operations
that can lead to prototype pollution attacks.
"""

import json


def is_dangerous_key(key):
    """
    Check if a key is dangerous and could lead to prototype pollution.
    
    Args:
        key: The key to check
        
    Returns:
        bool: True if the key is dangerous
    """
    dangerous_keys = {'__proto__', 'constructor', 'prototype'}
    return key in dangerous_keys


def safe_merge(target, source):
    """
    Safely merge two dictionaries without allowing prototype pollution.
    
    Args:
        target: The target dictionary to merge into
        source: The source dictionary to merge from
        
    Returns:
        dict: The merged dictionary
    """
    if not isinstance(source, dict):
        return source
    
    if not isinstance(target, dict):
        target = {}
    
    for key in source:
        # Block dangerous keys that could pollute prototypes
        if is_dangerous_key(key):
            continue
        
        value = source[key]
        
        if isinstance(value, dict):
            target[key] = safe_merge(target.get(key, {}), value)
        else:
            target[key] = value
    
    return target


def safe_json_parse(json_string):
    """
    Safely parse JSON without allowing prototype pollution.
    
    Args:
        json_string: The JSON string to parse
        
    Returns:
        The parsed JSON data with prototype pollution protection
    """
    parsed = json.loads(json_string)
    
    if not isinstance(parsed, dict):
        return parsed
    
    return safe_merge({}, parsed)


def safe_json_loads(json_string):
    """
    Alias for safe_json_parse for convenience.
    """
    return safe_json_parse(json_string)


if __name__ == "__main__":
    # Test the fix
    malicious_input = '{"__proto__": {"isAdmin": true}, "constructor": {"prototype": {"hacked": true}}, "name": "test"}'
    result = safe_json_parse(malicious_input)
    print(f"Parsed result: {result}")
    print(f"Has __proto__: {'__proto__' in result}")
    print(f"Has constructor: {'constructor' in result}")
    print(f"Has name: {'name' in result}")
print("fix #194")
