import json

def safe_merge(target, source):
    target.update(json.loads(json.dumps(source)))
    return target

# Example usage:
user_input = {"__proto__": {"pollute": "global"}}
safe_data = safe_merge({}, user_input)