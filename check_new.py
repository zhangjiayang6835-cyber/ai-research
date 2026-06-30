import yaml, yaml.constructor
import os
import sys

for i in [12,13,14,15,16]:
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# ... rest of check_new.py ...
    print()
