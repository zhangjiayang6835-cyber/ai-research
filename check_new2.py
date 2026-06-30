import yaml, yaml.constructor
import os
import sys

for i in [17,18,19,20,21,22,23,24,25,26,27,28]:
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# ... rest of check_new2.py ...
    except Exception as e:
        print(f"=== #{i} === ERROR: {e}")
    print()
