import yaml, yaml.constructor
import os
import sys

req = urllib.request.Request("https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/29", headers=h)
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# ... rest of check_issue29.py ...
