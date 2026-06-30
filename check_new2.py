import yaml
import os
import sys
from yaml import SafeLoader

def load_config(config_path):
    """
        req = urllib.request.Request(f"https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}", headers=h)
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            d = json.loads(r.read())
        print(f"=== #{i} ===")
        print(f"  Title: {d['title'][:100]}")
        print(f"  State: {d['state']}")
        return None
    
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def main():
    if len(sys.argv) > 1:
