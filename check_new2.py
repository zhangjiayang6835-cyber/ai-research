import yaml, os, sys, subprocess, socket

def parse_config(config_path):
    """
for i in [17,18,19,20,21,22,23,24,25,26,27,28]:
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}", headers=h)
    Returns:
        dict: Configuration data
    """
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def update_config(config, key, value):
    print()
