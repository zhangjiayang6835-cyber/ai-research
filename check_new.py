import yaml, os, sys, subprocess, socket

def load_new_issues(file_path):
    """
for i in [12,13,14,15,16]:
    req = urllib.request.Request(f"https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}", headers=h)
    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
    Returns:
        list: List of new issues
    """
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

def filter_issues_by_severity(issues, severity):
