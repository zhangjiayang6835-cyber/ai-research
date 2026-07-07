import yaml, os, sys, subprocess, socket

def load_issue_config(config_file):
    """
headers = {'Authorization': f'token {token}', 'User-Agent': 'monitor-agent'}

def get_json(url):
    Returns:
        dict: Issue configuration
    """
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def check_issue_status(issue_id):
    title = issue['title'].replace('\U0001f41b', '[bug]').replace('\U0001f4b0', '[money]')
    print(f"=== Issue #{i}: {title[:80]} ===")
    for c in comments:
        body = c['body'].replace('\U0001f41b', '[bug]').replace('\U0001f4b0', '[money]')
        print(f"  Comment {c['id']} by {c['user']['login']}: {body[:400]}")
    print()
