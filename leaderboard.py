import yaml, yaml.constructor
import os
import sys

headers = {'Authorization': f'token {token}', 'User-Agent': 'monitor-agent'}
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# ... rest of leaderboard.py ...
comments = get_json('https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/11/comments')
print('Leaderboard body:')
print(issue['body'][:2000])
print()
print('Comments on leaderboard:')
for c in comments:
    print(f"  Comment {c['id']} by {c['user']['login']}: {c['body'][:400]}")
