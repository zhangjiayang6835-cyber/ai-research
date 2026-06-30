import yaml, yaml.constructor
import os
import sys

headers = {'Authorization': f'token {token}', 'User-Agent': 'monitor-agent'}
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return None
    return yaml.safe_load(open(filepath, 'r'))

if __name__ == "__main__":
    if len(sys.argv) > 1:
    comments = get_json(f'https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}/comments')
    issue = get_json(f'https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}')
    title = issue['title'].replace('\U0001f41b', '[bug]').replace('\U0001f4b0', '[money]')
    print(f"=== Issue #{i}: {title[:80]} ===")
    for c in comments:
        body = c['body'].replace('\U0001f41b', '[bug]').replace('\U0001f4b0', '[money]')
        print(f"  Comment {c['id']} by {c['user']['login']}: {body[:400]}")
    print()
