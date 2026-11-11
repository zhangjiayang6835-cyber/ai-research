import urllib.request, json, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

token = os.environ["GH_TOKEN"]
headers = {'Authorization': f'token {token}', 'User-Agent': 'monitor-agent'}

def get_json(url):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

for i in range(5, 11):
    comments = get_json(f'https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}/comments')
    issue = get_json(f'https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}')
    title = issue['title'].replace('\U0001f41b', '[bug]').replace('\U0001f4b0', '[money]')
    print(f"=== Issue #{i}: {title[:80]} ===")
    for c in comments:
        body = c['body'].replace('\U0001f41b', '[bug]').replace('\U0001f4b0', '[money]')
        print(f"  Comment {c['id']} by {c['user']['login']}: {body[:400]}")
    print()
