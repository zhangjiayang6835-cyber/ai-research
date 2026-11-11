import urllib.request, json, sys, io, ssl
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
ctx = ssl.create_default_context()
h = {"Authorization": "token os.environ["GH_TOKEN"]", "User-Agent": "check-agent"}
for i in [12,13,14,15,16]:
    req = urllib.request.Request(f"https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}", headers=h)
    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
        d = json.loads(r.read())
    print(f"=== Issue #{i} ===")
    title = d["title"].replace("\ud83d\udc1b","[bug]")
    print(f"Title: {title}")
    print(f"Body: {d['body'][:300]}")
    print()
