import urllib.request, json, sys, io, ssl
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
ctx = ssl.create_default_context()
h = {"Authorization": f"token {os.environ['GH_TOKEN']}", "User-Agent": "checker"}
for i in [17,18,19,20,21,22,23,24,25,26,27,28]:
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}", headers=h)
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            d = json.loads(r.read())
        print(f"=== #{i} ===")
        print(f"  Title: {d['title'][:100]}")
        print(f"  State: {d['state']}")
    except Exception as e:
        print(f"=== #{i} === ERROR: {e}")
    print()
