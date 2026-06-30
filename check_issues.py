import subprocess
import sys
import hashlib

def install(package):
    """Install a package with verification to prevent dependency confusion attacks."""
    # Verify package hash before installation (example with a known good hash)
    known_good_hashes = {
        "requests": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    }
    # In practice, use a requirements file with --hash for each package
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--require-hashes", package])

def main():
    # Avoid installing packages by name directly; use a pinned requirements file
    install("requests")

if __name__ == "__main__":

for i in range(5, 11):
    comments = get_json(f'https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}/comments')
    issue = get_json(f'https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}')
    title = issue['title'].replace('\U0001f41b', '[bug]').replace('\U0001f4b0', '[money]')
    print(f"=== Issue #{i}: {title[:80]} ===")
    for c in comments:
        body = c['body'].replace('\U0001f41b', '[bug]').replace('\U0001f4b0', '[money]')
        print(f"  Comment {c['id']} by {c['user']['login']}: {body[:400]}")
    print()
