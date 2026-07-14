#!/usr/bin/env python3
"""
update_leaderboard.py — Create/update leaderboard Issue with latest data.

Called by CI after each evaluation.  Creates or updates the leaderboard
Issue (#LEADERBOARD_ISSUE) with the latest rankings.

Usage:
    python scripts/update_leaderboard.py
    python scripts/update_leaderboard.py --issue-number 42
"""

import argparse
import json
import os
import sys
import urllib.request
import ssl

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)

# Default issue to post the leaderboard to.
# Change this if #11 is permanently deleted; pick a new number.
LEADERBOARD_ISSUE = 650


def get_token() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("FATAL: No GitHub token found in GH_TOKEN or GITHUB_TOKEN", file=sys.stderr)
        sys.exit(1)
    return token


def api(method: str, path: str, data: dict = None) -> dict:
    token = get_token()
    url = f"https://api.github.com{path}"
    headers = {
        "Authorization": f"token {token}",
        "User-Agent": "leaderboard-updater",
        "Accept": "application/vnd.github+json",
    }
    body = json.dumps(data).encode("utf-8") if data else None
    if data:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 410:
            print(f"GONE: {url} — resource deleted", file=sys.stderr)
            return {}
        if e.code == 404:
            print(f"NOT_FOUND: {url}", file=sys.stderr)
            return {}
        raise


def create_or_update_issue(issue_number: int, body: str, title: str = None) -> int:
    """
    Create or update the leaderboard issue.
    Returns the issue number.
    """
    if not title:
        title = "🏆 AI 安全修复排行榜"

    # Check if issue exists
    existing = api("GET", f"/repos/zhangjiayang6835-cyber/ai-research/issues/{issue_number}")

    if existing and existing.get("state") == "open":
        # Update existing
        api("PATCH", f"/repos/zhangjiayang6835-cyber/ai-research/issues/{issue_number}", {
            "title": title,
            "body": body,
        })
        print(f"Updated Issue #{issue_number}")
        return issue_number
    else:
        # Create new
        # Find first available number
        for num in range(issue_number, issue_number + 100):
            check = api("GET", f"/repos/zhangjiayang6835-cyber/ai-research/issues/{num}")
            if not check or check.get("state") == "closed":
                new_issue = api("POST", "/repos/zhangjiayang6835-cyber/ai-research/issues", {
                    "title": title,
                    "body": body,
                    "labels": ["leaderboard"],
                })
                if new_issue:
                    print(f"Created Issue #{new_issue['number']}")
                    return new_issue["number"]
        print("FATAL: Could not create issue", file=sys.stderr)
        return 0


def main():
    parser = argparse.ArgumentParser(description="Update leaderboard Issue")
    parser.add_argument("--issue-number", type=int, default=LEADERBOARD_ISSUE,
                        help=f"Issue number for leaderboard (default: {LEADERBOARD_ISSUE})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the leaderboard body without updating")
    args = parser.parse_args()

    # Import the leaderboard module from the same directory
    sys.path.insert(0, HERE)
    import leaderboard

    data = leaderboard.build_leaderboard_data()
    body = leaderboard.build_markdown(data)

    if args.dry_run:
        print(body)
        return 0

    issue_num = create_or_update_issue(args.issue_number, body)
    if not issue_num:
        print("Failed to create/update issue", file=sys.stderr)
        return 1

    # Also regenerate SVG and JSON locally
    svg_path = os.path.join(REPO_ROOT, "docs", "leaderboard.svg")
    json_path = os.path.join(REPO_ROOT, "docs", "leaderboard.json")
    os.makedirs(os.path.dirname(svg_path), exist_ok=True)

    svg = leaderboard.build_svg(data)
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"SVG written to {svg_path}")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(leaderboard.build_json(data), f, indent=2, ensure_ascii=False)
    print(f"JSON written to {json_path}")

    print(f"\n✅ Leaderboard updated in Issue #{issue_num}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
