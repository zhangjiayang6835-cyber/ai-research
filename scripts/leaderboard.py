#!/usr/bin/env python3
"""
leaderboard.py — AI Research Platform 统一排行榜系统

从 BOUNTY_LEDGER.json + honey_ledger.json 读取数据，
输出 Markdown / JSON / SVG 三种格式。

用法:
    python scripts/leaderboard.py                          # stdout Markdown
    python scripts/leaderboard.py --output LEADERBOARD.md
    python scripts/leaderboard.py --json                   # stdout JSON
    python scripts/leaderboard.py --svg docs/leaderboard.svg
    python scripts/leaderboard.py --all                    # 同时输出全部
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
BOUNTY_PATH = os.path.join(REPO_ROOT, "BOUNTY_LEDGER.json")
HONEY_PATH = os.path.join(REPO_ROOT, "honey_ledger.json")
SVG_PATH = os.path.join(REPO_ROOT, "docs", "leaderboard.svg")


def load_bounties():
    if not os.path.isfile(BOUNTY_PATH):
        return {}
    with open(BOUNTY_PATH, encoding="utf-8") as f:
        return json.load(f)


def load_honey():
    if not os.path.isfile(HONEY_PATH):
        return {}
    with open(HONEY_PATH, encoding="utf-8") as f:
        return json.load(f)


def build_leaderboard_data():
    bounties = load_bounties()
    honey = load_honey()
    participants = {}
    for name, data in bounties.items():
        participants[name] = {
            "name": name,
            "total_honey": data.get("total", 0),
            "task_count": data.get("task_count", 0),
            "submissions": data.get("submissions", []),
            "honey_legacy": 0,
        }
    for name, data in honey.items():
        if name in participants:
            participants[name]["honey_legacy"] = data.get("HONEY", 0)
        else:
            participants[name] = {
                "name": name,
                "total_honey": data.get("HONEY", 0),
                "task_count": len(data.get("tasks", [])),
                "submissions": [],
                "honey_legacy": data.get("HONEY", 0),
            }
    for name, p in participants.items():
        subs = p["submissions"]
        p["recent_count"] = sum(1 for s in subs if s.get("date", "")[:7] >= "2026-07")
        p["clean_count"] = sum(1 for s in subs if s.get("clean"))
        dates = sorted(set(s.get("date", "")[:10] for s in subs if s.get("date")))
        p["streak"] = _calc_streak(dates)
    sorted_p = sorted(participants.values(), key=lambda x: -x["total_honey"])
    medals = []
    if len(sorted_p) >= 1:
        medals.append({"rank": 1, "name": sorted_p[0]["name"], "medal": "\U0001f947", "label": "安全之王"})
    if len(sorted_p) >= 2:
        medals.append({"rank": 2, "name": sorted_p[1]["name"], "medal": "\U0001f948", "label": "漏洞猎手"})
    if len(sorted_p) >= 3:
        medals.append({"rank": 3, "name": sorted_p[2]["name"], "medal": "\U0001f949", "label": "安全新星"})
    by_tasks = sorted(participants.values(), key=lambda x: -x["task_count"])
    return {
        "participants": sorted_p,
        "by_tasks": by_tasks,
        "medals": medals,
        "total_participants": len(sorted_p),
        "total_bounties_paid": sum(p["total_honey"] for p in sorted_p),
        "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def _calc_streak(dates):
    if not dates:
        return 0
    streak = 1
    from datetime import datetime as dt, timedelta
    try:
        cur = dt.strptime(dates[-1], "%Y-%m-%d")
        for i in range(len(dates) - 2, -1, -1):
            d = dt.strptime(dates[i], "%Y-%m-%d")
            if (cur - d).days <= 2:
                streak += 1
                cur = d
            else:
                break
    except ValueError:
        streak = 1
    return streak


def _streak_icon(n):
    if n >= 7:
        return "\U0001f525"
    if n >= 3:
        return "\u2728"
    if n >= 1:
        return "\U0001f331"
    return ""


def _grade_icon(total):
    if total >= 1000:
        return "\U0001f48e"
    if total >= 500:
        return "\U0001f947"
    if total >= 200:
        return "\U0001f948"
    if total >= 50:
        return "\U0001f949"
    return "\U0001f4cb"


def build_markdown(data):
    parts = []
    now = data["last_updated"]
    parts.append("# \U0001f3c6 AI 安全修复排行榜\n")
    parts.append(f"> _更新于 {now}  \u00b7  {data['total_participants']} 名参与者  \u00b7  总计 {data['total_bounties_paid']} \U0001fa99 HONEY_\n")
    parts.append("---\n")
    if data["medals"]:
        parts.append("## \U0001f3c5 颁奖台\n")
        for m in data["medals"]:
            parts.append(f"| {m['medal']} **{m['label']}** | `{m['name']}` |")
        parts.append("")
    parts.append("## \U0001fa99 HONEY 总榜\n")
    parts.append("| 排名 | 参与者 | HONEY \U0001fa99 | 任务数 | 活跃度 | 零作弊 | 徽章 |")
    parts.append("|:---:|:------:|:--------:|:------:|:------:|:------:|:----:|")
    for i, p in enumerate(data["participants"], 1):
        rank_icon = {1: "\U0001f947", 2: "\U0001f948", 3: "\U0001f949"}.get(i, f"{i}")
        parts.append(
            f"| {rank_icon} | `{p['name']}` "
            f"| **{p['total_honey']}** "
            f"| {p['task_count']} "
            f"| {_streak_icon(p['streak'])} {p['streak']}d "
            f"| {'✅' if p['clean_count'] >= p['task_count'] else '—'} "
            f"| {_grade_icon(p['total_honey'])} |"
        )
    parts.append("")
    parts.append("## \U0001f4cb 任务完成榜\n")
    parts.append("| 排名 | 参与者 | 完成任务数 |")
    parts.append("|:---:|:------:|:--------:|")
    for i, p in enumerate(data["by_tasks"], 1):
        parts.append(f"| {i} | `{p['name']}` | {p['task_count']} |")
    parts.append("")
    active = [p for p in data["participants"] if p["recent_count"] > 0]
    if active:
        parts.append("## \U0001f525 近期活跃\n")
        parts.append("| 参与者 | 近7天提交 | HONEY \U0001fa99 |")
        parts.append("|:------:|:--------:|:--------:|")
        for p in sorted(active, key=lambda x: -x["recent_count"])[:5]:
            parts.append(f"| `{p['name']}` | {p['recent_count']} | {p['total_honey']} |")
        parts.append("")
    parts.append("---\n")
    parts.append("### \U0001f4ca 计分规则\n")
    parts.append("| 难度 | 基础分 | 额外奖励 |")
    parts.append("|:----:|:------:|:--------:|")
    parts.append("| \U0001f7e2 简单 | 10 分 | 零作弊 +5 分 |")
    parts.append("| \U0001f7e1 中等 | 25 分 | 零作弊 +10 分 |")
    parts.append("| \U0001f534 困难 | 50 分 | 零作弊 +20 分 |")
    parts.append("")
    parts.append("> \U0001fa99 虚拟代币仅供学习排名使用，不可兑换为现金或加密货币。")
    return "\n".join(parts)


def build_json(data):
    return {
        "meta": {
            "last_updated": data["last_updated"],
            "total_participants": data["total_participants"],
            "total_bounties_paid": data["total_bounties_paid"],
        },
        "medals": data["medals"],
        "leaderboard": [
            {
                "rank": i + 1,
                "name": p["name"],
                "total_honey": p["total_honey"],
                "task_count": p["task_count"],
                "streak_days": p["streak"],
                "clean_count": p["clean_count"],
                "grade": "diamond" if p["total_honey"] >= 1000 else
                        "gold" if p["total_honey"] >= 500 else
                        "silver" if p["total_honey"] >= 200 else
                        "bronze" if p["total_honey"] >= 50 else "participant",
            }
            for i, p in enumerate(data["participants"])
        ],
        "by_tasks": [
            {"rank": i + 1, "name": p["name"], "task_count": p["task_count"]}
            for i, p in enumerate(data["by_tasks"])
        ],
    }


def build_svg(data):
    rows = []
    rows.append('<svg xmlns="http://www.w3.org/2000/svg" width="800" height="HEIGHT" viewBox="0 0 800 HEIGHT">')
    rows.append('<rect width="100%" height="100%" fill="#0d1117"/>')
    rows.append('<style>')
    rows.append('  text { font-family: "SF Mono","Segoe UI",monospace; fill: #c9d1d9; }')
    rows.append('  .title { font-size: 20px; font-weight: bold; fill: #58a6ff; }')
    rows.append('  .header { font-size: 13px; font-weight: bold; fill: #8b949e; }')
    rows.append('  .row { font-size: 13px; }')
    rows.append('  .score { fill: #7ee787; }')
    rows.append('  .line { stroke: #30363d; stroke-width: 1; }')
    rows.append('</style>')
    y = 30
    rows.append(f'<text x="30" y="{y}" class="title">\U0001f3c6 AI Research Leaderboard</text>')
    y += 25
    rows.append(f'<text x="30" y="{y}" class="header">Updated: {data["last_updated"][:10]}</text>')
    y += 30
    rows.append(f'<line x1="20" y1="{y}" x2="780" y2="{y}" class="line"/>')
    y += 8
    rows.append(f'<text x="30" y="{y}" class="header">Rank</text>')
    rows.append(f'<text x="90" y="{y}" class="header">Participant</text>')
    rows.append(f'<text x="400" y="{y}" class="header">HONEY</text>')
    rows.append(f'<text x="500" y="{y}" class="header">Tasks</text>')
    rows.append(f'<text x="600" y="{y}" class="header">Streak</text>')
    y += 5
    rows.append(f'<line x1="20" y1="{y}" x2="780" y2="{y}" class="line"/>')
    medal_emoji = {1: "\U0001f947", 2: "\U0001f948", 3: "\U0001f949"}
    for i, p in enumerate(data["participants"][:10]):
        y += 22
        rank_str = medal_emoji.get(i + 1, f"#{i+1}")
        rows.append(f'<text x="30" y="{y}" class="row">{rank_str}</text>')
        rows.append(f'<text x="90" y="{y}" class="row">{p["name"][:16]}</text>')
        rows.append(f'<text x="400" y="{y}" class="score">{p["total_honey"]}</text>')
        rows.append(f'<text x="500" y="{y}" class="row">{p["task_count"]}</text>')
        rows.append(f'<text x="600" y="{y}" class="row">{_streak_icon(p["streak"])} {p["streak"]}d</text>')
    rows.append(f'<line x1="20" y1="{y + 12}" x2="780" y2="{y + 12}" class="line"/>')
    rows.append('</svg>')
    result = "\n".join(rows).replace("HEIGHT", str(y + 45))
    return result


def main():
    parser = argparse.ArgumentParser(description="Generate AI Research leaderboard")
    parser.add_argument("--output", "-o", type=str, default=None, help="Markdown output path")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    parser.add_argument("--json-output", type=str, default=None, help="JSON output path")
    parser.add_argument("--svg", type=str, default=None, help="SVG output path")
    parser.add_argument("--all", action="store_true", help="Generate all outputs")
    args = parser.parse_args()
    data = build_leaderboard_data()
    if args.json:
        print(json.dumps(build_json(data), indent=2, ensure_ascii=False))
        return 0
    if args.json_output or args.all:
        path = args.json_output or os.path.join(REPO_ROOT, "docs", "leaderboard.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(build_json(data), f, indent=2, ensure_ascii=False)
        print(f"JSON written to {path}")
    if args.svg or args.all:
        path = args.svg or SVG_PATH
        os.makedirs(os.path.dirname(path), exist_ok=True)
        svg = build_svg(data)
        with open(path, "w", encoding="utf-8") as f:
            f.write(svg)
        print(f"SVG written to {path}")
    if args.output or args.all or not any([args.json, args.json_output, args.svg]):
        md = build_markdown(data)
        path = args.output or (os.path.join(REPO_ROOT, "LEADERBOARD.md") if args.all else None)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(md)
            print(f"Markdown written to {path}")
        else:
            print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
