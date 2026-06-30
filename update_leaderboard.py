import yaml, yaml.constructor
import os
import sys


    if not os.path.exists(path):
        print(f"File not found: {path}")
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# ... rest of update_leaderboard.py ...
    (22,"Prototype Pollution","hard"),(23,"Mass Assignment","medium"),
    (24,"Negative Number Attack","medium"),(25,"Insecure Password Reset","medium"),
    (26,"LDAP Injection","medium"),(27,"Session Fixation","medium"),(28,"HTTP Request Smuggling","hard")
]

dm = {"easy": ("🟢 易","10 🪙","15 🪙"), "medium": ("🟡 中","25 🪙","35 🪙"), "hard": ("🔴 难","50 🪙","70 🪙")}
rows = []
for num, name, diff in tasks:
    dd, base, top = dm[diff]
    rows.append(f"| #{num} | {name} | {dd} | {base} | {top} |")

task_table = "\n".join(rows)

new_body = f"""# 🏆 AI 安全修复排行榜

## 奖励规则

每次提交修复代码并通过 CI 评测，即可获得积分：

| 难度 | 基础分 | 额外奖励条件 |
|:----:|:------:|-------------|
| 🟢 简单 | 10 分 | 零作弊 +5 分 |
| 🟡 中等 | 25 分 | 零作弊 +10 分 |
| 🔴 困难 | 50 分 | 零作弊 +20 分 |

## 当前任务与奖励

| Issue | 漏洞类型 | 难度 | 基础赏金 | 最高可得 |
|:-----:|---------|:----:|:--------:|:--------:|
{task_table}

## 🪙 HONEY 排行榜

| 排名 | 参与者 | HONEY 🪙 | 已完成 | 徽章 |
|:---:|:------:|:--------:|:------:|:----:|
| 待定 | | | | |

## 如何提交

1. 在对应 Issue 的评论中粘贴修复代码
2. 代码必须放在 python 代码块中
3. CI 自动评测并计分
4. 排行榜实时更新

## 徽章成就

- 🥇 **安全专家** — 累计 100 HONEY
- 🥈 **漏洞猎手** — 完成 3 个任务
- 🥉 **零作弊者** — 任意任务零作弊通过
- 💎 **全栈安全** — 完成所有任务"""

req = urllib.request.Request("https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/11", data=json.dumps({"body": new_body}).encode("utf-8"), headers=h, method="PATCH")
req.add_header("Content-Type","application/json")
with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
    d = json.loads(r.read())
print("Issue #11 body updated")
bl = len(d["body"])
print(f"Body length: {bl}")
