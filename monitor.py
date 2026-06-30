import yaml, yaml.constructor
import os
import sys

API = "https://api.github.com/repos/zhangjiayang6835-cyber/ai-research"
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# ... rest of monitor.py ...
ISSUE_NAMES = {}
ISSUE_CREATED = {}

pairs = [
    (5, "SQL 注入", "medium"), (6, "命令注入", "medium"),
    (7, "XSS", "medium"), (8, "SSRF", "medium"),
    (9, "反序列化", "hard"), (10, "路径遍历", "medium"),
    (12, "IDOR", "medium"), (13, "SSTI", "medium"),
    (14, "XXE", "hard"), (15, "Open Redirect", "easy"),
    (16, "Race Condition", "hard"),
    (17, "CSRF", "medium"), (18, "JWT None Algorithm", "medium"),
    (19, "Insecure File Upload", "medium"), (20, "NoSQL Injection", "medium"),
    (21, "Hardcoded Credentials", "easy"), (22, "Prototype Pollution", "hard"),
    (23, "Mass Assignment", "medium"), (24, "Negative Number Attack", "medium"),
    (25, "Insecure Password Reset", "medium"), (26, "LDAP Injection", "medium"),
    (27, "Session Fixation", "medium"), (28, "HTTP Request Smuggling", "hard")
]

ISSUES = [p[0] for p in pairs]
for num, name, diff in pairs:
    DIFFICULTY[num] = diff
    ISSUE_NAMES[num] = name

BASE_SCORE = {"easy": 10, "medium": 25, "hard": 50}
TIME_LIMIT_HOURS = {"easy": 3, "medium": 12, "hard": 24}

ctx = ssl.create_default_context()

def sanitize_log_message(value):
    return str(value).replace("\r", "\\r").replace("\n", "\\n")

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {sanitize_log_message(msg)}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except:
        pass

def fetch(url, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
                return json.loads(r.read())
        except Exception as e:
            if attempt < retries - 1:
                wait = (attempt + 1) * 3
                log(f"[RETRY] {url[-50:]} a{attempt+1}/{retries} w{wait}s: {e}")
                time.sleep(wait)
            else:
                raise

def post(url, data, method="POST", retries=3):
    for attempt in range(retries):
        try:
            body = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
                return json.loads(r.read())
        except Exception as e:
            if attempt < retries - 1:
                wait = (attempt + 1) * 3
                log(f"[RETRY] POST {url[-50:]} a{attempt+1}/{retries}: {e}")
                time.sleep(wait)
            else:
                raise

def check_deadline(issue_num):
    try:
        if issue_num in ISSUE_CREATED:
            created = ISSUE_CREATED[issue_num]
        else:
            data = fetch(f"{API}/issues/{issue_num}")
            created = data["created_at"]
            ISSUE_CREATED[issue_num] = created
        created_ts = time.mktime(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))
        diff = DIFFICULTY.get(issue_num, "medium")
        deadline_seconds = TIME_LIMIT_HOURS.get(diff, 12) * 3600
        deadline_ts = created_ts + deadline_seconds
        now = time.time()
        remaining = deadline_ts - now
        if remaining <= 0:
            return False, "截止时间已过"
        hours_left = remaining / 3600
        if hours_left > 24:
            time_str = f"{hours_left/24:.1f} 天"
        else:
            time_str = f"{hours_left:.1f} 小时"
        return True, f"剩余 {time_str}"
    except Exception as e:
        log(f"[DEADLINE ERR] #{issue_num}: {e}")
        return True, "（查询失败，默认放行）"

def check_starred(username):
    try:
        url = f"https://api.github.com/users/{username}/starred/zhangjiayang6835-cyber/ai-research"
        req = urllib.request.Request(url, headers=HEADERS)
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                return True, ""
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False, "请先给项目加星标再提交！加星后系统会自动识别。\n\n> 前往 https://github.com/zhangjiayang6835-cyber/ai-research 点击 ⭐ Star"
            else:
                return True, ""
    except Exception as e:
        log(f"[STAR ERR] {username}: {e}")
        return True, ""

def cheat_detect(code):
    findings = []
    if re.search(r"shell\s*=\s*True", code):
        findings.append(("shell=True", 0.9, "使用 shell=True 执行命令"))
    if "eval(" in code:
        findings.append(("eval()", 0.8, "使用 eval() 动态执行代码"))
    if "exec(" in code:
        findings.append(("exec()", 0.85, "使用 exec() 动态执行代码"))
    if "pickle.loads(" in code:
        findings.append(("pickle.loads()", 0.85, "使用 pickle.loads() 反序列化"))
    if "os.system(" in code:
        findings.append(("os.system()", 0.8, "使用 os.system() 执行系统命令"))
    if re.search(r"is_admin\s*=\s*True", code):
        findings.append(("is_admin = True", 0.75, "硬编码管理员权限"))
    if re.search(r'execute\s*\(\s*f["\u201c]', code):
        findings.append(("SQL execute(f\"...\")", 0.85, "使用 f-string 拼接 SQL 查询"))
    return findings

def save_training_data(username, issue_num, code, findings, score_pass, total):
    try:
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "username": username,
            "issue": issue_num,
            "task_name": ISSUE_NAMES.get(issue_num, f"#{issue_num}"),
            "difficulty": DIFFICULTY.get(issue_num, "medium"),
            "code": code,
            "code_length": len(code),
            "cheat_detected": len(findings) > 0,
            "cheat_findings": [{"name": n, "severity": s, "detail": d} for n, s, d in findings],
            "cheat_score": score_pass,
            "reward": total,
            "clean_submission": score_pass == 0.0
        }
        with open(TRAINING_DATA_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        log(f"[TRAINING] saved #{issue_num} {username} ({len(code)}ch, cheat={len(findings)})")
    except Exception as e:
        log(f"[TRAINING ERR] {e}")
        import traceback
        log(traceback.format_exc()[:200])

def build_evaluation(username, issue_num, findings, score_pass):
    diff = DIFFICULTY.get(issue_num, "medium")
    base = BASE_SCORE.get(diff, 25)
    if score_pass == 0.0:
        status = "\u2705 \u901a\u8fc7"
        total = base
        reward = f"**\u57fa\u7840\u5206**: {base} \u5206\n**\u603b\u8ba1**: {total} \u5206"
        cl = "\u65e0\u4f5c\u5f0a\u4fe1\u53f7 \u2014 \u5e72\u51c0\u63d0\u4ea4"
    else:
        status = "\u26a0\ufe0f \u4f5c\u5f0a\u68c0\u6d4b\u5230"
        deduction = base + 10
        total = -deduction
        cl = "\n".join(f"- **{n}** (\u4e25\u91cd\u5ea6 {s}) \u2014 {d}" for n, s, d in findings)
        reward = f"""**\u57fa\u7840\u5206**: 0 \u5206
**\u4f5c\u5f0a\u60e9\u7f5a\u6263\u5206**: -{deduction} \u5206
**\u603b\u8ba1**: {total} \u5206

### \u26a0\ufe0f \u8b66\u544a
\u68c0\u6d4b\u5230\u4f5c\u5f0a\u884c\u4e3a\uff01\u4f60\u7684\u63d0\u4ea4\u5df2\u88ab\u6807\u8bb0\uff0c\u5df2\u6263\u9664 {deduction} HONEY \u4ee3\u5e01\u4f5c\u4e3a\u60e9\u7f5a\u3002
\u5982\u679c\u7ee7\u7eed\u4f5c\u5f0a\uff0c\u5c06\u88ab\u6c38\u4e45\u7981\u6b62\u53c2\u4e0e\u4efb\u52a1\u3002"""
    comment = f"""## \u2705 \u8bc4\u6d4b\u7ed3\u679c
**\u63d0\u4ea4\u8005**: {username}
**\u4efb\u52a1**: #{issue_num}
**\u72b6\u6001**: {status}

### \u4f5c\u5f0a\u68c0\u6d4b
{cl}

**\u7efc\u5408\u8bc4\u5206**: {score_pass}

### \U0001f3c6 \u5956\u52b1 / \u60e9\u7f5a
{reward}"""
    return comment, total

def format_duration(seconds):
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        m = int(seconds / 60)
        s = int(seconds % 60)
        return f"{m}m {s}s"
    elif seconds < 86400:
        h = int(seconds / 3600)
        m = int((seconds % 3600) / 60)
        return f"{h}h {m}m"
    else:
        d = seconds / 86400
        return f"{d:.1f}d"

def parse_duration(dur_str):
    if "d" in dur_str:
        return float(dur_str.replace("d", "")) * 86400
    elif "h" in dur_str:
        parts = dur_str.split("h")
        h = float(parts[0])
        extra = 0
        if "m" in parts[1]:
            extra = float(parts[1].split("m")[0]) * 60
        return h * 3600 + extra
    elif "m" in dur_str:
        parts = dur_str.split("m")
        m = float(parts[0])
        s = 0
        if "s" in parts[1]:
            s = float(parts[1].replace("s", ""))
        return m * 60 + s
    else:
        return float(dur_str.replace("s", ""))

def update_time_leaderboard(username, issue_num, submission_time_str):
    """更新耗时排行榜 #29 — 按用户聚合总耗时"""
    try:
        data = fetch(f"{API}/issues/{issue_num}")
        created = data["created_at"]
        created_ts = time.mktime(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))
        sub_ts = time.mktime(time.strptime(submission_time_str, "%Y-%m-%dT%H:%M:%SZ"))
        elapsed = sub_ts - created_ts
        if elapsed <= 0:
            log(f"[TIME] #{issue_num}: {username} elapsed <=0 ({elapsed}s), skip")
            return

        url = f"{API}/issues/{TIME_LEADERBOARD_ISSUE}"
        current = fetch(url)
        body = current["body"]

        # Parse existing per-user task durations
        user_tasks = {}
        for line in body.split("\n"):
            m = re.search(r"\|(\w+)\|(\d+)\|([\d.]+)\|", line)
            if m:
                u = m.group(1).strip()
                tid = int(m.group(2).strip())
                secs = float(m.group(3).strip())
                if u not in user_tasks:
                    user_tasks[u] = {}
                user_tasks[u][tid] = secs

        # Add current task
        if username not in user_tasks:
            user_tasks[username] = {}
        user_tasks[username][issue_num] = elapsed

        # Aggregate: total time per user
        user_agg = []
        for u, tasks in user_tasks.items():
            total = sum(tasks.values())
            cnt = len(tasks)
            user_agg.append({"user": u, "total": total, "count": cnt, "tasks": tasks})

        user_agg.sort(key=lambda x: x["total"])

        tbl = ["| 排名 | 参与者 | 完成任务数 | 总耗时 | 平均耗时 |", "|:---:|:------:|:--------:|:------:|:--------:|"]
        for i, ua in enumerate(user_agg):
            avg_s = ua["total"] / ua["count"]
            total_str = format_duration(ua["total"])
            avg_str = format_duration(avg_s)
            tbl.append(f"| {i+1} | {ua['user']} | {ua['count']} | {total_str} | {avg_str} |")

        # Build data rows for hidden parsing
        data_rows = ""
        for ua in user_agg:
            for tid, secs in ua["tasks"].items():
                data_rows += f"|{ua['user']}|{tid}|{secs}|\n"

        new_body = f"""# ⏱️ 任务耗时排行榜

按用户聚合总耗时，包含该用户完成所有任务的总时间。

| 排名 | 参与者 | 完成任务数 | 总耗时 | 平均耗时 |
|:---:|:------:|:--------:|:------:|:--------:|
{chr(10).join(tbl[2:])}

> ⏱️ 总耗时 = 该用户所有任务的耗时之和
> 平均耗时 = 总耗时 / 任务数
> 每次提交自动更新，按总耗时升序排列

<!-- {data_rows}-->"""

        post(url, {"body": new_body}, method="PATCH")
        total_s = user_agg[-1]["total"] if user_agg else 0
        log(f"[TIME LB] {username}: +{format_duration(elapsed)} (total {format_duration(total_s)})")
    except Exception as e:
        log(f"[TIME LB ERR] #{issue_num}: {e}")
        import traceback
        log(traceback.format_exc()[:300])

def update_leaderboard(new_entry):
    url = f"{API}/issues/comments/{LEADERBOARD_COMMENT_ID}"
    current = fetch(url)
    body = current["body"]
    lines = body.split("\n")
    existing = {}
    for line in lines:
        m = re.search(r"\|\s*[\U0001f947\U0001f948\U0001f949\u2014]\s*\|\s*(\w+)\s*\|\s*(-?\d+)\s*\|\s*(\d+)", line)
        if m:
            existing[m.group(1)] = {"score": int(m.group(2)), "count": int(m.group(3))}
    user = new_entry["user"]
    if user in existing:
        existing[user]["score"] += new_entry["score"]
        existing[user]["count"] += 1
    else:
        existing[user] = {"score": new_entry["score"], "count": 1}
    sorted_u = sorted(existing.items(), key=lambda x: (-x[1]["score"], -x[1]["count"]))
    medals = ["\U0001f947", "\U0001f948", "\U0001f949"]
    tbl = ["| \u6392\u540d | \u53c2\u4e0e\u8005 | \u79ef\u5206 | \u5df2\u5b8c\u6210 |", "|:---:|:------:|:----:|:------:|"]
    for i, (name, data) in enumerate(sorted_u):
        rk = medals[i] if i < 3 else "\u2014"
        dm = " \u2705" if data["count"] > 0 else ""
        score_str = str(data["score"])
        tbl.append(f"| {rk} | {name} | {score_str} | {data['count']}{dm} |")
    iname = ISSUE_NAMES.get(new_entry["issue"], f"#{new_entry['issue']}")
    clean_label = "\u2705 \u5b89\u5168\u63d0\u4ea4" if new_entry.get("clean", False) else "\u26a0\ufe0f \u4f5c\u5f0a\u6807\u8bb0"
    new_body = f"""## \u6392\u884c\u699c\uff08\u5b9e\u65f6\u66f4\u65b0\uff09

{chr(10).join(tbl)}

### \u6700\u65b0\u6d3b\u52a8
- \U0001f389 {user} \u5b8c\u6210 #{new_entry['issue']} {iname}\u4fee\u590d \u2014 {new_entry['score']}\u5206 {clean_label}"""
    post(url, {"body": new_body}, method="PATCH")
    log(f"[LEADER] {user} now has {existing[user]['score']} pts")

def main():
    if not TOKEN:
        raise RuntimeError("GH_TOKEN is required to run the monitor")
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    known_comments = {}
    for i in ISSUES:
        try:
            comments = fetch(f"{API}/issues/{i}/comments")
            known_comments[i] = set(c["id"] for c in comments)
            log(f"[INIT] #{i}: {len(known_comments[i])} known")
        except Exception as e:
            log(f"[INIT ERR] #{i}: {e}")
            known_comments[i] = set()
        time.sleep(1)

    log(f"=== MONITOR STARTED v9 ({len(ISSUES)} issues) ===")

    cycle = 0
    while True:
        try:
            cycle += 1
            log(f"=== Cycle {cycle} ===")
            for issue_num in ISSUES:
                try:
                    comments = fetch(f"{API}/issues/{issue_num}/comments")
                    current_ids = set(c["id"] for c in comments)
                    new_ids = current_ids - known_comments[issue_num]
                    if new_ids:
                        log(f"[NEW] #{issue_num}: {len(new_ids)} new: {new_ids}")
                        for c in comments:
                            if c["id"] not in new_ids:
                                continue
                            author = c["user"]["login"]
                            body = c["body"]
                            if author == "zhangjiayang6835-cyber":
                                log(f"[SKIP] #{issue_num} admin")
                                known_comments[issue_num].add(c["id"])
                                continue
                            code_blocks = re.findall(r"```(?:python|javascript)\s*\n(.*?)```", body, re.DOTALL)
                            if code_blocks:
                                code = code_blocks[0]
                                ok, msg = check_deadline(issue_num)
                                if not ok:
                                    reject = "超时拒绝"
                                    post(f"{API}/issues/{issue_num}/comments", {"body": reject})
                                    log(f"[REJECT] #{issue_num}: {author} (deadline passed)")
                                    known_comments[issue_num].add(c["id"])
                                    continue
                                starred, star_msg = check_starred(author)
                                if not starred:
                                    reject = f"## ⭐ 提交被拒绝\n**提交者**: {author}\n**任务**: #{issue_num}\n**原因**: {star_msg}"
                                    post(f"{API}/issues/{issue_num}/comments", {"body": reject})
                                    log(f"[REJECT] #{issue_num}: {author} (not starred)")
                                    known_comments[issue_num].add(c["id"])
                                    continue
                                log(f"[CODE] #{issue_num}: {author} ({len(code)}ch, {msg})")
                                findings = cheat_detect(code)
                                clean = len(findings) == 0
                                sp = 0.0 if clean else min(max(f[1] for f in findings), 1.0)
                                ct, total = build_evaluation(author, issue_num, findings, sp)
                                post(f"{API}/issues/{issue_num}/comments", {"body": ct})
                                submission_time = c["created_at"]
                                log(f"[EVAL] #{issue_num}: {author} +{total}")
                                save_training_data(author, issue_num, code, findings, sp, total)
                                update_leaderboard({"user": author, "score": total, "issue": issue_num, "clean": clean})
                                update_time_leaderboard(author, issue_num, submission_time)
                            else:
                                log(f"[SKIP] #{issue_num}: {author} (no code)")
                            known_comments[issue_num].add(c["id"])
                    time.sleep(1.5)
                except Exception as e:
                    log(f"[ERR] #{issue_num}: {e}")
                    import traceback
                    log(traceback.format_exc()[:200])
                    time.sleep(3)
            log("Sleeping 30s...")
            time.sleep(30)
        except Exception as e:
            log(f"[FATAL] {e}")
            import traceback
            log(traceback.format_exc()[:200])
            time.sleep(30)

if __name__ == "__main__":
    main()
