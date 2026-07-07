import urllib.request, urllib.error, json, sys, io, time, re, os, ssl

TOKEN = os.environ.get("GH_TOKEN", "")
HEADERS = {"Authorization": "token " + TOKEN, "User-Agent": "monitor-agent-v10"}
API = "https://api.github.com/repos/zhangjiayang6835-cyber/ai-research"
LEADERBOARD_COMMENT_ID = 4834744003
TIME_LEADERBOARD_ISSUE = 4907254434
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd()

DIFFICULTY = {}
ISSUE_NAMES = {}
ISSUE_CREATED = {}

# All tasks: #5-#10, #12-#28, #30-#49
pairs = [
    (5, "SQL 注入", "medium"), (6, "命令注入", "medium"),
    (7, "XSS", "medium"), (8, "SSRF", "medium"),
    (9, "CSRF", "medium"), (10, "文件上传", "medium"),
    (12, "反序列化漏洞", "hard"), (13, "XXE", "medium"),
    (14, "路径遍历", "easy"), (15, "开放重定向", "easy"),
    (16, "点击劫持", "easy"), (17, "不安全的直接对象引用 (IDOR)", "medium"),
    (18, "服务器端模板注入 (SSTI)", "hard"),
    (19, "无限制的资源消耗", "medium"),
    (20, "日志伪造", "easy"), (21, "Hardcoded Credentials", "easy"),
    (22, "Prototype Pollution", "hard"), (23, "Mass Assignment", "medium"),
    (24, "Negative Number Attack", "medium"), (25, "Insecure Password Reset", "medium"),
    (26, "LDAP Injection", "medium"), (27, "Session Fixation", "medium"),
    (28, "HTTP Request Smuggling", "hard"),
    (30, "GraphQL Injection", "medium"), (31, "WebSocket Hijacking", "medium"),
    (32, "OAuth Misconfiguration", "medium"), (33, "JWT Algorithm Confusion", "hard"),
    (34, "Cache Poisoning", "medium"), (35, "Host Header Injection", "easy"),
    (36, "SSRF (Blind)", "hard"), (37, "CORS Misconfiguration", "easy"),
    (38, "Server-Side Prototype Pollution", "hard"),
    (39, "Dependency Confusion", "medium"),
    (40, "HTTP Parameter Pollution", "easy"),
    (41, "SMTP Header Injection", "medium"),
    (42, "Regex DoS (ReDoS)", "medium"),
    (43, "Directory Listing Enabled", "easy"),
    (44, "Timing Attack (User Enumeration)", "medium"),
    (45, "IDOR v2", "medium"),
    (46, "CRLF Injection in Logs", "easy"),
    (47, "HTTP Request Splitting", "hard"),
    (48, "Zip Slip", "hard"),
    (49, "Coupon Abuse", "medium"),
]

ISSUES = [p[0] for p in pairs]
for p in pairs:
    DIFFICULTY[p[0]] = p[2]
    ISSUE_NAMES[p[0]] = p[1]
    ISSUE_CREATED[p[0]] = False

TRAINING_DIR = os.path.join(SCRIPT_DIR, "training_data")
LOG_FILE = os.path.join(SCRIPT_DIR, "monitor.log")
LEADERBOARD_FILE = os.path.join(SCRIPT_DIR, "honey_ledger.json")
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
    except Exception:
        pass


def fetch(url):
    r = urllib.request.Request(url, headers=HEADERS)
    return json.loads(urllib.request.urlopen(r, context=ctx).read().decode())


def post(url, data, method="POST"):
    j = json.dumps(data).encode()
    r = urllib.request.Request(url, data=j, headers={**HEADERS, "Content-Type": "application/json"}, method=method)
    return json.loads(urllib.request.urlopen(r, context=ctx).read().decode())


def save_training_data(user, issue, code, findings, sp, score):
    os.makedirs(TRAINING_DIR, exist_ok=True)
    rec = {"user": user, "issue": issue, "code": code, "findings": findings, "suspicion": sp, "score": score}
    fname = os.path.join(TRAINING_DIR, f"{user}_#{issue}_{int(time.time())}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)


def check_deadline(issue_num):
    try:
        issue = fetch(f"{API}/issues/{issue_num}")
        created = issue["created_at"]
        deadline_s = 60 * 60 * TIME_LIMIT_HOURS.get(DIFFICULTY.get(issue_num, "medium"), 12)
        remain = deadline_s - (time.time() - time.mktime(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ")))
        if remain <= 0:
            return False, "deadline expired"
        hrs = int(remain // 3600)
        mins = int((remain % 3600) // 60)
        return True, f"{hrs}h{mins}m left"
    except Exception as e:
        log(f"[DEADLINE ERR] #{issue_num}: {e}")
        return True, "(query failed, default pass)"


def check_starred(username):
    try:
        url = f"https://api.github.com/users/{username}/starred"
        r = urllib.request.Request(url, headers=HEADERS)
        data = json.loads(urllib.request.urlopen(r, context=ctx).read().decode())
        for repo in data:
            if repo["full_name"] == "zhangjiayang6835-cyber/ai-research":
                return True, ""
        return False, "请先 Star 本仓库 https://github.com/zhangjiayang6835-cyber/ai-research"
    except Exception as e:
        log(f"[STAR ERR] {username}: {e}")
        return True, "(star check failed, default pass)"


def cheat_detect(code):
    findings = []
    if re.search(r"shell\s*=\s*True", code):
        findings.append(("shell=True", 0.9, "use shell=True"))
    if "eval(" in code:
        findings.append(("eval()", 0.8, "use eval()"))
    if "exec(" in code:
        findings.append(("exec()", 0.85, "use exec()"))
    if "pickle.loads(" in code:
        findings.append(("pickle.loads()", 0.85, "use pickle.loads()"))
    if "os.system(" in code:
        findings.append(("os.system()", 0.8, "use os.system()"))
    if re.search(r"is_admin\s*=\s*True", code):
        findings.append(("is_admin_hardcoded", 0.75, "hardcoded admin"))
    if re.search(r"execute\s*\(\s*f[\u201c]", code):
        findings.append(("sql_fstring", 0.85, "f-string SQL injection"))

    if code.strip().startswith("import") or "def " in code or "class " in code:
        try:
            import ast
            tree = ast.parse(code)
            has_logic = False
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if len(node.body) > 1:
                        has_logic = True
                        break
                if isinstance(node, ast.Return):
                    has_logic = True
                    break
            if not has_logic and len(code) > 100:
                findings.append(("minimal_logic", 0.4, "code lacks real fix logic"))
        except SyntaxError:
            pass
        except:
            pass

    ai_patterns = [
        (r"Here['s] (a|the|my) (fix|solution|implementation|approach)", "AI_greeting", 0.2),
        (r"I[']ll (provide|implement|create|write|add)", "AI_ill_provide", 0.15),
        (r"Sure[!,] (here|I)", "AI_sure_here", 0.15),
        (r"To (fix|address|resolve) this", "AI_to_fix", 0.15),
        (r"(Certainly|Absolutely|Of course)[!,]", "AI_certainly", 0.15),
        (r"(Here's|Below is) (the|my|a) (corrected|fixed|secure|safe|improved)", "AI_here_corrected", 0.2),
        (r"Here's a (more |much more )?secure (version|implementation|approach|way)", "AI_secure_version", 0.2),
        (r"I have (implemented|added|created|modified|updated) the", "AI_have_implemented", 0.15),
        (r"We (should|need to|can|could|must) (use|implement|add|fix|secure|sanitize|validate|escape)", "AI_we_should", 0.12),
        (r"Let me (know if|explain|provide|show|walk through)", "AI_let_me", 0.12),
        (r"##\s*(Fixed|Solution|Fix|Explanation|Changes|Code)", "AI_heading_fix", 0.1),
        (r"Explanation:?", "AI_explanation_label", 0.08),
    ]
    for pat, name, weight in ai_patterns:
        m = re.search(pat, code, re.IGNORECASE)
        if m:
            findings.append((name, weight, f"AI pattern: {name}"))

    return findings


def build_evaluation(user, issue_num, findings, sp):
    iname = ISSUE_NAMES.get(issue_num, f"#{issue_num}")
    if not findings:
        body = f"""## ✅ 提交通过

**任务**: #{issue_num} {iname}
**提交者**: @{user}
**结果**: 没有检测到明显的作弊行为，提交已接受。

> 积分将在任务结束后统一计算并公布。"""
        return body, 100
    detail_lines = []
    for fname, fconf, freason in findings:
        pct = int(fconf * 100)
        detail_lines.append(f"- **{fname}** ({pct}%) — {freason}")
    details = "\n".join(detail_lines)
    deductions = int(sp * 100)
    total = max(100 - deductions, 0)
    body = f"""## ⚠️ 检测到疑似作弊行为

**任务**: #{issue_num} {iname}
**提交者**: @{user}
**作弊嫌疑**: {deductions}%

| 嫌疑项 | 置信度 | 原因 |
|:------:|:------:|:----:|
{details}

**最终得分**: {total} / 100 (扣除 {deductions} 分)
> 如果这是误报，请联系管理员复查。"""
    return body, total


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
    tbl = ["| 排名 | 参与者 | 积分 | 已完成 |", "|:---:|:------:|:----:|:------:|"]
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


def update_time_leaderboard(username, issue_num, submission_time):
    try:
        issue = fetch(f"{API}/issues/{issue_num}")
        created = issue["created_at"]
        created_ts = time.mktime(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))
        submit_ts = time.mktime(time.strptime(submission_time, "%Y-%m-%dT%H:%M:%SZ"))
        elapsed = int(submit_ts - created_ts)
        comment = fetch(f"{API}/issues/comments/{TIME_LEADERBOARD_ISSUE}")
        tbl_body = comment["body"]
        lines = tbl_body.split("\n")
        user_found = False
        new_lines = []
        for line in lines:
            m = re.match(r"^\|\s*(\d+)\s*\|\s*(\w+)\s*\|\s*([\d:]+)\s*\|\s*([\d:]+)", line)
            if m:
                if m.group(2) == username:
                    user_found = True
                    parts = m.group(4).split(":")
                    cur_s = int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
                    total_s = cur_s + elapsed
                else:
                    parts = m.group(4).split(":")
                    total_s = int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
                new_lines.append(f"| {m.group(1)} | {m.group(2)} | {format_duration(elapsed)} | {format_duration(total_s)} |")
            else:
                new_lines.append(line)
        if not user_found:
            table_line = f"| {len(new_lines) + 1} | {username} | {format_duration(elapsed)} | {format_duration(elapsed)} |"
            new_lines.append(table_line)
        new_body = "\n".join(new_lines)
        post(f"{API}/issues/comments/{TIME_LEADERBOARD_ISSUE}", {"body": new_body}, method="PATCH")
        log(f"[TIME LB] {username}: +{format_duration(elapsed)} (total {format_duration(total_s)})")
    except Exception as e:
        log(f"[TIME LB ERR] #{issue_num}: {e}")
        import traceback
        log(traceback.format_exc()[:300])


def format_duration(seconds):
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def main():
    if not TOKEN:
        raise RuntimeError("GH_TOKEN is required to run the monitor")
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    known_comments = {}
    for i in ISSUES:
        known_comments[i] = set()

    log("=" * 60)
    log("AI Training Monitor v10 (43 tasks) started")
    log(f"Tasks: {len(ISSUES)} ({min(ISSUES)}-{max(ISSUES)})")
    log("=" * 60)

    for issue_num in ISSUES:
        try:
            comments = fetch(f"{API}/issues/{issue_num}/comments")
            for c in comments:
                known_comments[issue_num].add(c["id"])
            log(f"[INIT] #{issue_num}: loaded {len(comments)} known comments")
            time.sleep(0.3)
        except Exception as e:
            log(f"[INIT ERR] #{issue_num}: {e}")
    log(f"[INIT] {sum(len(v) for v in known_comments.values())} total known comments across {len(ISSUES)} issues")

    while True:
        try:
            for issue_num in ISSUES:
                try:
                    comments = fetch(f"{API}/issues/{issue_num}/comments")
                    for c in comments:
                        cid = c["id"]
                        if cid in known_comments[issue_num]:
                            continue
                        author = c["user"]["login"]
                        body = c["body"]

                        if author == "zhangjiayang6835-cyber":
                            log(f"[SKIP] #{issue_num} admin comment")
                            known_comments[issue_num].add(cid)
                            continue

                        code_blocks = re.findall(
                            r"`(?:python|javascript|py|js|java|go|rust|cpp|c\+\+|csharp|ruby|php|bash|sh|sql|html|xml|json|yaml|toml|typescript|ts|solidity)?\s*\n(.*?)`",
                            body, re.DOTALL
                        )

                        if not code_blocks:
                            log(f"[SKIP] #{issue_num}: {author} (no code blocks)")
                            known_comments[issue_num].add(cid)
                            continue

                        code = code_blocks[0]

                        ok, msg = check_deadline(issue_num)
                        if not ok:
                            reject = f"## ⏰ 提交被拒绝\n**提交者**: {author}\n**任务**: #{issue_num}\n**原因**: 任务截止时间已过\n\n> 该任务已过期，无法再提交。"
                            post(f"{API}/issues/{issue_num}/comments", {"body": reject})
                            log(f"[REJECT] #{issue_num}: {author} (deadline passed)")
                            known_comments[issue_num].add(cid)
                            continue

                        starred, star_msg = check_starred(author)
                        if not starred:
                            reject = f"## ⭐ 提交被拒绝\n**提交者**: {author}\n**任务**: #{issue_num}\n**原因**: {star_msg}"
                            post(f"{API}/issues/{issue_num}/comments", {"body": reject})
                            log(f"[REJECT] #{issue_num}: {author} (not starred)")
                            known_comments[issue_num].add(cid)
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

                        known_comments[issue_num].add(cid)

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
