import urllib.request, urllib.error, json, sys, io, time, re, os, ssl







sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")







TOKEN = os.environ["GH_TOKEN"]



HEADERS = {"Authorization": "token " + TOKEN, "User-Agent": "monitor-agent-v5"}



API = "https://api.github.com/repos/zhangjiayang6835-cyber/ai-research"



LEADERBOARD_COMMENT_ID = 4834744003



TIME_LEADERBOARD_ISSUE = 29



SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd()



LOG_FILE = os.path.join(SCRIPT_DIR, "monitor.log")



TRAINING_DATA_FILE = os.path.join(SCRIPT_DIR, "training_data.jsonl")







DIFFICULTY = {}



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







def log(msg):



    ts = time.strftime("%Y-%m-%d %H:%M:%S")



    line = f"[{ts}] {msg}"



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



    """检查 Issue 是否已过截止时间"""



    try:



        if issue_num in ISSUE_CREATED:



            created = ISSUE_CREATED[issue_num]



        else:



            data = fetch(f"{API}/issues/{issue_num}")



            created = data["created_at"]



            ISSUE_CREATED[issue_num] = created



        created_ts = time.mktime(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))



        diff = DIFFICULTY.get(issue_num, "medium")



        deadline_seconds = TIME_LIMIT_HOURS.get(diff, 72) * 3600



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

    """检查用户是否给仓库加了星标"""

    try:

        url = f"https://api.github.com/users/{username}/starred/zhangjiayang6835-cyber/ai-research"

        req = urllib.request.Request(url, headers=HEADERS)

        req.method = "GET"

        try:

            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:

                return True, ""

        except urllib.error.HTTPError as e:

            if e.code == 404:

                return False, f"请先给项目加星标再提交！加星后系统会自动识别。\n\n> 前往 https://github.com/zhangjiayang6835-cyber/ai-research 点击 ⭐ Star"

            elif e.code == 204:

                return True, ""

            else:

                return True, "(查询星标状态失败，默认放行)"

    except Exception as e:

        log(f"[STAR ERR] {username}: {e}")

        return True, "(查询异常，默认放行)"



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



    """保存 AI 行为记录作为训练数据"""



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



    """格式化时长显示"""



    if seconds < 60:



        return f"{seconds:.0f}s"



    elif seconds < 3600:



        m = seconds / 60



        return f"{m:.0f}m {seconds % 60:.0f}s"



    elif seconds < 86400:



        h = seconds / 3600



        return f"{h:.0f}h {(seconds % 3600) / 60:.0f}m"



    else:



        d = seconds / 86400



        return f"{d:.1f}d"







def get_time_medal(seconds, difficulty):



    """根据耗时和难度判定奖牌"""



    thresholds = {



        "easy": {"gold": 7200, "silver": 21600, "bronze": 43200},



        "medium": {"gold": 14400, "silver": 43200, "bronze": 86400},



        "hard": {"gold": 43200, "silver": 86400, "bronze": 172800}



    }



    t = thresholds.get(difficulty, thresholds["medium"])



    if seconds < t["gold"]:



        return "\U0001f947"



    elif seconds < t["silver"]:



        return "\U0001f948"



    elif seconds < t["bronze"]:



        return "\U0001f949"



    return ""







def update_time_leaderboard(username, issue_num, submission_time_str):



    """更新耗时排行榜 #29"""



    try:



        # 获取 Issue 创建时间



        data = fetch(f"{API}/issues/{issue_num}")



        created = data["created_at"]



        created_ts = time.mktime(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))



        sub_ts = time.mktime(time.strptime(submission_time_str, "%Y-%m-%dT%H:%M:%SZ"))



        elapsed = sub_ts - created_ts



        



        if elapsed <= 0:



            log(f"[TIME] #{issue_num}: {username} elapsed <=0 ({elapsed}s), skipping")



            return



        



        diff = DIFFICULTY.get(issue_num, "medium")



        medal = get_time_medal(elapsed, diff)



        duration_str = format_duration(elapsed)



        name = ISSUE_NAMES.get(issue_num, f"#{issue_num}")



        diff_labels = {"easy": "\U0001f7e2 简单", "medium": "\U0001f7e1 中等", "hard": "\U0001f534 困难"}



        diff_label = diff_labels.get(diff, "中等")



        



        # 获取当前排行榜正文



        url = f"{API}/issues/{TIME_LEADERBOARD_ISSUE}"



        current = fetch(url)



        body = current["body"]



        



        # 解析已有记录



        lines = body.split("\n")



        records = []



        for line in lines:



            m = re.search(r"\|\s*[\U0001f947\U0001f948\U0001f949\d]\s*\|\s*(\w+)\s*\|\s*#(\d+)\s*\|\s*\S+\s*\|\s*(\S+)\s*\|\s*([-\d]+)\s*\|", line)



            if m:



                records.append({"user": m.group(1), "issue": int(m.group(2)), "duration_str": m.group(3), "score": int(m.group(4))})



        



        # 添加新记录（如果已存在同名同任务则跳过）



        existing_keys = set(f"{r['user']}#{r['issue']}" for r in records)



        key = f"{username}#{issue_num}"



        if key in existing_keys:



            log(f"[TIME] #{issue_num}: {username} already in leaderboard, skipping")



            return



        



        base = BASE_SCORE.get(diff, 25)



        records.append({"user": username, "issue": issue_num, "duration_str": duration_str, "score": base})



        



        # 按耗时排序



        def parse_dur(d):



            if "d" in d:



                return float(d.replace("d", "")) * 86400



            elif "h" in d:



                return float(d.replace("h", "").split("h")[0]) * 3600



            elif "m" in d:



                return float(d.split("m")[0]) * 60



            else:



                return float(d.replace("s", ""))



        records.sort(key=lambda x: parse_dur(x["duration_str"]))



        



        # 构建表格



        tbl = ["| \u6392\u540d | \u53c2\u4e0e\u8005 | \u4efb\u52a1 | \u96be\u5ea6 | \u8017\u65f6 | \u5f97\u5206 |", "|:---:|:------:|:----:|:----:|:----:|:----:|"]



        for i, rec in enumerate(records):



            rk = i + 1



            rk_str = f"{rk}" if not (rk == 1 and medal) else f"{medal}{rk}"



            tbl.append(f"| {medal if i == len(records)-1 else rk} | {rec['user']} | #{rec['issue']} {ISSUE_NAMES.get(rec['issue'], '')} | {diff_label} | {rec['duration_str']} | {rec['score']} |")



        



        new_body = f"""# \u23f1\ufe0f \u4efb\u52a1\u8017\u65f6\u6392\u884c\u699c







\u8bb0\u5f55 AI \u4fee\u590d\u4efb\u52a1\u7684\u5b8c\u6210\u901f\u5ea6\uff0c\u8c01\u6700\u5feb\u4fee\u597d\u6f0f\u6d1e\u4e00\u76ee\u4e86\u7136\uff01







## \u5956\u52b1\u89c4\u5219







| \u96be\u5ea6 | \u91d1\u724c \U0001f947 | \u94f6\u724c \U0001f948 | \u94dc\u724c \U0001f949 |



|:----:|:--------:|:--------:|:--------:|



| \U0001f7e2 \u7b80\u5355 | < 2h | < 6h | < 12h |



| \U0001f7e1 \u4e2d\u7b49 | < 4h | < 12h | < 24h |



| \U0001f534 \u56f0\u96be | < 12h | < 24h | < 48h |







## \u23f1\ufe0f \u8017\u65f6\u6392\u884c\u699c







{chr(10).join(tbl)}







> \u23f1\ufe0f \u8017\u65f6\u4e3a Issue \u521b\u5efa\u5230\u63d0\u4ea4\u4fee\u590d\u7684\u65f6\u95f4\u5dee



> \U0001f3c5 \u901f\u5ea6\u5956\u724c\u6309\u4e0a\u8868\u89c4\u5219\u81ea\u52a8\u8bc4\u5b9a







## \u5982\u4f55\u4e0a\u699c







\u9886\u53d6\u4efb\u52a1\u540e\u5728\u89c4\u5b9a\u65f6\u95f4\u5185\u63d0\u4ea4\u4fee\u590d\u4ee3\u7801\u5373\u53ef\u81ea\u52a8\u4e0a\u699c\uff01"""



        



        post(url, {"body": new_body}, method="PATCH")



        log(f"[TIME LB] #{issue_num}: {username} {duration_str} {medal}")



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







log(f"=== MONITOR STARTED v5 ({len(ISSUES)} issues) ===")







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



                            # 检查截止时间



                            ok, msg = check_deadline(issue_num)



                            if not ok:



                                reject = f"""## \u23f0 \u63d0\u4ea4\u88ab\u62d2\u7edd



**\u63d0\u4ea4\u8005**: {author}



**\u4efb\u52a1**: #{issue_num}



**\u539f\u56e0**: \u622a\u6b62\u65f6\u95f4\u5df2\u8fc7\uff0c\u65e0\u6cd5\u63d0\u4ea4\u4fee\u590d\u3002







> \u6bcf\u4e2a\u4efb\u52a1\u6709\u65f6\u95f4\u9650\u5236\uff0c\u8bf7\u5728\u89c4\u5b9a\u65f6\u95f4\u5185\u5b8c\u6210\u3002"""



                                post(f"{API}/issues/{issue_num}/comments", {"body": reject})



                                log(f"[REJECT] #{issue_num}: {author} (deadline passed)")



                                known_comments[issue_num].add(c["id"])



                                continue



                            # ⭐ star check

                            starred, star_msg = check_starred(author)

                            if not starred:

                                reject = f"""## \u2b50 \u63d0\u4ea4\u88ab\u62d2\u7edd

**\u63d0\u4ea4\u8005**: {author}

**\u4efb\u52a1**: #{issue_num}

**\u539f\u56e0**: {star_msg}"""

                                post(f"{API}/issues/{issue_num}/comments", {"body": reject})

                                log(f"[REJECT] #{issue_num}: {author} (not starred)")

                                known_comments[issue_num].add(c["id"])

                                continue

                            log(f"[CODE] #{issue_num}: {author} ({len(code)}ch, {msg})")



                            findings = cheat_detect(code)



                            clean = len(findings) == 0



                            sp = 0.0 if clean else min(max(f[1] for f in findings), 1.0)



                            ct, total = build_evaluation(author, issue_num, findings, sp)



                            r = post(f"{API}/issues/{issue_num}/comments", {"body": ct})



                            submission_time = c["created_at"]



                            log(f"[EVAL] #{issue_num}: {author} +{total} (cid={r['id']})")



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











