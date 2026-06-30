import smtplib, ssl, sys, json, os
from email.mime.text import MIMEText

def _load_config():
    return {
        "smtp_host": os.environ.get("SMTP_HOST", "smtp.qq.com"),
        "smtp_port": int(os.environ.get("SMTP_PORT", "465")),
        "smtp_user": os.environ.get("SMTP_USER", ""),
        "smtp_password": os.environ.get("SMTP_PASSWORD", ""),
        "notify_from": os.environ.get("NOTIFY_FROM", ""),
        "notify_to": os.environ.get("NOTIFY_TO", ""),
        "api_key": os.environ.get("NOTIFY_API_KEY", ""),
    }

def send_notification(event_type, username, issue_num, details):
    ts = __import__("time").strftime("%Y-%m-%d %H:%M:%S")
    cfg = _load_config()
    
    if not all([cfg["smtp_user"], cfg["smtp_password"], cfg["notify_from"]]):
        print("[EMAIL] Skipped: SMTP not configured (set SMTP_USER, SMTP_PASSWORD, NOTIFY_FROM env vars)")
        return
    
    if event_type == "submission":
        subject = f"[AI Research] {username} submitted fix for #{issue_num}"
        body = f"""
<h2>New Code Submission</h2>
<p><b>User:</b> {username}</p>
<p><b>Task:</b> #{issue_num}</p>
<p><b>Time:</b> {ts}</p>
<p><b>Status:</b> Evaluating...</p>
"""
    elif event_type == "completed":
        subject = f"[AI Research] {username} completed #{issue_num} - {details.get("score", 0)} HONEY"
        cheat = details.get("cheat", False)
        status = "CHEAT DETECTED" if cheat else "CLEAN"
        body = f"""
<h2>Task Completed!</h2>
<p><b>User:</b> {username}</p>
<p><b>Task:</b> #{issue_num}</p>
<p><b>Time:</b> {ts}</p>
<p><b>Status:</b> {status}</p>
<p><b>Reward:</b> {details.get("score", 0)} HONEY</p>
"""
    else:
        return
    
    html = f"""<html><body style="font-family:Arial,sans-serif;">{body}
<hr>
<p style="color:#888;font-size:12px;">AI Research Monitor | {ts}</p>
</body></html>"""
    
    msg = MIMEText(html, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = cfg["notify_from"]
    msg["To"] = cfg["notify_to"] or cfg["notify_from"]
    
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], context=ctx) as s:
        s.login(cfg["smtp_user"], cfg["smtp_password"])
        s.sendmail(cfg["notify_from"], cfg["notify_to"] or cfg["notify_from"], msg.as_string())
    print(f"[EMAIL] {subject}")

if __name__ == "__main__":
    event = json.loads(sys.stdin.read())
    if "api_key" not in event and not os.environ.get("NOTIFY_API_KEY", ""):
        print("[EMAIL] Hidden CLI endpoint blocked: no API key provided. Set NOTIFY_API_KEY env var.")
        sys.exit(1)
    send_notification(event["type"], event["user"], event["issue"], event.get("details", {}))
