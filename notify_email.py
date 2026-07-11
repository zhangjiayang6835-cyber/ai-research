--- comments.py ---
import sqlite3

def export_comments_to_csv(user_ids):
    conn = sqlite3.connect('comments.db')
    cursor = conn.cursor()
    
    # Use parameterized query to prevent SQL injection
    cursor.execute("SELECT * FROM comments WHERE id IN (?)", (user_ids,))
    
    rows = cursor.fetchall()
    with open('exported_comments.csv', 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow([description[0] for description in cursor.description])
        csvwriter.writerows(rows)
    
    conn.close()

def get_user_ids_from_input(input_data):
    # Sanitize input to prevent XSS
    sanitized_input = re.sub(r'[<>&"\'\n\r]', '', str(input_data))
    return tuple(map(int, sanitized_input.split(',')))

if __name__ == "__main__":
    user_ids = "1,2,3"
    export_comments_to_csv(get_user_ids_from_input(user_ids))
```

```python
--- notify_email.py ---
import smtplib
import dkim
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate

SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.example.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER', 'noreply@example.com')
SMTP_DOMAIN = SMTP_USER.split('@')[-1] if '@' in SMTP_USER else 'example.com'
DKIM_SELECTOR = os.getenv('DKIM_SELECTOR', 'default')
SMTP_PASS = os.getenv('SMTP_PASS', '')
FROM_NAME = os.getenv('FROM_NAME', 'AI Research Platform')

ts = __import__("time").strftime("%Y-%m-%d %H:%M:%S")

def verify_spf(sender_domain):
    try:
        answers = dns.resolver.resolve(sender_domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if b'v=spf1' in txt_string:
                    return True
        return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return False

def verify_dkim(sender_domain, selector='default'):
    try:
        dk = dkim.DKIM()
        dkim_domain = f"{selector}._domainkey.{sender_domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            return True
        return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return False

def sign_email_with_dkim(msg_bytes, selector, domain, private_key):
    try:
        dk = dkim.DKIM(private_key=private_key)
        signed_msg = dk.sign(message=msg_bytes.decode(), selector=selector, domain=domain)
        return signed_msg.encode()
    except Exception as e:
        print(f"DKIM signing failed: {e}")
        return msg_bytes

def send_email(to_addr, subject, body):
    msg = MIMEMultipart()
    msg['From'] = f"{FROM_NAME} <{SMTP_USER}>"
    msg['To'] = to_addr
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(body))

    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        if SMTP_PASS:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, to_addr, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Email sending failed: {e}")

if __name__ == "__main__":
    send_email("recipient@example.com", "Test Subject", f"<p><b>Time:</b> {ts}</p>")
```

```python
--- rate_limit.py ---
"""
Rate limiting middleware for login endpoints.
"""
import time
from functools import wraps

_attempts = {}
def rate_limit(max_attempts=5, window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*a,**kw):
            ip = _get_ip(*a)
            now = time.time()
            if ip not in _attempts: _attempts[ip] = []
            _attempts[ip] = [t for t in _attempts[ip] if now-t < window]
            if len(_attempts[ip]) >= max_attempts: return _block()
            _attempts[ip].append(now)
            return f(*a,**kw)
        return wrapper
    return decorator

def _get_ip(*a):
    for x in a:
        if hasattr(x,'remote_addr'): return x.remote_addr
        if hasattr(x,'META'): return x.META.get('REMOTE_ADDR','0.0.0.0')
    return '0.0.0.0'

def _block():
    try:
        from flask import jsonify
        return jsonify({'error':'Too many attempts'}),429
    except: 
        return {'error':'Too many attempts'},429

if __name__ == "__main__":
    pass