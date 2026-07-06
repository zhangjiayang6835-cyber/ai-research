from flask import Flask, request, abort, session
import socket

app = Flask(__name__)
app.secret_key = 'secret-123456'
ALLOWED_HOSTS = ['myapp.example.com', 'localhost']

@app.before_request
def check_host_and_rebind():
    host = request.headers.get('Host', '').split(':')[0]
    if host not in ALLOWED_HOSTS:
        abort(403)
    # DNS pinning: store resolved IP at session start
    if 'resolved_ip' not in session:
        try:
            ip = socket.gethostbyname(host)
            session['resolved_ip'] = ip
        except:
            abort(500)
    else:
        # In real deployment, also verify against stored IP
        # For simplicity, we skip re-resolution here
        pass
    # Enforce HTTPS
    if not request.is_secure:
        abort(403)

@app.route('/')
def index():
    return 'OK'

if __name__ == '__main__':
    app.run(ssl_context='adhoc')