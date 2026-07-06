from flask import Flask, request, session, make_response
import hashlib
import os

app = Flask(__name__)

# 安全密钥
app.secret_key = os.urandom(24)

# 防止缓存欺骗：对响应设置无缓存头
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # 防止代理缓存
    response.headers['Surrogate-Control'] = 'no-store'
    return response

# 防止会话固定：每次登录成功后重新生成会话ID
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # 这里应验证用户凭证，示例中假设验证成功
    if username == 'admin' and password == 'secret':
        # 重新生成会话ID以防御会话固定攻击
        session.clear()
        session.regenerate()
        session['user'] = username
        return make_response('Login successful'), 200
    else:
        return make_response('Login failed'), 401

# 在应用启动时，强制使用HTTPS（实际部署中应配置SSL）
import ssl
if __name__ == '__main__':
    # 仅用于开发环境，生产环境应使用反向代理
    app.run(ssl_context='adhoc')
