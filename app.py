from flask import Flask, request, jsonify
import urllib.request
import urllib.error
import re

app = Flask(__name__)

# 内部白名单 URL 模式（示例：仅允许本地主机和内部 IP）
ALLOWED_HOSTS = [
    r'^http://localhost(:\d+)?/.*',
    r'^http://127\.0\.0\.1(:\d+)?/.*',
    r'^http://10\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/.*',
    r'^http://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(:\d+)?/.*',
    r'^http://192\.168\.\d{1,3}\.\d{1,3}(:\d+)?/.*',
]

def is_allowed(url):
    for pattern in ALLOWED_HOSTS:
        if re.match(pattern, url):
            return True
    return False

@app.route("/api/proxy", methods=["POST"])
def proxy_request():
    target = request.json.get("url")
    data = request.json.get("data")
    
    if not target:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    
    if not is_allowed(target):
        return jsonify({"error": "URL not allowed"}), 403
    
    # 处理 data 为 None 的情况
    if data is None:
        data = ""
    encoded_data = data.encode()
    actual_length = len(encoded_data)
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(actual_length),
    }
    
    req = urllib.request.Request(target, data=encoded_data, headers=headers, method='POST')
    
    try:
        response = urllib.request.urlopen(req)
        return jsonify({"status": response.status, "body": response.read().decode()})
    except urllib.error.URLError as e:
        return jsonify({"error": str(e.reason)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run()
