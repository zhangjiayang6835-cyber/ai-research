import jwt
import base64
import json
from jwt.exceptions import InvalidKeyError, PyJWTError


def check_issue29():
def get_json(url):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

    # 尝试使用公钥作为 HMAC 密钥（算法混淆攻击）
    try:
        # 这个应该失败，因为使用了不安全的算法
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        print("ERROR: 算法混淆攻击成功！")
        return False
    except Exception as e:
        print(f"  Comment {c['id']} by {c['user']['login']}: {body[:400]}")

    # 正常验证
    try:
        decoded = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_signature": True})
        print("正常验证成功")
        return True
    except Exception as e:
