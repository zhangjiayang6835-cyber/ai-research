import jwt
import base64
import json
from jwt.exceptions import InvalidKeyError, PyJWTError


def check_issue29():
        req = urllib.request.Request(f"https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}", headers=h)
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            d = json.loads(r.read())
        print(f"=== #{i} ===")
        print(f"  Title: {d['title'][:100]}")
    # 尝试使用公钥作为 HMAC 密钥（算法混淆攻击）
    try:
        # 这个应该失败，因为使用了不安全的算法
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        print("ERROR: 算法混淆攻击成功！")
        return False
    except Exception as e:

    # 正常验证
    try:
        decoded = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_signature": True})
        print("正常验证成功")
        return True
    except Exception as e:
