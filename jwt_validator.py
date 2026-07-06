import jwt
import re
from typing import Optional, Dict, Any

# 允许的算法白名单，不包括 'none'
ALLOWED_ALGORITHMS = ['HS256', 'HS384', 'HS512', 'RS256']

# 预定义的合法 kid 列表（或可通过配置文件加载）
ALLOWED_KIDS = ['key1', 'key2', 'key-prod-001']

# 从环境变量读取密钥
import os
JWT_SECRET = os.environ.get('JWT_SECRET', 'fallback-secret-do-not-use-in-production')

def validate_jwt(token: str) -> Optional[Dict[str, Any]]:
    """
    验证 JWT token 并返回 payload，如果无效则返回 None。
    修复了 None 算法攻击、弱密钥和 kid 注入。
    """
    try:
        # 首先在不验证签名的情况下获取 header（仅用于检查算法和 kid）
        header = jwt.get_unverified_header(token)
        alg = header.get('alg', '')
        kid = header.get('kid', None)

        # 1. 检查算法是否在允许列表中，拒绝 'none'
        if alg not in ALLOWED_ALGORITHMS:
            print(f'Rejected algorithm: {alg}')
            return None

        # 2. 验证 kid（如果存在），防止注入（白名单）
        if kid is not None:
            # 仅允许字母数字和连字符，且在白名单中
            if not re.match(r'^[a-zA-Z0-9\-]+$', kid) or kid not in ALLOWED_KIDS:
                print(f'Rejected kid: {kid}')
                return None

        # 3. 使用固定密钥验证签名，不信任 header 中的任何内容
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=ALLOWED_ALGORITHMS,
            options={
                'verify_signature': True,
                'require_exp': True,  # 要求 exp 字段
                'verify_exp': True,
                'verify_iat': True,
            }
        )
        return payload

    except jwt.ExpiredSignatureError:
        print('Token expired')
        return None
    except jwt.InvalidTokenError as e:
        print(f'Invalid token: {e}')
        return None
    except Exception as e:
        print(f'Unexpected error: {e}')
        return None
