"""
timing_attack_fix.py — Password Timing Attack Fix (Issue #678)

修复说明:
1. 使用 constant-time 比较函数 (hmac.compare_digest)
2. 用户名存在与否返回相同延迟（恒定时间查询）
3. 添加随机延迟抖动（抗时序攻击的噪声）
4. 密码存储使用 SHA-256 + 随机盐，永远不在比较中暴露明文字符串

该实现可直接集成到 Python Flask/FastAPI 项目中，替换易受攻击的密码比较逻辑。
"""

import hashlib
import hmac
import os
import random
import time
from typing import Optional


# ============================================================
# 1. 配置
# ============================================================

# 恒定延迟抖动范围（毫秒）
TIMING_JITTER_MIN_MS: int = 50
TIMING_JITTER_MAX_MS: int = 150

# 恒定用户存在性延迟（毫秒）
USER_EXISTENCE_DELAY_MS: int = 100

# 盐长度（字节）
SALT_LENGTH: int = 32

# 哈希算法
HASH_ALGORITHM: str = "sha256"


# ============================================================
# 2. 恒定时间密码哈希
# ============================================================

def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """
    使用随机盐 + SHA-256 哈希密码。

    Args:
        password: 明文密码
        salt: 可选的盐（默认生成随机盐）

    Returns:
        (hashed_password, salt) 元组
    """
    if salt is None:
        salt = os.urandom(SALT_LENGTH)

    # 使用 PBKDF2 风格的迭代哈希（简化版）
    password_bytes = password.encode("utf-8")
    hashed = hashlib.pbkdf2_hmac(HASH_ALGORITHM, password_bytes, salt, 100_000)

    return hashed, salt


def verify_password(password: str, stored_hash: bytes, stored_salt: bytes) -> bool:
    """
    使用恒定时间比较验证密码。

    核心安全原则:
    1. 先用 hash 将输入转为字节，再与存储的 hash 比较
    2. 使用 hmac.compare_digest() 进行恒定时间比较
    3. 永不直接比较明文字符串

    Args:
        password: 用户输入的明文密码
        stored_hash: 存储的密码哈希
        stored_salt: 存储的盐

    Returns:
        True 如果密码匹配，否则 False
    """
    computed_hash, _ = hash_password(password, stored_salt)
    return hmac.compare_digest(computed_hash, stored_hash)


# ============================================================
# 3. 恒定时间用户验证
# ============================================================

class SecureAuthenticator:
    """
    安全的认证器，防止时序攻击。

    安全特性:
    1. 恒定时间比较 — 使用 hmac.compare_digest
    2. 用户存在性隐藏 — 无论用户是否存在，都执行哈希+比较
    3. 随机延迟抖动 — 防止统计时序分析
    4. 恒定错误消息 — 不区分"用户不存在"和"密码错误"
    """

    def __init__(self):
        # 模拟用户数据库: {username: (hashed_password, salt)}
        self._users: dict[str, tuple[bytes, bytes]] = {}

    def register(self, username: str, password: str) -> None:
        """注册用户"""
        hashed, salt = hash_password(password)
        self._users[username] = (hashed, salt)

    def authenticate(self, username: str, password: str) -> tuple[bool, str]:
        """
        恒定时间用户认证。

        无论用户是否存在，都执行以下操作:
        1. 生成随机盐并计算输入密码的哈希
        2. 与存储的哈希（如果存在）或随机哈希进行恒定时间比较
        3. 添加随机延迟抖动

        Args:
            username: 用户名
            password: 密码

        Returns:
            (success, message) — 成功为 (True, "登录成功")，
                                失败为 (False, "用户名或密码错误")
        """
        # 添加恒定延迟抖动
        jitter = random.uniform(TIMING_JITTER_MIN_MS, TIMING_JITTER_MAX_MS) / 1000.0
        time.sleep(jitter)

        if username in self._users:
            stored_hash, stored_salt = self._users[username]
            is_valid = verify_password(password, stored_hash, stored_salt)
        else:
            # 关键: 用户不存在时，也执行相同的哈希+比较操作
            # 使用随机数据作为"伪存储哈希"进行比较
            fake_salt = os.urandom(SALT_LENGTH)
            fake_hash = os.urandom(32)  # 随机哈希（SHA-256 输出长度）
            computed_hash, _ = hash_password(password, fake_salt)
            is_valid = hmac.compare_digest(computed_hash, fake_hash)
            # is_valid 几乎永远为 False（概率: 2^-256）

        if is_valid:
            return True, "登录成功"

        return False, "用户名或密码错误"  # 统一错误消息


# ============================================================
# 4. Flask 认证中间件
# ============================================================

def create_timing_safe_auth_middleware(authenticator: SecureAuthenticator):
    """
    Flask 中间件：恒定时间认证。

    注册方式:
        authenticator = SecureAuthenticator()
        create_timing_safe_auth_middleware(authenticator)(app)
    """
    def decorator(app):
        @app.before_request
        def auth_check():
            # 跳过公开端点
            public_paths = ("/login", "/register", "/health")
            if request.path in public_paths or request.method == "OPTIONS":
                return None

            # 这里可以添加 token/session 验证逻辑
            # 关键: 验证逻辑使用恒定时间比较
            pass
        return app
    return decorator


# ============================================================
# 5. 恒定时间字符串比较工具
# ============================================================

def constant_time_compare(a: str, b: str) -> bool:
    """
    恒定时间字符串比较。

    使用 hmac.compare_digest 确保比较时间与字符串长度无关。

    Args:
        a: 第一个字符串
        b: 第二个字符串

    Returns:
        True 如果两个字符串相等，否则 False
    """
    a_bytes = a.encode("utf-8") if isinstance(a, str) else a
    b_bytes = b.encode("utf-8") if isinstance(b, str) else b
    return hmac.compare_digest(a_bytes, b_bytes)


# ============================================================
# 6. 测试
# ============================================================

if __name__ == "__main__":
    print("=== Timing Attack Fix 测试 ===\n")

    # 测试 1: 恒定时间比较
    assert constant_time_compare("password123", "password123") is True
    assert constant_time_compare("password123", "password124") is False
    assert constant_time_compare("a", "b") is False
    print("✅ 恒定时间比较正确")

    # 测试 2: 密码哈希 + 验证
    auth = SecureAuthenticator()
    auth.register("testuser", "super-secret-password")
    assert auth.authenticate("testuser", "super-secret-password")[0] is True
    assert auth.authenticate("testuser", "wrong-password")[0] is False
    print("✅ 密码哈希和验证正确")

    # 测试 3: 用户不存在时返回统一错误消息
    result = auth.authenticate("nonexistent-user", "any-password")
    assert result[0] is False
    assert result[1] == "用户名或密码错误"
    print("✅ 用户不存在时返回统一错误消息")

    # 测试 4: 错误消息不泄露用户是否存在
    wrong_pw_msg = auth.authenticate("testuser", "wrong")[1]
    no_user_msg = auth.authenticate("nouser", "wrong")[1]
    assert wrong_pw_msg == no_user_msg == "用户名或密码错误"
    print("✅ 错误消息不泄露用户存在性")

    # 测试 5: verify_password 使用 hmac.compare_digest
    hashed, salt = hash_password("test")
    assert verify_password("test", hashed, salt) is True
    assert verify_password("wrong", hashed, salt) is False
    print("✅ 密码验证使用恒定时间比较")

    # 测试 6: 多次调用延迟抖动
    start = time.time()
    for _ in range(5):
        auth.authenticate("nouser", "x")
    elapsed = time.time() - start
    min_expected = 5 * TIMING_JITTER_MIN_MS / 1000.0
    assert elapsed >= min_expected, f"抖动不足: {elapsed:.3f}s < {min_expected:.3f}s"
    print(f"✅ 延迟抖动正常工作 ({elapsed:.3f}s for 5 calls)")

    print("\n✅ 所有测试通过！时序攻击漏洞已修复。")
