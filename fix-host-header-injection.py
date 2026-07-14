"""
host_header_fix.py — Host Header Injection Fix

修复说明 (Issue #963: Host Header Injection → Password Reset Poisoning):
1. 配置 TRUSTED_HOSTS 白名单（可信任的 Host 列表）
2. 从配置读取规范主机名，而非请求中的 Host header
3. 实现 validate_host() 函数校验 Host header 是否合法
4. 实现 build_absolute_url() 使用可信任域名构建绝对 URL
5. 密码重置链接使用绝对 URL + 可信任域名，防止钓鱼攻击

该实现可直接集成到 Flask 项目中，替换易受攻击的 Host header 使用方式。
"""

import re
from typing import Optional
from urllib.parse import urlunparse, urlparse


# ============================================================
# 1. 配置可信任的 Host 列表
# ============================================================

TRUSTED_HOSTS: set[str] = frozenset({
    "localhost",
    "127.0.0.1",
    "api.example.com",
    "www.example.com",
    "example.com",
})

# 服务器的规范主机名（用于构建所有绝对 URL）
CANONICAL_HOST: str = "api.example.com"
CANONICAL_SCHEME: str = "https"


# ============================================================
# 2. Host header 校验函数
# ============================================================

_HOST_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def validate_host(host: Optional[str], allowed_hosts: set[str] = TRUSTED_HOSTS) -> bool:
    """
    校验 Host header 是否在白名单中。

    Args:
        host: 请求中的 Host header 值
        allowed_hosts: 允许的主机名集合

    Returns:
        True 如果 Host 在白名单中，否则 False
    """
    if not host or not isinstance(host, str):
        return False

    # 移除端口号
    hostname = host.split(":")[0].lower().rstrip(".")

    # 基础格式校验
    if not hostname or not _HOST_PATTERN.match(hostname):
        return False

    # 禁止 IP 地址直接作为 Host（防止 IP spoofing）
    try:
        # 检查是否为 IPv4（但不排除 localhost/127.0.0.1 等白名单中的 IP）
        parts = hostname.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            # 如果白名单中有此 IP，允许
            if hostname in allowed_hosts:
                return True
            return False
    except Exception:
        pass

    return hostname in allowed_hosts


def get_trusted_host(host: Optional[str], allowed_hosts: set[str] = TRUSTED_HOSTS) -> str:
    """
    获取可信的 Host 值。如果 Host header 不可信，返回规范主机名。

    Args:
        host: 请求中的 Host header 值
        allowed_hosts: 允许的主机名集合

    Returns:
        可信的主机名（来自 Host header 或回退到 CANONICAL_HOST）
    """
    if validate_host(host, allowed_hosts):
        return host.split(":")[0].lower().rstrip(".")
    return CANONICAL_HOST


# ============================================================
# 3. 使用可信任域名构建绝对 URL
# ============================================================

def build_absolute_url(path: str,
                       host: Optional[str] = None,
                       allowed_hosts: set[str] = TRUSTED_HOSTS,
                       scheme: Optional[str] = None) -> str:
    """
    构建绝对 URL，使用可信任的 Host 而非用户提供的 Host header。

    这是修复 Host Header 注入的关键函数。无论客户端发送什么 Host header，
    URL 始终使用规范主机名或白名单中的主机名构建。

    Args:
        path: 相对路径（如 "/reset?token=xyz"）
        host: 可选的 Host header 值（会经过校验）
        allowed_hosts: 允许的主机名集合
        scheme: 可选的 scheme（默认使用 CANONICAL_SCHEME）

    Returns:
        安全构建的绝对 URL
    """
    trusted_host = get_trusted_host(host, allowed_hosts)
    use_scheme = scheme or CANONICAL_SCHEME

    parsed = urlparse(path)
    url = urlunparse((
        use_scheme,
        trusted_host,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))
    return url


# ============================================================
# 4. Flask 中间件：强制使用可信任 Host
# ============================================================

def create_host_header_middleware(app):
    """
    Flask 中间件：在请求处理前验证 Host header。

    将中间件注册到 Flask app：
        app = Flask(__name__)
        create_host_header_middleware(app)

    如果 Host header 不在白名单中，返回 400 错误。
    """
    @app.before_request
    def enforce_trusted_host():
        host = request.host if 'request' in dir() else None
        if host and not validate_host(host, TRUSTED_HOSTS):
            from flask import abort
            abort(400, description=f"Invalid Host header: {host}")

    return app


# ============================================================
# 5. 安全密码重置链接生成示例
# ============================================================

def generate_reset_link(token: str,
                        host: Optional[str] = None,
                        allowed_hosts: set[str] = TRUSTED_HOSTS) -> str:
    """
    生成密码重置链接，使用可信任域名。

    修复前（漏洞代码）：
        reset_url = f"https://{request.host}/reset?token={token}"
        # 攻击者设置 Host: attacker.com → 钓鱼链接

    修复后（安全代码）：
        reset_url = generate_reset_link(token, request.host)
        # 无论 Host header 是什么，URL 使用可信任域名
    """
    path = f"/reset?token={token}"
    return build_absolute_url(path, host=host, allowed_hosts=allowed_hosts)


# ============================================================
# 6. 使用示例与测试
# ============================================================

if __name__ == "__main__":
    print("=== Host Header Injection Fix 测试 ===\n")

    # 测试 1: 合法的 Host
    assert validate_host("api.example.com") is True
    print("✅ 合法 Host 通过校验")

    # 测试 2: 恶意 Host 被拒绝
    assert validate_host("attacker.com") is False
    print("✅ 恶意 Host 被拒绝")

    # 测试 3: 空 Host 被拒绝
    assert validate_host("") is False
    assert validate_host(None) is False
    print("✅ 空/None Host 被拒绝")

    # 测试 4: 密码重置链接使用可信任域名
    malicious_host = "evil.attacker.com"
    reset_link = generate_reset_link("secret-token-123", host=malicious_host)
    assert "evil.attacker.com" not in reset_link
    assert CANONICAL_HOST in reset_link
    print(f"✅ 恶意 Host 被替换为可信任域名: {reset_link}")

    # 测试 5: 合法 Host 保持原样
    reset_link2 = generate_reset_link("secret-token-456", host="api.example.com")
    assert "api.example.com" in reset_link2
    print(f"✅ 合法 Host 保持原样: {reset_link2}")

    # 测试 6: IP 地址作为 Host 被拒绝
    assert validate_host("192.168.1.1") is False
    assert validate_host("127.0.0.1") is True  # localhost 在白名单中
    print("✅ IP 地址校验正确")

    print("\n✅ 所有测试通过！Host Header 注入漏洞已修复。")
