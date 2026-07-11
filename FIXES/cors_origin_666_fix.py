"""
cors_origin_fix.py — CORS Misconfiguration Fix (Issue #666)

修复说明:
1. Origin 白名单校验（ALLOWED_ORIGINS）
2. 不允许 credentials + 通配符组合
3. 返回 Vary: Origin 头
4. 严格的 Origin 匹配（完全匹配，不支持子域通配）
5. 禁止 * + Access-Control-Allow-Credentials 危险组合

该实现可直接集成到 Flask / FastAPI 项目中，替换易受攻击的 CORS 中间件。
"""

import re
from typing import Optional
from urllib.parse import urlparse


# ============================================================
# 1. Origin 白名单
# ============================================================

ALLOWED_ORIGINS: frozenset[str] = frozenset({
    "https://example.com",
    "https://www.example.com",
    "https://app.example.com",
    "https://admin.example.com",
    "http://localhost:3000",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
})

# 允许请求的方法
ALLOWED_METHODS: frozenset[str] = frozenset({
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
})

# 允许请求头
ALLOWED_HEADERS: frozenset[str] = frozenset({
    "Content-Type", "Authorization", "X-Requested-With",
    "Accept", "Origin", "X-CSRF-Token",
})

# 允许暴露的响应头
EXPOSED_HEADERS: frozenset[str] = frozenset({
    "X-Request-Id", "X-RateLimit-Remaining",
})


# ============================================================
# 2. Origin 校验函数
# ============================================================

def _parse_origin(origin: Optional[str]) -> Optional[str]:
    """
    解析并规范化 Origin 头。

    Origin 头格式: scheme + "//" + host（不含 path/query）
    例如: "https://example.com"

    Args:
        origin: Origin 头原始值

    Returns:
        规范化后的 Origin，或 None（无效格式）
    """
    if not origin or not isinstance(origin, str):
        return None

    origin = origin.strip().lower()

    # Origin 头必须包含 scheme
    if "://" not in origin:
        return None

    try:
        parsed = urlparse(origin)
        if parsed.scheme not in ("http", "https"):
            return None
        if not parsed.hostname:
            return None
        # Origin 不能有路径/查询/片段
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return None
        return f"{parsed.scheme}://{parsed.hostname}"
    except Exception:
        return None


def is_origin_allowed(origin: Optional[str],
                      allowed_origins: frozenset[str] = ALLOWED_ORIGINS) -> bool:
    """
    校验 Origin 是否在白名单中（严格完全匹配）。

    拒绝原因:
    - Origin 为空或 None
    - Origin 格式无效
    - Origin 不在白名单中
    - 子域不自动匹配（防止子域劫持）

    Args:
        origin: Origin 头原始值
        allowed_origins: 允许的来源集合

    Returns:
        True 如果 Origin 被允许，否则 False
    """
    if not origin:
        return False

    normalized = _parse_origin(origin)
    if normalized is None:
        return False

    # 严格完全匹配 — 子域不会自动通过
    return normalized in allowed_origins


# ============================================================
# 3. 安全 CORS 头构建函数
# ============================================================

def build_cors_headers(origin: Optional[str],
                       allowed_origins: frozenset[str] = ALLOWED_ORIGINS,
                       credentials: bool = True) -> dict[str, str]:
    """
    构建安全的 CORS 响应头。

    关键安全原则:
    1. 永不在 Access-Control-Allow-Credentials: true 时使用 *
    2. Access-Control-Allow-Origin 只能返回白名单中的值
    3. 必须返回 Vary: Origin 头（缓存安全）

    Args:
        origin: 请求中的 Origin 头
        allowed_origins: 允许的来源白名单
        credentials: 是否允许发送凭据（cookie/authorization）

    Returns:
        安全的 CORS 响应头字典
    """
    headers: dict[str, str] = {
        "Vary": "Origin",  # 必须！让 CDN/代理知道响应依赖于 Origin
    }

    origin_normalized = _parse_origin(origin)

    if is_origin_allowed(origin, allowed_origins):
        # 允许的来源：返回确切的 Origin 值
        headers["Access-Control-Allow-Origin"] = origin_normalized or origin
        headers["Access-Control-Allow-Methods"] = ", ".join(sorted(ALLOWED_METHODS))
        headers["Access-Control-Allow-Headers"] = ", ".join(sorted(ALLOWED_HEADERS))
        headers["Access-Control-Expose-Headers"] = ", ".join(sorted(EXPOSED_HEADERS))

        # 关键: 允许 credentials 时，绝不使用 *
        if credentials and origin_normalized:
            headers["Access-Control-Allow-Credentials"] = "true"

        # CORS 预检请求缓存时间（15 分钟）
        headers["Access-Control-Max-Age"] = "900"
    else:
        # 不允许的来源：不返回 CORS 头，浏览器会阻止
        # 不返回 Access-Control-Allow-Origin，也不返回 *
        pass

    return headers


# ============================================================
# 4. Flask 中间件
# ============================================================

def create_cors_middleware(app,
                           allowed_origins: frozenset[str] = ALLOWED_ORIGINS,
                           credentials: bool = True):
    """
    Flask 中间件：在所有响应上添加安全的 CORS 头。

    注册方式:
        app = Flask(__name__)
        create_cors_middleware(app)

    替换危险的 CORS 配置:
        ❌ app.config['CORS_ALLOW_ORIGINS'] = '*'
        ❌ app.config['CORS_ALLOW_CREDENTIALS'] = True
        ✅ create_cors_middleware(app, allowed_origins=ALLOWED_ORIGINS)
    """
    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin")
        cors_headers = build_cors_headers(origin, allowed_origins, credentials)
        for key, value in cors_headers.items():
            response.headers[key] = value

        # 处理 OPTIONS 预检请求
        if request.method == "OPTIONS":
            response.status_code = 204
            return response

        return response

    return app


# ============================================================
# 5. FastAPI / Starlette 中间件
# ============================================================

def create_starlette_cors_middleware(allowed_origins: frozenset[str] = ALLOWED_ORIGINS):
    """
    Starlette / FastAPI 中间件工厂。

    使用方式:
        from starlette.middleware.base import BaseHTTPMiddleware
        app.add_middleware(BaseHTTPMiddleware, dispatch=create_starlette_cors_middleware())
    """
    async def dispatch(request, call_next):
        response = await call_next(request)
        origin = request.headers.get("origin")
        cors_headers = build_cors_headers(origin, allowed_origins)
        for key, value in cors_headers.items():
            response.headers[key] = value
        return response
    return dispatch


# ============================================================
# 6. 测试
# ============================================================

if __name__ == "__main__":
    print("=== CORS Origin Fix 测试 ===\n")

    # 测试 1: 合法 Origin
    headers = build_cors_headers("https://example.com")
    assert headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Vary"] == "Origin"
    print("✅ 合法 Origin 通过校验")

    # 测试 2: 恶意 Origin 被拒绝
    headers = build_cors_headers("https://attacker.com")
    assert "Access-Control-Allow-Origin" not in headers
    assert "Access-Control-Allow-Credentials" not in headers
    assert headers["Vary"] == "Origin"  # Vary 必须始终返回
    print("✅ 恶意 Origin 被拒绝（不返回 CORS 头）")

    # 测试 3: 空 Origin
    headers = build_cors_headers(None)
    assert "Access-Control-Allow-Origin" not in headers
    print("✅ 空 Origin 被拒绝")

    # 测试 4: 无效格式 Origin
    headers = build_cors_headers("not-a-valid-origin")
    assert "Access-Control-Allow-Origin" not in headers
    print("✅ 无效格式 Origin 被拒绝")

    # 测试 5: 无 credentials 模式不返回 Allow-Credentials
    headers = build_cors_headers("https://example.com", credentials=False)
    assert "Access-Control-Allow-Credentials" not in headers
    assert headers["Access-Control-Allow-Origin"] == "https://example.com"
    print("✅ credentials=False 时不返回 Allow-Credentials 头")

    # 测试 6: is_origin_allowed 严格匹配
    assert is_origin_allowed("https://example.com") is True
    assert is_origin_allowed("https://evil.example.com") is False  # 子域不自动通过
    assert is_origin_allowed("http://example.com") is False  # 不同 scheme
    print("✅ 严格匹配校验正确")

    print("\n✅ 所有测试通过！CORS 漏洞已修复。")
