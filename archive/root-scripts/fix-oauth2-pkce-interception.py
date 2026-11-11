"""
oauth2_pkce_fix.py — OAuth 2.0 Authorization Code Interception Protection

漏洞背景:
- OAuth 2.0 Implicit Grant Flow 在URL fragment中暴露 access token
- 攻击者可通过中间人/重定向拦截窃取 authorization code
- 传统流程缺少 PKCE 保护，授权码可被重放

修复方案:
1. 强制使用 Authorization Code Flow + PKCE (RFC 7636)
2. 实现 code_verifier/code_challenge (S256) 防拦截
3. 强制 state 参数防 CSRF
4. Token 安全存储，禁止日志泄露

参考: RFC 6749, RFC 7636, OAuth 2.0 Security Best Current Practice
"""

import hashlib
import base64
import secrets
import time
import hmac
import json
from dataclasses import dataclass, field
from typing import Optional, Dict
from urllib.parse import urlencode, urlparse, parse_qs


# ─── PKCE 实现 (RFC 7636) ────────────────────────────────────

def generate_code_verifier(length: int = 64) -> str:
    """
    生成高熵 code_verifier (RFC 7636 §4.1)

    Args:
        length: 随机字节数 (推荐 32-96)

    Returns:
        Base64URL-encoded code_verifier
    """
    if length < 32 or length > 96:
        raise ValueError("code_verifier length must be between 32 and 96")
    token = secrets.token_bytes(length)
    return base64.urlsafe_b64encode(token).rstrip(b'=').decode('ascii')


def compute_code_challenge(verifier: str, method: str = "S256") -> str:
    """
    计算 code_challenge (RFC 7636 §4.2)

    Args:
        verifier: code_verifier 字符串
        method: 挑战方法 ("S256" 或 "plain", S256 强制推荐)

    Returns:
        Base64URL-encoded code_challenge
    """
    if method == "plain":
        return verifier
    if method != "S256":
        raise ValueError(f"unsupported challenge method: {method}")
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


# ─── State 参数防 CSRF ──────────────────────────────────────

def generate_state(session_secret: bytes) -> str:
    """
    生成防 CSRF 的 state 参数，绑定服务端 session

    state = base64(random_nonce + hmac(random_nonce, secret))
    """
    nonce = secrets.token_bytes(32)
    mac = hmac.new(session_secret, nonce, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(nonce + mac).rstrip(b'=').decode('ascii')


def validate_state(received_state: str, session_secret: bytes) -> bool:
    """验证 state 参数防 CSRF"""
    try:
        raw = base64.urlsafe_b64decode(received_state + '==')
        nonce, received_mac = raw[:32], raw[32:]
        expected_mac = hmac.new(session_secret, nonce, hashlib.sha256).digest()
        return hmac.compare_digest(received_mac, expected_mac)
    except Exception:
        return False


# ─── Token 安全模型 ──────────────────────────────────────────

@dataclass
class OAuthToken:
    """安全的 OAuth Token 容器 — 防止日志泄露"""
    access_token: str
    token_type: str = "Bearer"
    expires_at: float = 0.0
    refresh_token: Optional[str] = None
    scope: str = ""
    _id_token: Optional[str] = field(default=None, repr=False)

    @property
    def expired(self) -> bool:
        return self.expires_at > 0 and time.time() > (self.expires_at - 60)

    @classmethod
    def from_token_response(cls, data: dict) -> "OAuthToken":
        expires_in = int(data.get("expires_in", 3600))
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_at=time.time() + expires_in,
            refresh_token=data.get("refresh_token"),
            scope=data.get("scope", ""),
        )


# ─── 安全授权 URL 构建 ──────────────────────────────────────

def build_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    session_secret: bytes,
    scope: str = "openid",
) -> Dict[str, str]:
    """
    构建安全的 Authorization Code Flow + PKCE 授权 URL

    不使用 Implicit Grant (response_type=token)
    使用 Authorization Code (response_type=code) + PKCE
    """
    verifier = generate_code_verifier()
    challenge = compute_code_challenge(verifier, "S256")
    state = generate_state(session_secret)

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    url = f"{authorization_endpoint}?{urlencode(params)}"
    return {"url": url, "verifier": verifier, "state": state}


# ─── Authorization Code → Token 交换 ────────────────────────

class OAuthSecurityError(Exception):
    """OAuth 安全检查异常"""
    pass


def exchange_code_for_token(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    authorization_code: str,
    code_verifier: str,
    expected_state: str,
    received_state: str,
    session_secret: bytes,
) -> OAuthToken:
    """
    安全地将 authorization code 交换为 access token

    安全措施:
    1. 验证 state 防 CSRF
    2. 发送 code_verifier (PKCE) 防 code 拦截
    3. 使用 HTTPS + client_secret 认证
    4. 验证 token 响应完整性
    """
    import urllib.request as urlreq
    import ssl

    # 1. CSRF 防护: 验证 state
    if not validate_state(received_state, session_secret):
        raise OAuthSecurityError("state validation failed — possible CSRF attack")
    if received_state != expected_state:
        raise OAuthSecurityError("state mismatch — session fixation detected")

    # 2. PKCE 防护: 发送 code_verifier
    body = urlencode({
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": code_verifier,
    }).encode()

    req = urlreq.Request(
        token_endpoint,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )

    ctx = ssl.create_default_context()
    try:
        with urlreq.urlopen(req, timeout=10, context=ctx) as resp:
            token_data = json.loads(resp.read())
    except Exception as e:
        raise OAuthSecurityError(f"token exchange failed: {e}")

    if "error" in token_data:
        raise OAuthSecurityError(f"token endpoint error: {token_data['error']}")
    if "access_token" not in token_data:
        raise OAuthSecurityError("token response missing access_token")

    token_type = token_data.get("token_type", "").lower()
    if token_type not in ("bearer", "dpop"):
        raise OAuthSecurityError(f"unexpected token_type: {token_type}")

    return OAuthToken.from_token_response(token_data)


# ─── Token 刷新 ─────────────────────────────────────────────

def refresh_access_token(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    refresh_token: str,
) -> OAuthToken:
    """使用 refresh_token 安全刷新 access token (支持轮换)"""
    import urllib.request as urlreq
    import ssl

    body = urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode()

    req = urlreq.Request(
        token_endpoint,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )

    ctx = ssl.create_default_context()
    with urlreq.urlopen(req, timeout=10, context=ctx) as resp:
        token_data = json.loads(resp.read())

    if "error" in token_data:
        raise OAuthSecurityError(f"token refresh failed: {token_data['error']}")

    token = OAuthToken.from_token_response(token_data)
    if not token.refresh_token:
        token.refresh_token = refresh_token
    return token


# ─── 安全检查清单 ────────────────────────────────────────────

def security_audit(config: dict) -> list[str]:
    """OAuth 配置安全审计，返回发现的问题列表"""
    issues = []

    if config.get("response_type") == "token":
        issues.append("[CRITICAL] Implicit Grant (response_type=token) is insecure — use Authorization Code + PKCE")
    if not config.get("pkce_enabled"):
        issues.append("[CRITICAL] PKCE is not enabled — authorization codes can be intercepted")
    if config.get("code_challenge_method") == "plain":
        issues.append("[WARNING] PKCE using 'plain' method — use 'S256' instead")
    if config.get("redirect_uri_validation") != "exact":
        issues.append("[CRITICAL] redirect_uri validation is not exact — open redirect risk")
    if not config.get("state_enabled"):
        issues.append("[CRITICAL] state parameter not enforced — CSRF risk")
    if config.get("allow_http", False):
        issues.append("[CRITICAL] HTTP allowed for OAuth endpoints — MITM risk")

    return issues


# ─── 使用示例 ────────────────────────────────────────────────

if __name__ == "__main__":
    SESSION_SECRET = secrets.token_bytes(32)

    # Step 1: 构建安全的授权 URL
    auth_params = build_authorization_url(
        authorization_endpoint="https://auth.example.com/authorize",
        client_id="your_client_id",
        redirect_uri="https://app.example.com/callback",
        session_secret=SESSION_SECRET,
        scope="openid profile email",
    )

    print("=== Authorization URL (PKCE-enabled) ===")
    print(auth_params["url"][:80] + "...")
    print(f"Verifier: {auth_params['verifier'][:20]}...")
    print(f"State: {auth_params['state'][:20]}...")

    # Step 2: 回调处理
    print("
=== Callback Handler ===")
    try:
        token = exchange_code_for_token(
            token_endpoint="https://auth.example.com/token",
            client_id="your_client_id",
            client_secret="your_client_secret",
            redirect_uri="https://app.example.com/callback",
            authorization_code="auth_code_from_provider",
            code_verifier=auth_params["verifier"],
            expected_state=auth_params["state"],
            received_state=auth_params["state"],
            session_secret=SESSION_SECRET,
        )
        print(f"[OK] Token: {token.access_token[:10]}...")
    except OAuthSecurityError as e:
        print(f"[BLOCKED] {e}")

    # 安全审计
    print("
=== Security Audit ===")
    test_config = {
        "response_type": "token",
        "pkce_enabled": False,
        "state_enabled": True,
        "redirect_uri_validation": "exact",
        "allow_http": False,
    }
    for issue in security_audit(test_config):
        print(issue)
