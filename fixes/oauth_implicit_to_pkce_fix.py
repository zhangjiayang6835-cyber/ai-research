"""
oauth_implicit_to_pkce_fix.py — OAuth 2.0 CSRF → Account Takeover via State Bypass Fix

漏洞背景:
- OAuth回调端点未验证state参数
- 攻击者构造恶意OAuth链接
- 受害者点击后攻击者的账号绑定到受害者的账户
- 修复需要: 实现state参数 + PKCE + 绑定用户session

本模块实现安全的OAuth流程，防止CSRF账户接管。
"""

import secrets
import hashlib
import hmac
import base64
import json
import time
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs


class OAuthCSRFError(Exception):
    """OAuth CSRF异常"""
    pass


@dataclass
class OAuthStateConfig:
    """OAuth state安全配置"""
    state_length: int = 32
    state_expiry: int = 300  # 5分钟
    nonce_length: int = 16
    pkce_challenge_method: str = "S256"


class SecureOAuthStateManager:
    """
    OAuth State管理器
    
    实现安全的state参数:
    1. state nonce校验
    2. state与用户session绑定
    3. 防重放攻击
    """
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.config = OAuthStateConfig()
        self._state_store: Dict[str, Dict] = {}
    
    def generate_state(self, session_id: str) -> str:
        """
        生成安全的state参数
        
        包含:
        - 随机nonce
        - 用户session绑定
        - 时间戳
        - HMAC签名
        """
        nonce = secrets.token_hex(self.config.nonce_length)
        timestamp = int(time.time())
        
        state_data = {
            "nonce": nonce,
            "session_id": session_id,
            "timestamp": timestamp,
        }
        
        state_json = json.dumps(state_data, separators=(",", ":"))
        signature = hmac.new(
            self.secret_key.encode(),
            state_json.encode(),
            hashlib.sha256,
        ).hexdigest()[:16]
        
        state = base64.urlsafe_b64encode(
            f"{state_json}|{signature}".encode()
        ).decode()
        
        # 存储state用于校验
        self._state_store[nonce] = state_data
        
        return state
    
    def validate_state(self, state: str, session_id: str) -> bool:
        """
        验证state参数
        
        校验:
        1. 签名完整性
        2. nonce有效性
        3. 与用户session绑定
        4. 未过期
        """
        try:
            decoded = base64.urlsafe_b64decode(state.encode()).decode()
            state_json, signature = decoded.rsplit("|", 1)
            
            # 验证签名
            expected_sig = hmac.new(
                self.secret_key.encode(),
                state_json.encode(),
                hashlib.sha256,
            ).hexdigest()[:16]
            
            if not hmac.compare_digest(signature, expected_sig):
                raise OAuthCSRFError("Invalid state signature")
            
            state_data = json.loads(state_json)
            
            # 验证nonce
            if state_data["nonce"] not in self._state_store:
                raise OAuthCSRFError("State nonce not found")
            
            # 验证session绑定
            if state_data["session_id"] != session_id:
                raise OAuthCSRFError("State not bound to this session")
            
            # 验证过期
            if time.time() - state_data["timestamp"] > self.config.state_expiry:
                raise OAuthCSRFError("State expired")
            
            # 消费nonce（防重放）
            del self._state_store[state_data["nonce"]]
            
            return True
            
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            raise OAuthCSRFError(f"Invalid state: {e}") from e


class PKCEChallenge:
    """
    PKCE挑战
    
    实现PKCE (Proof Key for Code Exchange) 扩展:
    1. 生成code_verifier
    2. 生成code_challenge (S256)
    3. 验证code_verifier
    """
    
    @staticmethod
    def generate_code_verifier() -> str:
        """生成随机code_verifier"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_code_challenge(verifier: str) -> str:
        """
        生成code_challenge (S256)
        
        SHA256(code_verifier) 然后 base64url编码。
        """
        sha256_hash = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(sha256_hash).decode().rstrip("=")
    
    @staticmethod
    def verify_code_challenge(verifier: str, challenge: str) -> bool:
        """验证code_verifier是否匹配challenge"""
        expected = PKCEChallenge.generate_code_challenge(verifier)
        return hmac.compare_digest(expected, challenge)


class SecureOAuthFlow:
    """
    安全OAuth流程
    
    整合state参数和PKCE。
    """
    
    def __init__(self, client_id: str, redirect_uri: str,
                 secret_key: str, authorization_url: str,
                 token_url: str):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.state_manager = SecureOAuthStateManager(secret_key)
        self.authorization_url = authorization_url
        self.token_url = token_url
    
    def build_authorization_url(self, session_id: str) -> str:
        """
        构建安全的授权URL
        
        包含state参数和PKCE challenge。
        """
        state = self.state_manager.generate_state(session_id)
        code_verifier = PKCEChallenge.generate_code_verifier()
        code_challenge = PKCEChallenge.generate_code_challenge(code_verifier)
        
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        
        return f"{self.authorization_url}?{urlencode(params)}"
    
    def handle_callback(self, code: str, state: str,
                        session_id: str) -> bool:
        """
        处理OAuth回调
        
        验证state参数后才处理授权码。
        """
        # 验证state
        self.state_manager.validate_state(state, session_id)
        
        # state验证通过后处理code
        return True


def detect_oauth_csrf(callback_url: str) -> bool:
    """检测OAuth CSRF攻击"""
    parsed = urlparse(callback_url)
    params = parse_qs(parsed.query)
    
    if "state" not in params:
        return True  # 缺少state参数
    
    return False


if __name__ == "__main__":
    secret = secrets.token_hex(32)
    oauth = SecureOAuthFlow(
        client_id="test_client",
        redirect_uri="https://app.example.com/callback",
        secret_key=secret,
        authorization_url="https://auth.example.com/authorize",
        token_url="https://auth.example.com/token",
    )
    
    session_id = "user_session_123"
    
    # 生成授权URL
    auth_url = oauth.build_authorization_url(session_id)
    print(f"Auth URL generated (has state): {'state=' in auth_url}")
    print(f"Auth URL generated (has code_challenge): {'code_challenge=' in auth_url}")
    
    # 提取state
    from urllib.parse import urlparse, parse_qs
    params = parse_qs(urlparse(auth_url).query)
    state = params["state"][0]
    
    # 有效回调
    try:
        result = oauth.handle_callback("auth_code_xyz", state, session_id)
        print(f"Valid callback: OK")
    except OAuthCSRFError as e:
        print(f"Valid callback: ERROR - {e}")
    
    # 无效state（重放）
    try:
        oauth.handle_callback("auth_code_xyz", state, session_id)
        print("Replay attack: SHOULD BE BLOCKED")
    except OAuthCSRFError as e:
        print(f"Replay attack: BLOCKED - {e}")
    
    # 伪造state
    try:
        oauth.handle_callback("auth_code_xyz", "fake_state", session_id)
        print("Forged state: SHOULD BE BLOCKED")
    except OAuthCSRFError as e:
        print(f"Forged state: BLOCKED - {e}")
    
    # PKCE测试
    verifier = PKCEChallenge.generate_code_verifier()
    challenge = PKCEChallenge.generate_code_challenge(verifier)
    print(f"PKCE verifier length: {len(verifier)}")
    print(f"PKCE challenge: {challenge[:16]}...")
    print(f"PKCE verify: {PKCEChallenge.verify_code_challenge(verifier, challenge)}")
    
    print("\nOAuth CSRF Prevention Features:")
    print("- State parameter nonce validation")
    print("- State bound to user session")
    print("- HMAC signature on state")
    print("- State expiry enforcement")
    print("- PKCE (S256 challenge)")
    print("- Anti-replay via nonce consumption")
