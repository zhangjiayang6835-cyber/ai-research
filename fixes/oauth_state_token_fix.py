"""
oauth_state_token_fix.py — Predictable OAuth State Token → CSRF + Account Takeover Fix

漏洞背景:
- OAuth state参数使用可预测的值（时间戳、递增ID）
- 攻击者可预测state参数发起CSRF攻击
- 修复需要: 使用加密安全的随机state + HMAC签名

本模块实现不可预测的OAuth state token。
"""

import secrets
import hashlib
import hmac
import time
import base64
import json
from typing import Dict, Optional


class OAuthStateTokenError(Exception):
    """OAuth state token异常"""
    pass


class SecureOAuthState:
    """安全OAuth state"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self._used_nonces: set = set()
    
    def generate(self, session_id: str) -> str:
        """生成不可预测的state"""
        nonce = secrets.token_hex(32)
        timestamp = int(time.time())
        
        payload = json.dumps({
            "nonce": nonce,
            "sid": session_id,
            "ts": timestamp,
        }, separators=(",", ":"))
        
        sig = hmac.new(
            self.secret_key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()[:16]
        
        token = base64.urlsafe_b64encode(
            f"{payload}|{sig}".encode()
        ).decode()
        
        self._used_nonces.add(nonce)
        return token
    
    def validate(self, token: str, session_id: str) -> bool:
        """验证state"""
        try:
            decoded = base64.urlsafe_b64decode(token.encode()).decode()
            payload, sig = decoded.rsplit("|", 1)
            
            expected = hmac.new(
                self.secret_key.encode(),
                payload.encode(),
                hashlib.sha256,
            ).hexdigest()[:16]
            
            if not hmac.compare_digest(sig, expected):
                return False
            
            data = json.loads(payload)
            
            if data["sid"] != session_id:
                return False
            
            if time.time() - data["ts"] > 300:
                return False
            
            if data["nonce"] in self._used_nonces:
                self._used_nonces.remove(data["nonce"])
                return True
            
            return False
        except Exception:
            return False


if __name__ == "__main__":
    secret = secrets.token_hex(32)
    state_mgr = SecureOAuthState(secret)
    
    session_id = "session_123"
    token = state_mgr.generate(session_id)
    print(f"Token: {token[:30]}...")
    print(f"Valid: {state_mgr.validate(token, session_id)}")
    print(f"Invalid session: {state_mgr.validate(token, 'session_456')}")
    
    print("\nOAuth State Protection:")
    print("- Cryptographic random nonce (256-bit)")
    print("- HMAC signature binding")
    print("- Session binding")
    print("- Timestamp expiry (5 min)")
    print("- Anti-replay via nonce tracking")
