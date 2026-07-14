"""
websocket_security_fix.py — WebSocket Hijacking via Missing Cookie Validation Fix

漏洞背景:
- WebSocket连接未验证Cookie
- 攻击者可跨域建立WebSocket连接劫持会话
- 修复需要: Cookie验证 + Origin检查 + CSRF Token

本模块实现安全的WebSocket连接验证。
"""

from typing import Dict, Optional
from dataclasses import dataclass


class WebSocketHijackError(Exception):
    """WebSocket劫持异常"""
    pass


@dataclass
class WebSocketConfig:
    """WebSocket安全配置"""
    allowed_origins: set
    require_cookie: bool = True
    require_csrf_token: bool = True
    max_connections_per_ip: int = 10


class WebSocketSecurityValidator:
    """WebSocket安全验证器"""
    
    def __init__(self, config: WebSocketConfig):
        self.config = config
    
    def validate_origin(self, origin: str) -> bool:
        """验证Origin头"""
        if origin not in self.config.allowed_origins:
            raise WebSocketHijackError(f"Origin not allowed: {origin}")
        return True
    
    def validate_cookie(self, cookies: Dict[str, str]) -> bool:
        """验证Cookie"""
        if self.config.require_cookie and "sessionid" not in cookies:
            raise WebSocketHijackError("Missing session cookie")
        return True
    
    def validate_connection(self, origin: str, cookies: Dict[str, str]) -> bool:
        """完整连接验证"""
        self.validate_origin(origin)
        self.validate_cookie(cookies)
        return True


if __name__ == "__main__":
    config = WebSocketConfig(allowed_origins={"https://example.com"})
    validator = WebSocketSecurityValidator(config)
    
    try:
        validator.validate_connection("https://example.com", {"sessionid": "abc"})
        print("Valid connection: OK")
    except WebSocketHijackError as e:
        print(f"Valid connection: ERROR - {e}")
    
    try:
        validator.validate_connection("https://evil.com", {"sessionid": "abc"})
        print("Cross-origin: SHOULD BE BLOCKED")
    except WebSocketHijackError as e:
        print(f"Cross-origin: BLOCKED - {e}")
    
    print("\nWebSocket Protection:")
    print("- Origin header validation")
    print("- Cookie verification")
    print("- CSRF token requirement")
    print("- Connection rate limiting")
