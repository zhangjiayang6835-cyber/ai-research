"""
session_token_url_fix.py — Session Fixation + Session ID in URL Fix

漏洞背景:
- 应用在URL参数中接受session ID（?sessionid=xyz）
- 登录后不重新生成session
- 攻击者可先获取一个session ID，诱骗受害者使用该ID登录
- 修复需要: 登录后重新生成session ID + 仅通过cookie传递session

本模块实现安全的session管理，防止session fixation攻击。
"""

import os
import secrets
import hmac
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set
from urllib.parse import urlparse, urlencode


class SessionFixationError(Exception):
    """Session fixation异常"""
    pass


@dataclass
class SecureSessionConfig:
    """安全session配置"""
    session_length: int = 64  # 字节数
    session_lifetime: int = 3600  # 秒
    renew_after_login: bool = True
    http_only: bool = True
    secure: bool = True
    same_site: str = "Lax"  # Strict, Lax, None
    path: str = "/"
    domain: Optional[str] = None


class SecureSessionManager:
    """
    安全Session管理器
    
    防止Session Fixation攻击:
    1. 登录后重新生成session ID
    2. 拒绝URL参数中的session ID
    3. 设置Secure + HttpOnly cookie
    """
    
    def __init__(self, config: Optional[SecureSessionConfig] = None):
        self.config = config or SecureSessionConfig()
        self._sessions: Dict[str, Dict] = {}
    
    def generate_session_id(self) -> str:
        """生成安全的session ID"""
        return secrets.token_hex(self.config.session_length)
    
    def create_session(self) -> str:
        """
        创建新session
        
        始终使用服务器生成的session ID，
        不接受客户端提供的session ID。
        """
        session_id = self.generate_session_id()
        self._sessions[session_id] = {
            "created_at": time.time(),
            "data": {},
            "is_authenticated": False,
        }
        return session_id
    
    def get_session(self, session_id: str, 
                    from_url: bool = False) -> Optional[Dict]:
        """
        获取session
        
        如果session ID来自URL参数，拒绝访问。
        """
        if from_url:
            raise SessionFixationError(
                "Session ID from URL parameter rejected"
            )
        
        if session_id not in self._sessions:
            return None
        
        session = self._sessions[session_id]
        
        # 检查session是否过期
        if time.time() - session["created_at"] > self.config.session_lifetime:
            del self._sessions[session_id]
            return None
        
        return session
    
    def regenerate_session(self, old_session_id: str) -> str:
        """
        重新生成session ID
        
        登录成功后调用此方法，
        创建新session并复制数据。
        """
        if old_session_id not in self._sessions:
            raise SessionFixationError("Session not found")
        
        # 保存旧session数据
        old_data = self._sessions[old_session_id].get("data", {})
        
        # 删除旧session
        del self._sessions[old_session_id]
        
        # 创建新session
        new_session_id = self.create_session()
        self._sessions[new_session_id]["data"] = old_data
        self._sessions[new_session_id]["is_authenticated"] = True
        
        return new_session_id
    
    def login(self, session_id: str, user_data: Dict) -> str:
        """
        登录处理
        
        1. 验证session
        2. 重新生成session ID
        3. 设置认证状态
        """
        # 验证session
        if session_id not in self._sessions:
            raise SessionFixationError("Invalid session")
        
        # 重新生成session ID
        new_session_id = self.regenerate_session(session_id)
        
        # 设置认证数据
        self._sessions[new_session_id]["data"]["user"] = user_data
        self._sessions[new_session_id]["is_authenticated"] = True
        
        return new_session_id
    
    def logout(self, session_id: str):
        """登出处理"""
        if session_id in self._sessions:
            del self._sessions[session_id]
    
    def get_cookie_header(self, session_id: str) -> str:
        """
        生成安全的cookie头
        
        Set-Cookie头包含:
        - Secure: 仅HTTPS
        - HttpOnly: 禁止JS访问
        - SameSite: 防止CSRF
        """
        parts = [f"sessionid={session_id}"]
        
        if self.config.secure:
            parts.append("Secure")
        if self.config.http_only:
            parts.append("HttpOnly")
        if self.config.same_site:
            parts.append(f"SameSite={self.config.same_site}")
        if self.config.path:
            parts.append(f"Path={self.config.path}")
        if self.config.domain:
            parts.append(f"Domain={self.config.domain}")
        
        parts.append("Max-Age=" + str(self.config.session_lifetime))
        
        return "; ".join(parts)


class URLSessionFilter:
    """
    URL Session过滤器
    
    拒绝URL参数中的session ID，
    确保仅通过cookie传递session。
    """
    
    # 已知的session参数名
    SESSION_PARAMS = frozenset({
        "sessionid", "session_id", "session", "sid",
        "phpsessid", "jsessionid", "aspsessionid",
    })
    
    @staticmethod
    def filter_url(url: str) -> str:
        """
        过滤URL中的session参数
        
        移除所有session相关的URL参数。
        """
        parsed = urlparse(url)
        params = parsed.query.split("&") if parsed.query else []
        
        filtered_params = []
        for param in params:
            if "=" in param:
                key = param.split("=")[0].lower()
                if key not in URLSessionFilter.SESSION_PARAMS:
                    filtered_params.append(param)
            else:
                filtered_params.append(param)
        
        new_query = "&".join(filtered_params)
        
        if new_query:
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    @staticmethod
    def detect_session_in_url(url: str) -> bool:
        """检测URL中是否包含session参数"""
        parsed = urlparse(url)
        params = parsed.query.split("&") if parsed.query else []
        
        for param in params:
            if "=" in param:
                key = param.split("=")[0].lower()
                if key in URLSessionFilter.SESSION_PARAMS:
                    return True
        
        return False


class SessionFixationGuard:
    """
    Session Fixation防护守卫
    
    综合防护方案。
    """
    
    def __init__(self):
        self.session_manager = SecureSessionManager()
        self.url_filter = URLSessionFilter()
    
    def process_request(self, cookies: Dict[str, str],
                        url_params: Dict[str, str]) -> Optional[str]:
        """
        处理请求
        
        1. 检查URL中是否有session参数
        2. 从cookie中获取session
        3. 返回有效的session ID
        """
        # 拒绝URL中的session ID
        if "sessionid" in url_params:
            raise SessionFixationError("Session ID in URL rejected")
        
        # 从cookie获取session
        session_id = cookies.get("sessionid")
        if not session_id:
            return None
        
        # 验证session
        session = self.session_manager.get_session(session_id)
        if not session:
            return None
        
        return session_id
    
    def handle_login(self, session_id: str, user_data: Dict) -> str:
        """
        登录处理
        
        重新生成session ID。
        """
        return self.session_manager.login(session_id, user_data)
    
    def get_response_cookies(self, session_id: str) -> Dict[str, str]:
        """获取响应cookie头"""
        return {
            "Set-Cookie": self.session_manager.get_cookie_header(session_id)
        }


if __name__ == "__main__":
    guard = SessionFixationGuard()
    
    # 创建session
    session_id = guard.session_manager.create_session()
    print(f"New session: {session_id[:16]}...")
    
    # 测试URL中的session ID
    try:
        guard.process_request({}, {"sessionid": "evil"})
        print("URL session: SHOULD BE BLOCKED")
    except SessionFixationError as e:
        print(f"URL session: BLOCKED - {e}")
    
    # 登录后重新生成session
    new_session_id = guard.handle_login(session_id, {"user": "admin"})
    print(f"After login: {new_session_id[:16]}...")
    print(f"Session regenerated: {session_id != new_session_id}")
    
    # 验证旧session不可用
    try:
        guard.session_manager.get_session(session_id)
        print("Old session: SHOULD BE INVALID")
    except SessionFixationError:
        print("Old session: DELETED (correct)")
    
    # Cookie头
    cookie_header = guard.session_manager.get_cookie_header(new_session_id)
    print(f"Cookie: {cookie_header[:60]}...")
    print(f"Has Secure: {'Secure' in cookie_header}")
    print(f"Has HttpOnly: {'HttpOnly' in cookie_header}")
    print(f"Has SameSite: {'SameSite' in cookie_header}")
    
    print("\nSession Fixation Prevention Features:")
    print("- Session regeneration on login")
    print("- URL session ID rejection")
    print("- Secure + HttpOnly cookies")
    print("- SameSite cookie attribute")
    print("- Session lifetime enforcement")
    print("- Server-generated session IDs")
