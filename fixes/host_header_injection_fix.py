"""
host_header_injection_fix.py — Host Header Injection → Password Reset Poisoning Fix

漏洞背景:
- 应用信任Host头用于密码重置链接生成
- 攻击者可篡改Host头指向恶意服务器
- 修复需要: 验证Host头 + 使用白名单

本模块实现Host头验证防止密码重置投毒。
"""

from typing import Dict, Set, Optional


class HostHeaderInjectionError(Exception):
    """Host头注入异常"""
    pass


ALLOWED_HOSTS = frozenset({
    "example.com", "www.example.com", "api.example.com",
    "app.example.com", "admin.example.com",
})


class SecureHostValidator:
    """安全Host验证器"""
    
    @staticmethod
    def validate_host(host: str) -> bool:
        """验证Host头"""
        if not host:
            raise HostHeaderInjectionError("Missing Host header")
        
        # 移除端口号
        clean_host = host.split(":")[0] if ":" in host else host
        
        if clean_host not in ALLOWED_HOSTS:
            raise HostHeaderInjectionError(f"Invalid Host: {clean_host}")
        
        return True
    
    @staticmethod
    def get_secure_reset_link(email: str, token: str) -> str:
        """生成安全的密码重置链接"""
        return f"https://example.com/reset?email={email}&token={token}"


if __name__ == "__main__":
    validator = SecureHostValidator()
    
    try:
        validator.validate_host("example.com")
        print("Valid host: OK")
    except HostHeaderInjectionError as e:
        print(f"Valid host: ERROR - {e}")
    
    try:
        validator.validate_host("evil.com")
        print("Invalid host: SHOULD BE BLOCKED")
    except HostHeaderInjectionError as e:
        print(f"Invalid host: BLOCKED - {e}")
    
    link = SecureHostValidator.get_secure_reset_link("user@example.com", "token123")
    print(f"Reset link: {link}")
    
    print("\nHost Header Protection:")
    print("- Host whitelist validation")
    print("- Hardcoded domain for reset links")
    print("- Port stripping for comparison")
    print("- Missing host detection")
