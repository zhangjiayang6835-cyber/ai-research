"""
gopher_ssrf_fix.py — SSRF via Gopher Protocol → Redis RCE Fix

漏洞背景:
- 应用允许Gopher协议请求
- Gopher协议可伪造Redis命令
- 攻击者可利用SSRF通过Gopher协议执行Redis命令

本模块实现URL协议白名单和SSRF防护。
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Optional, Set


class GopherSSRFError(Exception):
    """Gopher SSRF异常"""
    pass


# 允许的协议白名单
ALLOWED_PROTOCOLS = frozenset({"http", "https", "ftp", "ftps"})

# 禁止的协议黑名单
BLOCKED_PROTOCOLS = frozenset({
    "gopher", "file", "dict", "ldap", "ldaps",
    "tftp", "smtp", "pop3", "imap", "mysql",
    "redis", "mongodb", "docker", "oci",
})

# 内部IP范围
PRIVATE_IPS = frozenset({
    "127.", "10.", "192.168.", "172.16.", "172.17.",
    "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.",
})


class URLProtocolValidator:
    """URL协议验证器"""
    
    @staticmethod
    def validate_protocol(url: str) -> bool:
        """验证URL协议是否安全"""
        parsed = urlparse(url)
        protocol = parsed.scheme.lower()
        
        if protocol in BLOCKED_PROTOCOLS:
            raise GopherSSRFError(f"Blocked protocol: {protocol}")
        
        if protocol not in ALLOWED_PROTOCOLS:
            raise GopherSSRFError(f"Unknown protocol: {protocol}")
        
        return True
    
    @staticmethod
    def validate_host(host: str) -> bool:
        """验证主机是否安全"""
        for private_ip in PRIVATE_IPS:
            if host.startswith(private_ip):
                raise GopherSSRFError(f"Internal IP blocked: {host}")
        
        if host == "localhost" or host == "127.0.0.1":
            raise GopherSSRFError("Localhost blocked")
        
        if host.startswith("0."):
            raise GopherSSRFError("Zero IP blocked")
        
        return True
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """完整URL验证"""
        URLProtocolValidator.validate_protocol(url)
        parsed = urlparse(url)
        URLProtocolValidator.validate_host(parsed.hostname or "")
        return True


class SSRFGuard:
    """SSRF防护守卫"""
    
    def __init__(self):
        self.validator = URLProtocolValidator()
    
    def check_url(self, url: str) -> bool:
        """检查URL是否安全"""
        return self.validator.validate_url(url)


if __name__ == "__main__":
    guard = SSRFGuard()
    
    # 安全URL
    safe_urls = ["https://example.com", "http://api.example.com/data"]
    for url in safe_urls:
        try:
            guard.check_url(url)
            print(f"Safe URL '{url}': OK")
        except GopherSSRFError as e:
            print(f"Safe URL '{url}': ERROR - {e}")
    
    # 危险URL
    dangerous_urls = [
        "gopher://redis:6379/_SET%20key%20value",
        "file:///etc/passwd",
        "dict://internal:11211/",
        "http://127.0.0.1/admin",
        "http://192.168.1.1/config",
    ]
    for url in dangerous_urls:
        try:
            guard.check_url(url)
            print(f"Dangerous URL '{url[:20]}...': SHOULD BE BLOCKED")
        except GopherSSRFError as e:
            print(f"Dangerous URL '{url[:20]}...': BLOCKED - {e}")
    
    print("\nSSRF Protection Features:")
    print("- Protocol whitelist (http/https/ftp)")
    print("- Gopher/dict/file protocol blocking")
    print("- Internal IP range blocking")
    print("- Localhost blocking")
    print("- URL parsing validation")
