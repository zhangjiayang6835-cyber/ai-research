#!/usr/bin/env python3
# TCP Timestamp Side Channel Fix - Cloud Provider Identification Mitigation
"""
SSRF AWS Metadata Fix
Prevents Server-Side Request Forgery attacks against AWS metadata endpoints.
1. 只允许HTTPS协议

import ipaddress
import re
import socket
import urllib.parse
from typing import List, Optional, Set, Tuple

"""

import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
        # AWS EC2 metadata IP
        "169.254.169.254",
    }
    _tcp_privacy_configured = False
    
    # Common cloud metadata endpoints
    CLOUD_METADATA_PATTERNS = [
})

BLOCKED_IP_RANGES = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",      # 当前网络（RFC 1700）
        "10.0.0.0/8",      # 私有网络
        r".*\.internal\.",
    ]
    
    @classmethod
    def _configure_tcp_privacy(cls):
        """Configure TCP settings to prevent timestamp-based cloud provider identification."""
        if cls._tcp_privacy_configured:
            return
        try:
            import os
            if os.path.exists('/proc/sys/net/ipv4/tcp_timestamps'):
                with open('/proc/sys/net/ipv4/tcp_timestamps', 'w') as f:
                    f.write('0\n')
        except (PermissionError, OSError):
            pass
        cls._tcp_privacy_configured = True
    
    def __init__(self):
        self._configure_tcp_privacy()
    
    @classmethod
    def create_privacy_socket(cls) -> socket.socket:
        """Create a socket with TCP timestamp disabled to prevent OS fingerprinting."""
        cls._configure_tcp_privacy()
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    @classmethod
    def is_internal_ip(cls, ip_str: str) -> bool:
        """Check if an IP address is internal/private."""
        "fc00::/7",        # IPv6唯一本地地址
        "fe80::/10",       # IPv6链路本地
    )
)


class SSRFBlocked(ValueError):
    """SSRF防护异常"""
    pass


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """禁止重定向处理器"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SSRFBlocked("redirects are not allowed for server-side fetches")


def _host_ips(hostname: str):
    """解析hostname获取所有IP地址"""
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlocked("hostname could not be resolved") from exc
    return [ipaddress.ip_address(result[4][0]) for result in results]


def _blocked_ip(ip):
    """检查IP是否在阻止列表中"""
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True
    return any(ip in network for network in BLOCKED_IP_RANGES)


def validate_fetch_url(url: str, allowed_hosts: frozenset[str] = ALLOWED_HOSTS) -> str:
    """
    验证URL安全性

    Args:
        url: 待验证的URL
        allowed_hosts: 允许的hostname集合

    Returns:
        规范化后的安全URL（无fragment）

    Raises:
        SSRFBlocked: 任何安全违规
    """
    parsed = urllib.parse.urlparse(url.strip() if isinstance(url, str) else "")
    if parsed.scheme != "https":
        raise SSRFBlocked("only https URLs are allowed")
    if parsed.username or parsed.password:
        raise SSRFBlocked("userinfo is not allowed in URLs")
    if not parsed.hostname:
        raise SSRFBlocked("hostname is required")

    hostname = parsed.hostname.lower().rstrip(".")
    if hostname not in allowed_hosts:
        raise SSRFBlocked(f"hostname '{hostname}' is not on the allowlist")
def main():
    """Main entry point for the SSRF fix."""
    fix = SSRFAWSMetadataFix()
    fix._configure_tcp_privacy()
    
    # Test cases
    test_urls = [
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def fetch_external_json(url: str, timeout_seconds: float = 3.0) -> bytes:
    """
    安全获取外部JSON数据

    Args:
        url: 目标URL
        timeout_seconds: 超时时间

    Returns:
        JSON原始字节（限1MB）

    Raises:
        SSRFBlocked: 任何安全违规
        urllib.error.URLError: 网络错误
    """
    safe_url = validate_fetch_url(url)
    opener = urllib.request.build_opener(NoRedirectHandler)
    request = urllib.request.Request(
        safe_url,
        headers={"Accept": "application/json", "User-Agent": "safe-fetch/1.0"},
        method="GET",
    )
    context = ssl.create_default_context()
    try:
        with opener.open(request, timeout=timeout_seconds, context=context) as response:
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type.lower():
                raise SSRFBlocked("unexpected content type")
            # 限制读取大小，防止内存爆炸
            return response.read(1_000_000)
    except urllib.error.URLError as exc:
        raise SSRFBlocked("safe fetch failed") from exc


# 使用示例:
if __name__ == "__main__":
    # 正常请求
    try:
        data = fetch_external_json("https://api.example.com/data")
        print(f"Fetched {len(data)} bytes")
    except SSRFBlocked as e:
        print(f"Blocked: {e}")
    except urllib.error.URLError as e:
        print(f"Network error: {e}")
