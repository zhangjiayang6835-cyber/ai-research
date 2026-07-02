#!/usr/bin/env python3
"""
AWS Metadata Service SSRF Fix

修复说明:
This module provides a secure HTTP client that prevents Server-Side Request Forgery (SSRF)
attacks against the AWS Instance Metadata Service (IMDS).
"""

import ipaddress
import re
import socket
该实现可直接集成到原有项目中，替换脆弱的requests调用。
from urllib.parse import urlparse, urlunparse


# Blocked IP ranges that should not be accessible
BLOCKED_IP_RANGES = [
    # AWS Instance Metadata Service
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local addresses including IMDS
import urllib.parse
    ipaddress.ip_network("10.0.0.0/8"),      # Private network (example)
]

# Blocked hostnames and patterns
BLOCKED_HOSTS = [
    "169.254.169.254",
    "localhost",
    "cdn.example.com"
})

BLOCKED_IP_RANGES = tuple(
    "metadata.google.internal",
]

# Regex patterns for blocked hosts
BLOCKED_HOST_PATTERNS = [
    re.compile(r"^169\.254\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
        "169.254.0.0/16",  # 链路本地 (含AWS Metadata 169.254.169.254)
        "172.16.0.0/12",   # 私有网络
]


#: Set of dangerous URL schemes
DANGEROUS_SCHEMES = {
    "file",
    "ftp",


class SSRFBlocked(ValueError):
    """SSRF防护异常"""
    pass

}


#: Maximum redirect hops to prevent infinite loops
MAX_REDIRECTS = 5



    """Raised when a URL is blocked due to SSRF protection."""
    pass


class SSRFProtectionError(SecurityError):
    """Raised when SSRF protection detects a blocked request."""
    pass
    return [ipaddress.ip_address(result[4][0]) for result in results]

class SecureHTTPClient:
    """
    HTTP client with SSRF protection against AWS metadata service and other internal endpoints.
    This client blocks requests to internal IP ranges, localhost, and cloud metadata endpoints.
    """

    def __init__(self, max_redirects: int = MAX_REDIRECTS):

        self._session = requests.Session()
        self._session.max_redirects = max_redirects


    def _is_blocked_host(self, hostname: str) -> bool:
        """Check if a hostname is in the blocked list."""
        hostname_lower = hostname.lower()
        url: 待验证的URL
        allowed_hosts: 允许的hostname集合

    Returns:
                return True
        return False


    def _is_blocked_ip(self, ip_str: str) -> bool:
        """Check if an IP address is in a blocked range."""
        try:
    if parsed.scheme != "https":
        raise SSRFBlocked("only https URLs are allowed")
    if parsed.username or parsed.password:
        raise SSRFBlocked("userinfo is not allowed in URLs")
        except ValueError:
            return False


    def _resolve_and_validate(self, hostname: str) -> bool:
        """
        Resolve hostname to IP and validate it's not blocked.

    resolved = _host_ips(hostname)
    if not resolved or any(_blocked_ip(ip) for ip in resolved):
        raise SSRFBlocked("hostname resolves to a blocked address")

    # 移除fragment避免信息泄露
    return urllib.parse.urlunparse(parsed._replace(fragment=""))
        except (socket.gaierror, socket.herror):
            return False


    def validate_url(self, url: str) -> str:
        """
        Validate a URL for SSRF safety.
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

        return url


    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Perform a GET request with SSRF protection.
        validated_url = self.validate_url(url)
        return self._session.get(validated_url, **kwargs)


    def post(self, url: str, **kwargs) -> requests.Response:
        """
        Perform a POST request with SSRF protection.
        validated_url = self.validate_url(url)
        return self._session.post(validated_url, **kwargs)


    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Perform an HTTP request with SSRF protection.
        validated_url = self.validate_url(url)
        return self._session.request(method, validated_url, **kwargs)


    def close(self):
        """Close the session."""
        self._session.close()
    def __enter__(self):
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

def create_secure_client() -> SecureHTTPClient:
    """
    Factory function to create a new secure HTTP client.

    Returns:
        SecureHTTPClient: A new secure HTTP client instance.
    """
def safe_fetch_url(url: str, timeout: int = 30) -> requests.Response:
    """
    Convenience function to safely fetch a URL with SSRF protection.

    Args:
        url: The URL to fetch
        timeout: Request timeout in seconds
        client.close()


# Example usage and basic tests
if __name__ == "__main__":
    # Test cases
    client = SecureHTTPClient()
        print(f"✅ Blocked dangerous URL: {dangerous_url}")

    client.close()
    print("\n✅ All SSRF protection tests passed!")
