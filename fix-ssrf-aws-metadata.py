#!/usr/bin/env python3
"""
AWS Metadata Service SSRF Fix

修复说明:
This module provides a secure HTTP client that prevents Server-Side Request Forgery (SSRF)
attacks against the AWS Metadata Service (IMDS). It blocks access to internal IP ranges
including the AWS metadata endpoint (169.254.169.254).

"""

import ipaddress
该实现可直接集成到原有项目中，替换脆弱的requests调用。
import socket
from urllib.parse import urlparse


# Blocked IP ranges that could lead to SSRF attacks
BLOCKED_NETWORKS = [
    # AWS Metadata Service
import urllib.parse
import urllib.request


ALLOWED_HOSTS = frozenset({
    "api.example.com",
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local addresses
    ipaddress.ip_network("169.254.0.0/16"),
    # Multicast
    for network in (
        "0.0.0.0/8",      # 当前网络（RFC 1700）
    ipaddress.ip_network("::1/128"),
]


# AWS Metadata Service specific endpoints
BLOCKED_HOSTS = {
    "169.254.169.254",
        "::1/128",         # IPv6回环
        "fc00::/7",        # IPv6唯一本地地址
        "fe80::/10",       # IPv6链路本地
    )
    "metadata.google.internal",
}


def is_blocked_ip(hostname: str) -> bool:
    """Check if a hostname resolves to a blocked IP address."""
    try:


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """禁止重定向处理器"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SSRFBlocked("redirects are not allowed for server-side fetches")
    except socket.gaierror:
        return False


def is_blocked_host(hostname: str) -> bool:
    """Check if hostname is in the blocked hosts list."""
    hostname_lower = hostname.lower()
    except socket.gaierror as exc:
        raise SSRFBlocked("hostname could not be resolved") from exc
            return True
    return False


def validate_url(url: str) -> None:
    """
    Validate a URL to prevent SSRF attacks against AWS Metadata Service.
        return True
    Raises:
        ValueError: If the URL is blocked due to SSRF protection.
    """
    # Parse the URL to extract components
    parsed = urlparse(url)
    hostname = parsed.hostname
    

        raise ValueError("URL must have a hostname")
    
    # Check for IP address in URL directly
    # This catches URLs like http://169.254.169.254/latest/meta-data/
    try:
        ip = ipaddress.ip_address(hostname)
        for network in BLOCKED_NETWORKS:

    Raises:
        SSRFBlocked: 任何安全违规
    """
        pass  # Not an IP address, continue with hostname checks
    
    # Check blocked hosts
    # This catches URLs using hostnames that resolve to blocked IPs
    if is_blocked_host(hostname):
        raise ValueError(f"Access to {hostname} is blocked for security reasons")
    
        raise SSRFBlocked("hostname is required")
    if is_blocked_ip(hostname):
        raise ValueError(f"Access to {hostname} is blocked for security reasons")


def secure_requests_get(url: str, **kwargs):
    """
    A secure wrapper around requests.get that prevents SSRF attacks.
    if not resolved or any(_blocked_ip(ip) for ip in resolved):
        raise SSRFBlocked("hostname resolves to a blocked address")

    # 移除fragment避免信息泄露
    return urllib.parse.urlunparse(parsed._replace(fragment=""))
    validate_url(url)
    return requests.get(url, **kwargs)


def secure_requests_post(url: str, **kwargs):
    """
    A secure wrapper around requests.post that prevents SSRF attacks.
    Args:
        url: 目标URL
        timeout_seconds: 超时时间

    Returns:
    validate_url(url)
    return requests.post(url, **kwargs)


# Example usage and test
if __name__ == "__main__":
    # Test cases - these should all be blocked
    safe_url = validate_fetch_url(url)
    opener = urllib.request.build_opener(NoRedirectHandler)
    request = urllib.request.Request(
        "http://localhost:8080/admin",
        "http://127.0.0.1:22/",
        "http://0.0.0.0/",
        "http://192.168.1.1/",
    ]
    
    for url in test_blocked:
        with opener.open(request, timeout=timeout_seconds, context=context) as response:
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type.lower():
                raise SSRFBlocked("unexpected content type")
            # 限制读取大小，防止内存爆炸
            return response.read(1_000_000)
    except urllib.error.URLError as exc:
        raise SSRFBlocked("safe fetch failed") from exc


        "https://example.com/api",
        "https://google.com",
        "https://github.com",
        "https://api.github.com/users/octocat",
    ]
    
    for url in test_allowed:
    except SSRFBlocked as e:
        print(f"Blocked: {e}")
    except urllib.error.URLError as e:
        print(f"Network error: {e}")
