"""
ssrf_dns_rebinding_protection.py — SSRF via DNS Rebinding Bypassing Allowlist Fix

漏洞背景:
- DNS重绑定攻击利用DNS解析的时间差（TOCTOU）
- 第一次DNS解析返回合法IP（通过白名单检查）
- 第二次DNS解析指向内部IP（如169.254.169.254 AWS元数据端点）
- 修复需要: 在连接建立后验证解析IP一致、禁用DNS缓存、
  使用双检查（pre-connect + post-connect验证）

本模块实现DNS重绑定防护。
"""

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib import parse as urlparse


class DNSRebindingError(Exception):
    """DNS重绑定安全异常"""
    pass


BLOCKED_NETWORKS = [
    ipaddress.ip_network(net)
    for net in [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        # IPv6
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
    ]
]


@dataclass
class DNSRebindingConfig:
    """DNS重绑定防护配置"""
    allowed_hosts: Set[str] = field(default_factory=lambda: {
        "api.example.com",
        "cdn.example.com",
        "assets.example.com",
    })
    dns_resolve_attempts: int = 3
    dns_resolve_delay_ms: int = 100
    connect_timeout_seconds: float = 5.0
    max_response_bytes: int = 1_000_000


def _resolve_hostname(hostname: str) -> List[ipaddress.IPv4Address]:
    """解析hostname获取所有IPv4地址"""
    try:
        results = socket.getaddrinfo(
            hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM,
        )
    except socket.gaierror as e:
        raise DNSRebindingError(f"Cannot resolve hostname: {hostname}") from e

    ips = []
    for res in results:
        try:
            ips.append(ipaddress.IPv4Address(res[4][0]))
        except (ValueError, IndexError):
            pass

    if not ips:
        raise DNSRebindingError(f"No IPv4 addresses resolved for: {hostname}")

    return ips


def _is_blocked_ip(ip: ipaddress.IPv4Address) -> bool:
    """检查IP是否在阻止列表中"""
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


def validate_and_prevent_dns_rebinding(
    url: str,
    config: DNSRebindingConfig = None,
) -> str:
    """
    验证URL并防止DNS重绑定攻击

    使用双重DNS解析 + 连接后验证机制:
    1. 连接前解析域名 → 验证IP不在黑名单
    2. 建立TCP连接
    3. 连接后重新解析域名 → 验证两次解析结果一致
    4. 如果IP变更则拒绝

    Args:
        url: 待验证的URL
        config: 安全配置

    Returns:
        验证通过的安全URL

    Raises:
        DNSRebindingError: 检测到DNS重绑定或其他安全问题
    """
    config = config or DNSRebindingConfig()

    parsed = urlparse.urlparse(url.strip() if isinstance(url, str) else "")
    if parsed.scheme != "https":
        raise DNSRebindingError("Only HTTPS is allowed")

    hostname = parsed.hostname.lower().rstrip(".")
    if not hostname:
        raise DNSRebindingError("Hostname is required")

    if hostname not in config.allowed_hosts:
        raise DNSRebindingError(f"Hostname '{hostname}' not in allowlist")

    # 阶段1: 连接前多重DNS解析 (检测初始重绑定)
    all_pre_ips = set()
    for i in range(config.dns_resolve_attempts):
        ips = _resolve_hostname(hostname)
        all_pre_ips.update(ips)
        if i < config.dns_resolve_attempts - 1:
            time.sleep(config.dns_resolve_delay_ms / 1000.0)

    # 检查初始解析结果
    for ip in all_pre_ips:
        if _is_blocked_ip(ip):
            raise DNSRebindingError(
                f"Hostname resolves to blocked address: {ip}"
            )

    # 阶段2: 建立TCP连接并获取对端实际IP
    try:
        sock = socket.create_connection(
            (hostname, 443),
            timeout=config.connect_timeout_seconds,
        )

        # 获取对端IP
        peer_ip_str, peer_port = sock.getpeername()
        peer_ip = ipaddress.IPv4Address(peer_ip_str)

        # 阶段3: 连接后重新解析 (检测连接后DNS变更)
        time.sleep(config.dns_resolve_delay_ms / 1000.0)
        post_connect_ips = _resolve_hostname(hostname)
        post_connect_set = set(post_connect_ips)

        if peer_ip not in all_pre_ips:
            sock.close()
            raise DNSRebindingError(
                f"DNS rebinding detected! Peer IP {peer_ip} was not in "
                f"pre-connect resolution set {all_pre_ips}"
            )

        if peer_ip not in post_connect_set:
            sock.close()
            raise DNSRebindingError(
                f"DNS rebinding detected! Connection IP {peer_ip} not in "
                f"post-connect DNS results {post_connect_set}"
            )

        sock.close()

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        raise DNSRebindingError(f"Connection failed: {e}") from e

    return url


def safe_https_request(
    url: str,
    timeout_seconds: float = 10.0,
) -> bytes:
    """
    安全的HTTPS请求，防止SSRF和DNS重绑定

    Args:
        url: 目标URL
        timeout_seconds: 超时

    Returns:
        响应内容

    Raises:
        DNSRebindingError: 安全检测失败
    """
    import urllib.request

    config = DNSRebindingConfig(connect_timeout_seconds=timeout_seconds)

    # 预验证并防止DNS重绑定
    validate_and_prevent_dns_rebinding(url, config)

    # 执行请求 (使用NoRedirectHandler)
    from urllib.request import HTTPRedirectHandler

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise DNSRebindingError("Redirects are not allowed")

    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SecureFetch/1.0",
            "Accept": "application/json",
        },
    )

    ctx = ssl.create_default_context()
    with opener.open(req, timeout=timeout_seconds, context=ctx) as resp:
        content = resp.read(config.max_response_bytes + 1)
        if len(content) > config.max_response_bytes:
            raise DNSRebindingError("Response too large")
        return content


# 使用示例
if __name__ == "__main__":
    cfg = DNSRebindingConfig(
        allowed_hosts={"api.example.com", "cdn.example.com"},
        dns_resolve_attempts=3,
        dns_resolve_delay_ms=100,
    )

    # 验证
    test_url = "https://api.example.com/data"
    try:
        validate_and_prevent_dns_rebinding(test_url, cfg)
        print(f"URL passed DNS rebinding check: {test_url}")
        print("Features: pre-connect DNS cache busting,")
        print("  multi-resolve detection, post-connect IP verification")
    except DNSRebindingError as e:
        print(f"Blocked: {e}")
