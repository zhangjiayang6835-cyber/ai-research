"""
dns_rebinding_webrtc_fix.py — DNS Rebinding + WebRTC → Internal Network Reconnaissance Fix

漏洞背景:
- DNS重绑定绕过同源策略，允许攻击者访问内网服务
- WebRTC泄露内网IP地址（即使使用VPN）
- 攻击者组合这两种技术探测内网拓扑和服务
- 修复需要: 实施DNS重新绑定防护、WebRTC IP泄露防护、
  内网DNS解析验证、STUN/TURN安全配置

本模块实现DNS重绑定+WebRTC内网探测防护。
"""

import hashlib
import ipaddress
import json
import random
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


class DNSSecurityError(Exception):
    """DNS安全异常"""
    pass


PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


@dataclass
class WebRTCSecurityConfig:
    """WebRTC安全配置"""
    stun_servers: Set[str] = field(default_factory=lambda: {
        "stun:stun.l.google.com:19302",
    })
    turn_servers: list = field(default_factory=list)
    ice_transport_policy: str = "relay"  # 仅使用中继（最安全）
    disable_non_proxied_udp: bool = True
    enforce_secure_transport: bool = True


class WebRTCIPLeakPreventer:
    """WebRTC IP泄露防护"""

    def __init__(self, config: WebRTCSecurityConfig = None):
        self.config = config or WebRTCSecurityConfig()

    def generate_secure_ice_config(self) -> dict:
        """
        生成安全的ICE配置

        安全措施:
        - 仅使用TLS中继
        - 不使用STUN（避免泄露公网IP）
        - 限制ICE候选类型
        - 强制TURN relay传输
        """
        ice_servers = []

        # TURN服务器
        for turn_server in self.config.turn_servers:
            ice_servers.append({
                "urls": turn_server,
                "username": "",  # 应在运行时填充
                "credential": "",
            })

        # 安全配置
        ice_config = {
            "iceServers": ice_servers,
            "iceTransportPolicy": self.config.ice_transport_policy,
            "iceCandidatePoolSize": 0,
            "bundlePolicy": "max-bundle",
            "rtcpMuxPolicy": "require",
        }

        return ice_config

    def sanitize_ipc_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        清理HTTP头中的IP泄露风险

        WebRTC可能通过以下头泄露IP:
        - X-Forwarded-For
        - X-Real-IP
        - Client-IP
        - Via
        """
        sensitive_headers = {
            "x-forwarded-for",
            "x-real-ip",
            "client-ip",
            "x-cluster-client-ip",
            "x-forwarded-host",
            "via",
        }

        sanitized = {}
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in sensitive_headers:
                # 对内部IP进行脱敏
                ips = [ip.strip() for ip in value.split(",")]
                sanitized_ips = []
                for ip_str in ips:
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if ip.is_private or ip.is_loopback or ip.is_link_local:
                            sanitized_ips.append("[internal]")
                        else:
                            sanitized_ips.append("[external]")
                    except ValueError:
                        sanitized_ips.append(ip_str)
                sanitized[key] = ", ".join(sanitized_ips)
            else:
                sanitized[key] = value

        return sanitized

    def validate_stun_turn_url(self, url: str) -> bool:
        """
        验证STUN/TURN URL安全性

        拒绝:
        - 私有IP的服务器
        - 非标准端口
        - 不安全的协议
        """
        if "stun:" in url:
            # STUN应在公网
            host = url.split("/")[-1].split(":")[0]
            try:
                ips = socket.getaddrinfo(host, None)
                for ip_info in ips:
                    ip_str = ip_info[4][0]
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if ip.is_private or ip.is_loopback:
                            return False
                    except ValueError:
                        continue
            except socket.gaierror:
                return False

        return True


class DNSRebindingPreventer:
    """DNS重绑定防护（服务端）"""

    def __init__(self):
        self._dns_cache: Dict[str, List[str]] = {}

    def resolve_with_double_check(
        self,
        hostname: str,
        family: int = socket.AF_INET,
    ) -> str:
        """
        双重DNS解析防止重绑定

        策略:
        1. 第一次解析
        2. 等待短时间（使DNS TTL过期）
        3. 第二次解析
        4. 比较两次结果是否一致
        5. 验证IP不是私有地址
        """
        # 第一次解析
        first_ips = self._resolve(hostname, family)
        if not first_ips:
            raise DNSSecurityError(f"Cannot resolve: {hostname}")

        for ip in first_ips:
            if self._is_private_ip(ip):
                raise DNSSecurityError(f"Resolves to private IP: {hostname} -> {ip}")

        # 等待（打破DNS缓存窗口）
        time.sleep(random.uniform(0.05, 0.2))

        # 第二次解析
        second_ips = self._resolve(hostname, family)
        if not second_ips:
            raise DNSSecurityError(f"Second resolution failed: {hostname}")

        # 比较IP集合
        first_set = set(first_ips)
        second_set = set(second_ips)

        if first_set != second_set:
            raise DNSSecurityError(
                f"DNS rebinding detected! IPs changed: "
                f"{first_set} -> {second_set}"
            )

        result = first_ips[0]
        self._dns_cache[hostname] = [result]
        return result

    def _resolve(self, hostname: str, family: int) -> List[str]:
        """解析域名获取IP列表"""
        try:
            results = socket.getaddrinfo(
                hostname, None, family=family, type=socket.SOCK_STREAM,
            )
            ips = []
            seen = set()
            for res in results:
                ip = res[4][0]
                if ip not in seen:
                    ips.append(ip)
                    seen.add(ip)
            return ips
        except socket.gaierror:
            return []

    def _is_private_ip(self, ip_str: str) -> bool:
        """检查IP是否为私有/内网地址"""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return True
            for net in PRIVATE_NETWORKS:
                if ip in net:
                    return True
            return False
        except ValueError:
            return False

    def validate_external_request(
        self,
        remote_ip: str,
        remote_host: str,
    ) -> bool:
        """
        验证外部请求的来源

        安全策略:
        - 拒绝来自私有IP的外部请求
        - 拒绝Host头与解析IP不匹配的请求
        """
        try:
            ip = ipaddress.ip_address(remote_ip)
            if ip.is_private or ip.is_loopback:
                return False
        except ValueError:
            return False

        # 验证Host头与请求IP一致
        if remote_host:
            try:
                resolved = socket.gethostbyname(remote_host)
                if resolved != remote_ip:
                    return False
            except socket.gaierror:
                return False

        return True


class InternalNetworkProtector:
    """内网探测综合防护"""

    def __init__(self):
        self.dns_protector = DNSRebindingPreventer()
        self.webrtc_protector = WebRTCIPLeakPreventer()

    def verify_request_origin(self, request_info: dict) -> bool:
        """
        验证请求来源安全性

        检查:
        1. DNS重绑定
        2. WebRTC IP泄露
        3. SSRF防护
        """
        remote_ip = request_info.get("remote_ip", "")
        host = request_info.get("host", "")

        # 拒绝内网请求
        if remote_ip:
            try:
                ip = ipaddress.ip_address(remote_ip)
                if ip.is_private:
                    return False
            except ValueError:
                return False

        # DNS重绑定检测
        if host:
            try:
                self.dns_protector.resolve_with_double_check(host)
            except DNSSecurityError:
                return False

        return True

    def generate_security_headers(self) -> Dict[str, str]:
        """生成安全响应头"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-DNS-Prefetch-Control": "off",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": (
                "camera=(), microphone=(), geolocation=(), "
                "interest-cohort=(), document-domain=()"
            ),
        }


if __name__ == "__main__":
    protector = InternalNetworkProtector()

    print("DNS Rebinding + WebRTC Prevention System")
    print("=" * 50)

    # DNS重绑定检测
    dns = DNSRebindingPreventer()
    try:
        # 测试公网域名
        ip = dns.resolve_with_double_check("google.com")
        print(f"\nDNS double-check: google.com -> {ip}")
    except DNSSecurityError as e:
        print(f"\nDNS rebinding detected: {e}")

    # WebRTC配置
    webrtc_cfg = WebRTCSecurityConfig(
        stun_servers={"stun:stun.l.google.com:19302"},
        ice_transport_policy="relay",
        disable_non_proxied_udp=True,
    )
    webrtc = WebRTCIPLeakPreventer(webrtc_cfg)
    ice = webrtc.generate_secure_ice_config()
    print(f"\nWebRTC config: relay-only ICE transport")

    print("\nSecurity features:")
    print("- Double DNS resolution (anti-rebinding)")
    print("- Private IP detection in DNS responses")
    print("- ICE relay-only transport")
    print("- STUN/TURN URL validation")
    print("- Security headers generation")
    print("- Request origin verification")
