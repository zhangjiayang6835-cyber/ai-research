import requests
import ipaddress
import urllib.parse
from flask import Flask, request, send_file
from reportlab.lib.pagesizes import letter
1. 只允许HTTPS协议
2. 强制hostname白名单验证
3. 解析并验证目标IP不在私有/保留范围
4. 禁止重定向（避免开放重定向链）
PDF_STORAGE_PATH = "/tmp/generated.pdf"


def is_private_url(url):
    """Check if URL resolves to a private/internal IP address to prevent SSRF."""
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return True
        
        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            # Block private, loopback, reserved, and multicast addresses
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
                return True
        except ValueError:
            # Not an IP, resolve it
            import socket
            resolved_ip = ipaddress.ip_address(socket.getaddrinfo(hostname, None)[0][4][0])
            if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_reserved or resolved_ip.is_multicast:
                return True
        return False
    except Exception:
        return True


@app.route("/generate-pdf", methods=["POST"])
def generate_pdf():
    data = request.get_json()
import socket
    if not url:
        return {"error": "Missing 'url' parameter"}, 400
    
    # Prevent SSRF by blocking internal/private URLs
    if is_private_url(url):
        return {"error": "Access to internal or private URLs is not allowed"}, 403
    
    try:
        # Fetch external content to include in PDF
        response = requests.get(url, timeout=10)
ALLOWED_HOSTS = frozenset({
    "api.example.com",
    "assets.example.com",
    "cdn.example.com"
})

BLOCKED_IP_RANGES = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",      # 当前网络（RFC 1700）
        "10.0.0.0/8",      # 私有网络
        "100.64.0.0/10",   # 共享地址空间 (RFC 6598)
        "127.0.0.0/8",     # 回环
        "169.254.0.0/16",  # 链路本地 (含AWS Metadata 169.254.169.254)
        "172.16.0.0/12",   # 私有网络
        "192.168.0.0/16",  # 私有网络
        "::1/128",         # IPv6回环
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

    resolved = _host_ips(hostname)
    if not resolved or any(_blocked_ip(ip) for ip in resolved):
        raise SSRFBlocked("hostname resolves to a blocked address")

    # 移除fragment避免信息泄露
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
