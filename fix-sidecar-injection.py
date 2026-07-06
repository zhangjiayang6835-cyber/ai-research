#!/usr/bin/env python3
"""
Fix for BGP Hijacking Simulation → TLS Certificate Bypass vulnerability.

- 在K8s服务网格（如Istio、Linkerd）中，sidecar代理自动注入到pod
- 攻击者可利用注入机制插入恶意sidecar，拦截流量
- 修复需要: 强制mTLS、验证配置来源、限制注入授权

本模块提供运行时验证和配置硬化建议。
import ssl
import socket
import hashlib
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timezone

from typing import Set, Optional

    'verify_mode': ssl.CERT_REQUIRED,
    'check_hostname': True,
    'minimum_version': ssl.TLSVersion.TLSv1_2,
    'purpose': ssl.Purpose.SERVER_AUTH,
}

# Certificate pinning for known good CAs (defense in depth)
    allowed_injectors: Set[str]  # 允许的注入器标识
    'sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    'sha256//BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
}

def _create_ssl_context() -> ssl.SSLContext:
    """Create a secure SSL context with strong defaults."""
    context = ssl.create_default_context()

    context.check_hostname = _SSL_CONFIG['check_hostname']
    context.minimum_version = _SSL_CONFIG['minimum_version']
    context.load_default_certs()
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    return context


        self.known_injectors = {
            "istio-sidecar-injector",
    'Connection': 'close',
}


def fetch_url(url: str, timeout: int = 30) -> dict:
    """
    Fetch a URL with strong TLS verification.
        injection_config: dict,
        signature: str,
        injector_id: str
    ) -> bool:
        """
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        raise ValueError("Only HTTPS URLs are allowed")
    
    # Prevent IP-based URL bypasses (BGP hijacking vector)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("Invalid URL: no hostname")
    
    # Reject raw IP addresses to prevent BGP hijacking via IP direct access
    try:
        ipaddress.ip_address(hostname)
        raise ValueError("Direct IP access is not allowed to prevent BGP hijacking")
    except ValueError:
        pass  # Not an raw IP, proceed
    
    # Additional check: ensure hostname is not empty and is valid
    if not hostname or '.' not in hostname:
        raise ValueError("Invalid hostname")

    context = _create_ssl_context()


        Returns:
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            port=parsed.port or 443,
            context=context,  # type: ignore[arg-type]
            timeout=timeout,
        )
        conn.request('GET', parsed.path or '/', headers=_DEFAULT_HEADERS)
        expected_hex = expected.hex()

        # Verify certificate pinning
        cert_binary = response.getpeercert(binary_form=True)
        if not cert_binary or not isinstance(cert_binary, bytes):
            raise ssl.SSLError("No certificate received from server")

        cert_hash = hashlib.sha256(cert_binary).hexdigest()
    ) -> bool:
        """
        检查命名空间是否允许注入
        if not pin_valid:
            raise ssl.SSLError("Certificate pinning failed - possible BGP hijack")

        body = response.read().decode('utf-8', errors='replace')

        return {
            'status': response.status,
        """
        return "*" in allowed_namespaces or namespace in allowed_namespaces

    def is_ip_allowed(
    finally:
        if conn:
            conn.close()

    ) -> bool:
        """
        检查sidecar IP是否在允许范围内

        注意: 实际应使用ipaddress库进行CIDR检查
        """
        # 简化实现 - 生产中应使用ipaddress module
        return any(sidecar_ip.startswith(prefix.split('/')[0]) for prefix in config.allowed_ips)

    def enforce(
        self,
        config: SidecarConfig,
        injection_config: dict,
        signature: str,
        injector_id: str,
        namespace: str,
        sidecar_ip: str
    ) -> bool:
        """
        完整安全策略执行

        Returns:
            bool: 是否通过所有检查
        """
        # 1. 验证签名
        if not self.verify_injection_signature(injection_config, signature, injector_id):
            return False

        # 2. 检查命名空间
        allowed_ns = {"default", "production", "staging"}
        if not self.validate_namespace(namespace, allowed_ns):
            return False

        # 3. 验证IP白名单
        if not self.is_ip_allowed(sidecar_ip, config):
            return False

        # 4. 强制mTLS
        if config.require_mtls and not injection_config.get("mtls_enabled", False):
            return False

        return True


def generate_secure_injection_config(
    namespace: str,
    service_account: str,
    mtls_mode: str = "STRICT"
) -> dict:
    """
    生成安全的sidecar注入配置模板

    Returns:
        dict: 安全的注入配置
    """
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "namespace": namespace,
            "annotations": {
                "sidecar.istio.io/inject": "true",
                "istio.io/rev": "default",
                "sidecar.istio.io/rewriteAppHTTPProbers": "true"
            }
        },
        "spec": {
            "serviceAccountName": service_account,
            "containers": [
                {
                    "name": "app",
                    "image": "your-app:latest"
                }
            ],
            # 关键安全设置
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 1000,
                "fsGroup": 1000
            }
        }
    }


# 使用示例
if __name__ == "__main__":
    # 配置
    secret = b"super-secret mesh key"
    enforcer = SidecarSecurityEnforcer(secret)

    config = SidecarConfig(
        namespace="production",
        service_account="app-sa",
        allowed_injectors={"istio-sidecar-injector"},
        require_mtls=True,
        allowed_ips={"10.0.0.0/8", "127.0.0.1"}
    )

    # 模拟注入配置
    inj_cfg = generate_secure_injection_config("production", "app-sa")
    # 在真实场景中，签名由注入器生成
    sig = "dummy"  # 这里应计算HMAC

    result = enforcer.enforce(
        config=config,
        injection_config=inj_cfg,
        signature=sig,
        injector_id="istio-sidecar-injector",
        namespace="production",
        sidecar_ip="10.1.2.3"
    )
    print(f"Sidecar injection valid: {result}")
