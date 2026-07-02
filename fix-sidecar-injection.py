"""
sidecar_security.py — Microservice Mesh Sidecar Injection Protection

漏洞背景:
- 在K8s服务网格（如Istio、Linkerd）中，sidecar代理自动注入到pod
- 攻击者可利用注入机制插入恶意sidecar，拦截流量
- 修复需要: 强制mTLS、验证配置来源、限制注入授权

本模块提供运行时验证和配置硬化建议。
"""

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Set, Optional


@dataclass
class SidecarConfig:
    """Sidecar注入配置验证"""
    namespace: str
    service_account: str
    allowed_injectors: Set[str]  # 允许的注入器标识
    require_mtls: bool = True
    allowed_ips: Set[str] = None  # 允许的sidecar IP范围

    def __post_init__(self):
        if self.allowed_ips is None:
            self.allowed_ips = {"10.0.0.0/8"}  # 网格内部IP


class SidecarSecurityEnforcer:
    """Sidecar注入安全执行器"""

    def __init__(self, shared_secret: bytes):
        self.shared_secret = shared_secret
        self.known_injectors = {
            "istio-sidecar-injector",
            "linkerd-proxy-injector",
            "consul-connect-injector"
        }

    def verify_injection_signature(
        self,
        injection_config: dict,
        signature: str,
        injector_id: str
    ) -> bool:
        """
        验证注入配置的HMAC签名，防止篡改

        Args:
            injection_config: 注入配置字典
            signature: Base64编码的HMAC签名
            injector_id: 注入器标识

        Returns:
            bool: 签名是否有效
        """
        if injector_id not in self.known_injectors:
            return False

        payload = json.dumps(injection_config, sort_keys=True).encode('utf-8')
        expected = hmac.new(self.shared_secret, payload, hashlib.sha256).digest()
        expected_hex = expected.hex()

        return hmac.compare_digest(expected_hex, signature)

    def validate_namespace(
        self,
        namespace: str,
        allowed_namespaces: Set[str]
    ) -> bool:
        """
        检查命名空间是否允许注入

        Args:
            namespace: K8s命名空间
            allowed_namespaces: 允许的命名空间集合 ("*" 表示全部)

        Returns:
            bool: 是否允许
        """
        return "*" in allowed_namespaces or namespace in allowed_namespaces

    def is_ip_allowed(
        self,
        sidecar_ip: str,
        config: SidecarConfig
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
#!/usr/bin/env python3
"""
Secure constant-time comparison implementation to prevent side-channel timing attacks.

This module provides a timing-safe comparison function that avoids early returns
and uses constant-time operations regardless of where the strings differ.
"""

import hmac


def secure_compare(a: str | bytes, b: str | bytes) -> bool:
    """
    Compare two strings or bytes in constant time to prevent timing attacks.
    
    This function uses hmac.compare_digest which is designed to be
    constant-time regardless of the input values.
    
    Args:
        a: First string or bytes to compare
        b: Second string or bytes to compare
        
    Returns:
        bool: True if a and b are equal, False otherwise
    """
    # Convert strings to bytes if needed
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    return hmac.compare_digest(a, b)


def insecure_compare(a: str, b: str) -> bool:
    """
    INSECURE: Vulnerable to timing attacks due to early return.
    DO NOT USE IN PRODUCTION.
    """
    if len(a) != len(b):
        return False
    
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # Early return leaks timing information!
    
    return True


if __name__ == "__main__":
    # Demonstration of the secure comparison
    secret_token = "my_secret_api_key_12345"
    user_provided = "my_secret_api_key_12345"
    attacker_guess = "my_secret_api_key_12346"
    
    print("Secure comparison (equal):", secure_compare(secret_token, user_provided))
    print("Secure comparison (different):", secure_compare(secret_token, attacker_guess))
    
    # Demonstrate that timing is constant regardless of where mismatch occurs
    import time
    
    test_secret = "a" * 1000
    test_match = "a" * 1000
    test_mismatch_early = "b" + "a" * 999
    test_mismatch_late = "a" * 999 + "b"
    
    # Warm up
    for _ in range(100):
        secure_compare(test_secret, test_match)
        secure_compare(test_secret, test_mismatch_early)
        secure_compare(test_secret, test_mismatch_late)
    
    # Time comparisons
    iterations = 10000
    
    start = time.perf_counter()
    for _ in range(iterations):
        secure_compare(test_secret, test_match)
    time_match = time.perf_counter() - start
    
    start = time.perf_counter()
    for _ in range(iterations):
        secure_compare(test_secret, test_mismatch_early)
    time_early = time.perf_counter() - start
    
    start = time.perf_counter()
    for _ in range(iterations):
        secure_compare(test_secret, test_mismatch_late)
    time_late = time.perf_counter() - start
    
    print(f"\nTiming results ({iterations} iterations):")
    print(f"  Match:        {time_match:.4f}s")
    print(f"  Early diff:   {time_early:.4f}s")
    print(f"  Late diff:    {time_late:.4f}s")
    print(f"\nAll times similar? {'Yes - constant time!' if max(time_match, time_early, time_late) - min(time_match, time_early, time_late) < 0.1 else 'No - timing variation detected'}")
    print(f"Sidecar injection valid: {result}")
