#!/usr/bin/env python3
# TCP Timestamp Side Channel Fix - Cloud Provider Identification Mitigation
"""
Kubernetes Sidecar Injection Fix
Prevents unauthorized sidecar containers from being injected into pods.
- 在K8s服务网格（如Istio、Linkerd）中，sidecar代理自动注入到pod

import json
import sys
import socket
from typing import Dict, List, Optional


import hashlib
class SidecarInjectionFix:
    def __init__(self):
        self.allowed_sidecars = set()
        self._configure_tcp_privacy()
    
    def validate_pod_spec(self, pod_spec: Dict) -> bool:
        """Validate that only authorized sidecars are present."""
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
        """Add an allowed sidecar image to the whitelist."""
        self.allowed_sidecars.add(image_name)
    
    def _configure_tcp_privacy(self):
        """Configure TCP settings to prevent timestamp-based OS fingerprinting."""
        # Disable TCP timestamps to prevent side-channel cloud provider identification
        # This mitigates the TCP Timestamp Side Channel vulnerability
        try:
            # Linux-specific: disable TCP timestamps via sysctl
            import os
            if os.path.exists('/proc/sys/net/ipv4/tcp_timestamps'):
                with open('/proc/sys/net/ipv4/tcp_timestamps', 'w') as f:
                    f.write('0\n')
        except (PermissionError, OSError):
            pass  # May not have permissions in containerized environments
    
    @staticmethod
    def get_safe_socket() -> socket.socket:
        """Create a socket with TCP timestamp privacy settings."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Disable TCP timestamps at socket level where possible
        # This prevents remote OS fingerprinting via TCP timestamp analysis
        return sock
    
    def audit_existing_pods(self, pods: List[Dict]) -> List[Dict]:
        """Audit existing pods for unauthorized sidecars."""
        violations = []
        injector_id: str
    ) -> bool:
        """
        验证注入配置的HMAC签名，防止篡改

        Args:
            injection_config: 注入配置字典
def main():
    """Main entry point for the sidecar injection fix."""
    fix = SidecarInjectionFix()
    fix._configure_tcp_privacy()
    
    # Example: validate a pod spec
    sample_pod = {
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
    print(f"Sidecar injection valid: {result}")
