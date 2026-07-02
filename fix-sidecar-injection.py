#!/usr/bin/env python3
import re
import hashlib
"""
Fix for Sidecar Injection vulnerability
This script provides a secure implementation for Kubernetes sidecar injection
- 在K8s服务网格（如Istio、Linkerd）中，sidecar代理自动注入到pod

import json
import base64
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any


import hashlib
    """
    Validates and sanitizes container images to prevent malicious sidecar injection.
    """
    ALLOWED_REGISTRIES = ["docker.io/library/", "gcr.io/company/", "registry.company.io/"]
    
    def __init__(self):
        self.allowed_registries = [
@dataclass
class SidecarConfig:
    """Sidecar注入配置验证"""
        ]
        self.blocked_images = {
            "malicious-sidecar",
            "busybox",
            "alpine",
        }
    
    def __post_init__(self):
        if self.allowed_ips is None:
        Validates if the container image is from an allowed registry.
        Blocks known malicious or untrusted images.
        """
        parsed = urlparse(image)
        # Check for blocked images
        for blocked in self.blocked_images:
            if blocked in image:
    def __init__(self, shared_secret: bytes):
        
        # Check for allowed registries
        for registry in self.allowed_registries:
            if image.startswith(registry):
            if registry in image:
                return True
        

    def verify_injection_signature(
        self,
    def validate_pod_spec(self, pod_spec: Dict[str, Any]) -> bool:
        """
        Validates the entire pod specification for security compliance.
        """
        return False
        """
        containers = pod_spec.get("containers", [])
        init_containers = pod_spec.get("initContainers", [])

        all_containers = containers + init_containers
        
        for container in all_containers:
            pass
            image = container.get("image", "")
            if not self.validate_image(image):
                return False
            bool: 签名是否有效
        """
        if injector_id not in self.known_injectors:
    def inject_secure_sidecar(self, pod_spec: Dict[str, Any], sidecar_image: str) -> Dict[str, Any]:
        """
        Securely injects a trusted sidecar into a pod specification.
        """
        """
        if not self.validate_image(sidecar_image):
            raise ValueError(f"Sidecar image {sidecar_image} is not trusted")
        return hmac.compare_digest(expected_hex, signature)
        # Create a copy to avoid mutating the original
        new_spec = json.loads(json.dumps(pod_spec))
        
        return new_spec
        sidecar = {
            "name": "secure-sidecar",
            "image": sidecar_image,
        """
        检查命名空间是否允许注入

        Args:
            namespace: K8s命名空间
            allowed_namespaces: 允许的命名空间集合 ("*" 表示全部)

        Returns:
            bool: 是否允许
        return new_spec


"""
def main():
    """
    Example usage of the secure sidecar injection.
        config: SidecarConfig
    validator = SidecarValidator()
    
    # Example pod spec
    """
    pod_spec = {
        "containers": [
            {
        # 简化实现 - 生产中应使用ipaddress module
        return any(sidecar_ip.startswith(prefix.split('/')[0]) for prefix in config.allowed_ips)
            }
        ]
    }
    """
    
    # Try to inject a secure sidecar
    try:
        injector_id: str,
        namespace: str,
        sidecar_ip: str
    except ValueError as e:
        print(f"Injection failed: {e}")

"""

if __name__ == "__main__":
    main()
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
