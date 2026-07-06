"""
k8s_rbac_security_fix.py — Kubernetes RBAC Bypass via API Server Misconfiguration Fix

漏洞背景:
- Kubernetes RBAC配置不当可导致权限提升
- API Server配置允许未授权访问（匿名认证、RBAC未启用）
- ServiceAccount绑定过度宽松的ClusterRole
- Pod可访问宿主节点kubelet API绕过RBAC
- 修复需要: 强制RBAC、最小权限原则、API Server安全硬化、
  kubelet认证授权、NetworkPolicy隔离

本模块提供K8s RBAC安全检测与修复配置。
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


class RBACError(Exception):
    """RBAC安全异常"""
    pass


@dataclass
class K8sClusterConfig:
    """K8s集群安全配置"""
    enable_rbac: bool = True
    anonymous_auth_disabled: bool = True
    kubelet_https: bool = True
    kubelet_anonymous_auth: bool = False
    api_server_secure_port: int = 6443
    audit_policy_file: str = "/etc/kubernetes/audit-policy.yaml"
    encryption_provider_config: str = "/etc/kubernetes/encryption-config.yaml"
    enable_admission_plugins: Set[str] = field(default_factory=lambda: {
        "NamespaceLifecycle",
        "LimitRanger",
        "ServiceAccount",
        "NodeRestriction",
        "MutatingAdmissionWebhook",
        "ValidatingAdmissionWebhook",
        "ResourceQuota",
        "PodSecurityPolicy",
        "PodNodeSelector",
        "PodTolerationRestriction",
    })


@dataclass
class RBACPolicy:
    """RBAC安全策略"""
    cluster_admin_role_prefixes: Set[str] = field(default_factory=lambda: {
        "cluster-admin",
    })
    dangerous_verbs: Set[str] = field(default_factory=lambda: {
        "create", "update", "patch", "delete",
        "impersonate", "bind", "escalate",
    })
    protected_namespaces: Set[str] = field(default_factory=lambda: {
        "kube-system", "kube-public", "kube-node-lease",
    })


class RBACSecurityAuditor:
    """K8s RBAC安全审计器"""

    def __init__(self, config: K8sClusterConfig = None,
                 policy: RBACPolicy = None):
        self.config = config or K8sClusterConfig()
        self.policy = policy or RBACPolicy()

    def audit_role_binding(self, role_binding: Dict[str, Any],
                           context: Dict[str, Any] = None) -> List[str]:
        """
        审计RoleBinding的安全性

        Args:
            role_binding: RoleBinding资源定义
            context: 额外的上下文信息

        Returns:
            安全问题列表
        """
        issues = []

        role_ref = role_binding.get("roleRef", {})
        role_name = role_ref.get("name", "")
        subjects = role_binding.get("subjects", [])

        # 检查高危ClusterRole绑定
        if role_name in self.policy.cluster_admin_role_prefixes:
            issues.append(
                f"High-risk: '{role_name}' bound to {len(subjects)} subjects"
            )

        # 检查是否绑定到ServiceAccount
        for subject in subjects:
            sub_kind = subject.get("kind", "")
            sub_name = subject.get("name", "")
            sub_ns = subject.get("namespace", "default")

            # ServiceAccount应仅限于特定命名空间
            if sub_kind == "ServiceAccount":
                if not sub_ns:
                    issues.append(
                        f"ServiceAccount '{sub_name}' has no namespace restriction"
                    )

            # 检查system:anonymous
            if sub_name == "system:anonymous" or sub_name == "system:unauthenticated":
                issues.append(f"Dangerous subject: '{sub_name}' in role binding")

            # 用户冒充风险
            if sub_kind == "User" and ":" in sub_name:
                parts = sub_name.split(":")
                if len(parts) > 1 and parts[0] not in {"system", "user"}:
                    issues.append(
                        f"Suspicious user subject format: '{sub_name}'"
                    )

        return issues

    def validate_api_server_flags(self, flags: Dict[str, Any]) -> List[str]:
        """验证API Server启动参数安全性"""
        issues = []

        # 检查匿名认证
        anon_auth = flags.get("--anonymous-auth", "true")
        if anon_auth == "true" and self.config.anonymous_auth_disabled:
            issues.append(
                "Anonymous authentication is enabled "
                "(should be '--anonymous-auth=false')"
            )

        # 检查授权模式
        auth_mode = flags.get("--authorization-mode", "")
        if "RBAC" not in auth_mode:
            issues.append(
                f"RBAC not in authorization mode: '{auth_mode}'"
            )
        if auth_mode == "AlwaysAllow":
            issues.append("Authorization mode is 'AlwaysAllow' - no access control")

        # 检查kubelet端口
        kubelet_port = flags.get("--kubelet-port", "10250")
        if kubelet_port == "10250":  # 默认安全端口
            pass

        # 检查ETCD加密
        enc_provider = flags.get("--encryption-provider-config", "")
        if not enc_provider:
            issues.append("ETCD encryption not configured")

        # 检查admission plugins
        enable_plugins = set(flags.get("--enable-admission-plugins", "").split(","))
        for required in self.config.enable_admission_plugins:
            if required not in enable_plugins:
                issues.append(f"Required admission plugin '{required}' not enabled")

        return issues

    def generate_secure_api_server_config(self) -> Dict[str, str]:
        """生成安全的API Server配置"""
        return {
            "--anonymous-auth": "false",
            "--authorization-mode": "Node,RBAC",
            "--kubelet-https": "true",
            "--kubelet-certificate-authority": "/etc/kubernetes/pki/ca.crt",
            "--kubelet-client-certificate": "/etc/kubernetes/pki/apiserver-kubelet-client.crt",
            "--kubelet-client-key": "/etc/kubernetes/pki/apiserver-kubelet-client.key",
            "--enable-admission-plugins": ",".join(sorted(
                self.config.enable_admission_plugins
            )),
            "--encryption-provider-config": self.config.encryption_provider_config,
            "--audit-policy-file": self.config.audit_policy_file,
            "--audit-log-path": "/var/log/kubernetes/audit.log",
            "--audit-log-maxage": "30",
            "--audit-log-maxbackup": "10",
            "--audit-log-maxsize": "100",
            "--service-account-lookup": "true",
            "--service-account-key-file": "/etc/kubernetes/pki/sa.pub",
            "--service-account-signing-key-file": "/etc/kubernetes/pki/sa.key",
            "--service-account-issuer": "https://kubernetes.default.svc",
            "--request-timeout": "300s",
        }

    def validate_service_account(self, sa: Dict[str, Any]) -> List[str]:
        """验证ServiceAccount安全性"""
        issues = []
        name = sa.get("metadata", {}).get("name", "")
        namespace = sa.get("metadata", {}).get("namespace", "default")
        automount = sa.get("automountServiceAccountToken", True)

        if automount:
            issues.append(
                f"ServiceAccount '{name}' in '{namespace}' "
                f"automounts service account token"
            )

        secrets = sa.get("secrets", [])
        for secret in secrets:
            if "get" not in [r.get("verbs", []) for r in secret.get("rules", [])]:
                issues.append(
                    f"Secret reference in SA '{name}' without explicit read"
                )

        return issues

    def generate_pod_security_policy(self) -> Dict[str, Any]:
        """生成Pod安全策略"""
        return {
            "apiVersion": "policy/v1beta1",
            "kind": "PodSecurityPolicy",
            "metadata": {"name": "restricted"},
            "spec": {
                "privileged": False,
                "allowPrivilegeEscalation": False,
                "requiredDropCapabilities": ["ALL"],
                "volumes": ["configMap", "emptyDir", "projected",
                            "secret", "downwardAPI", "persistentVolumeClaim"],
                "hostNetwork": False,
                "hostPID": False,
                "hostIPC": False,
                "runAsUser": {
                    "rule": "MustRunAsNonRoot",
                },
                "seLinux": {
                    "rule": "RunAsAny",
                },
                "supplementalGroups": {
                    "rule": "MustRunAs",
                    "ranges": [{"min": 1, "max": 65535}],
                },
                "fsGroup": {
                    "rule": "MustRunAs",
                    "ranges": [{"min": 1, "max": 65535}],
                },
                "readOnlyRootFilesystem": True,
            },
        }


def generate_minimal_rbac_roles() -> Dict[str, Any]:
    """生成最小权限RBAC角色"""
    return {
        "readonly": {
            "apiGroups": [""],
            "resources": ["pods", "services", "endpoints",
                          "configmaps", "secrets"],
            "verbs": ["get", "list", "watch"],
        },
        "pod-exec": {
            "apiGroups": [""],
            "resources": ["pods/exec", "pods/log"],
            "verbs": ["get", "create"],
        },
        "deployment-manager": {
            "apiGroups": ["apps", "extensions"],
            "resources": ["deployments", "replicasets"],
            "verbs": ["get", "list", "watch", "create", "update", "patch"],
        },
    }


if __name__ == "__main__":
    # 检测API Server配置
    auditor = RBACSecurityAuditor()
    flags = {
        "--anonymous-auth": "true",
        "--authorization-mode": "AlwaysAllow",
        "--enable-admission-plugins": "NamespaceLifecycle,LimitRanger",
        "--encryption-provider-config": "",
    }
    issues = auditor.validate_api_server_flags(flags)
    print("API Server Security Issues:")
    for issue in issues:
        print(f"  - {issue}")

    print("\nSecure API Server Config:")
    secure = auditor.generate_secure_api_server_config()
    for k, v in secure.items():
        print(f"  {k}={v}")

    print("\nK8s RBAC Security Features:")
    print("- API Server flag validation")
    print("- RBAC role binding audit")
    print("- ServiceAccount security check")
    print("- PodSecurityPolicy generation")
    print("- Minimal privilege role templates")
    print("- Admission plugin enforcement")
