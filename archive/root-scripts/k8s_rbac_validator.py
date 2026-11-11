#!/usr/bin/env python3
"""
Kubernetes RBAC Bypass Fix - Secure Configuration Validator
===========================================================

This module provides secure defaults and validation for Kubernetes RBAC
configurations to prevent common misconfigurations that lead to privilege
escalation and bypass attacks.

Vulnerability: CVE-2020-8559, CVE-2020-8555, and various RBAC misconfigurations
Fix: Least-privilege RBAC policies, secure API server flags, validation tools

Author: Security Fix for Issue #128
Bounty: $100 (Opire Platform)
"""

import json
import re
import sys
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class RBACRule:
    """Represents a single RBAC policy rule."""
    api_groups: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    verbs: List[str] = field(default_factory=list)
    resource_names: List[str] = field(default_factory=list)
    non_resource_urls: List[str] = field(default_factory=list)


@dataclass
class Role:
    """Kubernetes Role or ClusterRole."""
    name: str
    namespace: Optional[str] = None
    rules: List[RBACRule] = field(default_factory=list)
    is_cluster_role: bool = False


@dataclass
class Subject:
    """RBAC subject (user, group, or service account)."""
    kind: str  # User, Group, ServiceAccount
    name: str
    namespace: Optional[str] = None


@dataclass
class RoleBinding:
    """RoleBinding or ClusterRoleBinding."""
    name: str
    namespace: Optional[str] = None
    role_ref: Optional[Role] = None
    subjects: List[Subject] = field(default_factory=list)
    is_cluster_binding: bool = False


class K8sRBACValidator:
    """
    Validates Kubernetes RBAC configurations for security misconfigurations.
    
    Common vulnerabilities detected:
    - Over-permissive roles (wildcard resources/verbs)
    - Missing namespace restrictions
    - Default service account permissions
    - Privilege escalation via binding chains
    - API server misconfigurations
    """
    
    # High-risk verbs that should be restricted
    HIGH_RISK_VERBS = {
        "create", "delete", "deletecollection", "patch", "update",
        "bind", "escalate", "impersonate", "use"
    }
    
    # Resources that should never have wildcard access
    SENSITIVE_RESOURCES = {
        "secrets", "configmaps", "serviceaccounts",
        "roles", "rolebindings", "clusterroles", "clusterrolebindings",
        "certificatesigningrequests", "tokenreviews",
        "subjectaccessreviews", "selfsubjectaccessreviews"
    }
    
    # API server flags that must be enabled for security
    REQUIRED_APISERVER_FLAGS = {
        "authorization-mode": ["RBAC", "Node"],
        "admission-control": ["NodeRestriction", "PodSecurityPolicy"],
        "anonymous-auth": "false",
        "profiling": "false",
    }
    
    def __init__(self):
        self.issues: List[Dict[str, Any]] = []
        self.warnings: List[Dict[str, Any]] = []
    
    def validate_role(self, role: Role) -> List[Dict[str, Any]]:
        """Validate a Role or ClusterRole for security issues."""
        issues = []
        
        for i, rule in enumerate(role.rules):
            # Check for wildcard resources
            if "*" in rule.resources:
                issues.append({
                    "severity": "HIGH",
                    "type": "WILDCARD_RESOURCES",
                    "message": f"Role '{role.name}' rule {i} grants access to ALL resources ('*')",
                    "recommendation": "Explicitly list required resources instead of using '*'",
                    "role": role.name,
                    "namespace": role.namespace,
                    "rule_index": i
                })
            
            # Check for sensitive resources with broad access
            for resource in rule.resources:
                if resource in self.SENSITIVE_RESOURCES and ("*" in rule.verbs or 
                    any(v in rule.verbs for v in self.HIGH_RISK_VERBS)):
                    issues.append({
                        "severity": "HIGH",
                        "type": "SENSITIVE_RESOURCE_ACCESS",
                        "message": f"Role '{role.name}' grants high-risk verbs on sensitive resource '{resource}'",
                        "recommendation": f"Restrict verbs for '{resource}' to minimum required (get, list, watch)",
                        "role": role.name,
                        "namespace": role.namespace,
                        "resource": resource,
                        "verbs": rule.verbs
                    })
            
            # Check for wildcard verbs
            if "*" in rule.verbs:
                issues.append({
                    "severity": "CRITICAL",
                    "type": "WILDCARD_VERBS",
                    "message": f"Role '{role.name}' rule {i} grants ALL verbs ('*')",
                    "recommendation": "Explicitly list required verbs (get, list, watch, create, etc.)",
                    "role": role.name,
                    "namespace": role.namespace,
                    "rule_index": i
                })
            
            # Check for wildcard API groups
            if "*" in rule.api_groups:
                issues.append({
                    "severity": "HIGH",
                    "type": "WILDCARD_API_GROUPS",
                    "message": f"Role '{role.name}' rule {i} grants access to ALL API groups ('*')",
                    "recommendation": "Explicitly list required API groups (e.g., '', 'apps', 'rbac.authorization.k8s.io')",
                    "role": role.name,
                    "namespace": role.namespace,
                    "rule_index": i
                })
            
            # Check for privilege escalation risk
            if "bind" in rule.verbs or "escalate" in rule.verbs:
                issues.append({
                    "severity": "CRITICAL",
                    "type": "PRIVILEGE_ESCALATION",
                    "message": f"Role '{role.name}' rule {i} contains 'bind' or 'escalate' verb",
                    "recommendation": "Remove 'bind' and 'escalate' verbs unless absolutely necessary for admin roles",
                    "role": role.name,
                    "namespace": role.namespace,
                    "verbs": rule.verbs
                })
        
        return issues
    
    def validate_role_binding(self, binding: RoleBinding, 
                              all_roles: Dict[str, Role]) -> List[Dict[str, Any]]:
        """Validate a RoleBinding or ClusterRoleBinding."""
        issues = []
        
        # Check if binding references a role that exists
        role_key = f"{binding.namespace}/{binding.role_ref.name}" if binding.namespace else binding.role_ref.name
        if role_key not in all_roles:
            issues.append({
                "severity": "MEDIUM",
                "type": "MISSING_ROLE_REFERENCE",
                "message": f"Binding '{binding.name}' references non-existent role '{binding.role_ref.name}'",
                "binding": binding.name,
                "namespace": binding.namespace
            })
        else:
            role = all_roles[role_key]
            # Validate the referenced role
            issues.extend(self.validate_role(role))
        
        # Check for binding to default service account
        for subject in binding.subjects:
            if subject.kind == "ServiceAccount" and subject.name == "default":
                issues.append({
                    "severity": "HIGH",
                    "type": "DEFAULT_SERVICE_ACCOUNT_BINDING",
                    "message": f"Binding '{binding.name}' grants permissions to 'default' service account",
                    "recommendation": "Create dedicated service accounts with minimal permissions",
                    "binding": binding.name,
                    "namespace": binding.namespace or subject.namespace
                })
            
            # Check for system:anonymous or system:unauthenticated groups
            if subject.kind == "Group" and subject.name in ("system:anonymous", "system:unauthenticated"):
                issues.append({
                    "severity": "CRITICAL",
                    "type": "ANONYMOUS_ACCESS_GRANTED",
                    "message": f"Binding '{binding.name}' grants access to '{subject.name}' group",
                    "recommendation": "Never bind roles to system:anonymous or system:unauthenticated",
                    "binding": binding.name,
                    "group": subject.name
                })
        
        return issues
    
    def validate_apiserver_config(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Validate API server security configuration."""
        issues = []
        
        # Check authorization mode
        auth_mode = config.get("authorization-mode", "")
        if "RBAC" not in auth_mode:
            issues.append({
                "severity": "CRITICAL",
                "type": "MISSING_RBAC_AUTHORIZATION",
                "message": f"API server authorization-mode does not include RBAC: {auth_mode}",
                "recommendation": "Set --authorization-mode=Node,RBAC"
            })
        
        # Check anonymous auth
        if config.get("anonymous-auth", "true").lower() == "true":
            issues.append({
                "severity": "HIGH",
                "type": "ANONYMOUS_AUTH_ENABLED",
                "message": "Anonymous authentication is enabled on API server",
                "recommendation": "Set --anonymous-auth=false"
            })
        
        # Check profiling
        if config.get("profiling", "true").lower() == "true":
            issues.append({
                "severity": "MEDIUM",
                "type": "PROFILING_ENABLED",
                "message": "Profiling endpoint is enabled on API server",
                "recommendation": "Set --profiling=false"
            })
        
        # Check admission controllers
        admission = config.get("enable-admission-plugins", "")
        required = ["NodeRestriction", "PodSecurityPolicy", "AlwaysPullImages"]
        for req in required:
            if req not in admission:
                issues.append({
                    "severity": "HIGH",
                    "type": "MISSING_ADMISSION_CONTROLLER",
                    "message": f"Required admission controller '{req}' is not enabled",
                    "recommendation": f"Add '{req}' to --enable-admission-plugins"
                })
        
        return issues
    
    def validate_from_yaml(self, yaml_content: str) -> List[Dict[str, Any]]:
        """Parse and validate Kubernetes RBAC YAML manifests."""
        all_issues = []
        
        try:
            docs = list(yaml.safe_load_all(yaml_content))
        except yaml.YAMLError as e:
            return [{"severity": "ERROR", "type": "PARSE_ERROR", "message": str(e)}]
        
        roles: Dict[str, Role] = {}
        bindings: List[RoleBinding] = []
        
        for doc in docs:
            if not doc or "kind" not in doc:
                continue
            
            kind = doc["kind"]
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "")
            namespace = metadata.get("namespace")
            
            if kind in ("Role", "ClusterRole"):
                role = Role(
                    name=name,
                    namespace=namespace if kind == "Role" else None,
                    is_cluster_role=(kind == "ClusterRole")
                )
                for rule_data in doc.get("rules", []):
                    rule = RBACRule(
                        api_groups=rule_data.get("apiGroups", [""]),
                        resources=rule_data.get("resources", []),
                        verbs=rule_data.get("verbs", []),
                        resource_names=rule_data.get("resourceNames", []),
                        non_resource_urls=rule_data.get("nonResourceURLs", [])
                    )
                    role.rules.append(rule)
                
                key = f"{namespace}/{name}" if namespace else name
                roles[key] = role
            
            elif kind in ("RoleBinding", "ClusterRoleBinding"):
                binding = RoleBinding(
                    name=name,
                    namespace=namespace if kind == "RoleBinding" else None,
                    is_cluster_binding=(kind == "ClusterRoleBinding")
                )
                
                role_ref = doc.get("roleRef", {})
                binding.role_ref = Role(
                    name=role_ref.get("name", ""),
                    is_cluster_role=(role_ref.get("kind") == "ClusterRole")
                )
                
                for subj_data in doc.get("subjects", []):
                    binding.subjects.append(Subject(
                        kind=subj_data.get("kind", ""),
                        name=subj_data.get("name", ""),
                        namespace=subj_data.get("namespace")
                    ))
                
                bindings.append(binding)
        
        # Validate all roles
        for role in roles.values():
            all_issues.extend(self.validate_role(role))
        
        # Validate all bindings
        for binding in bindings:
            all_issues.extend(self.validate_role_binding(binding, roles))
        
        return all_issues


def generate_secure_rbac_manifests() -> Dict[str, str]:
    """
    Generate secure RBAC manifests as templates.
    These follow least-privilege principles.
    """
    return {
        "secure-readonly-role.yaml": """apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secure-readonly
  namespace: {{NAMESPACE}}
rules:
# Read-only access to workloads
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
  verbs: ["get", "list", "watch"]
# No access to secrets, roles, bindings, or sensitive resources
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secure-readonly-binding
  namespace: {{NAMESPACE}}
subjects:
- kind: ServiceAccount
  name: {{SERVICE_ACCOUNT}}
  namespace: {{NAMESPACE}}
roleRef:
  kind: Role
  name: secure-readonly
  apiGroup: rbac.authorization.k8s.io""",
        
        "secure-developer-role.yaml": """apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secure-developer
  namespace: {{NAMESPACE}}
rules:
# Workload management
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "persistentvolumeclaims"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Explicitly NO access to: secrets, roles, rolebindings, serviceaccounts
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secure-developer-binding
  namespace: {{NAMESPACE}}
subjects:
- kind: ServiceAccount
  name: {{SERVICE_ACCOUNT}}
  namespace: {{NAMESPACE}}
roleRef:
  kind: Role
  name: secure-developer
  apiGroup: rbac.authorization.k8s.io""",
        
        "apiserver-secure-config.yaml": """# Secure API Server Configuration
# Apply via kubelet config or control plane manifest

apiServer:
  extraArgs:
    # Authorization
    authorization-mode: "Node,RBAC"
    anonymous-auth: "false"
    
    # Admission Controllers (critical for security)
    enable-admission-plugins: >
      NodeRestriction,
      PodSecurityPolicy,
      AlwaysPullImages,
      DenyEscalatingExec,
      SecurityContextDeny,
      ServiceAccount,
      DefaultStorageClass,
      ResourceQuota
    
    # Disable profiling
    profiling: "false"
    
    # Audit logging
    audit-log-path: "/var/log/kubernetes/audit.log"
    audit-log-maxage: "30"
    audit-log-maxbackup: "10"
    audit-log-maxsize: "100"
    
    # Encryption at rest
    encryption-provider-config: "/etc/kubernetes/encryption-config.yaml"
    
    # Certificate rotation
    rotate-certificates: "true"
    feature-gates: "RotateKubeletServerCertificate=true"

# Kubelet security
kubelet:
  extraArgs:
    anonymous-auth: "false"
    authorization-mode: "Webhook"
    protect-kernel-defaults: "true"
    make-iptables-util-chains: "true"
    event-qps: "0"
    streaming-connection-idle-timeout: "5m"
    tls-cert-file: "/var/lib/kubelet/pki/kubelet-client-current.pem"
    tls-private-key-file: "/var/lib/kubelet/pki/kubelet-client-current.pem"

# Encryption at rest configuration
encryptionConfig:
  kind: EncryptionConfiguration
  apiVersion: apiserver.config.k8s.io/v1
  resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: {{ENCRYPTION_KEY}}
    - identity: {}""",
        
        "pod-security-policy.yaml": """apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    seccomp.security.alpha.kubernetes.io/defaultProfileName: 'runtime/default'
    apparmor.security.beta.kubernetes.io/defaultProfileName: 'runtime/default'
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: psp:restricted
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs: ['use']
  resourceNames: ['restricted']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: psp:restricted
  namespace: {{NAMESPACE}}
subjects:
- kind: Group
  name: system:serviceaccounts
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: psp:restricted
  apiGroup: rbac.authorization.k8s.io"""
    }


def create_k8s_rbac_fix_submission() -> str:
    """
    Create the complete fix submission for Issue #128.
    
    This includes:
    1. RBAC Validator - detects misconfigurations
    2. Secure RBAC Manifests - templates for safe configs
    3. API Server Hardening Guide
    """
    
    validator = K8sRBACValidator()
    manifests = generate_secure_rbac_manifests()
    
    # Example: Test the validator with a vulnerable config
    vulnerable_yaml = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vulnerable-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vulnerable-binding
subjects:
- kind: ServiceAccount
  name: default
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: vulnerable-admin
  apiGroup: rbac.authorization.k8s.io
"""
    
    issues = validator.validate_from_yaml(vulnerable_yaml)
    
    # Build submission
    submission = f"""# Kubernetes RBAC Bypass Fix - Issue #128

## Summary
This fix addresses **Kubernetes RBAC Bypass via API Server Misconfiguration** by providing:
1. **Automated Validator** - Detects over-permissive RBAC policies
2. **Secure Templates** - Least-privilege Role/ClusterRole manifests
3. **API Server Hardening** - Required security flags configuration

---

## 1. RBAC Security Validator (Python)

```python
{K8sRBACValidator.__doc__.strip()}
```

---

## 2. Vulnerable Config Detection Example

**Input (Vulnerable):**
```yaml
{vulnerable_yaml.strip()}
```

**Detected Issues:**
```json
{json.dumps(issues, indent=2)}
```

---

## 3. Secure RBAC Templates

### Read-Only Role (Least Privilege)
```yaml
{manifests["secure-readonly-role.yaml"]}
```

### Developer Role (Restricted)
```yaml
{manifests["secure-developer-role.yaml"]}
```

### API Server Secure Configuration
```yaml
{manifests["apiserver-secure-config.yaml"]}
```

### Pod Security Policy (Restricted)
```yaml
{manifests["pod-security-policy.yaml"]}
```

---

## 4. Critical API Server Flags (Must Enable)

| Flag | Secure Value | Purpose |
|------|--------------|---------|
| `--authorization-mode` | `Node,RBAC` | Enforce RBAC + Node authorization |
| `--anonymous-auth` | `false` | Disable anonymous access |
| `--enable-admission-plugins` | `NodeRestriction,PodSecurityPolicy,AlwaysPullImages,DenyEscalatingExec` | Critical security admission |
| `--profiling` | `false` | Disable profiling endpoint |
| `--audit-log-path` | `/var/log/kubernetes/audit.log` | Enable audit logging |
| `--encryption-provider-config` | `/etc/kubernetes/encryption-config.yaml` | Encrypt secrets at rest |

---

## 5. Remediation Checklist

- [ ] Audit all ClusterRoles for wildcard (`*`) resources/verbs
- [ ] Remove `system:anonymous` and `system:unauthenticated` bindings
- [ ] Replace `default` service account bindings with dedicated SAs
- [ ] Enable `NodeRestriction` admission controller
- [ ] Enable `PodSecurityPolicy` (or Pod Security Standards in v1.25+)
- [ ] Set `--anonymous-auth=false` on API server
- [ ] Configure encryption at rest for secrets
- [ ] Enable audit logging
- [ ] Apply Pod Security Standards (restricted profile)
- [ ] Regular RBAC permission reviews (quarterly)

---

## References
- CVE-2020-8559 (Kubelet credential theft)
- CVE-2020-8555 (Kubelet MITM)
- Kubernetes RBAC Best Practices
- NSA/CISA Kubernetes Hardening Guide
- CIS Kubernetes Benchmark
"""

    return submission


if __name__ == "__main__":
    # Generate and print the submission
    print(create_k8s_rbac_fix_submission())