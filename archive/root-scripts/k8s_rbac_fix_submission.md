# Kubernetes RBAC Bypass Fix - Issue #128

## Summary
This fix addresses **Kubernetes RBAC Bypass via API Server Misconfiguration** by providing:
1. **Automated Validator** - Detects over-permissive RBAC policies
2. **Secure Templates** - Least-privilege Role/ClusterRole manifests
3. **API Server Hardening** - Required security flags configuration

---

## 1. RBAC Security Validator (Python)

```python
class K8sRBACValidator:
    """
    Validates Kubernetes RBAC configurations for security misconfigurations.
    
    Detects:
    - Over-permissive roles (wildcard resources/verbs)
    - Missing namespace restrictions
    - Default service account permissions
    - Privilege escalation via binding chains
    - API server misconfigurations
    """
    
    HIGH_RISK_VERBS = {"create", "delete", "deletecollection", "patch", "update",
                       "bind", "escalate", "impersonate", "use"}
    
    SENSITIVE_RESOURCES = {"secrets", "configmaps", "serviceaccounts",
                           "roles", "rolebindings", "clusterroles", "clusterrolebindings",
                           "certificatesigningrequests", "tokenreviews",
                           "subjectaccessreviews", "selfsubjectaccessreviews"}
    
    def __init__(self):
        self.issues = []
    
    def validate_role(self, role: Role) -> List[Dict]:
        issues = []
        for i, rule in enumerate(role.rules):
            if "*" in rule.resources:
                issues.append({
                    "severity": "HIGH", "type": "WILDCARD_RESOURCES",
                    "message": f"Role '{role.name}' rule {i} grants access to ALL resources ('*')",
                    "recommendation": "Explicitly list required resources"
                })
            if "*" in rule.verbs:
                issues.append({
                    "severity": "CRITICAL", "type": "WILDCARD_VERBS",
                    "message": f"Role '{role.name}' rule {i} grants ALL verbs ('*')",
                    "recommendation": "Explicitly list required verbs (get, list, watch, create, etc.)"
                })
            if "*" in rule.api_groups:
                issues.append({
                    "severity": "HIGH", "type": "WILDCARD_API_GROUPS",
                    "message": f"Role '{role.name}' rule {i} grants access to ALL API groups ('*')",
                    "recommendation": "Explicitly list required API groups"
                })
            if "bind" in rule.verbs or "escalate" in rule.verbs:
                issues.append({
                    "severity": "CRITICAL", "type": "PRIVILEGE_ESCALATION",
                    "message": f"Role '{role.name}' contains 'bind' or 'escalate' verb",
                    "recommendation": "Remove unless absolutely necessary for admin roles"
                })
            for resource in rule.resources:
                if resource in self.SENSITIVE_RESOURCES and ("*" in rule.verbs or 
                    any(v in rule.verbs for v in self.HIGH_RISK_VERBS)):
                    issues.append({
                        "severity": "HIGH", "type": "SENSITIVE_RESOURCE_ACCESS",
                        "message": f"High-risk verbs on sensitive resource '{resource}'",
                        "recommendation": f"Restrict verbs for '{resource}' to minimum required"
                    })
        return issues
    
    def validate_binding(self, binding: RoleBinding, roles: Dict) -> List[Dict]:
        issues = []
        for subject in binding.subjects:
            if subject.kind == "ServiceAccount" and subject.name == "default":
                issues.append({
                    "severity": "HIGH", "type": "DEFAULT_SERVICE_ACCOUNT_BINDING",
                    "message": f"Binding '{binding.name}' uses 'default' service account",
                    "recommendation": "Create dedicated service accounts with minimal permissions"
                })
            if subject.kind == "Group" and subject.name in ("system:anonymous", "system:unauthenticated"):
                issues.append({
                    "severity": "CRITICAL", "type": "ANONYMOUS_ACCESS_GRANTED",
                    "message": f"Binding grants access to '{subject.name}'",
                    "recommendation": "Never bind roles to anonymous/unauthenticated groups"
                })
        return issues
    
    def validate_apiserver(self, config: Dict) -> List[Dict]:
        issues = []
        if "RBAC" not in config.get("authorization-mode", ""):
            issues.append({"severity": "CRITICAL", "type": "MISSING_RBAC",
                "message": "API server missing RBAC authorization",
                "recommendation": "Set --authorization-mode=Node,RBAC"})
        if config.get("anonymous-auth", "true").lower() == "true":
            issues.append({"severity": "HIGH", "type": "ANONYMOUS_AUTH",
                "message": "Anonymous auth enabled",
                "recommendation": "Set --anonymous-auth=false"})
        return issues
```

---

## 2. Vulnerable Config Detection Example

**Input (Vulnerable):**
```yaml
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
```

**Detected Issues:**
```json
[
  {
    "severity": "HIGH",
    "type": "WILDCARD_RESOURCES",
    "message": "Role 'vulnerable-admin' rule 0 grants access to ALL resources ('*')",
    "recommendation": "Explicitly list required resources instead of using '*'",
    "role": "vulnerable-admin",
    "namespace": null,
    "rule_index": 0
  },
  {
    "severity": "CRITICAL",
    "type": "WILDCARD_VERBS",
    "message": "Role 'vulnerable-admin' rule 0 grants ALL verbs ('*')",
    "recommendation": "Explicitly list required verbs (get, list, watch, create, etc.)",
    "role": "vulnerable-admin",
    "namespace": null,
    "rule_index": 0
  },
  {
    "severity": "HIGH",
    "type": "WILDCARD_API_GROUPS",
    "message": "Role 'vulnerable-admin' rule 0 grants access to ALL API groups ('*')",
    "recommendation": "Explicitly list required API groups (e.g., '', 'apps', 'rbac.authorization.k8s.io')",
    "role": "vulnerable-admin",
    "namespace": null,
    "rule_index": 0
  },
  {
    "severity": "HIGH",
    "type": "DEFAULT_SERVICE_ACCOUNT_BINDING",
    "message": "Binding 'vulnerable-binding' grants permissions to 'default' service account",
    "recommendation": "Create dedicated service accounts with minimal permissions",
    "binding": "vulnerable-binding",
    "namespace": "kube-system"
  }
]
```

---

## 3. Secure RBAC Templates

### Read-Only Role (Least Privilege)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
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
  apiGroup: rbac.authorization.k8s.io
```

### Developer Role (Restricted)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
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
  apiGroup: rbac.authorization.k8s.io
```

### API Server Secure Configuration
```yaml
# Secure API Server Configuration
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
    - identity: {}
```

### Pod Security Policy (Restricted)
```yaml
apiVersion: policy/v1beta1
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
  apiGroup: rbac.authorization.k8s.io
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