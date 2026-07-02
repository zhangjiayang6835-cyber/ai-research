 ```diff
--- a/k8s_rbac_validator.py
+++ b/k8s_rbac_validator.py
@@ -1,3 +1,4 @@
+#!/usr/bin/env python3
 """
 Kubernetes RBAC Security Validator
 
@@ -7,6 +8,7 @@
 import json
 import re
 import sys
+import subprocess
 from pathlib import Path
 from typing import Dict, List, Optional, Set, Tuple
 
@@ -14,6 +16,7 @@
 class RBACConfig:
     """Represents a Kubernetes RBAC configuration."""
     
+    # Default secure values - deny all by default
     def __init__(self):
         self.api_server_flags: Dict[str, str] = {}
         self.rbac_rules: List[Dict] = []
@@ -21,6 +24,7 @@ def __init__(self):
         self.service_accounts: List[Dict] = []
         self.anonymous_auth_enabled: bool = False
         self.rbac_enabled: bool = False
+        self.authorization_mode: str = "RBAC"
 
 
 class RBACSecurityScanner:
@@ -28,6 +32,7 @@ class RBACSecurityScanner:
     
     CRITICAL_ROLES = ["cluster-admin", "admin", "edit", "view"]
     DANGEROUS_VERBS = ["*", "create", "delete", "update", "patch", "escalate"]
+    DANGEROUS_RESOURCES = ["pods/exec", "pods/attach", "secrets", "serviceaccounts"]
     
     def __init__(self):
         self.findings: List[Dict] = []
@@ -35,6 +40,7 @@ def __init__(self):
     def scan_api_server_config(self, config: RBACConfig) -> List[Dict]:
         """Scan API server configuration for RBAC bypass vulnerabilities."""
         findings = []
+        flags = config.api_server_flags
         
         # Check for anonymous authentication
         if config.anonymous_auth_enabled:
:
@@ -35,6 +40,7 @@ def __init__(self):
     def scan_api_server_config(self, config: RBACConfig) -> List[Dict]:
         """Scan API server configuration for RBAC bypass vulnerabilities."""
         findings = []
+        flags = config.api_server_flags
         
         # Check for anonymous authentication
         if config.anonymous_auth_enabled:
@@ -42,6 +48,7 @@ def scan_api_server_config(self, config: RBACConfig) -> List[Dict]:
                 "severity": "CRITICAL",
                 "category": "anonymous_auth",
                 "description": "Anonymous authentication is enabled on the API server",
+                "fix": "Add --anonymous-auth=false to kube-apiserver flags",
                 "mitigation": "Disable anonymous authentication with --anonymous-auth=false"
             })
         
@@ -51,6 +58,7 @@ def scan_api_server_config(self, config: RBACConfig) -> List[Dict]:
                 "severity": "CRITICAL",
                 "category": "rbac_disabled",
                 "description": "RBAC authorization is not enabled",
+                "fix": "Add --authorization-mode=RBAC to kube-apiserver flags",
                 "mitigation": "Enable RBAC with --authorization-mode=RBAC"
             })
         
@@ -60,9 +68,22 @@ def scan_api_server_config(self, config: RBACConfig) -> List[Dict]:
                 "severity": "HIGH",
                 "category": "always_allow_paths",
                 "description": f"AlwaysAllow paths configured: {config.always_allow_paths}",
+                "fix": "Remove --authorization-always-allow-paths or set to empty",
                 "mitigation": "Remove sensitive paths from authorization bypass"
             })
         
+        # Check for insecure authorization mode
+        auth_mode = flags.get("authorization-mode", "")
+        if "AlwaysAllow" in auth_mode:
+            findings.append({
+                "severity": "CRITICAL",
+                "category": "always_allow_auth",
+                "description": "Authorization mode includes AlwaysAllow",
+                "fix": "Remove AlwaysAllow from --authorization-mode",
+                "mitigation": "Use only RBAC, Node, or Webhook authorization modes"
+            })
+        
+        # Check for insecure port enabled
+        if flags.get("insecure-port", "0") != "0":
+            findings.append({
+                "severity": "CRITICAL",
+                "category": "insecure_port",
+                "description": "Insecure port is enabled on API server",
+                "fix": "Set --insecure-port=0",
+                "mitigation": "Disable insecure port by setting --insecure-port=0"
+            })
+        
         return findings
     
     def scan_role_bindings(self, config: RBACConfig) -> List[Dict]:
@@ -73,6 +94,7 @@ def scan_role_bindings(self, config: RBACConfig) -> List[Dict]:
                 "severity": "HIGH",
                 "category": "wildcard_permissions",
                 "description": f"Role {role.get('name')} has wildcard permissions",
+                "fix": "Replace '*' with explicit verbs and resources",
                 "mitigation": "Use explicit permissions instead of wildcards"
             })
         
@@ -82,6 +104,7 @@ def scan_role_bindings(self, config: RBACConfig) -> List[Dict]:
                 "severity": "MEDIUM",
                 "category": "privileged_escalation",
                 "description": f"Role {role.get('name')} allows privilege escalation",
+                "fix": "Remove escalate verb or add restrictions",
                 "mitigation": "Restrict privilege escalation permissions"
             })
         
@@ -91,6 +114,7 @@ def scan_role_bindings(self, config: RBACConfig) -> List[Dict]:
                 "severity": "HIGH",
                 "category": "cluster_admin_binding",
                 "description": f"Service account bound to cluster-admin: {sa.get('name')}",
+                "fix": "Use least-privilege role instead of cluster-admin",
                 "mitigation": "Apply principle of least privilege"
             })
         
@@ -100,6 +124,7 @@ def scan_role_bindings(self, config: RBACConfig) -> List[Dict]:
                 "severity": "HIGH",
                 "category": "dangerous_resource_access",
                 "description": f"Role {role.get('name')} has access to secrets",
+                "fix": "Limit secret access to specific namespaces and names",
                 "mitigation": "Restrict secret access to necessary namespaces only"
             })
         
@@ -109,6 +134,7 @@ def scan_role_bindings(self, config: RBACConfig) -> List[Dict]:
                 "severity": "HIGH",
                 "category": "dangerous_resource_access",
                 "description": f"Role {role.get('name')} has pod exec access",
+                "fix": "Remove pods/exec permission unless explicitly required",
                 "mitigation": "Restrict pod exec access to necessary pods only"
             })
         
@@ -118,6 +144,7 @@ def scan_role_bindings(self, config: RBACConfig) -> List[Dict]:
                 "severity":