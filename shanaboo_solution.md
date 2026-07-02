 ```diff
--- a/k8s_rbac_validator.py
+++ b/k8s_rbac_validator.py
@@ -1,4 +1,4 @@
-#!/usr/bin/env python3
+#!/usr/bin/env python3
 """
 Kubernetes RBAC Security Validator
 
@@ -10,6 +10,7 @@
 import json
 import subprocess
 import sys
+import re
 from typing import Dict, List, Optional, Tuple
 
 
@@ -17,6 +18,7 @@
     """Represents a security misconfiguration in Kubernetes RBAC."""
     
     def __init__(self, name: str, severity: str, description: str, 
+                 remediation: str = "", check_func=None):
                  remediation: str = "", check_func=None):
         self.name = name
         self.severity = severity
@@ -25,6 +27,7 @@ def __init__(self, name: str, severity: str, description: str,
         self.check_func = check_func
 
 
+class K8sRBACValidator:
 class K8sRBACValidator:
     """Validates Kubernetes cluster for RBAC misconfigurations."""
     
@@ -32,6 +35,7 @@ def __init__(self, kubeconfig: Optional[str] = None):
         self.kubeconfig = kubeconfig
         self.vulnerabilities: List[Vulnerability] = []
         self._setup_checks()
+        self._api_server_url: Optional[str] = None
     
     def _setup_checks(self):
         """Initialize all security checks."""
@@ -41,6 +45,7 @@ def _setup_checks(self):
             self._check_anonymous_auth,
             self._check_abac_mode,
             self._check_weak_kubelet,
+            self._check_api_server_rbac_bypass,
         ]
     
     def run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
@@ -48,6 +53,7 @@ def run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
         try:
             result = subprocess.run(
                 cmd, capture_output=True, text=True, timeout=30
+            )
             )
             return result.returncode, result.stdout, result.stderr
         except subprocess.TimeoutExpired:
@@ -55,6 +61,7 @@ def run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
         except FileNotFoundError:
             return 1, "", "kubectl not found"
     
+    def _get_api_server_config(self) -> Dict:
     def _get_api_server_config(self) -> Dict:
         """Fetch API server configuration from the cluster."""
         # Try to get API server pod configuration
@@ -62,6 +69,7 @@ def _get_api_server_config(self) -> Dict:
             "kubectl", "get", "pods", "-n", "kube-system",
             "-l", "component=kube-apiserver",
             "-o", "json"
+        ])
         ])
         
         if code != 0:
@@ -69,6 +77,7 @@ def _get_api_server_config(self) -> Dict:
         
         try:
             data = json.loads(stdout)
+            return data
             return data
         except json.JSONDecodeError:
             return {}
@@ -76,6 +85,7 @@ def _get_api_server_config(self) -> Dict:
     def _check_anonymous_auth(self) -> Optional[Vulnerability]:
         """Check if anonymous authentication is enabled."""
         config = self._get_api_server_config()
+        if not config:
         if not config:
             return None
         
@@ -83,6 +93,7 @@ def _check_anonymous_auth(self) -> Optional[Vulnerability]:
         for item in config.get("items", []):
             containers = item.get("spec", {}).get("containers", [])
             for container in containers:
+                args = container.get("args", [])
                 args = container.get("args", [])
                 for arg in args:
                     if "--anonymous-auth=true" in arg:
@@ -91,6 +102,7 @@ def _check_anonymous_auth(self) -> Optional[Vulnerability]:
                             "high",
                             "Anonymous authentication is enabled on the API server. "
                             "This allows unauthenticated access to the API.",
+                            "Set --anonymous-auth=false on the API server."
                             "Set --anonymous-auth=false on the API server."
                         )
         return None
@@ -98,6 +110,7 @@ def _check_anonymous_auth(self) -> Optional[Vulnerability]:
     def _check_abac_mode(self) -> Optional[Vulnerability]:
         """Check if ABAC authorization mode is used (deprecated and insecure)."""
         config = self._get_api_server_config()
+        if not config:
         if not config:
             return None
         
@@ -105,6 +118,7 @@ def _check_abac_mode(self) -> Optional[Vulnerability]:
         for item in config.get("items", []):
             containers = item.get("spec", {}).get("containers", [])
             for container in containers:
+                args = container.get("args", [])
                 args = container.get("args", [])
                 for arg in args:
                     if "--authorization-mode=" in arg and "ABAC" in arg:
@@ -113,6 +127,7 @@ def _check_abac_mode(self) -> Optional[Vulnerability]:
                             "high",
                             "ABAC authorization mode is enabled. RBAC should be used instead. "
                             "ABAC is deprecated and provides coarse-grained access control.",
+                            "Switch to --authorization-mode=RBAC and remove ABAC."
                             "Switch to --authorization-mode=RBAC and remove ABAC."
                         )
         return None
@@ -120,6 +135,7 @@ def _check_abac_mode(self) -> Optional[Vulnerability]:
     def _check_weak_kubelet(self) -> Optional[Vulnerability]:
         """Check if kubelet has weak authentication."""
         # Check kubelet configuration
+        code, stdout, stderr = self.run_command([
         code, stdout, stderr = self.run_command([
             "kubectl", "get", "configmap", "kubelet-config", "-n", "kube-system",
             "-o", "json"
@@ -129,6 +145,7 @@ def _check_weak_kubelet(self) -> Optional[Vulnerability]:
             return None
         
         try:
+            data = json.loads(stdout)
             data = json.loads(stdout)
             # Check for weak settings
             # This is a simplified check
@@ -136,6 +153,7 @@ def _check_weak_kubelet(self) -> Optional[Vulnerability]:
         except json.JSONDecodeError:
             return None
     
+    def _check_api_server_rbac_bypass(self) -> Optional[Vulnerability]:
     def _check_api_server_rbac_bypass(self) -> Optional[Vulnerability]:
         """
         Check for API server misconfigurations that allow RBAC bypass.
@@ -143,6 +161,7 @@ def _check_api_server_rbac_bypass(self) -> Optional[Vulnerability]:
         This checks for:
         1. --insecure-port being set to non-zero
         2. --insecure