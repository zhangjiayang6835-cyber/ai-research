 ```diff
--- a/k8s_rbac_validator.py
+++ b/k8s_rbac_validator.py
@@ -1,12 +1,85 @@
 #!/usr/bin/env python3
 """
-Kubernetes RBAC Security Validator
-Validates API server configurations to prevent RBAC bypass vulnerabilities.
+Kubernetes RBAC Security Validator and Fixer
+Validates and fixes API server configurations to prevent RBAC bypass vulnerabilities.
 """
 
 import json
 import sys
+import os
+import re
+from pathlib import Path
+
+
+def get_kube_apiserver_manifest_path():
+    """Find the kube-apiserver manifest path on common locations."""
+    common_paths = [
+        "/etc/kubernetes/manifests/kube-apiserver.yaml",
+        "/etc/kubernetes/manifests/kube-apiserver.yml",
+        "/var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml",
+        "/var/lib/rancher/k3s/server/manifests/kube-apiserver.yaml",
+    ]
+    for path in common_paths:
+        if os.path.exists(path):
+            return path
+    return None
+
+
+def read_apiserver_manifest(path=None):
+    """Read the kube-apiserver manifest."""
+    if path is None:
+        path = get_kube_apiserver_manifest_path()
+    if not path or not os.path.exists(path):
+        return None
+    with open(path, 'r') as f:
+        return f.read()
+
+
+def fix_apiserver_manifest(manifest_content):
+    """
+    Fix the kube-apiserver manifest to enable and enforce RBAC.
+    Returns the fixed manifest content.
+    """
+    if not manifest_content:
+        return None
+    
+    lines = manifest_content.split('\n')
+    fixed_lines = []
+    in_command = False
+    command_idx = -1
+    
+    for i, line in enumerate(lines):
+        fixed_lines.append(line)
+        if 'command:' in line:
+            in_command = True
+            command_idx = i
+        elif in_command and (line.strip().startswith('- ') or line.strip().startswith('--')):
+            continue
+        elif in_command and not line.startswith(' '):
+            in_command = False
+    
+    # Rebuild with proper RBAC flags
+    if command_idx >= 0:
+        new_lines = fixed_lines[:command_idx + 1]
+        new_lines.append('    - --authorization-mode=RBAC')
+        new_lines.append('    - --enable-admission-plugins=NodeRestriction,RBAC')
+        new_lines.append('    - --anonymous-auth=false')
+        new_lines.append('    - --insecure-port=0')
+        new_lines.append('    - --secure-port=6443')
+        new_lines.append('    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt')
+        new_lines.append('    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key')
+        new_lines.append('    - --client-ca-file=/etc/kubernetes/pki/ca.crt')
+        new_lines.append('    - --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt')
+        new_lines.append('    - --enable-bootstrap-token-auth=false')
+        new_lines.append('    - --service-account-lookup=true')
+        new_lines.append('    - --service-account-key-file=/etc/kubernetes/pki/sa.pub')
+        new_lines.append('    - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt')
+        new_lines.append('    - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key')
+        new_lines.append('    - --kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt')
+        return '\n'.join(new_lines)
+    
+    return manifest_content
 
 
 def validate_rbac_config(config):
@@ -14,6 +87,10 @@ def validate_rbac_config(config):
     Validate Kubernetes API server configuration for RBAC bypass vulnerabilities.
     Returns a list of issues found.
     """
+    if config is None:
+        return [{"severity": "CRITICAL", "issue": "Could not read API server configuration. Ensure you have access to /etc/kubernetes/manifests/"}]
+    
+    config_str = str(config) if not isinstance(config, str) else config
     issues = []
     
     # Check for anonymous auth enabled
@@ -21,6 +98,12 @@ def validate_rbac_config(config):
         issues.append({
             "severity": "HIGH",
             "issue": "Anonymous authentication is enabled. Set --anonymous-auth=false"
+        })
+    
+    # Check for insecure port enabled
+    if '--insecure-port=0' not in config_str and '--insecure-port' in config_str:
+        issues.append({
+            "severity": "CRITICAL",
+            "issue": "Insecure port is enabled. Set --insecure-port=0 to disable unencrypted HTTP"
         })
     
     # Check for RBAC in authorization modes
@@ -28,6 +111,12 @@ def validate_rbac_config(config):
         issues.append({
             "severity": "CRITICAL",
             "issue": "RBAC authorization is not enabled. Add RBAC to --authorization-mode"
+        })
+    
+    # Check for AlwaysAllow authorization mode (bypasses all auth)
+    if 'AlwaysAllow' in config_str:
+        issues.append({
+            "severity": "CRITICAL",
+            "issue": "AlwaysAllow authorization mode is enabled. This bypasses ALL authorization checks. Remove it immediately."
         })
     
     # Check for insecure bind address
@@ -36,6 +125,30 @@ def validate_rbac_config(config):
             "severity": "CRITICAL",
             "issue": "API server is bound to insecure address 0.0.0.0 without proper authentication"
         })
+    
+    # Check for missing admission plugins
+    if '--enable-admission-plugins' not in config_str:
+        issues.append({
+            "severity": "HIGH",
+            "issue": "Admission plugins not configured. Enable NodeRestriction and RBAC admission plugins"
+        })
+    
+    # Check for insecure HTTP enabled
+    if '--insecure-bind-address' in config_str:
+        issues.append({
+            "severity": "CRITICAL",
+            "issue": "Insecure HTTP bind address is configured. Remove --insecure-bind-address flag"
+        })
+    
+    # Check for token auth file (bypasses RBAC)
+    if '--token-auth-file' in config_str:
+        issues.append({
+            "severity": "CRITICAL",
+            "issue": "Static token authentication file is configured. This bypasses RBAC. Use service accounts instead"
+        })
+    
+    # Check for ABAC mode (less secure than RBAC)
+    if 'ABAC' in config_str and 'RBAC' not in