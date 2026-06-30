 ```diff
--- a/eval-engine
+++ b/eval-engine
@@ -1 +1,2 @@
+#!/usr/bin/env python3
 # eval-engine - Docker sandbox execution and evaluation engine
--- a/eval-engine/docker_utils.py
+++ b/eval-engine/docker_utils.py
@@ -0,0 +1,245 @@
+#!/usr/bin/env python3
+"""
+Secure Docker utility functions for eval-engine.
+Prevents Docker container escape via mounted Docker socket.
+"""
+
+import os
+import re
+import json
+import logging
+import tempfile
+import hashlib
+from pathlib import Path
+from typing import Dict, List, Optional, Set, Tuple, Any
+
+# Configure logging
+logger = logging.getLogger(__name__)
+
+
+class DockerSecurityError(Exception):
+    """Raised when a Docker security violation is detected."""
+    pass
+
+
+# Security constants
+DOCKER_SOCKET_PATHS = [
+    '/var/run/docker.sock',
+    '/run/docker.sock',
+    '/var/run/docker.pid',
+]
+
+# Dangerous mount patterns that could lead to container escape
+DANGEROUS_MOUNT_PATTERNS = [
+    # Docker socket mounts
+    r'.*/docker\.sock$',
+    r'.*/docker\.pid$',
+    # Host root filesystem mounts
+    r'^/+$',
+    r'^/[^/]+$',
+    # Sensitive system directories
+    r'^/proc$',
+    r'^/proc/.*',
+    r'^/sys$',
+    r'^/sys/.*',
+    r'^/dev$',
+    r'^/dev/.*',
+    # SSH keys and credentials
+    r'.*/\.ssh$',
+    r'.*/\.ssh/.*',
+    r'.*/\.aws$',
+    r'.*/\.aws/.*',
+    r'.*/\.kube$',
+    r'.*/\.kube/.*',
+]
+
+# Dangerous Docker capabilities that can lead to escape
+DANGEROUS_CAPABILITIES = {
+    'CAP_SYS_ADMIN',
+    'CAP_SYS_PTRACE',
+    'CAP_SYS_MODULE',
+    'CAP_DAC_READ_SEARCH',
+    'CAP_DAC_OVERRIDE',
+    'CAP_SETUID',
+    'CAP_SETGID',
+    'CAP_NET_ADMIN',
+    'CAP_NET_RAW',
+    'CAP_SYS_RAWIO',
+    'CAP_SYSLOG',
+    'CAP_WAKE_ALARM',
+    'CAP_BLOCK_SUSPEND',
+    'CAP_AUDIT_CONTROL',
+    'CAP_AUDIT_WRITE',
+    'CAP_MAC_ADMIN',
+    'CAP_MAC_OVERRIDE',
+    'CAP_MKNOD',
+    'CAP_SYS_PACCT',
+    'CAP_SYS_TIME',
+    'CAP_SYS_TTY_CONFIG',
+    'CAP_LEASE',
+}
+
+# Dangerous security options
+DANGEROUS_SECURITY_OPTS = [
+    'seccomp=unconfined',
+    'apparmor=unconfined',
+    'label=disable',
+    'no-new-privileges=false',
+]
+
+
+def is_docker_socket_mount(host_path: str, container_path: str) -> bool:
+    """
+    Check if a mount involves the Docker socket.
+    
+    Args:
+        host_path: The host path of the mount
+        container_path: The container path of the mount
+        
+    Returns:
+        True if this is a Docker socket mount
+    """
+    host_path = os.path.abspath(os.path.expanduser(host_path))
+    
+    # Check if host path is a Docker socket
+    for socket_path in DOCKER_SOCKET_PATHS:
+        if host_path == socket_path or host_path.startswith(socket_path + '/'):
+            return True
+    
+    # Check if container path contains docker socket reference
+    if 'docker.sock' in container_path or 'docker.pid' in container_path:
+        return True
+    
+    return False
+
+
+def is_dangerous_mount(host_path: str, container_path: str) -> Tuple[bool, str]:
+    """
+    Check if a mount is dangerous and could lead to container escape.
+    
+    Args:
+        host_path: The host path of the mount
+        container_path: The container path of the mount
+        
+    Returns:
+        Tuple of (is_dangerous, reason)
+    """
+    host_path = os.path.abspath(os.path.expanduser(host_path))
+    container_path = os.path.abspath(os.path.expanduser(container_path))
+    
+    # Check for Docker socket mounts
+    if is_docker_socket_mount(host_path, container_path):
+        return True, f"Docker socket mount detected: {host_path}:{container_path}"
+    
+    # Check against dangerous patterns
+    for pattern in DANGEROUS_MOUNT_PATTERNS:
+        if re.match(pattern, host_path):
+            return True, f"Dangerous host mount detected: {host_path} (pattern: {pattern})"
+    
+    # Check for bind mounts of sensitive files
+    sensitive_files = [
+        '/etc/shadow',
+        '/etc/passwd',
+        '/etc/hosts',
+        '/etc/resolv.conf',
+        '/etc/kubernetes',
+        '/var/lib/kubelet',
+    ]
+    for sensitive in sensitive_files:
+        if host_path == sensitive or host_path.startswith(sensitive + '/'):
+            return True, f"Sensitive system file mount detected: {host_path}"
+    
+    return False, ""
+
+
+def validate_volume_mounts(volume_mounts: List[Dict[str, str]]) -> None:
+    """
+    Validate volume mounts for security issues.
+    
+    Args:
+        volume_mounts: List of volume mount dictionaries with 'host_path' and 'container_path'
+        
+    Raises:
+        DockerSecurityError: If a dangerous mount is detected
+    """
+    if not volume_mounts:
+        return
+    
+    for mount in volume_mounts:
+        host_path = mount.get('host_path', mount.get('source', ''))
+        container_path = mount.get('container_path', mount.get('target', ''))
+        
+        is_dangerous, reason = is_dangerous_mount(host_path, container_path)
+        if is_dangerous:
+            raise DockerSecurityError(
+                f"SECURITY VIOLATION: Dangerous volume mount detected. {reason}. "
+                f"Mount: {host_path}:{container_path}. "
+                f"Docker socket mounts allow container escape. "
+                f"Use the Docker API securely or avoid mounting the socket."
+            )
+
+
+def validate_container_config(config: Dict[str, Any]) -> None:
+    """
+    Validate a container configuration for security issues.
+    
+    Args:
+        config: Container configuration dictionary
+        
+    Raises:
+        DockerSecurityError: If a security issue is detected
