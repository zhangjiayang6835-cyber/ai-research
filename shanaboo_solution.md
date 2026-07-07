 ```diff
--- a/eval-engine
+++ b/eval-engine
@@ -0,0 +1,1 @@
+#!/bin/bash
+# eval-engine - Docker sandbox execution engine for AI research platform
+# This file is a directory marker, actual implementation is in eval-engine/
+
--- a/eval-engine/docker_utils.py
+++ b/eval-engine/docker_utils.py
@@ -0,0 +1,245 @@
+#!/usr/bin/env python3
+"""
+Secure Docker utility module for eval-engine.
+Prevents Docker container escape via mounted Docker socket.
+"""
+
+import os
+import re
+import json
+import logging
+import subprocess
+from typing import List, Dict, Optional, Set
+from dataclasses import dataclass
+from enum import Enum
+
+logger = logging.getLogger(__name__)
+
+
+class SecurityPolicy(Enum):
+    """Security policies for Docker container execution."""
+    DENY = "deny"
+    ALLOW = "allow"
+    SANITIZE = "sanitize"
+
+
+@dataclass
+class VolumeMount:
+    """Represents a volume mount configuration."""
+    source: str
+    destination: str
+    mode: str = "rw"
+    
+    def is_docker_socket(self) -> bool:
+        """Check if this mount is for a Docker socket."""
+        socket_paths = [
+            "/var/run/docker.sock",
+            "/run/docker.sock",
+            "/var/run/docker",
+            "/run/docker",
+        ]
+        normalized_source = os.path.abspath(os.path.expanduser(self.source))
+        for sock_path in socket_paths:
+            if normalized_source == sock_path or normalized_source.startswith(sock_path):
+                return True
+        return False
+    
+    def is_sensitive_system_path(self) -> bool:
+        """Check if mount targets a sensitive system path."""
+        sensitive_paths = [
+            "/proc", "/sys", "/dev", "/boot", "/etc/shadow",
+            "/root/.ssh", "/home/*/.ssh", "/etc/docker",
+            "/var/lib/docker", "/usr/bin/docker", "/usr/local/bin/docker",
+        ]
+        normalized_dest = os.path.abspath(self.destination)
+        for path in sensitive_paths:
+            if path.endswith("*"):
+                # Handle wildcard patterns
+                import fnmatch
+                if fnmatch.fnmatch(normalized_dest, path):
+                    return True
+            elif normalized_dest.startswith(path):
+                return True
+        return False
+
+
+class DockerSecurityValidator:
+    """
+    Validates Docker configurations to prevent container escape
+    via mounted Docker socket and other dangerous configurations.
+    """
+    
+    # Dangerous capabilities that can lead to container escape
+    DANGEROUS_CAPABILITIES: Set[str] = {
+        "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
+        "CAP_DAC_READ_SEARCH", "CAP_DAC_OVERRIDE", "CAP_SYS_RAWIO",
+        "CAP_SYS_BOOT", "CAP_SYSLOG", "CAP_NET_ADMIN",
+    }
+    
+    # Dangerous security options
+    DANGEROUS_SECURITY_OPTS: Set[str] = {
+        "seccomp=unconfined", "apparmor=unconfined", "label=disable",
+    }
+    
+    def __init__(self, policy: SecurityPolicy = SecurityPolicy.DENY):
+        self.policy = policy
+        self.violations: List[str] = []
+    
+    def validate_volume_mounts(self, mounts: List[VolumeMount]) -> bool:
+        """
+        Validate volume mounts for security issues.
+        Returns True if safe, False if dangerous mounts detected.
+        """
+        is_safe = True
+        
+        for mount in mounts:
+            # Check for Docker socket mounts
+            if mount.is_docker_socket():
+                self.violations.append(
+                    f"SECURITY VIOLATION: Docker socket mount detected: "
+                    f"{mount.source}:{mount.destination}"
+                )
+                is_safe = False
+            
+            # Check for sensitive system path mounts
+            if mount.is_sensitive_system_path():
+                self.violations.append(
+                    f"SECURITY VIOLATION: Sensitive system path mount detected: "
+                    f"{mount.source}:{mount.destination}"
+                )
+                is_safe = False
+        
+        return is_safe
+    
+    def validate_capabilities(self, capabilities: List[str]) -> bool:
+        """Validate container capabilities."""
+        is_safe = True
+        for cap in capabilities:
+            cap_upper = cap.upper() if not cap.startswith("CAP_") else cap.upper()
+            if cap_upper in self.DANGEROUS_CAPABILITIES:
+                self.violations.append(
+                    f"SECURITY VIOLATION: Dangerous capability requested: {cap}"
+                )
+                is_safe = False
+        return is_safe
+    
+    def validate_security_options(self, options: List[str]) -> bool:
+        """Validate security options."""
+        is_safe = True
+        for opt in options:
+            opt_lower = opt.lower()
+            if opt_lower in self.DANGEROUS_SECURITY_OPTS:
+                self.violations.append(
+                    f"SECURITY VIOLATION: Dangerous security option: {opt}"
+                )
+                is_safe = False
+        return is_safe
+    
+    def validate_privileged_mode(self, privileged: bool) -> bool:
+        """Validate privileged mode setting."""
+        if privileged:
+            self.violations.append(
+                "SECURITY VIOLATION: Privileged mode is not allowed"
+            )
+            return False
+        return True
+    
+    def validate_host_pid(self, host_pid: bool) -> bool:
+        """Validate host PID namespace setting."""
+        if host_pid:
+            self.violations.append(
+                "SECURITY VIOLATION: Host PID namespace sharing is not allowed"
+            )
+            return False
+        return True
+    
+    def validate_host_network(self, host_network: bool) -> bool:
+        """Validate host network setting."""
+        if host_network:
+            self.violations.append(
+                "SECURITY VIOLATION: Host network mode is not allowed"
+            )
+            return False
+        return True
+    
+    def validate_all(self, 
+                     mounts: Optional[List[VolumeMount]] = None,
+                     capabilities: Optional[List[str]] = None,
+                     security_options: Optional[List[str]] = None,
+                     privileged: bool = False,
+                     host_pid: bool = False,
+                     host_network: bool = False) -> bool:
+        """
+        Run all validation checks.
+        Returns True if configuration is safe, False otherwise.
+        """
+        self.violations = []
+        
+        results = []
+        if mounts is not None:
+            results.append(self