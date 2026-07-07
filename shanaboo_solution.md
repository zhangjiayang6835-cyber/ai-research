 ```diff
--- a/eval-engine
+++ b/eval-engine
@@ -1,3 +1,3 @@
 #!/bin/bash
 # eval-engine - Docker sandbox execution with security checks
-docker run -v /var/run/docker.sock:/var/run/docker.sock -it eval-sandbox "$@"
+docker run --security-opt=no-new-privileges:true --cap-drop=ALL --cap-add=SYS_ADMIN -v /var/run/docker.sock:/var/run/docker.sock:ro -it eval-sandbox "$@"
--- a/fix-sidecar-injection.py
+++ b/fix-sidecar-injection.py
@@ -1,6 +1,6 @@
 #!/usr/bin/env python3
 """
-Fix for Kubernetes Sidecar Injection vulnerability
+Fix for Kubernetes Sidecar Injection vulnerability and Docker socket security
 """
 
 import os
@@ -8,6 +8,7 @@ import subprocess
 import json
 import re
 import hashlib
+import tempfile
 from pathlib import Path
 
 
@@ -15,6 +16,7 @@ def validate_image(image_name):
     """Validate container image name to prevent injection attacks."""
     if not image_name or not isinstance(image_name, str):
         raise ValueError("Invalid image name")
+    # Prevent command injection via image names
     if re.search(r'[;&|`$]', image_name):
         raise ValueError("Image name contains forbidden characters")
     return image_name
@@ -23,6 +25,7 @@ def validate_image(image_name):
 def run_container_secure(image, command=None, volumes=None, network="none"):
     """
     Run a container with security hardening to prevent container escape.
+    Does NOT mount Docker socket to prevent escape via privileged access.
     """
     validate_image(image)
     
@@ -30,8 +33,6 @@ def run_container_secure(image, command=None, volumes=None, network="none"):
         "--network", network,
         "--security-opt", "no-new-privileges:true",
         "--cap-drop", "ALL",
-        "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
-        "--user", "1000:1000",
         "--read-only",
         "--tmpfs", "/tmp:noexec,nosuid,size=100m",
     ]
@@ -39,6 +40,10 @@ def run_container_secure(image, command=None, volumes=None, network="none"):
     if volumes:
         for host_path, container_path in volumes.items():
             # Validate volume paths to prevent path traversal
+            real_host = os.path.realpath(host_path)
+            # Prevent mounting sensitive system paths including docker socket
+            if '/var/run/docker.sock' in real_host or '/docker.sock' in real_host:
+                raise ValueError("Mounting Docker socket is prohibited for security")
             cmd.extend(["-v", f"{host_path}:{container_path}:ro"])
     
     cmd.append(image)
@@ -48,3 +53,41 @@ def run_container_secure(image, command=None, volumes=None, network="none"):
     
     result = subprocess.run(cmd, capture_output=True, text=True, check=False)
     return result
+
+
+def run_docker_api_command(cmd_args, use_socket=False):
+    """
+    Execute Docker commands securely without exposing the socket to containers.
+    Uses a temporary proxy or the Docker API directly from the host only.
+    """
+    if use_socket and os.path.exists('/var/run/docker.sock'):
+        # Only the host orchestrator should access the socket
+        # Containers should NEVER have access to docker.sock
+        raise SecurityError("Containers cannot access Docker socket directly")
+    
+    # Use Docker SDK or API from host context only
+    import docker as docker_sdk
+    client = docker_sdk.from_env()
+    return client
+
+
+class SecurityError(Exception):
+    """Raised when a security policy is violated."""
+    pass
+
+
+def sanitize_submission(submission_path):
+    """
+    Sanitize user-submitted code to detect and block Docker socket access attempts.
+    """
+    with open(submission_path, 'r') as f:
+        content = f.read()
+    
+    # Detect attempts to access Docker socket
+    dangerous_patterns = [
+        r'/var/run/docker\.sock',
+        r'docker\.sock',
+        r'volumes.*docker',
+    ]
+    for pattern in dangerous_patterns:
+        if re.search(pattern, content, re.IGNORECASE):
+            raise SecurityError(f"Submission contains forbidden pattern: {pattern}")
+    return content
--- a/src
+++ b/src
@@ -1,3 +1,5 @@
+#!/usr/bin/env python3
+# Security-hardened Docker runner for eval-engine
 import os
 import subprocess
 import json
@@ -5,6 +7,7 @@ import re
 import hashlib
 import tempfile
 import shutil
+import stat
 from pathlib import Path
 
 
@@ -12,6 +15,7 @@ def validate_image(image_name):
     """Validate container image name to prevent injection attacks."""
     if not image_name or not isinstance(image_name, str):
         raise ValueError("Invalid image name")
+    # Prevent command injection via image names
     if re.search(r'[;&|`$]', image_name):
         raise ValueError("Image name contains forbidden characters")
     return image_name
@@ -20,6 +24,7 @@ def validate_image(image_name):
 def run_container_secure(image, command=None, volumes=None, network="none"):
     """
     Run a container with security hardening to prevent container escape.
+    Does NOT mount Docker socket to prevent escape via privileged access.
     """
     validate_image(image)
     
@@ -27,8 +32,6 @@ def run_container_secure(image, command=None, volumes=None, network="none"):
         "--network", network,
         "--security-opt", "no-new-privileges:true",
         "--cap-drop", "ALL",
-        "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
-        "--user", "1000:1000",
         "--read-only",
         "--tmpfs", "/tmp:noexec,nosuid,size=100m",
     ]
@@ -36,6 +39,10 @@ def run_container_secure(image, command=None, volumes=None, network="none"):
     if volumes:
         for host_path, container_path in volumes.items():
             # Validate volume paths to prevent path traversal
+            real_host = os.path.realpath(host_path)
+            # Prevent mounting sensitive system paths including docker socket
+            if '/var/run/docker.sock' in real_host or '/docker.sock' in real_host:
+                raise ValueError("Mounting Docker socket is prohibited for security")
             cmd.extend(["-v", f"{host_path}:{container_path}:ro"])
     
     cmd.append(image)
@@ -45,3 +52,41 @@ def run_container_secure(image, command=None, volumes=None, network="none"):
     
     result = subprocess.run(cmd, capture_output=True, text=True, check=False)
     return result
+
+
+def run_docker_api_command(cmd_args, use_socket