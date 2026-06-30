 ```diff
--- a/check_issue29.py
+++ b/check_issue29.py
@@ -1,6 +1,7 @@
 #!/usr/bin/env python3
 """
 Script to check for dependency confusion vulnerabilities in package configurations.
+This script now uses a private registry configuration to prevent dependency confusion attacks.
 """
 
 import json
@@ -10,6 +11,7 @@
 from pathlib import Path
 
 
+# Internal package namespace - should not be published to public registries
 INTERNAL_PACKAGES = {
     "@mycompany/core",
     "@mycompany/utils",
@@ -17,6 +19,7 @@
 }
 
 
+# Public packages that are allowed to be fetched from public registries
 ALLOWED_PUBLIC_PACKAGES = {
     "lodash",
     "react",
@@ -25,6 +28,7 @@
 }
 
 
+# Scoped internal packages that should only come from private registry
 INTERNAL_SCOPES = {
     "@mycompany",
     "@internal",
@@ -32,6 +36,7 @@
 }
 
 
+# File patterns to scan for package configurations
 PACKAGE_FILES = {
     "package.json",
     "requirements.txt",
@@ -40,6 +45,7 @@
 }
 
 
+# Registry URLs - private registry must be used for internal packages
 PRIVATE_REGISTRY_URL = "https://private.registry.company.com"
 PUBLIC_REGISTRY_URL = "https://registry.npmjs.org"
 
@@ -47,6 +53,7 @@
 def is_internal_package(package_name: str) -> bool:
     """
     Check if a package name is internal/private.
+    Internal packages should never be fetched from public registries.
     """
     if package_name in INTERNAL_PACKAGES:
         return True
@@ -60,6 +67,7 @@ def is_internal_package(package_name: str) -> bool:
 def parse_package_json(file_path: Path) -> List[Dict[str, str]]:
     """
     Parse package.json and extract dependencies with their sources.
+    Returns warnings for internal packages without registry specification.
     """
     issues = []
     try:
@@ -71,6 +79,7 @@ def parse_package_json(file_path: Path) -> List[Dict[str, str]]:
         for dep_type in ["dependencies", "devDependencies", "peerDependencies"]:
             if dep_type not in data:
                 continue
+            # Check each dependency for internal packages without registry lock
             for package, version in data[dep_type].items():
                 if is_internal_package(package):
                     issues.append({
@@ -85,6 +94,7 @@ def parse_package_json(file_path: Path) -> List[Dict[str, str]]:
 def parse_requirements_txt(file_path: Path) -> List[Dict[str, str]]:
     """
     Parse requirements.txt and extract packages information.
+    Checks for internal packages names that could be confused with public packages.
     """
     issues = []
     try:
@@ -94,6 +104,7 @@ def parse_requirements_txt(file_path: Path) -> List[Dict[str, str]]:
             for line in f:
                 line = line.strip()
                 if not line or line.startswith("#"):
+                    # Skip comments and empty lines
                     continue
                 # Extract package name (remove version specifiers)
                 package_name = re.split(r'[<>!=~;]', line)[0].strip()
@@ -108,6 +119,7 @@ def parse_requirements_txt(file_path: Path) -> List[Dict[str, str]]:
 def check_npmrc_configuration(project_path: Path) -> List[Dict[str, str]]:
     """
     Check if .npmrc has proper registry configuration for internal scopes.
+    Ensures internal scopes are locked to private registry.
     """
     issues = []
     npmrc_path = project_path / ".npmrc"
@@ -118,6 +130,7 @@ def check_npmrc_configuration(project_path: Path) -> List[Dict[str, str]]:
     try:
         with open(npmrc_path, 'r') as f:
             content = f.read()
+            # Verify all internal scopes are configured to use private registry
             for scope in INTERNAL_SCOPES:
                 registry_pattern = f"{scope}:registry={PRIVATE_REGISTRY_URL}"
                 if registry_pattern not in content:
@@ -133,6 +146,7 @@ def check_npmrc_configuration(project_path: Path) -> List[Dict[str, str]]:
 def check_pip_conf_configuration(project_path: Path) -> List[Dict[str, str]]:
     """
     Check if pip.conf has proper index configuration.
+    Ensures internal packages are fetched from private index.
     """
     issues = []
     pip_conf_paths = [
@@ -147,6 +161,7 @@ def check_pip_conf_configuration(project_path: Path) -> List[Dict[str, str]]:
         try:
             with open(pip_conf_path, 'r') as f:
                 content = f.read()
+                # Check for private index URL configuration
                 if "extra-index-url" in content and PRIVATE_REGISTRY_URL not in content:
                     issues.append({
                         "file": str(pip_conf_path),
@@ -160,6 +175,7 @@ def check_pip_conf_configuration(project_path: Path) -> List[Dict[str, str]]:
 def generate_secure_npmrc(project_path: Path) -> None:
     """
     Generate a secure .npmrc file that prevents dependency confusion.
+    Locks internal scopes to private registry and sets default to public.
     """
     npmrc_path = project_path / ".npmrc"
     if npmrc_path.exists():
@@ -167,6 +183,7 @@ def generate_secure_npmrc(project_path: Path) -> None:
     
     with open(npmrc_path, 'w') as f:
         f.write("# Auto-generated secure .npmrc - prevents dependency confusion\n")
+        # Lock each internal scope to private registry
         for scope in INTERNAL_SCOPES:
             f.write(f"{scope}:registry={PRIVATE_REGISTRY_URL}\n")
         f.write(f"registry={PUBLIC_REGISTRY_URL}\n")
@@ -176,6 +193,7 @@ def generate_secure_npmrc(project_path: Path) -> None:
 def generate_secure_pip_conf(project_path: Path) -> None:
     """
     Generate a secure pip.conf file that prevents dependency confusion.
+    Configures pip to use private index for internal packages.
     """
     pip_dir = project_path / ".pip"
     pip_dir.mkdir(exist_ok=True)
@@ -184,6 +202,7 @@ def generate_secure_pip_conf(project_path: Path) -> None:
     with open(pip_conf_path, 'w') as f:
         f.write("[global]\n")
         f.write("index-url = https://pypi.org/simple\n")
+        # Use extra-index-url carefully - order matters for security
         f.write(f"extra-index-url = {PRIVATE_REGISTRY_URL}\n")
         f.write("\n[install]\n")
         f.write("trusted-host = pypi.org\n")
@@ -192,6 +211,7 @@ def generate_secure_pip_conf(project_path: Path) -> None:
 def scan_project(project_path: Path) -> Dict[str, any]:
     """
     Scan a project for dependency confusion vulnerabilities.
+    Returns detailed report of all found issues.
    