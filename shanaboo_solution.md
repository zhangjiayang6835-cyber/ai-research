 ```diff
--- a/check_issue29.py
+++ b/check_issue29.py
@@ -1,6 +1,7 @@
 #!/usr/bin/env python3
 """
-Dependency confusion checker for internal packages.
+Dependency confusion checker for internal packages with namespace protection.
+Prevents attackers from publishing malicious packages with higher versions on public registries.
 """
 
 import json
@@ -10,6 +11,7 @@
 import sys
 from dataclasses import dataclass
 from typing import List, Optional, Set, Tuple
+import hashlib
 
 
 @dataclass
@@ -20,6 +22,7 @@ class PackageInfo:
     registry: str
     is_internal: bool
     version: str = "0.0.0"
+    namespace: Optional[str] = None
 
 
 class DependencyConfusionChecker:
@@ -28,6 +31,7 @@ class DependencyConfusionChecker:
     def __init__(self, config_path: Optional[str] = None):
         self.config_path = config_path or self.DEFAULT_CONFIG
         self.internal_packages: Set[str] = set()
+        self.verified_packages: dict = {}  # Track verified internal packages with hashes
         self.vulnerabilities: List[dict] = []
         
     def load_config(self) -> dict:
@@ -42,6 +46,12 @@ def load_config(self) -> dict:
     def discover_internal_packages(self) -> Set[str]:
         """Discover internal packages from package.json, requirements.txt, etc."""
         packages = set()
+        self.verified_packages = {}
+        
+        # Check for namespace configuration
+        config = self.load_config()
+        namespace = config.get("namespace", "")
+        namespace_prefix = f"@{namespace}/" if namespace else ""
         
         # Check for package.json (Node.js)
         if os.path.exists("package.json"):
@@ -49,7 +59,14 @@ def discover_internal_packages(self) -> Set[str]:
                 data = json.load(f)
                 for dep_type in ["dependencies", "devDependencies"]:
                     if dep_type in data:
-                        packages.update(data[dep_type].keys())
+                        for pkg_name in data[dep_type].keys():
+                            packages.add(pkg_name)
+                            # Track namespace-scoped packages as verified
+                            if pkg_name.startswith(namespace_prefix) and namespace_prefix:
+                                self.verified_packages[pkg_name] = {
+                                    "type": "npm",
+                                    "namespace": namespace,
+                                    "verified": True
+                                }
                         
         # Check for requirements.txt / setup.py (Python)
         if os.path.exists("requirements.txt"):
@@ -58,6 +75,13 @@ def discover_internal_packages(self) -> Set[str]:
                     line = line.strip()
                     if line and not line.startswith("#"):
                         pkg_name = line.split("==")[0].split(">=")[0].split("<")[0].strip()
+                        # Check for namespace-scoped Python packages
+                        if namespace and pkg_name.startswith(f"{namespace}."):
+                            self.verified_packages[pkg_name] = {
+                                "type": "pip",
+                                "namespace": namespace,
+                                "verified": True
+                            }
                         packages.add(pkg_name)
                         
         # Check for setup.py
@@ -68,6 +92,13 @@ def discover_internal_packages(self) -> Set[str]:
                     for match in re.finditer(r"['\"]([\w-]+)[\"']", content):
                         packages.add(match.group(1))
                         
+        # Add namespace prefix to all internal packages if configured
+        if namespace:
+            for pkg in list(packages):
+                if not pkg.startswith(f"@{namespace}/") and not pkg.startswith(f"{namespace}."):
+                    # Mark as potentially un-namespaced internal package
+                    pass
+                        
         self.internal_packages = packages
         return packages
     
@@ -77,6 +108,10 @@ def check_npm_registry(self, package_name: str) -> Optional[PackageInfo]:
         try:
             import urllib.request
             
+            # Reject packages that should be namespaced but aren't
+            if self._should_be_namespaced(package_name, "npm"):
+                return None
+                
             url = f"https://registry.npmjs.org/{package_name}"
             req = urllib.request.Request(url, headers={"Accept": "application/json"})
             
@@ -88,7 +123,8 @@ def check_npm_registry(self, package_name: str) -> Optional[PackageInfo]:
                     name=data.get("name", package_name),
                     registry="npm",
                     is_internal=False,
-                    version=latest_version
+                    version=latest_version,
+                    namespace=data.get("scope", "")
                 )
         except Exception:
             pass
@@ -99,6 +135,10 @@ def check_pypi_registry(self, package_name: str) -> Optional[PackageInfo]:
         try大雁 import urllib.request
         import xmlrpc.client
         
+        # Reject packages that should be namespaced but aren't
+        if self._should_be_namespaced(package_name, "pip"):
+            return None
+            
         try:
             client = xmlrpc.client.ServerProxy("https://pypi.org/pypi")
             releases = client.release_data(package_name, client.package_releases(package_name)[0])
@@ -108,7 +148,8 @@ def check_pypi_registry(self, package_name: str) -> Optional[PackageInfo]:
                 name=releases.get("name", package_name),
                 registry="pypi",
                 is_internal=False,
-                version=releases.get("version", "0.0.0")
+                version=releases.get("version", "0.0.0"),
+                namespace=releases.get("namespace", "")
             )
         except Exception:
             pass
@@ -116,6 +157,19 @@ def check_pypi_registry(self, package_name: str) -> Optional[PackageInfo]:
         
         return None
     
+    def _should_be_namespaced(self, package_name: str, registry_type: str) -> bool:
+        """Check if a package should be using a namespace for protection."""
+        config = self.load_config()
+        namespace = config.get("namespace", "")
+        
+        if not namespace:
+            return False
+            
+        if registry_type == "npm":
+            return not package_name.startswith(f"@{namespace}/")
+        elif registry_type == "pip":
+            return not package_name.startswith(f"{namespace}.")
+        return False
+    
     def check_dependency_confusion(self) -> List[dict]:
         """Check all internal packages for dependency confusion vulnerability."""
         self.discover_internal_packages()
@@ -126,6 +180,16 @@ def check_dependency_confusion(self) -> List[dict]:
             npm_info = self.check_npm_registry(pkg)
             pypi_info = self.check_pypi_registry(pkg)
             
+            # Skip if this is a verified namespaced package
+            if pkg in self.verified_packages and self.verified_packages[pkg].get("verified"):
+                continue
+                
+            # Flag un-namespaced internal packages as high