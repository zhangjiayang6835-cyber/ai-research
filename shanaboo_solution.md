 ```diff
--- a/fix-sidecar-injection.py
+++ b/fix-sidecar-injection.py
@@ -1,4 +1,4 @@
-#!/usr/bin/env python3
+#!/usr/bin/env python3
 """
 Fix for Sidecar Injection vulnerability in Kubernetes-like environments.
 This script validates and sanitizes sidecar configurations to prevent
@@ -10,6 +10,7 @@
 import json
 import re
 import hashlib
+import ssl
 from urllib.parse import urlparse
 
 
@@ -45,6 +46,10 @@
     "imagePullPolicy": "IfNotPresent"
 }
 
+# TLS Security Constants
+MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2
+CERTIFICATE_PINNING_ENABLED = True
+
 
 class SidecarInjectionError(Exception):
     """Custom exception for sidecar injection errors."""
@@ -52,6 +57,115 @@
     pass
 
 
+class CertificateValidator:
+    """
+    Validates TLS certificates to prevent BGP hijacking → TLS bypass attacks.
+    Implements certificate pinning, hostname verification, and TLS version enforcement.
+    """
+    
+    def __init__(self):
+        self._pinned_certificates = {}
+        self._trusted_ca_bundle = None
+    
+    def pin_certificate(self, hostname: str, cert_fingerprint: str) -> None:
+        """
+        Pin a certificate fingerprint for a specific hostname.
+        Prevents acceptance of fraudulent certificates during BGP hijacking.
+        """
+        if not cert_fingerprint or len(cert_fingerprint) < 32:
+            raise SidecarInjectionError("Invalid certificate fingerprint for pinning")
+        self._pinned_certificates[hostname] = cert_fingerprint.lower()
+    
+    def validate_tls_connection(self, hostname: str, port: int = 443, 
+                                timeout: int = 10) -> dict:
+        """
+        Validate TLS connection with strict security checks.
+        Returns connection info or raises exception on validation failure.
+        """
+        context = ssl.create_default_context()
+        context.minimum_version = MIN_TLS_VERSION
+        context.check_hostname = True
+        context.verify_mode = ssl.CERT_REQUIRED
+        
+        # Load custom CA bundle if available
+        if self._trusted_ca_bundle:
+            context.load_verify_locations(self._trusted_ca_bundle)
+        
+        try:
+            with socket.create_connection((hostname, port), timeout=timeout) as sock:
+                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
+                    # Verify TLS version
+                    if ssock.version() in ('TLSv1', 'TLSv1.1'):
+                        raise SidecarInjectionError(
+                            f"TLS version {ssock.version()} not allowed for {hostname}"
+                        )
+                    
+                    # Get certificate
+                    cert = ssock.getpeercert(binary_form=True)
+                    if not cert:
+                        raise SidecarInjectionError(f"No certificate received from {hostname}")
+                    
+                    # Calculate certificate fingerprint
+                    import hashlib
+                    cert_fingerprint = hashlib.sha256(cert).hexdigest()
+                    
+                    # Check certificate pinning
+                    if hostname in self._pinned_certificates:
+                        expected = self._pinned_certificates[hostname]
+                        actual = cert_fingerprint
+                        if expected != actual:
+                            raise SidecarInjectionError(
+                                f"Certificate pinning failed for {hostname}: "
+                                f"expected {expected}, got {actual}"
+                            )
+                    
+                    return {
+                        "hostname": hostname,
+                        "tls_version": ssock.version(),
+                        "cipher": ssock.cipher(),
+                        "cert_fingerprint": cert_fingerprint,
+                        "pinned": hostname in self._pinned_certificates
+                    }
+                    
+        except ssl.SSLError as e:
+            raise SidecarInjectionError(f"TLS validation failed for {hostname}: {str(e)}")
+        except socket.timeout:
+            raise SidecarInjectionError(f"Connection timeout to {hostname}")
+        except Exception as e:
+            raise SidecarInjectionError(f"Connection failed to {hostname}: {str(e)}")
+    
+    def verify_image_registry(self, image_url: str) -> dict:
+        """
+        Verify TLS security of image registry before pulling.
+        Prevents BGP hijacking attacks on container registries.
+        """
+        parsed = urlparse(image_url)
+        registry = parsed.netloc or parsed.path.split('/')[0]
+        
+        # Skip verification for local/private registries with explicit allowlist
+        if registry in ('localhost', '127.0.0.1') or registry.startswith('10.'):
+            return {"status": "skipped", "reason": "local_registry"}
+        
+        # Validate TLS for remote registries
+        try:
+            result = self.validate_tls_connection(registry, port=443)
+            result["status"] = "verified"
+            return result
+        except SidecarInjectionError:
+            # Try with fallback port for some registries
+            if registry.endswith('.local') or registry.endswith('.cluster'):
+                return {"status": "skipped", "reason": "internal_domain"}
+            raise
+
+
 class SidecarValidator:
     """
     Validates and sanitizes sidecar injection configurations.
@@ -61,6 +175,7 @@
     def __init__(self):
         self.allowed_registries = set(ALLOWED_REGISTRIES)
         self.blocked_capabilities = set(BLOCKED_CAPABILITIES)
+        self.cert_validator = CertificateValidator()
     
     def validate_image(self, image: str) -> bool:
         """
@@ -78,6 +193,14 @@
         if registry not in self.allowed_registries:
             raise SidecarInjectionError(f"Registry '{registry}' not in allowed list")
         
+        # Verify TLS certificate for remote registries (BGP hijacking protection)
+        try:
+            tls_info = self.cert_validator.verify_image_registry(image)
+            logger.info(f"TLS verification for {registry}: {tls_info['status']}")
+        except SidecarInjectionError as e:
+            logger.error(f"TLS verification failed for {image}: {e}")
+            raise SidecarInjectionError(f"Cannot verify secure connection to registry: {e}")
+        
         return True
     
     def validate_security_context(self, security_context: dict) -> dict:
@@ -196,6 +319,7 @@
         self.validator = SidecarValidator()
         self.audit_log = []
         self.injected_sidecars = {}
+        self.cert_validator = CertificateValidator()
     
     def _log_action(self, action: str, details: dict) -> None:
         """Log an action for audit purposes."""
@@ -210,6 +334,14 @@
         """
         self._log_action("inject_sidecar", {"pod_name": pod_name, "sidecar": sidecar_name})
         
+        # Verify registry TLS before injection (BGP hijacking protection)
+        image = sidecar_config.get("image", "")
+        if image:
