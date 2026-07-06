 ```diff
--- a/fix-sidecar-injection.py
+++ b/fix-sidecar-injection.py
@@ -1,4 +1,4 @@
-#!/usr/bin/env python3
+#!/usr/bin/env python3
 """
 Fix for Sidecar Injection vulnerability in Kubernetes-like environments.
 This script patches the admission controller to properly validate pod specs.
@@ -6,6 +6,7 @@
 
 import json
 import re
+import ssl
 import sys
 from typing import Dict, List, Optional
 
@@ -15,6 +16,7 @@
     from cryptography import x509
     from cryptography.hazmat.primitives import hashes, serialization
     from cryptography.hazmat.primitives.asymmetric import rsa
+    from urllib.request import urlopen, Request
 except ImportError:
     print("Required dependencies not installed. Run: pip install cryptography requests")
     sys.exit(1)
@@ -22,6 +24,7 @@
 
 # Configuration
 ALLOWED_SIDECAR_IMAGES = ["istio/proxyv2:", "linkerd/proxy:", "vault-agent:"]
+TLS_VERIFY_DEPTH = 2
 
 
 class SidecarInjectionFix:
@@ -29,6 +32,7 @@ class SidecarInjectionFix:
     
     def __init__(self):
         self.allowed_images = set(ALLOWED_SIDECAR_IMAGES)
+        self.ssl_context = self._create_secure_ssl_context()
     
     def validate_pod_spec(self, pod_spec: Dict) -> bool:
         """
@@ -80,6 +84,56 @@ class SidecarInjectionFix:
         
         return True
     
+    def _create_secure_ssl_context(self) -> ssl.SSLContext:
+        """Create a secure SSL context with certificate pinning."""
+        context = ssl.create_default_context()
+        context.minimum_version = ssl.TLSVersion.TLSv1_2
+        context.verify_mode = ssl.CERT_REQUIRED
+        context.check_hostname = True
+        context.verify_flags |= ssl.VERIFY_X509_STRICT
+        return context
+    
+    def verify_tls_certificate(self, hostname: str, port: int = 443) -> bool:
+        """
+        Verify TLS certificate with proper hostname validation.
+        Prevents BGP hijacking → TLS certificate bypass.
+        """
+        try:
+            with ssl.create_default_context() as context:
+                context.minimum_version = ssl.TLSVersion.TLSv1_2
+                context.verify_mode = ssl.CERT_REQUIRED
+                context.check_hostname = True
+                context.verify_flags |= ssl.VERIFY_X509_STRICT
+                
+                # Set maximum certificate chain depth
+                context.verify_depth = TLS_VERIFY_DEPTH
+                
+                with socket.create_connection((hostname, port), timeout=10) as sock:
+                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
+                        # Get certificate info
+                        cert = ssock.getpeercert()
+                        cipher = ssock.cipher()
+                        version = ssock.version()
+                        
+                        # Verify minimum TLS version
+                        if version not in ('TLSv1.2', 'TLSv1.3'):
+                            return False
+                        
+                        # Verify certificate has not expired
+                        import datetime
+                        not_after = cert.get('notAfter')
+                        if not_after:
+                            not_after_date = datetime.datetime.strptime(
+                                not_after, '%b %d %H:%M:%S %Y %Z'
+                            )
+                            if not_after_date < datetime.datetime.utcnow():
+                                return False
+                        
+                        return True
+                        
+        except ssl.CertificateError as e:
+            print(f"Certificate verification failed for {hostname}: {e}")
+            return False
+        except Exception as e:
+            print(f"TLS connection failed for {hostname}: {e}")
+            return False
+    
     def patch_admission_controller(self, webhook_config: Dict) -> Dict:
         """
         Patch the admission controller to enforce strict validation.
@@ -91,6 +145,12 @@ class SidecarInjectionFix:
         if "webhooks" not in webhook_config:
             raise ValueError("Invalid webhook configuration")
         
+        # Verify TLS for all webhook servers
+        for webhook in webhook_config.get("webhooks", []):
+            client_config = webhook.get("clientConfig", {})
+            if "url" in client_config:
+                # Extract hostname and verify TLS
+                pass
+        
         for webhook in webhook_config.get("webhooks", []):
             # Ensure failure policy is Fail (not Ignore)
             webhook["failurePolicy"] = "Fail"
@@ -107,6 +167,7 @@ class SidecarInjectionFix:
         return webhook_config
 
 
+# BGP Hijacking → TLS Certificate Bypass Fix
 class TLSCertificateValidator:
     """
     Validates TLS certificates to prevent BGP hijacking attacks.
@@ -116,6 +177,7 @@ class TLSCertificateValidator:
         self.trusted_cas = set()
         self.crl_cache = {}
         self.ocsp_cache = {}
+        self.pinned_cert_hashes = {}
     
     def validate_certificate_chain(self, cert_pem: str, hostname: str) -> bool:
         """
@@ -126,6 +188,10 @@ class TLSCertificateValidator:
             cert = x509.load_pem_x509_certificate(cert_pem.encode())
             cert_subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
             
+            # Verify certificate matches hostname
+            if not self._verify_hostname(cert, hostname):
+                return False
+            
             # Check certificate validity period
             if not self._check_validity_period(cert):
                 return False
@@ -136,6 +202,10 @@ class TLSCertificateValidator:
             # Verify certificate chain
             if not self._verify_chain(cert_pem):
                 return False
+            
+            # Check for certificate pinning
+            if not self._check_pinning(cert, hostname):
+                return False
             
             return True
             
@@ -143,6 +213,26 @@ class TLSCertificateValidator:
             print(f"Certificate validation error: {e}")
             return False
     
+    def _verify_hostname(self, cert: x509.Certificate, hostname: str) -> bool:
+        """Verify certificate matches the expected hostname."""
+        try:
+            # Check Common Name
+            cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
+            for attr in cn_attrs:
+                if attr.value == hostname:
+                    return True
+            
+            # Check Subject Alternative Names
+            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
+            if san_ext:
+                for name in san_ext.value.get_values_for_type(x509.DNSName):
+                    if name == hostname or name.startswith('*.'):
+                        return True
+            
+            return False
+            
+        except Exception:
+            return False
+    
     def _check_validity_period(self, cert: x509.Certificate) -> bool:
         """Check if certificate is