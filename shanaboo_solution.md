 ```diff
--- a/fix-sidecar-injection.py
+++ b/fix-sidecar-injection.py
@@ -1,3 +1,4 @@
+#!/usr/bin/env python3
 """
 BGP Hijacking Simulation → TLS Certificate Bypass Fix
 
@@ -5,6 +6,7 @@
 This script provides a secure implementation that prevents TLS certificate
 bypass attacks that can occur during BGP hijacking scenarios.
 """
+
 import ssl
 import socket
 import hashlib
@@ -12,6 +14,7 @@
 import requests
 import urllib3
 from urllib.parse import urlparse
+from functools import wraps
 
 
 class CertificatePinningError(Exception):
@@ -19,6 +22,7 @@ class CertificatePinningError(Exception):
     pass
 
 
+class TLSSecurityError(Exception):
     """Raised when a TLS security violation is detected."""
     pass
 
@@ -30,6 +34,7 @@ class SecureHTTPClient:
     def __init__(self, pinned_cert_hashes=None, verify_mode=ssl.CERT_REQUIRED):
         """
         Initialize secure HTTP client with certificate pinning.
+        
         Args:
             pinned_cert_hashes: Set of valid certificate SHA-256 hashes
             verify_mode: SSL verification mode (default: CERT_REQUIRED)
@@ -38,6 +43,7 @@ def __init__(self, pinned_cert_hashes=None, verify_mode=ssl.CERT_REQUIRED):
         self.verify_mode = verify_mode
         self.session = requests.Session()
         
+        # Disable warnings but enforce strict verification
         urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
         
         # Configure secure SSL context
@@ -46,6 +52,7 @@ def __init__(self, pinned_cert_hashes=None, verify_mode=ssl.CERT_REQUIRED):
     def _create_ssl_context(self):
         """Create a secure SSL context with modern TLS settings."""
         context = ssl.create_default_context()
+        
         # Require certificate verification
         context.verify_mode = self.verify_mode
         context.check_hostname = True
@@ -56,6 +63,7 @@ def _create_ssl_context(self):
         context.minimum_version = ssl.TLSVersion.TLSv1_2
         
         # Disable insecure protocols
+        context.options |= ssl.OP_NO_SSLv2
         context.options |= ssl.OP_NO_SSLv3
         context.options |= ssl.OP_NO_TLSv1
         context.options |= ssl.OP_NO_TLSv1_1
@@ -65,6 +73,7 @@ def _create_ssl_context(self):
     def get_cert_fingerprint(self, hostname, port=443):
         """
         Get the SHA-256 fingerprint of a server's certificate.
+        
         Args:
             hostname: Server hostname
             port: Server port (default 443)
@@ -73,6 +82,7 @@ def get_cert_fingerprint(self, hostname, port=443):
             str: Certificate SHA-256 fingerprint
         """
         context = self._create_ssl_context()
+        
         with socket.create_connection((hostname, port), timeout=10) as sock:
             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                 cert = ssock.getpeercert(binary_form=True)
@@ -81,6 +91,7 @@ def get_cert_fingerprint(self, hostname, port=443):
     def verify_certificate_pinning(self, hostname, port=443):
         """
         Verify that a server's certificate matches pinned hash.
+        
         Args:
             hostname: Server hostname
             port: Server port (default 443)
@@ -89,6 +100,7 @@ def verify_certificate_pinning(self, hostname, port=443):
             CertificatePinningError: If certificate doesn't match pinned hash
         """
         if not self.pinned_cert_hashes:
+            # No pinning configured, skip
             return True
             
         cert_hash = self.get_cert_fingerprint(hostname, port)
@@ -97,6 +109,7 @@ def verify_certificate_pinning(self, hostname, port=443):
         if cert_hash not in self.pinned_cert_hashes:
             raise CertificatePinningError(
                 f"Certificate pinning failed for {hostname}. "
+                f"Expected one of: {self.pinned_cert_hashes}, got: {cert_hash}"
             )
         
         return True
@@ -104,6 +117,7 @@ def verify_certificate_pinning(self, hostname, port=443):
     def secure_get(self, url, **kwargs):
         """
         Perform secure GET request with certificate verification.
+        
         Args:
             url: URL to fetch
             **kwargs: Additional requests parameters
@@ -112,6 +126,7 @@ def secure_get(self, url, **kwargs):
             requests.Response: Response object
             
         Raises:
+            TLSSecurityError: If security validation fails
         """
         parsed = urlparse(url)
         hostname = parsed.hostname
@@ -119,6 +134,7 @@ def secure_get(self, url, **kwargs):
         
         # Verify certificate pinning before request
         if self.pinned_cert_hashes:
+            self.verify_certificate_pinning(hostname, port)
         
         # Perform request with strict verification
         response = self.session.get(
@@ -126,6 +142,7 @@ def secure_get(self, url, **kwargs):
             verify=True,  # Always verify certificates
             timeout=kwargs.get('timeout', 30)
         )
+        
         return response
 
 
@@ -133,6 +150,7 @@ class BGPAttackSimulator:
     """
     Simulates BGP hijacking attack and demonstrates secure mitigation.
     """
+    
     def __init__(self):
         self.legitimate_ips = set()
         self.hijacked_ips = set()
@@ -140,6 +158,7 @@ def __init__(self):
     def add_legitimate_ip(self, ip):
         """
         Add a legitimate IP address for a domain.
+        
         Args:
             ip: IP address string
         """
@@ -148,6 +167,7 @@ def add_legitimate_ip(self, ip):
     def is_ip_hijacked(self, ip):
         """
         Check if an IP address has been hijacked.
+        
         Args:
             ip: IP address string
             
@@ -155,12 +175,14 @@ def is_ip_hijacked(self, ip):
             bool: True if IP is not in legitimate set
|false
         """
         return ip not in self.legitimate_ips
+    
     def simulate_bgp_hijack(self, domain, malicious_ip):
         """
         Simulate a BGP hijack by returning a malicious IP.
+        
         Args:
             domain: Target domain
             malicious_ip: Attacker-controlled IP
             
@@ -168,6 +190,7 @@ def simulate_bgp_hijack(self, domain, malicious_ip):
             str: The malicious IP (simulating DNS resolution compromise)
         """
         print(f"[BGP HIJACK] Domain {domain} resolved to malicious IP: {malicious_ip}")
+        return malicious_ip
 
 
 def create_secure_ssl_context():
@@ -177,6 +200,7 @@ def create_secure_ssl_context():
     Returns:
         ssl.SSLContext: Secure SSL context
     """
+    context = ssl.create_default_context