 ```diff
--- a/fix-sidecar-injection.py
+++ b/fix-sidecar-injection.py
@@ -1,4 +1,4 @@
-#!/usr/bin/env python3
+#!/usr/bin/env python3
 """
 BGP Hijacking Simulation → TLS Certificate Bypass Fix
 
@@ -6,6 +6,7 @@
 This module provides secure TLS certificate validation to prevent
 BGP hijacking attacks that attempt to bypass certificate checks.
 """
+
 import hashlib
 import hmac
 import os
@@ -13,6 +14,7 @@
 import ssl
 import subprocess
 import sys
+import ipaddress
 from urllib.parse import urlparse
 
 
@@ -20,6 +22,7 @@
     """Custom exception for TLS security errors."""
     pass
 
+
 class CertificatePinningError(TLSSecurityError):
     """Raised when certificate pinning fails."""
     pass
@@ -29,6 +32,7 @@
 # Certificate Pinning Database
 # =============================================================================
 
+
 class CertificatePinManager:
     """
     Manages pinned certificates for known services.
@@ -36,7 +40,7 @@
     """
     
     # Known certificate fingerprints (SHA-256)
-    # In production, these would be loaded from a secure configuration
+    # In production, these would be loaded from a secure configuration.
     _PINNED_CERTS = {
         'api.github.com': [
             'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
@@ -46,7 +50,7 @@
             'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
         ],
     }
-    
+
     @classmethod
     def get_expected_pins(cls, hostname):
         """Get expected certificate pins for a hostname."""
@@ -56,7 +60,7 @@
     @classmethod
     def verify_pin(cls, hostname, cert_der):
         """
-        Verify certificate pin against known good pins.
+        Verify a certificate pin against known good pins.
         
         Args:
             hostname: The hostname to verify
@@ -67,7 +71,7 @@
         """
         expected_pins = cls.get_expected_pins(hostname)
         if not expected_pins:
-            # No pinning for this host, skip
+            # No pinning for this host; skip
             return True
         
         cert_hash = hashlib.sha256(cert_der).digest()
@@ -81,6 +85,7 @@
 # Secure TLS Context Creation
 # =============================================================================
 
+
 def create_secure_ssl_context():
     """
     Create a secure SSL context with proper certificate validation.
@@ -89,7 +94,7 @@
         ssl.SSLContext: A properly configured SSL context
     """
     context = ssl.create_default_context(
-        purpose=ssl.Purpose.SERVER_AUTH,
+        purpose=ssl.Purpose.SERVER_AUTH
     )
     
     # Enforce TLS 1.2 or higher
@@ -97,7 +102,7 @@
     context.minimum_version = ssl.TLSVersion.TLSv1_2
     
     # Enable certificate verification
-    context.verify_mode = ssl.CERT_REQUIRED
+    context.verify_mode = ssl.CERT_REQUIRED  # noqa: S322
     context.check_hostname = True
     
     # Disable insecure protocols and ciphers
@@ -105,7 +110,7 @@
     context.options |= ssl.OP_NO_SSLv3
     context.options |= ssl.OP_NO_TLSv1
     context.options |= ssl.OP_NO_TLSv1_1
-    
+
     return context
 
 
@@ -113,6 +118,7 @@
 # Secure URL Fetching with Certificate Validation
 # =============================================================================
 
+
 def secure_fetch_url(url, timeout=30, expected_pins=None):
     """
     Securely fetch a URL with full certificate validation.
@@ -126,7 +132,7 @@
     Returns:
         bytes: The response content
         
-    Raises:
+    Raises:  # noqa: D401
         TLSSecurityError: If certificate validation fails
         CertificatePinningError: If certificate pinning fails
     """
@@ -134,7 +140,7 @@
     if not parsed.scheme == 'https':
         raise TLSSecurityError(f"Non-HTTPS URL not allowed: {url}")
     
-    hostname = parsed.hostname
+    hostname = parsed.hostname or ''
     port = parsed.port or 443
     
     context = create_secure_ssl_context()
@@ -142,7 +148,7 @@
     try:
         with socket.create_connection((hostname, port), timeout=timeout) as sock:
             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
-                # Get certificate
+                # Get the peer certificate
                 cert = ssock.getpeercert(binary_form=True)
                 if not cert:
                     raise TLSSecurityError("No certificate presented by server")
@@ -152,7 +158,7 @@
                     pin_manager = CertificatePinManager()
                     if not pin_manager.verify_pin(hostname, cert):
                         raise CertificatePinningError(
-                            f"Certificate pinning failed for {hostname}"
+                            f"Certificate pinning failed for {hostname}",
                         )
                 
                 # Read response
@@ -164,6 +170,7 @@
 # BGP Hijacking Detection
 # =============================================================================
 
+
 class BGPHijackingDetector:
     """
     Detects potential BGP hijacking attempts.
@@ -171,7 +178,7 @@
     """
     
     # Known legitimate IP ranges for services
-    # In production, load from secure database
+    # In production, load from a secure database.
     _LEGITIMATE_RANGES = {
         'api.github.com': ['140.82.112.0/20', '140.82.121.0/24'],
         'api.openai.com': ['104.18.0.0/20'],
@@ -186,7 +193,7 @@
             hostname: The hostname to check
             
         Returns:
-            list: List of legitimate IP networks
+            list: A list of legitimate IP networks
         """
         return cls._LEGITIMATE_RANGES.get(hostname, [])
     
@@ -202,7 +209,7 @@
             True if the IP is in a legitimate range
         """
         try:
-            ip_obj = ipaddress.ip_address(ip_address)
+            ip_obj = ipaddress.ip_address(ip_address)  # noqa: F821
             legitimate_ranges = cls.get_legitimate_ranges(hostname)
             
             for range_str in legitimate_ranges:
@@ -213,7 +220,7 @@
             return False
         
         return False
-    
+
     @classmethod
     def verify_ip_legitimacy(cls, hostname, ip_address):
         """
@@ -226,7 +233,7 @@
             True if the IP is legitimate
             
         Raises:
-            TLSSecurityError: If IP is not in legitimate range
+            TLSSecurityError: If the IP is not in a legitimate range
         """
         if not cls.is_ip_in_legitimate_range(hostname, ip_address):
             raise TLSSecurityError(
@@ -239,6 +246,7 @@
 # Main Security Wrapper
