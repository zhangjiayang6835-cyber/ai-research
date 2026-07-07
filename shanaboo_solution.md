 ```diff
--- a/fix-sidecar-injection.py
+++ b/fix-sidecar-injection.py
@@ -1,4 +1,4 @@
-#!/usr/bin/env python3
+#!/usr/bin/env python3
 """
 BGP Hijacking Simulation → TLS Certificate Bypass Fix
 
@@ -6,6 +6,7 @@
 - Proper TLS certificate validation
 - Certificate pinning to prevent MITM attacks
 - BGP hijacking detection and prevention
+- Hostname verification and certificate chain validation
 """
 
 import ssl
@@ -14,6 +15,8 @@
 import hashlib
 import base64
 import socket
+import ipaddress
+from urllib.parse import urlparse
 from typing import Optional, List, Dict, Tuple
 
 
@@ -21,6 +24,7 @@
     """Custom exception for TLS security failures."""
     pass
 
+
 class CertificatePinningError(TLSSecurityError):
     """Raised when certificate pinning validation fails."""
     pass
@@ -30,6 +34,10 @@
     """Raised when BGP hijacking is detected."""
     pass
 
+class HostnameValidationError(TLSSecurityError):
+    """Raised when hostname validation fails."""
+    pass
+
 
 class CertificatePin:
     """Represents a pinned certificate with its expected hash."""
@@ -37,7 +45,7 @@
     def __init__(self, hostname: str, expected_hash: str, hash_algorithm: str = "sha256"):
         self.hostname = hostname
         self.expected_hash = expected_hash
-        self.hash_algorithm = hash_algorithm
+        self.hash_algorithm = hash_algorithm.lower()
     
     def verify(self, cert_der: bytes) -> bool:
         """Verify certificate matches expected hash."""
@@ -48,6 +56,7 @@
         else:
             raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")
 
+
 class SecureTLSContext:
     """
     Secure TLS context with certificate pinning and BGP hijacking protection.
@@ -56,7 +65,8 @@
     def __init__(self):
         self.pinned_certs: Dict[str, CertificatePin] = {}
         self.trusted_ca_certs: Optional[str] = None
-        self.min_tls_version = ssl.TLSVersion.TLSv1_2
+        self.min_tls_version = ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, 'TLSv1_3') else ssl.TLSVersion.TLSv1_2
+        self.verify_mode = ssl.CERT_REQUIRED
     
     def add_pin(self, pin: CertificatePin) -> None:
         """Add a certificate pin for a hostname."""
@@ -67,6 +77,9 @@
         self.trusted_ca_certs = ca_file
         return self
     
+    def _is_ip_address(self, hostname: str) -> bool:
+        """Check if hostname is an IP address."""
+        try:
+            ipaddress.ip_address(hostname)
+            return True
+        except ValueError:
+            return False
+    
     def _create_ssl_context(self) -> ssl.SSLContext:
         """Create a secure SSL context with proper settings."""
         context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
@@ -74,6 +87,7 @@
         # Set minimum TLS version
         context.minimum_version = self.min_tls_version
         context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
+        context.verify_mode = self.verify_mode
         
         # Load default CA certificates
         if self.trusted_ca_certs:
@@ -81,9 +95,15 @@
         else:
             context.load_default_certs()
         
-        # Disable insecure protocols
-        context.options |= ssl.OP_NO_SSLv2
-        context.options |= ssl.OP_NO_SSLv3
+        # Disable insecure protocols and enable security options
+        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
+        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
+        
+        # Enable certificate verification and hostname checking
+        if hasattr(context, 'hostname_checks_common_name'):
+            context.hostname_checks_common_name = True
+        
+        # Set strong cipher suites
+        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
         
         return context
     
@@ -91,6 +111,10 @@
         """Check for potential BGP hijacking indicators."""
         # Check if IP matches expected DNS resolution
         try:
+            # Validate that hostname is not an IP address for SNI
+            if self._is_ip_address(hostname):
+                return True  # IP addresses can't be hijacked via DNS, but need special handling
+            
             resolved_ips = socket.getaddrinfo(hostname, None)
             resolved = set()
             for info in resolved_ips:
@@ -98,7 +122,7 @@
             
             # If we have a known good IP, verify it matches
             if expected_ip and expected_ip not in resolved:
-                raise BGPHijackingDetected(
+                raise BGPHijackingDetected(
                     f"BGP Hijacking detected: {hostname} resolved to unexpected IP. "
                     f"Expected: {expected_ip}, Got: {resolved}"
                 )
@@ -106,7 +130,7 @@
             return True
             
         except socket.gaierror as e:
-            raise BGPHijackingDetected(f"DNS resolution failed for {hostname}: {e}")
+            raise BGPHijackingDetected(f"DNS resolution failed for {hostname}: {e}")
     
     def verify_certificate_pin(self, hostname: str, cert_der: bytes) -> bool:
         """Verify certificate against pinned hash."""
@@ -117,6 +141,52 @@
             return pin.verify(cert_der)
         
         return True  # No pin set, allow
+    
+    def _verify_hostname(self, ssl_sock: ssl.SSLSocket, hostname: str) -> None:
+        """Verify that the certificate matches the hostname."""
+        # Get the peer certificate
+        cert = ssl_sock.getpeercert()
+        if not cert:
+            raise HostnameValidationError("No certificate received from server")
+        
+        # Use SSL library's built-in hostname verification if available
+        try:
+            ssl.match_hostname(cert, hostname)
+        except ssl.CertificateError as e:
+            raise HostnameValidationError(f"Hostname validation failed: {e}")
+    
+    def _get_certificate_der(self, ssl_sock: ssl.SSLSocket) -> bytes:
+        """Extract certificate in DER format from SSL socket."""
+        cert = ssl_sock.getpeercert(binary_form=True)
+        if not cert:
+            raise TLSSecurityError("Failed to get peer certificate")
+        return cert
+    
+    def create_secure_connection(
+        self,
+        hostname: str,
+        port: int = 443,
+        expected_ip: Optional[str] = None,
+        timeout: float