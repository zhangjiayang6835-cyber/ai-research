 ```diff
--- a/fix.py
+++ b/fix.py
@@ -0,0 +1,0 @@
-# Placeholder fix file - needs to be replaced with actual BGP hijacking TLS bypass fix
+#!/usr/bin/env python3
+"""
+BGP Hijacking Simulation → TLS Certificate Bypass Fix
+
+This module provides secure TLS certificate verification that prevents
+BGP hijacking attacks by properly validating certificates and using
+certificate pinning where appropriate.
+"""
+
+import ssl
+import socket
+import hashlib
+import base64
+from urllib.parse import urlparse
+from typing import Optional, Dict, Set
+import logging
+
+logger = logging.getLogger(__name__)
+
+
+class CertificatePinStore:
+    """
+    Secure certificate pin store for critical domains.
+    Prevents BGP hijacking by ensuring certificates match expected pins.
+    """
+    
+    def __init__(self):
+        self._pins: Dict[str, Set[str]] = {}
+        self._lock = None  # Simple implementation, use threading.Lock in production
+    
+    def add_pin(self, hostname: str, pin: str) -> None:
+        """Add a known good certificate pin for a hostname."""
+        if hostname not in self._pins:
+            self._pins[hostname] = set()
+        self._pins[hostname].add(pin)
+    
+    def verify_pin(self, hostname: str, cert_der: bytes) -> bool:
+        """Verify a certificate against stored pins."""
+        if hostname not in self._pins:
+            # No pin for this host - require explicit pin or use other validation
+            logger.warning(f"No certificate pin for {hostname}")
+            return False
+        
+        # Calculate SPKI hash (Subject Public Key Info)
+        try:
+            from cryptography import x509
+            from cryptography.hazmat.primitives import serialization
+            
+            cert = x509.load_der_x509_certificate(cert_der)
+            spki = cert.public_key().public_bytes(
+                serialization.Encoding.DER,
+                serialization.PublicFormat.SubjectPublicKeyInfo
+            )
+            pin = base64.b64encode(hashlib.sha256(spki).digest()).decode('ascii')
+            
+            return pin in self._pins[hostname]
+        except ImportError:
+            # Fallback: hash the entire certificate
+            pin = base64.b64encode(hashlib.sha256(cert_der).digest()).decode('ascii')
+            fallback_pin = hashlib.sha256(cert_der).hexdigest()
+            return pin in self._pins[hostname] or fallback_pin in self._pins[hostname]
+
+
+class SecureTLSContext:
+    """
+    Creates a secure TLS context with proper certificate validation
+    to prevent BGP hijacking and man-in-the-middle attacks.
+    """
+    
+    # Known certificate transparency log endpoints
+    CT_LOGS = [
+        "ct.googleapis.com",
+        "ct1.digicert-ct.com",
+    ]
+    
+    def __init__(self, verify_mode: int = ssl.CERT_REQUIRED):
+        self.context = ssl.create_default_context()
+        self.context.verify_mode = verify_mode
+        self.context.check_hostname = True
+        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
+        
+        # Disable insecure protocols
+        self.context.options |= ssl.OP_NO_SSLv2
+        self.context.options |= ssl.OP_NO_SSLv3
+        self.context.options |= ssl.OP_NO_TLSv1
+        self.context.options |= ssl.OP_NO_TLSv1_1
+        
+        # Certificate pinning store
+        self.pin_store = CertificatePinStore()
+        
+        # Track expected hostnames to detect hijacking
+        self._expected_hosts: Dict[str, str] = {}
+    
+    def set_expected_ip(self, hostname: str, expected_ip: str) -> None:
+        """
+        Set the expected IP address for a hostname.
+        Helps detect BGP hijacking where DNS resolves to wrong IP.
+        """
+        self._expected_hosts[hostname] = expected_ip
+    
+    def add_trusted_pin(self, hostname: str, pin: str) -> None:
+        """Add a certificate pin for a hostname."""
+        self.pin_store.add_pin(hostname, pin)
+    
+    def _verify_ip_not_hijacked(self, hostname: str, resolved_ip: str) -> bool:
+        """Check if the resolved IP matches expected IP for hostname."""
+        if hostname not in self._expected_hosts:
+            return True  # No expectation set
+        return self._expected_hosts[hostname] == resolved_ip
+    
+    def create_secure_connection(
+        self,
+        url: str,
+        timeout: float = 30.0,
+        port: Optional[int] = None
+    ) -> ssl.SSLSocket:
+        """
+        Create a secure connection with full verification.
+        
+        Args:
+            url: The URL to connect to
+            timeout: Connection timeout in seconds
+            port: Optional port override
+            
+        Returns:
+            ssl.SSLSocket: Verified secure socket
+            
+        Raises:
+            ssl.SSLError: If certificate validation fails
+            ConnectionError: If BGP hijacking is detected
+        """
+        parsed = urlparse(url)
+        hostname = parsed.hostname or url
+        default_port = 443 if parsed.scheme == 'https' else 80
+        target_port = port or parsed.port or default_port
+        
+        # Resolve IP and check for potential hijacking
+        try:
+            addr_info = socket.getaddrinfo(hostname, target_port, 
+                                           socket.AF_INET, socket.SOCK_STREAM)
+            if not addr_info:
+                raise ConnectionError(f"Could not resolve {hostname}")
+            
+            resolved_ip = addr_info[0][4][0]
+            
+            # Check for BGP hijacking via unexpected IP
+            if not self._verify_ip_not_hijacked(hostname, resolved_ip):
+                raise ConnectionError(
+                    f"Potential BGP hijacking detected: "
+                    f"{hostname} resolved to unexpected IP {resolved_ip}. "
+                    f"Expected: {self._expected_hosts[hostname]}"
+                )
+                
+        except socket.gaierror as e:
+            raise ConnectionError(f"DNS resolution failed for {hostname}: {e}")
+        
+        # Create connection with certificate verification
+        try:
+            with socket.create_connection((hostname, target_port), 
+                                          timeout=timeout) as sock:
+                
+                # Wrap with TLS
+                with self.context.wrap_socket(
+                    sock, 
+                    server_hostname=hostname
+                ) as ssock:
+                    # Get certificate for additional verification
+                    cert = ssock.getpeercert(binary_form=True)
+                    
+                    if cert:
+                        # Verify certificate pin if