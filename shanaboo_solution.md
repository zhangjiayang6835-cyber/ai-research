 ```diff
--- a/src/webrtc_handler.py
+++ b/src/webrtc_handler.py
@@ -0,0 +1,247 @@
+"""
+Secure WebRTC handler with DNS rebinding and internal network protection.
+Fixes DNS Rebinding + WebRTC → Internal Network Reconnaissance vulnerability.
+"""
+
+import ipaddress
+import re
+import socket
+from functools import wraps
+from typing import Callable, List, Optional, Set
+
+
+class DNSRebindingProtection:
+    """
+    Protects against DNS rebinding attacks by validating IP addresses
+    and preventing access to internal/private network ranges.
+    """
+    
+    # Private/internal IP ranges that should never be accessible
+    PRIVATE_RANGES: List[ipaddress.IPv4Network] = [
+        ipaddress.ip_network('10.0.0.0/8'),
+        ipaddress.ip_network('172.16.0.0/12'),
+        ipaddress.ip_network('192.168.0.0/16'),
+        ipaddress.ip_network('127.0.0.0/8'),
+        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
+        ipaddress.ip_network('0.0.0.0/8'),       # Current network
+        ipaddress.ip_network('224.0.0.0/4'),     # Multicast
+        ipaddress.ip_network('240.0.0.0/4'),     # Reserved
+    ]
+    
+    # IPv6 private ranges
+    PRIVATE_RANGES_V6: List[ipaddress.IPv6Network] = [
+        ipaddress.ip_network('::1/128'),          # Loopback
+        ipaddress.ip_network('fc00::/7'),          # Unique local
+        ipaddress.ip_network('fe80::/10'),         # Link-local
+        ipaddress.ip_network('::ffff:0:0/96'),     # IPv4-mapped
+    ]
+    
+    # Cache for resolved hostnames to prevent TOCTOU attacks
+    _dns_cache: dict = {}
+    
+    @classmethod
+    def is_private_ip(cls, ip_str: str) -> bool:
+        """Check if an IP address is in a private/internal range."""
+        try:
+            ip = ipaddress.ip_address(ip_str)
+            if isinstance(ip, ipaddress.IPv4Address):
+                return any(ip in network for network in cls.PRIVATE_RANGES)
+            else:
+                return any(ip in network for network in cls.PRIVATE_RANGES_V6)
+        except ValueError:
+            return False
+    
+    @classmethod
+    def validate_hostname(cls, hostname: str, expected_ips: Optional[List[str]] = None) -> List[str]:
+        """
+        Validate a hostname and return its resolved IPs.
+        Raises exception if any IP is private/internal.
+        """
+        if not hostname or not isinstance(hostname, str):
+            raise ValueError("Invalid hostname")
+        
+        # Prevent direct IP addresses as hostnames (common in DNS rebinding)
+        try:
+            ipaddress.ip_address(hostname)
+            # It's an IP address, validate it directly
+            if cls.is_private_ip(hostname):
+                raise SecurityError(f"Direct private IP access blocked: {hostname}")
+            return [hostname]
+        except ValueError:
+            pass  # Not an IP, continue with hostname validation
+        
+        # Check for suspicious patterns
+        if cls._is_suspicious_hostname(hostname):
+            raise SecurityError(f"Suspicious hostname pattern detected: {hostname}")
+        
+        # Resolve hostname
+        try:
+            resolved_ips = socket.gethostbyname_ex(hostname)[2]
+        except socket.gaierror:
+            raise SecurityError(f"Could not resolve hostname: {hostname}")
+        
+        # Validate all resolved IPs
+        for ip in resolved_ips:
+            if cls.is_private_ip(ip):
+                raise SecurityError(
+                    f"Hostname {hostname} resolves to private IP {ip}. "
+                    f"DNS rebinding attack detected."
+                )
+        
+        return resolved_ips
+    
+    @classmethod
+    def _is_suspicious_hostname(cls, hostname: str) -> bool:
+        """Detect suspicious hostname patterns used in DNS rebinding."""
+        # Check for IP-like patterns in hostname
+        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
+        if ip_pattern.match(hostname):
+            return True
+        
+        # Check for very short TTL patterns (often used in rebinding)
+        # This is a heuristic - real protection comes from IP validation
+        suspicious_patterns = [
+            r'xip\.io$',
+            r'nip\.io$',
+            r'sslip\.io$',
+        ]
+        for pattern in suspicious_patterns:
+            if re.search(pattern, hostname, re.IGNORECASE):
+                return True
+        
+        return False
+
+
+class SecurityError(Exception):
+    """Raised when a security violation is detected."""
+    pass
+
+
+class SecureWebRTC:
+    """
+    Secure WebRTC connection handler that prevents internal network reconnaissance.
+    """
+    
+    def __init__(self):
+        self.allowed_ice_servers: List[dict] = []
+        self.blocked_candidates: Set[str] = set()
+        self.connection_validated = False
+    
+    def validate_ice_server(self, server_url: str) -> bool:
+        """
+        Validate an ICE server URL to prevent DNS rebinding attacks.
+        Only allows public STUN/TURN servers.
+        """
+        # Parse URL to extract hostname
+        from urllib.parse import urlparse
+        parsed = urlparse(server_url)
+        hostname = parsed.hostname
+        
+        if not hostname:
+            raise SecurityError(f"Invalid ICE server URL: {server_url}")
+        
+        # Validate the hostname - this will raise SecurityError if private
+        DNSRebindingProtection.validate_hostname(hostname)
+        
+        # Additional check: only allow known public STUN/TURN servers
+        # or validate that resolved IPs are public
+        return True
+    
+    def filter_ice_candidate(self, candidate: dict) -> Optional[dict]:
+        """
+        Filter out ICE candidates that expose internal network information.
+        Returns the candidate if safe, None if it should be blocked.
+        """
+        if not candidate:
+            return None
+        
+        # Check for IP address in candidate
+        candidate_str = str(candidate)
+        
+        # Extract IP from candidate string (simplified parsing)
+        # Real implementation would use proper SDP parsing
+        ip_pattern = re.compile(r