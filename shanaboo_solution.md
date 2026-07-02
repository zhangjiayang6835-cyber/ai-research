 ```diff
--- a/src/webrtc_handler.py
+++ b/src/webrtc_handler.py
@@ -0,0 +1,156 @@
+"""
+WebRTC handler with DNS rebinding protection.
+ sovereign security fix for DNS Rebinding + WebRTC → Internal Network Reconnaissance
+"""
+
+import ipaddress
+import re
+import socket
+from urllib.parse import urlparse
+
+
+class DNSRebindingProtection:
+    """
+    Protects against DNS rebinding attacks by validating that resolved IPs
+    are not internal/private addresses that could be used for reconnaissance.
+    """
+    
+    # Private/internal IP ranges that should not be accessible
+    PRIVATE_NETWORKS = [
+        ipaddress.ip_network('0.0.0.0/8'),       # Current network
+        ipaddress.ip_network('10.0.0.0/8'),      # Private
+        ipaddress.ip_network('127.0.0.0/8'),     # Loopback
+        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
+        ipaddress.ip_network('172.16.0.0/12'),   # Private
+        ipaddress.ip_network('192.0.0.0/24'),    # IETF Protocol Assignments
+        ipaddress.ip_network('192.0.2.0/24'),    # TEST-NET-1
+        ipaddress.ip_network('192.88.99.0/24'),  # 6to4 Relay Anycast
+        ipaddress.ip_network('192.168.0.0/16'),  # Private
+        ipaddress.ip_network('198.18.0.0/15'),   # Benchmarking
+        ipaddress.ip_network('198.51.100.0/24'), # TEST-NET-2
+        ipaddress.ip_network('203.0.113.0/24'),  # TEST-NET-3
+        ipaddress.ip_network('224.0.0.0/4'),     # Multicast
+        ipaddress.ip_network('240.0.0.0/4'),     # Reserved
+        ipaddress.ip_network('255.255.255.255/32'), # Broadcast
+    ]
+    
+    # IPv6 private ranges
+    PRIVATE_NETWORKS_V6 = [
+        ipaddress.ip_network('::1/128'),         # Loopback
+        ipaddress.ip_network('fc00::/7'),         # Unique local
+        ipaddress.ip_network('fe80::/10'),        # Link-local
+        ipaddress.ip_network('::ffff:0:0/96'),    # IPv4-mapped
+    ]
+    
+    @classmethod
+    def is_private_ip(cls, ip_str):
+        """Check if an IP address is private/internal."""
+        try:
+            ip = ipaddress.ip_address(ip_str)
+            if isinstance(ip, ipaddress.IPv4Address):
+                for network in cls.PRIVATE_NETWORKS:
+                    if ip in...