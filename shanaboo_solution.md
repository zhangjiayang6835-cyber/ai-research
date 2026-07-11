Based on the issue description, I need to fix a DNS Zone Transfer vulnerability by:
1. Restricting AXFR to trusted slave servers only
2. Enabling TSIG signature authentication
3. Implementing split-horizon DNS for internal domains

Since the repo structure shows this is a security research platform with various fix files, I'll create a comprehensive DNS configuration fix. The most appropriate approach is to create a fix file that addresses all three requirements.

```diff
--- /dev/null
+++ b/fix-dns-zone-transfer.py
@@ -0,0 +1,298 @@
+#!/usr/bin/env python3
+"""
+DNS Zone Transfer Security Fix
+==============================
+Fixes: AXFR unrestricted → Internal network mapping leak
+
+Implements:
+1. Restrict AXFR to trusted slave IPs only
+2. Enable TSIG signature authentication
+3. Split-horizon DNS for internal/external views
+
+Usage: python3 fix-dns-zone-transfer.py [--apply] [--dry-run]
+"""
+
+import os
+import sys
+import json
+import hashlib
+import hmac
+import base64
+import ipaddress
+import argparse
+from datetime import datetime, timedelta
+from typing import List, Dict, Set, Optional, Tuple
+
+
+# ============================================================================
+# Configuration
+# ============================================================================
+
+class DNSSecurityConfig:
+    """Secure DNS configuration with split-horizon and TSIG support."""
+    
+    # Trusted slave DNS servers (IPs allowed to perform AXFR)
+    TRUSTED_SLAVES: List[str] = [
+        "10.0.1.10",      # Internal slave DNS 1
+        "10.0.1.11",      # Internal slave DNS 2
+        "192.168.50.5",   # DMZ slave DNS
+    ]
+    
+    # TSIG keys (name → base64-encoded secret)
+    TSIG_KEYS: Dict[str, str] = {
+        "slave-dns-1.internal.": "YmFzZTY0ZW5jb2RlZHRzaWdrZXkxMjM0NTY3ODkwYWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NQ==",
+        "slave-dns-2.internal.": "YmFzZTY0ZW5jb2RlZHRzaWdrZXkyMjM0NTY3ODkwYWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NQ==",
+        "dmz-slave.internal.":   "YmFzZTY0ZW5jb2RlZHRzaWdrZXkzMjM0NTY3ODkwYWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NQ==",
+    }
+    
+    # TSIG algorithm
+    TSIG_ALGORITHM = "hmac-sha256"
+    
+    # Split-horizon: internal zones (never exposed externally)
+    INTERNAL_ZONES: Set[str] = {
+        "internal.example.com",
+        "admin.internal.example.com",
+        "db.internal.example.com",
+        "monitoring.internal.example.com",
+        "vpn.internal.example.com",
+        "ci.internal.example.com",
+        "backup.internal.example.com",
+    }
+    
+    # Split-horizon: internal-only records per zone
+    INTERNAL_RECORDS: Dict[str, List[Dict[str, str]]] = {
+        "internal.example.com": [
+            {"name": "ldap.internal.example.com.", "type": "A", "value": "10.0.2.10"},
+            {"name": "postgres.internal.example.com.", "type": "A", "value": "10.0.2.20"},
+            {"name": "redis.internal.example.com.", "type": "A", "value": "10.0.2.30"},
+            {"name": "k8s-api.internal.example.com.", "type": "A", "value": "10.0.3.1"},
+            {"name": "vault.internal.example.com.", "type": "A", "value": "10.0.3.10"},
+        ],
+        "admin.internal.example.com": [
+            {"name": "admin.internal.example.com.", "type": "A", "value": "10.0.4.1"},
+            {"name": "jenkins.internal.example.com.", "type": "CNAME", "value": "admin.internal.example.com."},
+        ],
+        "db.internal.example.com": [
+            {"name": "db-master.internal.example.com.", "type": "A", "value": "10.0.5.10"},
+            {"name": "db-slave.internal.example.com.", "type": "A", "value": "10.0.5.11"},
+        ],
+    }
+    
+    # External zones (publicly resolvable)
+    EXTERNAL_ZONES: Set[str] = {
+        "example.com",
+        "www.example.com",
+        "api.example.com",
+        "cdn.example.com",
+    }
+    
+    # External-only records
+    EXTERNAL_RECORDS: Dict[str, List[Dict[str, str]]] = {
+        "example.com": [
+            {"name": "example.com.", "type": "A", "value": "203.0.113.10"},
+            {"name": "example.com.", "type": "MX", "value": "10 mail.example.com."},
+            {"name": "example.com.", "type": "TXT", "value": '"v=spf1 mx -all"'},
+        ],
+        "www.example.com": [
+            {"name": "www.example.com.", "type": "A", "value": "203.0.113.10"},
+        ],
+        "api.example.com": [
+            {"name": "api.example.com.", "type": "A", "value": "203.0.113.20"},
+        ],
+    }
+
+
+# ============================================================================
+# TSIG Signature Verification
+# ============================================================================
+
+class TSIGVerifier:
+    """Verify TSIG-signed DNS requests."""
+    
+    def __init__(self, keys: Dict[str, str], algorithm: str = "hmac-sha256"):
+        self.keys = {}
+        for name, b64_secret in keys.items():
+            self.keys[name] = base64.b64decode(b64_secret)
+        self.algorithm = algorithm
+    
+    def verify_request(
