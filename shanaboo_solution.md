Based on the issue description, this is a DNS Zone Transfer security vulnerability that needs to be fixed. The issue requires:

1. Restricting AXFR to trusted slave servers only
2. Enabling TSIG signature authentication
3. Implementing split-horizon DNS for internal domains

Since the repo structure shows various fix files and a `fixes` directory, I'll create a comprehensive DNS configuration fix. The most appropriate approach is to create a BIND DNS configuration fix that addresses all three requirements.

```diff
--- /dev/null
+++ b/fix-dns-zone-transfer.py
@@ -0,0 +1,204 @@
+#!/usr/bin/env python3
+"""
+DNS Zone Transfer Security Fix
+===============================
+Fixes: AXFR unrestricted → Internal network mapping vulnerability
+
+This script generates secure BIND9 DNS configurations that:
+1. Restrict AXFR to trusted slave servers only
+2. Enable TSIG signature authentication
+3. Implement split-horizon DNS for internal domains
+
+Bounty: $150 | Difficulty: Hard
+"""
+
+import os
+import sys
+import hashlib
+import hmac
+import base64
+import argparse
+from datetime import datetime
+from typing import List, Dict, Optional
+
+
+class DNSSecurityFix:
+    """Generates hardened BIND9 DNS configurations."""
+
+    def __init__(
+        self,
+        domain: str,
+        slave_ips: List[str],
+        internal_subnets: List[str],
+        tsig_key_name: str = "transfer-key",
+        output_dir: str = "/etc/bind",
+    ):
+        self.domain = domain
+        self.slave_ips = slave_ips
+        self.internal_subnets = internal_subnets
+        self.tsig_key_name = tsig_key_name
+        self.output_dir = output_dir
+        self.tsig_secret = self._generate_tsig_secret()
+
+    def _generate_tsig_secret(self) -> str:
+        """Generate a cryptographically secure TSIG key (base64-encoded)."""
+        random_bytes = os.urandom(32)
+        return base64.b64encode(random_bytes).decode("utf-8")
+
+    def generate_named_conf(self) -> str:
+        """Generate the main named.conf with TSIG keys and ACLs."""
+        acl_entries = "\n\t".join(f"{ip};" for ip in self.slave_ips)
+
+        config = f"""// Secure BIND9 Configuration
+// Generated: {datetime.utcnow().isoformat()}Z
+// Domain: {self.domain}
+
+// --- TSIG Key for authenticated zone transfers ---
+key "{self.tsig_key_name}" {{
+    algorithm hmac-sha256;
+    secret "{self.tsig_secret}";
+}};
+
+// --- ACL: Trusted slave servers ---
+acl "trusted-slaves" {{
+    {acl_entries}
+}};
+
+// --- ACL: Internal networks (split-horizon) ---
+acl "internal-networks" {{
+    {self._format_acl(self.internal_subnets)}
+}};
+
+// --- Global options ---
+options {{
+    directory "/var/cache/bind";
+    recursion yes;
+    allow-recursion {{ "internal-networks"; }};
+    allow-query {{ any; }};
+    allow-query-cache {{ "internal-networks"; }};
+
+    // CRITICAL: Restrict zone transfers globally
+    allow-transfer {{ !{{ any; }}; }};
+    allow-update {{ none; }};
+
+    // Rate limiting
+    rate-limit {{
+        responses-per-second 10;
+        slip 2;
+    }};
+
+    // DNSSEC validation
+    dnssec-validation auto;
+
+    // Hide version
+    version "DNS Server";
+
+    listen-on {{ any; }};
+    listen-on-v6 {{ any; }};
+}};
+
+// --- Split-Horizon Views ---
+// Internal view: full zone data including internal hosts
+view "internal" {{
+    match-clients {{ "internal-networks"; }};
+    recursion yes;
+
+    // Zone transfers restricted to slaves with TSIG
+    allow-transfer {{
+        !{{ !"trusted-slaves"; }};
+        key "{self.tsig_key_name}";
+    }};
+
+    zone "{self.domain}" {{
+        type master;
+        file "/etc/bind/zones/internal/db.{self.domain}";
+        allow-transfer {{
+            !{{ !"trusted-slaves"; }};
+            key "{self.tsig_key_name}";
+        }};
+        also-notify {{ {"; ".join(self.slave_ips)}; }};
+        notify yes;
+    }};
+
+    // Reverse zones for internal subnets
+    {self._generate_reverse_zones("internal")}
+}};
+
+// External view: public-only zone data (no internal hosts)
+view "external" {{
+    match-clients {{ !"internal-networks"; }};
+    recursion no;
+
+    // Zone transfers restricted to slaves with TSIG
+    allow-transfer {{
+        !{{ !"trusted-slaves"; }};
+        key "{self.tsig_key_name}";
+    }};
+
+    zone "{self.domain}" {{
+        type master;
+        file "/etc/bind/zones/external/db.{self.domain}";
+        allow-transfer {{
+            !{{ !"trusted-slaves"; }};
+            key "{self.tsig_key_name}";
+        }};
+        also-notify {{ {"; ".join(self.slave_ips)}; }};
+        notify yes;
+    }};
+}};
+"""
+        return config
+
+    def _format_acl(self, subnets: List[str]) -> str:
+        return "\n\t".join(f"{subnet};" for subnet in subnets)
+
+    def _generate_reverse_zones(self, view: str) -> str:
+        """Generate reverse DNS zones for internal subnets."""
+        zones = []
+        for subnet in self.internal_subnets:
+            # Extract network portion for reverse zone name
+            parts = subnet.split("/")[0].split(".")
+            if len(parts) == 4:
+                reverse_zone = f"{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
+                zones.append(f"""
+    zone "{reverse_zone}" {{
+        type master;
+        file "/etc/bind/zones/{view}/db.{reverse_zone}";
+        allow-transfer